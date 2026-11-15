package espresso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	espressofw "github.com/suryakencana007/espresso/v2"

	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

// #163 — the identity throttle's transport half.
//
// identity.WithThrottling makes Login, VerifyTOTP and VerifyRecoveryCode
// return *identity.ThrottledError before any store read. Those errors
// reached mapAuthWireError's default branch and shipped as 500 INTERNAL:
// the limiter reported its own refusal as a server fault. These tests pin
// the fixed contract — 429, the route gate's code, a Retry-After header, and
// no account detail — and the regression that the new branch does not widen
// into its neighbours.
//
// The fakes below return exactly what identity.Core returns; proving the
// error exists is identity/throttle_test.go's job, and this file only has
// to prove the wire mapping. See PHASE7-MULTITENANCY-SKETCH.md, M5
// amendment.

// throttledSecondFactor returns err from whichever second-factor check the
// route chose, so one fake drives both the TOTP and the recovery-code legs.
type throttledSecondFactor struct {
	IdentityService
	err error
}

func (f *throttledSecondFactor) VerifyTOTPPending(context.Context, tenant.ID, string) (string, error) {
	return "u-1", nil
}

func (f *throttledSecondFactor) VerifyTOTP(context.Context, tenant.ID, string, string) error {
	return f.err
}

func (f *throttledSecondFactor) VerifyRecoveryCode(context.Context, tenant.ID, string, string) error {
	return f.err
}

// throttledEnroller stands in for the application's own
// EnrollTOTPViaSession, which is where that leg's limiter lives: the
// method is app policy, not an identity.Core verb.
type throttledEnroller struct {
	IdentityService
	err error
}

func (f *throttledEnroller) EnrollTOTPViaSession(context.Context, tenant.ID, string, string) (*TOTPEnrollment, *AuthResult, error) {
	return nil, nil, f.err
}

type wireErrBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decodeWireErr(t *testing.T, body string) wireErrBody {
	t.Helper()
	var b wireErrBody
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		t.Fatalf("decode error envelope %q: %v", body, err)
	}
	return b
}

// renderThrottled renders err the way the framework writes it and returns the
// recorder, so a test can read the Retry-After header the error now carries.
func renderThrottled(t *testing.T, err error) *httptest.ResponseRecorder {
	t.Helper()
	var w interface {
		WriteResponse(http.ResponseWriter) error
	}
	if !errors.As(err, &w) {
		t.Fatalf("error %v (%T) does not render a response", err, err)
	}
	rec := httptest.NewRecorder()
	if werr := w.WriteResponse(rec); werr != nil {
		t.Fatalf("WriteResponse: %v", werr)
	}
	return rec
}

// assertThrottled429 renders err and asserts the whole contract: 429, the
// route gate's stable code, the fixed message, the Retry-After header (or none
// when the error carried no hint), no leftover body detail, and that none of
// the forbidden strings (the attempted address, the key) reached the body.
func assertThrottled429(t *testing.T, err error, wantSeconds int, forbidden ...string) {
	t.Helper()
	rec := renderThrottled(t, err)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	got := decodeWireErr(t, body)
	if got.Error.Code != ThrottledCode {
		t.Errorf("code = %q, want %q", got.Error.Code, ThrottledCode)
	}
	if got.Error.Message != "too many attempts" {
		t.Errorf("message = %q, want the fixed %q", got.Error.Message, "too many attempts")
	}
	if hdr := rec.Header().Get("Retry-After"); wantSeconds == 0 {
		if hdr != "" {
			t.Errorf("Retry-After = %q on an error that carried no hint", hdr)
		}
	} else if hdr != strconv.Itoa(wantSeconds) {
		t.Errorf("Retry-After = %q, want %d", hdr, wantSeconds)
	}
	// The pre-v2.5.0 body detail is removed, not kept beside the header.
	if strings.Contains(body, "retry_after_seconds") {
		t.Errorf("body still carries the removed retry_after_seconds detail: %s", body)
	}
	for _, s := range forbidden {
		if s != "" && strings.Contains(body, s) {
			t.Errorf("body carries %q; the message must not echo the attempted address or key: %s", s, body)
		}
	}
}

// The branch matches the SENTINEL, not the concrete type: identity returns
// a bare ErrThrottled on some paths and *ThrottledError on the throttled
// ones, and either must map.
func TestWire_ThrottledMapsTo429(t *testing.T) {
	for name, tc := range map[string]struct {
		err         error
		wantSeconds int
	}{
		"sentinel":       {identity.ErrThrottled, 0},
		"throttledError": {&identity.ThrottledError{RetryAfter: 90 * time.Second}, 90},
		"wrapped": {fmt.Errorf("identity: login: %w",
			&identity.ThrottledError{RetryAfter: 90 * time.Second}), 90},
		"zero-hint": {&identity.ThrottledError{}, 0},
	} {
		t.Run(name, func(t *testing.T) {
			assertThrottled429(t, mapAuthWireError(tc.err, defaultValidationMessage), tc.wantSeconds)
		})
	}
}

// TestWire_RetryAfterRoundsUp mirrors TestThrottled_RetryAfterRoundsUp:
// the identity error's Retry-After header and the middleware's must name the
// same instant, and neither may round down to an instant at which the caller
// is still refused.
func TestWire_RetryAfterRoundsUp(t *testing.T) {
	for _, tc := range []struct {
		after time.Duration
		want  int
	}{
		{time.Millisecond, 1},
		{999 * time.Millisecond, 1},
		{time.Second, 1},
		{1500 * time.Millisecond, 2},
		{2 * time.Second, 2},
		{2100 * time.Millisecond, 3},
	} {
		t.Run(tc.after.String(), func(t *testing.T) {
			err := mapAuthWireError(&identity.ThrottledError{RetryAfter: tc.after}, defaultValidationMessage)
			assertThrottled429(t, err, tc.want)
		})
	}
}

// TestWire_RetryAfterHeaderMatchesTheGate pins the structural claim that the
// identity path and the route gate cannot diverge: both call retryAfterSeconds.
// It compares the rendered error's header against setRetryAfter's, so a future
// edit that reintroduces a second rounding for one wait goes red here.
func TestWire_RetryAfterHeaderMatchesTheGate(t *testing.T) {
	for _, after := range []time.Duration{
		time.Millisecond, 999 * time.Millisecond, time.Second,
		1500 * time.Millisecond, 2 * time.Second, 90 * time.Second,
	} {
		err := mapAuthWireError(&identity.ThrottledError{RetryAfter: after}, defaultValidationMessage)
		identityHdr := renderThrottled(t, err).Header().Get("Retry-After")
		gateRec := httptest.NewRecorder()
		setRetryAfter(gateRec, after)
		if gateHdr := gateRec.Header().Get("Retry-After"); identityHdr != gateHdr {
			t.Errorf("after %v: identity answered Retry-After %q, the gate %q", after, identityHdr, gateHdr)
		}
	}
}

// mapTOTPWireError has no throttled case of its own — it inherits the auth
// mapping through its fallthrough. Asserted so a future edit that turns
// that fallthrough into a hard default is caught at the second-factor
// surface.
func TestWire_TOTPFallsThroughToThrottled(t *testing.T) {
	err := mapTOTPWireError(&identity.ThrottledError{RetryAfter: 30 * time.Second}, defaultValidationMessage)
	assertThrottled429(t, err, 30)
}

// TestWire_ThrottledBranchDoesNotWiden: the neighbours keep the answers
// they had. A branch that swallowed credentials or TOTP failures would be
// worse than the missing mapping it replaces — it would tell an attacker
// to back off from a wrong password.
func TestWire_ThrottledBranchDoesNotWiden(t *testing.T) {
	code, body := wire(t, mapAuthWireError(identity.ErrInvalidCredentials, defaultValidationMessage))
	if code != http.StatusUnauthorized || decodeWireErr(t, body).Error.Code != "INVALID_CREDENTIALS" {
		t.Errorf("ErrInvalidCredentials = %d %s, want 401 INVALID_CREDENTIALS", code, body)
	}

	code, body = wire(t, mapAuthWireError(errors.New("database is down"), defaultValidationMessage))
	if code != http.StatusInternalServerError {
		t.Errorf("an unmapped error = %d %s, want 500", code, body)
	}

	code, body = wire(t, mapTOTPWireError(identity.ErrInvalidTOTP, defaultValidationMessage))
	if code != http.StatusUnauthorized || decodeWireErr(t, body).Error.Code != "INVALID_TOTP" {
		t.Errorf("ErrInvalidTOTP = %d %s, want 401 INVALID_TOTP", code, body)
	}
}

// --- the route handlers ------------------------------------------------

// TestAuthRoutes_LoginThrottledIs429 drives the real handler with the error
// identity.Core returns when WithThrottling refuses. The email and password
// are asserted ABSENT from the body: the limiter must not echo the
// attempted address, which is what turns a refusal into a receipt.
func TestAuthRoutes_LoginThrottledIs429(t *testing.T) {
	const email = "victim@example.com"
	const password = "hunter2"
	svc := &fakeIdentity{login: func(string, string) (AuthResult, error) {
		return AuthResult{}, &identity.ThrottledError{RetryAfter: 90 * time.Second}
	}}

	_, err := testRoutes(t, svc).Login(context.Background(),
		&espressofw.JSON[LoginReq]{Data: LoginReq{Email: email, Password: password}})
	assertThrottled429(t, err, 90, email, password)
}

// TestAuthRoutes_TOTPVerifyThrottledIs429 runs both second-factor legs:
// six digits pick VerifyTOTP, anything else VerifyRecoveryCode. The
// session token is asserted absent, since it names the pending login.
func TestAuthRoutes_TOTPVerifyThrottledIs429(t *testing.T) {
	for _, tc := range []struct{ name, code string }{
		{"totp", "123456"},
		{"recovery", "ABCD-EFGH"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const session = "session-tok"
			svc := &throttledSecondFactor{err: &identity.ThrottledError{RetryAfter: 30 * time.Second}}

			_, err := testRoutes(t, svc).VerifyTOTP(context.Background(),
				&espressofw.JSON[TOTPVerifyReq]{Data: TOTPVerifyReq{SessionToken: session, Code: tc.code}})
			assertThrottled429(t, err, 30, session, tc.code)
		})
	}
}

// TestAuthRoutes_EnrollSessionThrottledIs429 covers the leg that only a
// throttled application can produce: EnrollTOTPViaSession is app policy,
// so the 429 arrives when the app's implementation returns ErrThrottled
// (typically because it validated current_code through a throttled
// VerifyTOTP).
func TestAuthRoutes_EnrollSessionThrottledIs429(t *testing.T) {
	const session = "session-tok"
	svc := &throttledEnroller{err: &identity.ThrottledError{RetryAfter: 15 * time.Second}}

	_, err := testRoutes(t, svc).EnrollSession(context.Background(),
		&espressofw.JSON[TOTPEnrollSessionReq]{
			Data: TOTPEnrollSessionReq{SessionToken: session, CurrentCode: "123456"},
		})
	assertThrottled429(t, err, 15, session)
}

// realCoreLogin adapts *identity.Core's Login to the port so the test can
// drive the REAL limiter rather than a fake that returns its error.
type realCoreLogin struct {
	IdentityService
	core *identity.Core
}

func (a *realCoreLogin) Login(ctx context.Context, tid tenant.ID, email, password string) (AuthResult, error) {
	u, tokens, err := a.core.Login(ctx, tid, email, password)
	if err != nil {
		return AuthResult{}, err
	}
	return AuthResult{User: &u, Tokens: tokens}, nil
}

// TestAuthRoutes_LoginWithRealRefusingThrottleIs429 is the issue's own
// scenario end to end: identity.WithThrottling with a Throttle that always
// refuses, driven through the real route handler. The fake-based tests
// above return the error the core is known to produce (proved in
// identity/throttle_test.go); this closes the loop and proves the whole
// chain — limiter, core, port, mapping — answers 429.
func TestAuthRoutes_LoginWithRealRefusingThrottleIs429(t *testing.T) {
	const email = "victim@example.com"
	const password = "hunter2"

	core, err := identity.New(identity.NewMemStore(),
		crypto.NewJWTService(crypto.JWTConfig{
			Secret: "test-secret-long-enough-for-signing",
			TTL:    time.Hour,
			Issuer: "tamper-test",
		}),
		identity.WithThrottling(identity.Throttling{
			Throttle:        &gateThrottle{refuse: true, after: 90 * time.Second},
			LoginKey:        func(_, email string) string { return "login:" + email },
			SecondFactorKey: func(userID, step string) string { return "2fa:" + step + ":" + userID },
		}),
	)
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}

	_, err = testRoutes(t, &realCoreLogin{core: core}).Login(context.Background(),
		&espressofw.JSON[LoginReq]{Data: LoginReq{Email: email, Password: password}})
	assertThrottled429(t, err, 90, email, password)
}
