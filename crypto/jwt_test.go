package crypto

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/suryakencana007/tamper/tenant"
)

// issueSingle mints an access token for the single tenant, authenticated
// now with the local-password ACR. Most tests here are about the token
// envelope and do not care which tenant it is for.
func issueSingle(j *JWTService, userID string) (string, error) {
	return j.IssueAccess(userID, tenant.Single, j.now().Unix(), ACRLocalPassword)
}

// verifySingle verifies an access token for the single tenant and
// returns its subject.
func verifySingle(j *JWTService, tok string) (string, error) {
	claims, err := j.VerifyAccess(tok, tenant.Single)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

func newTestJWT(t *testing.T, secret string) *JWTService {
	t.Helper()
	return NewJWTService(JWTConfig{
		Secret: secret,
		TTL:    time.Hour,
		Issuer: "barista-test",
	})
}

func TestJWT_RoundTrip(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	tok, err := issueSingle(svc, "u-42")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := verifySingle(svc, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != "u-42" {
		t.Errorf("Verify subject = %q, want %q", got, "u-42")
	}
}

func TestJWT_RejectsEmptyUserID(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	_, err := issueSingle(svc, "")
	if err == nil {
		t.Fatalf("Issue: expected error for empty userID")
	}
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Issue error %v: not wrapping ErrInvalidToken", err)
	}
}

func TestJWT_Expired(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	fixed := time.Now()
	// issue as if we were in the past so the token is already expired
	svc.Testing().SetNow(func() time.Time { return fixed.Add(-2 * time.Hour) })
	tok, err := issueSingle(svc, "u-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	svc.Testing().SetNow(func() time.Time { return fixed })
	if _, err := verifySingle(svc, tok); err == nil {
		t.Fatalf("Verify: expected expired-token error")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify error %v: not wrapping ErrInvalidToken", err)
	}
}

func TestJWT_ZeroTTLFailsImmediately(t *testing.T) {
	svc := NewJWTService(JWTConfig{
		Secret: "s3cr3t",
		TTL:    0,
		Issuer: "barista-test",
	})
	tok, err := issueSingle(svc, "u-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Force clock to advance by 1ns so exp < now even with exact equality.
	svc.Testing().SetNow(func() time.Time { return time.Now().Add(time.Second) })
	if _, err := verifySingle(svc, tok); err == nil {
		t.Fatalf("Verify: expected expired-token error for 0-TTL")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify error %v: not wrapping ErrInvalidToken", err)
	}
}

func TestJWT_WrongSecret(t *testing.T) {
	signer := newTestJWT(t, "secret-A")
	verifier := newTestJWT(t, "secret-B")

	tok, err := issueSingle(signer, "u-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := verifySingle(verifier, tok); err == nil {
		t.Fatalf("Verify: expected error for wrong secret")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify error %v: not wrapping ErrInvalidToken", err)
	}
}

func TestJWT_TamperedSignature(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	tok, err := issueSingle(svc, "u-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Flip the first character of the signature. We deliberately
	// avoid the last character: base64url encodes 6 bits per char but
	// the final char of a 43-char HS256 signature has only 4
	// meaningful bits — the bottom 2 are padding. Go's
	// base64.RawURLEncoding.Decode is non-strict by default and
	// discards those padding bits, so flipping the last char can
	// yield the same decoded signature bytes (1 in 16 runs), making
	// the test flaky. A middle-of-signature flip changes 6 real bits
	// every time.
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token does not have 3 parts: %q", tok)
	}
	sig := parts[2]
	flipped := flipByte(sig[0]) + sig[1:]
	parts[2] = flipped
	tampered := strings.Join(parts, ".")

	if _, err := verifySingle(svc, tampered); err == nil {
		t.Fatalf("Verify: expected error for tampered signature")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify error %v: not wrapping ErrInvalidToken", err)
	}
}

func TestJWT_Malformed(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	for _, in := range []string{"", "not-a-token", "a.b", "a.b.c.d"} {
		if _, err := verifySingle(svc, in); err == nil {
			t.Errorf("Verify(%q): expected error", in)
		} else if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("Verify(%q) error %v: not wrapping ErrInvalidToken", in, err)
		}
	}
}

func TestJWT_MissingSub(t *testing.T) {
	secret := []byte("s3cr3t")
	now := time.Now()
	// Hand-craft a token that is complete except for the Subject, so
	// the missing subject is the only thing that can refuse it.
	claims := AccessClaims{
		AuthTime: now.Unix(),
		ACR:      ACRLocalPassword,
		Purpose:  purposeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "barista-test",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	svc := newTestJWT(t, "s3cr3t")
	_, err = verifySingle(svc, tok)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
	if !errors.Is(err, errMissingSubject) {
		t.Errorf("refused for another reason than the missing subject: %#v", errors.Unwrap(err))
	}
}

func TestJWT_WrongIssuer(t *testing.T) {
	secret := []byte("s3cr3t")
	now := time.Now()
	// Complete except for the issuer, so the issuer is the only thing
	// that can refuse it.
	claims := AccessClaims{
		AuthTime: now.Unix(),
		ACR:      ACRLocalPassword,
		Purpose:  purposeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "u-1",
			Issuer:    "someone-else",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	svc := newTestJWT(t, "s3cr3t")
	_, err = verifySingle(svc, tok)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
	if !errors.Is(err, jwt.ErrTokenInvalidIssuer) {
		t.Errorf("refused for another reason than the issuer: %#v", errors.Unwrap(err))
	}

	// The same token with the right issuer verifies: the fixture is
	// complete.
	claims.Issuer = "barista-test"
	good, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := verifySingle(svc, good); err != nil {
		t.Fatalf("the complete fixture does not verify: %v", err)
	}
}

func TestNewJWTService_PanicsOnEmptySecret(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic for empty secret")
		}
	}()
	_ = NewJWTService(JWTConfig{Secret: ""})
}

// v1.14 Sprint 0 task 00: IssueAccess + VerifyAccess + ACR claims
// round-trip + boundary cases. Pre-v1.14 JWTs (issued via the v0.1
// shim shape, no auth_time + no acr claims) MUST still parse via
// VerifyAccess with zero values — the migration story for live
// sessions during the v1.14 rollout.

func TestIssueAccess_RoundTrip(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	want := int64(1733574000) // arbitrary fixed Unix timestamp.
	tok, err := svc.IssueAccess("u-42", tenant.Single, want, ACRIncommonSilver)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	claims, err := svc.VerifyAccess(tok, tenant.Single)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if claims.Subject != "u-42" {
		t.Errorf("Subject = %q, want u-42", claims.Subject)
	}
	if claims.AuthTime != want {
		t.Errorf("AuthTime = %d, want %d", claims.AuthTime, want)
	}
	if claims.ACR != ACRIncommonSilver {
		t.Errorf("ACR = %q, want %q", claims.ACR, ACRIncommonSilver)
	}
}

func TestIssueAccess_RejectsEmptySub(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	_, err := svc.IssueAccess("", tenant.Single, 1733574000, ACRLocalPassword)
	if err == nil || !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("IssueAccess empty sub: err = %v, want ErrInvalidToken", err)
	}
}

func TestIssueAccess_RejectsZeroAuthTime(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	for _, at := range []int64{0, -1, -1733574000} {
		_, err := svc.IssueAccess("u-1", tenant.Single, at, ACRLocalPassword)
		if err == nil || !errors.Is(err, ErrInvalidToken) {
			t.Errorf("IssueAccess auth_time=%d: err = %v, want ErrInvalidToken", at, err)
		}
	}
}

func TestIssueAccess_RejectsEmptyACR(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	_, err := svc.IssueAccess("u-1", tenant.Single, 1733574000, "")
	if err == nil || !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("IssueAccess empty acr: err = %v, want ErrInvalidToken", err)
	}
}

// A token must carry every claim IssueAccess writes. One without an
// auth_time or an acr was not minted here as an access token, and it is
// refused: step-up reads both and must not have to decide what a missing
// one means.
func TestVerifyAccess_RejectsATokenWithoutAuthContext(t *testing.T) {
	secret := []byte("s3cr3t")
	now := time.Now()
	reg := jwt.RegisteredClaims{
		Subject:   "u-1",
		Issuer:    "barista-test",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}
	svc := newTestJWT(t, "s3cr3t")
	for name, claims := range map[string]AccessClaims{
		"no auth_time":       {ACR: ACRLocalPassword, Purpose: purposeAccess, RegisteredClaims: reg},
		"negative auth_time": {AuthTime: -1, ACR: ACRLocalPassword, Purpose: purposeAccess, RegisteredClaims: reg},
		"no acr":             {AuthTime: now.Unix(), Purpose: purposeAccess, RegisteredClaims: reg},
		"neither":            {Purpose: purposeAccess, RegisteredClaims: reg},
	} {
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
		if err != nil {
			t.Fatalf("%s: sign: %v", name, err)
		}
		got, err := svc.VerifyAccess(tok, tenant.Single)
		if !errors.Is(err, ErrInvalidToken) || got != nil {
			t.Errorf("%s: VerifyAccess = %v, %v; want nil and ErrInvalidToken", name, got, err)
		}
		if !errors.Is(err, errMissingAuthContext) {
			t.Errorf("%s: refused for another reason: %#v", name, errors.Unwrap(err))
		}
		if got, err := svc.ParseAccess(tok); !errors.Is(err, ErrInvalidToken) || got != nil {
			t.Errorf("%s: ParseAccess = %v, %v; want nil and ErrInvalidToken", name, got, err)
		}
	}

	// The fixture is not rejecting everything: the same claims, complete.
	full := AccessClaims{AuthTime: now.Unix(), ACR: ACRLocalPassword, Purpose: purposeAccess, RegisteredClaims: reg}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, full).SignedString(secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := svc.VerifyAccess(tok, tenant.Single); err != nil {
		t.Fatalf("a complete token was refused: %v", err)
	}
}

// TestVerifyAccess_TamperedAuthTime — flipping the auth_time claim
// after signing must invalidate the signature. Guards against an
// attacker bumping their own auth_time forward to evade the step-up
// gate.
func TestVerifyAccess_TamperedAuthTime(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	tok, err := svc.IssueAccess("u-1", tenant.Single, 1733574000, ACRIncommonSilver)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	// Re-mint with a different secret so signature mismatches.
	attacker := newTestJWT(t, "attacker-secret")
	attackerTok, _ := attacker.IssueAccess("u-1", tenant.Single, 9999999999, ACRIncommonSilver)
	if attackerTok == tok {
		t.Fatalf("attacker token = legitimate; clock collision somehow?")
	}
	if _, err := svc.VerifyAccess(attackerTok, tenant.Single); err == nil {
		t.Fatalf("VerifyAccess: expected error for foreign-signed token")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("VerifyAccess err %v: not wrapping ErrInvalidToken", err)
	}
}

func flipByte(b byte) string {
	// Produce a different printable character in the base64url alphabet.
	if b == 'A' {
		return "B"
	}
	return "A"
}

// Token-purpose discrimination. The totp-pending session token and the
// access JWT are signed with the SAME secret and differ only by the
// `purpose` claim, so each Verify* entry point must refuse the other's
// token.
//
// The regression these pin: VerifyTOTPPending had always checked
// purpose, but VerifyAccess never did — so the pending token handed to
// the client after a password-only login (espresso/authroutes.go
// returns it in the 200 body as SessionToken) verified cleanly as a
// full access token and authenticated every RequireAuth route for its
// 5-minute lifetime. A complete 2FA bypass for an attacker holding
// only the password. The doc on totpPendingClaims had claimed the
// bidirectional guard existed since v0.8; only one direction did.

func TestVerifyAccess_RejectsTOTPPendingToken(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	pending, err := svc.IssueTOTPPending("u-42", tenant.Single)
	if err != nil {
		t.Fatalf("IssueTOTPPending: %v", err)
	}

	if _, err := svc.VerifyAccess(pending, tenant.Single); err == nil {
		t.Fatal("VerifyAccess accepted a totp-pending token — 2FA bypass")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("VerifyAccess err %v: not wrapping ErrInvalidToken", err)
	}
}

func TestVerifyTOTPPending_RejectsAccessToken(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	access, err := svc.IssueAccess("u-42", tenant.Single, 1733574000, ACRIncommonSilver)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}

	if _, err := svc.VerifyTOTPPending(access, tenant.Single); err == nil {
		t.Fatal("VerifyTOTPPending accepted an access token")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("VerifyTOTPPending err %v: not wrapping ErrInvalidToken", err)
	}
}

func TestIssueAccess_StampsPurpose(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	tok, err := svc.IssueAccess("u-42", tenant.Single, 1733574000, ACRIncommonSilver)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	claims, err := svc.VerifyAccess(tok, tenant.Single)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if claims.Purpose != purposeAccess {
		t.Errorf("Purpose = %q, want %q", claims.Purpose, purposeAccess)
	}
}

func TestVerifyAccess_RejectsUnknownPurpose(t *testing.T) {
	// A future token shape minted under the same secret must not be
	// accepted as an access token just because its purpose is unknown.
	secret := []byte("s3cr3t")
	now := time.Now()
	claims := AccessClaims{
		AuthTime: now.Unix(),
		ACR:      ACRLocalPassword,
		Purpose:  "password_reset",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "u-1",
			Issuer:    "barista-test",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	svc := newTestJWT(t, "s3cr3t")
	_, err = svc.VerifyAccess(tok, tenant.Single)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
	if !errors.Is(err, errWrongPurpose) {
		t.Errorf("refused for another reason than the purpose: %#v", errors.Unwrap(err))
	}
}

func TestVerifyAccess_RejectsATokenWithoutPurpose(t *testing.T) {
	// Every access token this service mints says purpose="access". One
	// that says nothing is refused like one that says something else:
	// "no purpose" must not be a second way to be an access token.
	//
	// Two fixtures, because "nothing" has two spellings on the wire: the
	// claim absent, and the claim present and empty. Both are otherwise
	// complete, so the purpose is the only thing that can refuse them.
	secret := []byte("s3cr3t")
	now := time.Now()
	reg := jwt.RegisteredClaims{
		Subject:   "u-1",
		Issuer:    "barista-test",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}
	absent := struct {
		AuthTime int64  `json:"auth_time"`
		ACR      string `json:"acr"`
		jwt.RegisteredClaims
	}{now.Unix(), ACRIncommonSilver, reg}
	empty := AccessClaims{AuthTime: now.Unix(), ACR: ACRIncommonSilver, RegisteredClaims: reg}

	svc := newTestJWT(t, "s3cr3t")
	for name, tc := range map[string]struct {
		claims     jwt.Claims
		wantOnWire bool
	}{
		"claim absent":            {absent, false},
		"claim present and empty": {empty, true},
	} {
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, tc.claims).SignedString(secret)
		if err != nil {
			t.Fatalf("%s: sign: %v", name, err)
		}
		// Assert the WIRE shape: decode the payload, so the fixture is
		// proven to be the spelling its name says.
		raw, derr := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
		if derr != nil {
			t.Fatalf("%s: decode payload: %v", name, derr)
		}
		if got := strings.Contains(string(raw), `"purpose"`); got != tc.wantOnWire {
			t.Fatalf("%s: test setup: purpose key on the wire = %v, want %v (%s)", name, got, tc.wantOnWire, raw)
		}

		got, err := svc.VerifyAccess(tok, tenant.Single)
		if !errors.Is(err, ErrInvalidToken) || got != nil {
			t.Errorf("%s: VerifyAccess = %v, %v; want nil and ErrInvalidToken", name, got, err)
		}
		if !errors.Is(err, errWrongPurpose) {
			t.Errorf("%s: refused for another reason than the purpose: %#v", name, errors.Unwrap(err))
		}
	}
}

// IssueAccess is the only mint of an ordinary access token. The zero
// tenant.ID has the same string form as tenant.Single, so without a
// check an unresolved tenant would mint a valid single-tenant token.
func TestIssueAccess_DeniesUnsetTenant(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	now := time.Now().Unix()
	for name, unset := range map[string]tenant.ID{"the zero ID": {}, `tenant.New("")`: tenant.New("")} {
		tok, err := svc.IssueAccess("u-1", unset, now, ACRLocalPassword)
		if !errors.Is(err, ErrTenantRequired) || tok != "" {
			t.Errorf("%s: IssueAccess = %q, %v; want no token and ErrTenantRequired", name, tok, err)
		}
	}
	// Before the other arguments are looked at: a wiring bug reads the
	// same whatever else is wrong with the call.
	if _, err := svc.IssueAccess("", tenant.ID{}, 0, ""); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("unset tenant with other bad arguments: err = %v, want ErrTenantRequired", err)
	}
	// tenant.Single is not unset.
	if _, err := svc.IssueAccess("u-1", tenant.Single, now, ACRLocalPassword); err != nil {
		t.Errorf("IssueAccess(tenant.Single): %v", err)
	}
}

// --- Phase 7 slice 7c-1: the `tid` claim ---------------------------

// pinnedPre7cToken is a GOLDEN VECTOR: an access token for the single
// tenant, captured once and pasted here verbatim. It pins the wire
// format. A value written down cannot drift when the code changes, which
// a freshly-computed expectation could. (The name records where it was
// captured; the token carries every claim an access token carries now.)
const (
	pinnedSecret  = "pin-secret"
	pinnedIssuer  = "pin-issuer"
	pinnedSubject = "user-1"
	pinnedNow     = 1700000000
	pinnedAuthAt  = 1699999000

	pinnedPre7cPayload = "eyJhdXRoX3RpbWUiOjE2OTk5OTkwMDAsImFjciI6InVybjp0YW1wZXI6YXV0aDpsb2NhbC1wYXNzd29yZCIsInB1cnBvc2UiOiJhY2Nlc3MiLCJpc3MiOiJwaW4taXNzdWVyIiwic3ViIjoidXNlci0xIiwiZXhwIjoxNzAwMDAzNjAwLCJpYXQiOjE3MDAwMDAwMDB9"

	pinnedPre7cToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + pinnedPre7cPayload +
		".AJXqC7-FmGqvpioil-LBHnweaYrqTafXSI3XRdVkmLk"
)

func pinnedService(t *testing.T) *JWTService {
	t.Helper()
	s := NewJWTService(JWTConfig{Secret: pinnedSecret, TTL: time.Hour, Issuer: pinnedIssuer})
	s.Testing().SetNow(func() time.Time { return time.Unix(pinnedNow, 0).UTC() })
	return s
}

// TestIssueAccess_GoldenVector pins the wire format of a single-tenant
// access token. The assertion is on the ENCODED token, not the parsed
// struct, because a struct comparison cannot see what would change it:
// a `"tid":""` key appearing on the wire, a reordered claim, a new
// header field.
func TestIssueAccess_GoldenVector(t *testing.T) {
	s := pinnedService(t)

	tok, err := s.IssueAccess(pinnedSubject, tenant.Single, pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	if parts[1] != pinnedPre7cPayload {
		t.Errorf("encoded payload drifted from the golden vector.\n got: %s\nwant: %s\n"+
			"A single-tenant token carries no tid claim — check that omitempty is still on TenantID.",
			parts[1], pinnedPre7cPayload)
	}
	// The signature covers header+payload, so a whole-token match proves
	// the header did not move either.
	if tok != pinnedPre7cToken {
		t.Errorf("full token drifted:\n got: %s\nwant: %s", tok, pinnedPre7cToken)
	}

	// And the vector verifies, for the single tenant and for no other.
	claims, err := s.VerifyAccess(pinnedPre7cToken, tenant.Single)
	if err != nil {
		t.Fatalf("the golden vector does not verify: %v", err)
	}
	if claims.TenantID != "" || claims.Subject != pinnedSubject {
		t.Errorf("tid=%q sub=%q, want empty / %q", claims.TenantID, claims.Subject, pinnedSubject)
	}
	if _, err := s.VerifyAccess(pinnedPre7cToken, tenant.New("acme")); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a tid-less token verified for a named tenant: %v", err)
	}
}

// TestIssueAccessForTenant_RoundTrip: a tenant goes in, the same tenant
// comes out, and the claim is actually on the wire.
func TestIssueAccessForTenant_RoundTrip(t *testing.T) {
	s := pinnedService(t)

	tok, err := s.IssueAccess(pinnedSubject, tenant.New("acme"), pinnedAuthAt, ACRIncommonSilver)
	if err != nil {
		t.Fatalf("IssueAccessForTenant: %v", err)
	}
	claims, err := s.VerifyAccess(tok, tenant.New("acme"))
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if claims.TenantID != "acme" {
		t.Errorf("TenantID = %q, want %q", claims.TenantID, "acme")
	}
	if claims.Subject != pinnedSubject || claims.ACR != ACRIncommonSilver {
		t.Errorf("other claims disturbed: %+v", claims)
	}

	// The claim is `tid` on the wire, not the Go field name. Decode the
	// payload rather than trusting the struct tag by inspection.
	payload := decodeSegment(t, tok)
	if !strings.Contains(payload, `"tid":"acme"`) {
		t.Errorf("payload does not carry tid: %s", payload)
	}
}

// TestIssueAccessForTenant_RejectionsUnchanged: adding a parameter must
// not weaken the existing guards.
func TestIssueAccessForTenant_RejectionsUnchanged(t *testing.T) {
	s := pinnedService(t)
	for _, tc := range []struct {
		name     string
		subject  string
		authTime int64
		acr      string
	}{
		{"empty subject", "", pinnedAuthAt, ACRLocalPassword},
		{"zero auth_time", pinnedSubject, 0, ACRLocalPassword},
		{"negative auth_time", pinnedSubject, -1, ACRLocalPassword},
		{"empty acr", pinnedSubject, pinnedAuthAt, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.IssueAccess(tc.subject, tenant.New("acme"), tc.authTime, tc.acr); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("err = %v, want ErrInvalidToken", err)
			}
		})
	}
}

// decodeSegment returns the token's decoded payload as a string.
func decodeSegment(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return string(raw)
}

// --- Phase 7 slice 7c-2: VerifyAccess ----------------------

// TestVerifyAccess_Matrix is the whole rule. Only exact equality
// passes; absent, empty and mismatched all reject.
//
// v0.5.0 note on the fixtures: the single-tenant cases pass
// [tenant.Single], NOT tenant.New(""). They are not the same value and
// never were -- New("") is documented as INVALID and returns the zero
// ID, while Single is the explicit single-tenant value. This test used
// New("") for "untenanted", which happened to pass only because
// VerifyAccess compared String() (where both render "") instead of
// checking Valid(). That is precisely the ambiguity tenant.ID exists to
// remove, and the unset case now has its own subtest below.
func TestVerifyAccess_Matrix(t *testing.T) {
	s := pinnedService(t)
	for _, tc := range []struct {
		name        string
		tokenTenant tenant.ID
		routeTenant tenant.ID
		wantOK      bool
	}{
		// The compatibility path — a single-tenant deployment's token on
		// a single-tenant route. Must still verify.
		{"single-tenant token, single-tenant route", tenant.Single, tenant.Single, true},
		// Where 7c-1's legacy tolerance ends. A route that names a tenant
		// cannot accept a token that names none.
		{"single-tenant token, tenanted route", tenant.Single, tenant.New("acme"), false},
		{"tenanted token, single-tenant route", tenant.New("acme"), tenant.Single, false},
		{"matching", tenant.New("acme"), tenant.New("acme"), true},
		{"cross tenant", tenant.New("acme"), tenant.New("globex"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := s.IssueAccess(pinnedSubject, tc.tokenTenant, pinnedAuthAt, ACRLocalPassword)
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			claims, err := s.VerifyAccess(tok, tc.routeTenant)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("VerifyAccess: %v", err)
				}
				if claims.TenantID != tc.tokenTenant.String() {
					t.Errorf("TenantID = %q, want %q", claims.TenantID, tc.tokenTenant.String())
				}
				return
			}
			if err == nil {
				t.Fatal("expected a rejection")
			}
			if !errors.Is(err, ErrInvalidToken) {
				t.Errorf("err = %v, want ErrInvalidToken", err)
			}
			if claims != nil {
				t.Errorf("rejection returned claims: %+v", claims)
			}
		})
	}
}

// TestVerifyAccess_MismatchIsIndistinguishable pins the
// anti-oracle property at the crypto layer. A wrong-tenant rejection
// must not be separable from an ordinary invalid-token one: if it were,
// a caller could enumerate which tenants exist by watching the error
// change, and could learn that its token is genuine but misaimed.
func TestVerifyAccess_MismatchIsIndistinguishable(t *testing.T) {
	s := pinnedService(t)

	tok, err := s.IssueAccess(pinnedSubject, tenant.New("acme"), pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, crossErr := s.VerifyAccess(tok, tenant.New("globex"))
	if crossErr == nil {
		t.Fatal("cross-tenant token verified")
	}

	// The reference: a token whose signature does not check out at all.
	forged := tok[:len(tok)-4] + "AAAA"
	_, badErr := s.VerifyAccess(forged, tenant.New("globex"))
	if badErr == nil {
		t.Fatal("forged token verified")
	}

	if !errors.Is(crossErr, ErrInvalidToken) || !errors.Is(badErr, ErrInvalidToken) {
		t.Fatalf("both must wrap ErrInvalidToken: cross=%v bad=%v", crossErr, badErr)
	}
	// The cross-tenant message must not name the tenant, the claim, or
	// the fact that a comparison happened.
	msg := crossErr.Error()
	for _, leak := range []string{"acme", "globex", "tenant", "tid", "mismatch"} {
		if strings.Contains(strings.ToLower(msg), leak) {
			t.Errorf("cross-tenant error discloses %q: %s", leak, msg)
		}
	}
}

// TestVerifyAccess_PreservesVerifyAccessRejections: pinning a
// tenant must not weaken any check VerifyAccess already made.
func TestVerifyAccess_PreservesVerifyAccessRejections(t *testing.T) {
	s := pinnedService(t)
	for _, tc := range []struct{ name, token string }{
		{"malformed", "not-a-jwt"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.VerifyAccess(tc.token, tenant.Single); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("err = %v, want ErrInvalidToken", err)
			}
		})
	}
	// A totp-pending token must not authenticate, tenant or no tenant.
	pending, err := s.IssueTOTPPending(pinnedSubject, tenant.Single)
	if err != nil {
		t.Fatalf("IssueTOTPPending: %v", err)
	}
	if _, err := s.VerifyAccess(pending, tenant.Single); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("totp-pending token accepted as an access token: %v", err)
	}
}

// --- v0.5.0 (M2 slice 3): unset-tenant hardening --------------------

// TestVerifyAccess_DeniesUnsetTenant closes the gap tenant.ID was
// created to close and that this entry point had left open.
//
// The zero ID and tenant.Single both render "" from String(), and
// VerifyAccess compared String() values -- so a caller that never
// resolved a tenant compared "" against a tid-less token's "" and
// VERIFIED IT. The deployment looked correct: single-tenant tokens
// sailed through, and the missing tenancy wiring would only surface the
// day a pooled tenant was introduced, as a silent cross-tenant accept.
//
// tenant/id.go states the rule plainly -- "Every tenant-scoped entry
// point checks this and denies when it is false". This one now does.
//
// Mutation check: delete the Valid() gate and this fails.
func TestVerifyAccess_DeniesUnsetTenant(t *testing.T) {
	s := pinnedService(t)

	for _, tokenTenant := range []tenant.ID{tenant.Single, tenant.New("acme")} {
		tok, err := s.IssueAccess(pinnedSubject, tokenTenant, pinnedAuthAt, ACRLocalPassword)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		var unset tenant.ID // what "I forgot to thread it" produces
		claims, err := s.VerifyAccess(tok, unset)
		if !errors.Is(err, ErrTenantRequired) {
			t.Errorf("token tenant %q: err = %v, want ErrTenantRequired", tokenTenant.String(), err)
		}
		if claims != nil {
			t.Errorf("token tenant %q: rejection returned claims: %+v", tokenTenant.String(), claims)
		}
	}

	// tenant.New("") is the same unset value, reached the way a real
	// caller reaches it: a routing header or config lookup that produced
	// nothing. It must deny identically rather than selecting the
	// single-tenant bucket.
	tok, err := s.IssueAccess(pinnedSubject, tenant.Single, pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := s.VerifyAccess(tok, tenant.New("")); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("New(\"\") route: err = %v, want ErrTenantRequired", err)
	}
}

// TestVerifyAccess_UnsetTenantDeniesBeforeParsing pins the ordering.
//
// A wiring bug must report identically whether the token that happened
// to arrive was well-formed, expired, or outright garbage. If the parse
// ran first, an operator debugging the same misconfiguration would see
// a different error depending on which request tripped it -- and the
// most likely one, "invalid token", points at the client rather than at
// the missing tenant resolution.
func TestVerifyAccess_UnsetTenantDeniesBeforeParsing(t *testing.T) {
	s := pinnedService(t)
	var unset tenant.ID
	for _, tok := range []string{"", "not-a-jwt", "a.b.c"} {
		if _, err := s.VerifyAccess(tok, unset); !errors.Is(err, ErrTenantRequired) {
			t.Errorf("token %q: err = %v, want ErrTenantRequired (the tenant gate must precede the parse)", tok, err)
		}
	}
}

// TestVerifyAccess_SingleTenantIsUnaffected is the compatibility pin.
// The hardening must deny the FORGOTTEN tenant and nothing else: a
// single-tenant deployment passes tenant.Single explicitly and keeps
// working byte-for-byte.
func TestVerifyAccess_SingleTenantIsUnaffected(t *testing.T) {
	s := pinnedService(t)
	tok, err := s.IssueAccess(pinnedSubject, tenant.Single, pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := s.VerifyAccess(tok, tenant.Single)
	if err != nil {
		t.Fatalf("single-tenant verify broke: %v", err)
	}
	if claims.TenantID != "" {
		t.Errorf("TenantID = %q, want empty", claims.TenantID)
	}
}

// --- TD-10: the tenant-bound totp-pending token ---------------------
//
// The pending token is the only credential the totp-verify endpoint
// sees, and until TD-10 it named a user and nothing else. In a pooled
// deployment that let a globex user's pending token finish its login at
// acme's endpoint. These pin the `tid` claim that closes it, on the same
// terms the access token's `tid` is pinned above: exact equality, no
// oracle, an unset tenant denies, and the single-tenant shape does not
// move by a byte.

// pinnedPreTD10PendingToken is a GOLDEN VECTOR: a totp-pending token for
// the single tenant, captured once and pasted here verbatim — the same
// fixed-point discipline as pinnedPre7cToken. Its payload decodes to
//
//	{"purpose":"totp_pending","iss":"pin-issuer","sub":"user-1","exp":1700000300,"iat":1700000000}
const pinnedPreTD10PendingToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJwdXJwb3NlIjoidG90cF9wZW5kaW5nIiwiaXNzIjoicGluLWlzc3VlciIsInN1YiI6InVzZXItMSIsImV4cCI6MTcwMDAwMDMwMCwiaWF0IjoxNzAwMDAwMDAwfQ" +
	".WBe2JU1m0w8aVN1NvqMhwYg7LWsgfv2z-gmpqHvOeCQ"

// TestIssueTOTPPending_GoldenVector pins the wire format of a
// single-tenant pending token. The comparison is on the whole encoded
// token, because the thing that would change it — a `"tid":""` key
// appearing on the wire — is invisible to a parsed-struct comparison.
func TestIssueTOTPPending_GoldenVector(t *testing.T) {
	s := pinnedService(t)

	tok, err := s.IssueTOTPPending(pinnedSubject, tenant.Single)
	if err != nil {
		t.Fatalf("IssueTOTPPending: %v", err)
	}
	if tok != pinnedPreTD10PendingToken {
		t.Errorf("single-tenant pending token drifted from the golden vector.\n got: %s\nwant: %s\n"+
			"check that omitempty is still on totpPendingClaims.TenantID", tok, pinnedPreTD10PendingToken)
	}
	sub, err := s.VerifyTOTPPending(pinnedPreTD10PendingToken, tenant.Single)
	if err != nil {
		t.Fatalf("the golden vector does not verify: %v", err)
	}
	if sub != pinnedSubject {
		t.Errorf("sub = %q, want %q", sub, pinnedSubject)
	}
}

// TestTOTPPending_RoundTrip: a tenant goes in, the subject comes
// out for that tenant, and the claim is actually on the wire as `tid`.
func TestTOTPPending_RoundTrip(t *testing.T) {
	s := pinnedService(t)
	acme := tenant.New("acme")

	tok, err := s.IssueTOTPPending(pinnedSubject, acme)
	if err != nil {
		t.Fatalf("IssueTOTPPending: %v", err)
	}
	sub, err := s.VerifyTOTPPending(tok, acme)
	if err != nil {
		t.Fatalf("VerifyTOTPPending: %v", err)
	}
	if sub != pinnedSubject {
		t.Errorf("sub = %q, want %q", sub, pinnedSubject)
	}
	payload := decodeSegment(t, tok)
	if !strings.Contains(payload, `"tid":"acme"`) {
		t.Errorf("payload does not carry tid: %s", payload)
	}
	if !strings.Contains(payload, `"purpose":"totp_pending"`) {
		t.Errorf("payload lost its purpose: %s", payload)
	}
}

// TestVerifyTOTPPending_Matrix is the whole rule, and it is the
// VerifyAccess table row for row. Only exact equality passes.
//
// Mutation check: delete the tid comparison in VerifyTOTPPending
// and the three rejecting rows fail.
func TestVerifyTOTPPending_Matrix(t *testing.T) {
	s := pinnedService(t)
	for _, tc := range []struct {
		name        string
		tokenTenant tenant.ID
		routeTenant tenant.ID
		wantOK      bool
	}{
		{"single-tenant token, single-tenant route", tenant.Single, tenant.Single, true},
		// A route that names a tenant cannot accept a token that names
		// none: absence is not a match.
		{"single-tenant token, tenanted route", tenant.Single, tenant.New("acme"), false},
		{"tenanted token, single-tenant route", tenant.New("acme"), tenant.Single, false},
		{"matching", tenant.New("acme"), tenant.New("acme"), true},
		// TD-10 itself: the password step ran in globex, the token is
		// replayed at acme's verify endpoint.
		{"cross tenant", tenant.New("globex"), tenant.New("acme"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := s.IssueTOTPPending(pinnedSubject, tc.tokenTenant)
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			sub, err := s.VerifyTOTPPending(tok, tc.routeTenant)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("VerifyTOTPPending: %v", err)
				}
				if sub != pinnedSubject {
					t.Errorf("sub = %q, want %q", sub, pinnedSubject)
				}
				return
			}
			if err == nil {
				t.Fatal("expected a rejection")
			}
			if !errors.Is(err, ErrInvalidToken) {
				t.Errorf("err = %v, want ErrInvalidToken", err)
			}
			if sub != "" {
				t.Errorf("rejection returned a subject: %q", sub)
			}
		})
	}
}

// TestVerifyTOTPPending_MismatchIsIndistinguishable pins the
// anti-oracle property for the pending token, as
// TestVerifyAccess_MismatchIsIndistinguishable does for the
// access token. A wrong-tenant rejection that read differently would
// tell the holder its token is genuine and merely misaimed.
func TestVerifyTOTPPending_MismatchIsIndistinguishable(t *testing.T) {
	s := pinnedService(t)
	acme, globex := tenant.New("acme"), tenant.New("globex")

	pending, err := s.IssueTOTPPending(pinnedSubject, globex)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, crossErr := s.VerifyTOTPPending(pending, acme)
	if crossErr == nil {
		t.Fatal("cross-tenant pending token verified")
	}
	if !errors.Is(crossErr, ErrInvalidToken) {
		t.Fatalf("cross-tenant err = %v, want ErrInvalidToken", crossErr)
	}

	// The reference is VerifyAccess's own cross-tenant rejection, which
	// already carries this property. The two must read the same down to
	// the text, not merely share a sentinel — "mirrors VerifyAccess" is
	// then a fact a test holds rather than a sentence in a comment.
	access, err := s.IssueAccess(pinnedSubject, globex, pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	_, accessErr := s.VerifyAccess(access, acme)
	if accessErr == nil {
		t.Fatal("cross-tenant access token verified")
	}
	if crossErr.Error() != accessErr.Error() {
		t.Errorf("pending cross-tenant message %q differs from VerifyAccess's %q", crossErr, accessErr)
	}

	// And it names neither tenant, nor the claim, nor the comparison.
	msg := strings.ToLower(crossErr.Error())
	for _, leak := range []string{"acme", "globex", "tenant", "tid", "mismatch"} {
		if strings.Contains(msg, leak) {
			t.Errorf("cross-tenant error discloses %q: %s", leak, msg)
		}
	}
}

// TestTOTPPending_DeniesUnsetTenant: the zero tenant.ID is what
// a caller who forgot to thread the tenant produces, and both halves of
// the pair refuse it rather than reading it as tenant.Single.
//
// On the verify side the gate must precede the parse, so a wiring bug
// reports identically whatever token arrived. On the issue side the
// alternative would be a tid-less token minted for a caller who never
// said single-tenant.
//
// Mutation check: delete either Valid() gate and this fails.
func TestTOTPPending_DeniesUnsetTenant(t *testing.T) {
	s := pinnedService(t)
	var unset tenant.ID

	tok, err := s.IssueTOTPPending(pinnedSubject, unset)
	if !errors.Is(err, ErrTenantRequired) {
		t.Errorf("issue: err = %v, want ErrTenantRequired", err)
	}
	if tok != "" {
		t.Errorf("issue: a REFUSED mint returned a token: %s", tok)
	}
	// The tenant gate outranks the subject check, for the same reason it
	// outranks the parse on the verify side.
	if _, err := s.IssueTOTPPending("", unset); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("issue with empty sub: err = %v, want ErrTenantRequired", err)
	}

	valid, err := s.IssueTOTPPending(pinnedSubject, tenant.New("acme"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	for _, in := range []string{valid, pinnedPreTD10PendingToken, "", "not-a-jwt", "a.b.c"} {
		sub, err := s.VerifyTOTPPending(in, unset)
		if !errors.Is(err, ErrTenantRequired) {
			t.Errorf("verify %q: err = %v, want ErrTenantRequired (the tenant gate must precede the parse)", in, err)
		}
		if sub != "" {
			t.Errorf("verify %q: rejection returned a subject: %q", in, sub)
		}
	}
}

// TestTOTPPending_RejectionsUnchanged: adding the tenant must not
// weaken a check the pair already made.
func TestTOTPPending_RejectionsUnchanged(t *testing.T) {
	s := pinnedService(t)
	acme := tenant.New("acme")

	if _, err := s.IssueTOTPPending("", acme); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("empty sub: err = %v, want ErrInvalidToken", err)
	}
	for _, tok := range []string{"", "not-a-jwt", "a.b.c"} {
		if _, err := s.VerifyTOTPPending(tok, acme); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("token %q: err = %v, want ErrInvalidToken", tok, err)
		}
	}

	// Expiry: the five-minute lifetime is not extended by the binding.
	tok, err := s.IssueTOTPPending(pinnedSubject, acme)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	s.Testing().SetNow(func() time.Time { return time.Unix(pinnedNow, 0).UTC().Add(5*time.Minute + time.Second) })
	if _, err := s.VerifyTOTPPending(tok, acme); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expired pending token: err = %v, want ErrInvalidToken", err)
	}
}

// TestTOTPPending_PurposeStaysBidirectional: the two token shapes
// now share a `tid` claim as well as a secret, so the purpose check is
// the ONLY thing separating a tenant-bound pending token from a
// tenant-bound access token. A matching tenant must not be enough to
// cross over in either direction — one way is a 2FA bypass, the other
// lets a leaked access token stand in for the password step.
func TestTOTPPending_PurposeStaysBidirectional(t *testing.T) {
	s := pinnedService(t)
	acme := tenant.New("acme")

	pending, err := s.IssueTOTPPending(pinnedSubject, acme)
	if err != nil {
		t.Fatalf("IssueTOTPPending: %v", err)
	}
	if _, err := s.VerifyAccess(pending, acme); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("VerifyAccess accepted a tenant-bound pending token in its own tenant — 2FA bypass: %v", err)
	}
	if _, err := s.ParseAccess(pending); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("ParseAccess accepted a tenant-bound pending token: %v", err)
	}

	access, err := s.IssueAccess(pinnedSubject, acme, pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	if _, err := s.VerifyTOTPPending(access, acme); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("VerifyTOTPPending accepted an access token in its own tenant: %v", err)
	}
}
