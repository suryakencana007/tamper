package identity

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/crypto"
)

// Slice 7k-1 — rate limiting on the credential surfaces.
//
// The mechanics live in crypto/throttle_test.go. What is proved here is
// the property the mechanics cannot prove on their own: that wiring a
// limiter onto the login path did not turn it into the account-existence
// oracle the collapsed ErrInvalidCredentials exists to prevent.

// recordingThrottle refuses everything and records the keys it was
// asked about, so a test can assert both the answer and the dimension.
type recordingThrottle struct {
	mu     sync.Mutex
	keys   []string
	refuse bool
	after  time.Duration
}

var _ crypto.Throttle = (*recordingThrottle)(nil)

func (r *recordingThrottle) Allow(_ context.Context, key string) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = append(r.keys, key)
	if r.refuse {
		return false, r.after
	}
	return true, 0
}

func (r *recordingThrottle) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.keys...)
}

// denyAll builds the Throttling a test installs to refuse everything.
func denyAll(after time.Duration) (*recordingThrottle, Throttling) {
	rt := &recordingThrottle{refuse: true, after: after}
	return rt, Throttling{
		Throttle:        rt,
		LoginKey:        func(tenantID, email string) string { return "login:" + tenantID + ":" + email },
		SecondFactorKey: func(userID, step string) string { return "2fa:" + step + ":" + userID },
	}
}

// countingStore records whether the credential path reached the store.
type countingStore struct {
	*MemStore
	mu    sync.Mutex
	reads int
}

func (s *countingStore) UserByEmail(ctx context.Context, email string) (User, error) {
	s.mu.Lock()
	s.reads++
	s.mu.Unlock()
	return s.MemStore.UserByEmail(ctx, email)
}

func (s *countingStore) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

// --- the disclosure invariant ------------------------------------------

// TestThrottle_ResponseIsIdenticalForRealAndUnknownAccounts is the
// invariant the slice exists to protect, and it is the one that would
// have been easy to break: a limiter placed one line lower — after the
// user lookup, or keyed on anything the store returned — answers
// "throttled" only for addresses that resolve, and the login endpoint
// starts confirming which of a leaked address list are customers.
//
// Compared as whole values, not field by field. A future field that
// varied by account would slip past a hand-written comparison, and the
// whole point is that NOTHING varies.
func TestThrottle_ResponseIsIdenticalForRealAndUnknownAccounts(t *testing.T) {
	ctx := context.Background()
	_, cfg := denyAll(90 * time.Second)
	c, _ := testCore(t, WithThrottling(cfg))

	// One address is real, with a known-good password; the other never
	// existed. Registration happens before the limiter is consulted for
	// login, so it is unaffected.
	if _, _, err := c.Register(ctx, "real@example.com", "correct-horse"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	realUser, realTokens, realErr := c.Login(ctx, "real@example.com", "correct-horse")
	ghostUser, ghostTokens, ghostErr := c.Login(ctx, "ghost@example.com", "correct-horse")

	if !reflect.DeepEqual(realUser, ghostUser) {
		t.Errorf("the returned User differs between a real and an unknown account:\n"+
			" real: %+v\nghost: %+v\nthe throttled response discloses account existence",
			realUser, ghostUser)
	}
	if !reflect.DeepEqual(realTokens, ghostTokens) {
		t.Errorf("the returned Tokens differ: real %+v ghost %+v", realTokens, ghostTokens)
	}
	if realErr == nil || ghostErr == nil {
		t.Fatalf("throttling did not refuse: real %v ghost %v", realErr, ghostErr)
	}
	if realErr.Error() != ghostErr.Error() {
		t.Errorf("the error MESSAGE differs between a real and an unknown account:\n"+
			" real: %q\nghost: %q", realErr.Error(), ghostErr.Error())
	}
	if !errors.Is(realErr, ErrThrottled) || !errors.Is(ghostErr, ErrThrottled) {
		t.Errorf("errors.Is(err, ErrThrottled) failed: real %v ghost %v", realErr, ghostErr)
	}

	// The retry hint is a property of the bucket. If it differed by
	// account it would be the same oracle wearing a number.
	var realT, ghostT *ThrottledError
	if !errors.As(realErr, &realT) || !errors.As(ghostErr, &ghostT) {
		t.Fatalf("errors.As(*ThrottledError) failed: real %v ghost %v", realErr, ghostErr)
	}
	if realT.RetryAfter != ghostT.RetryAfter {
		t.Errorf("RetryAfter differs: real %v ghost %v", realT.RetryAfter, ghostT.RetryAfter)
	}
}

// TestThrottle_RefusalDoesNotReachTheStore is the structural half of the
// property above. Equal responses could still be reached by two
// different paths, and a refusal that queries first has already paid the
// timing cost and touched the row — measurable from outside even when
// the bytes match.
func TestThrottle_RefusalDoesNotReachTheStore(t *testing.T) {
	ctx := context.Background()
	store := &countingStore{MemStore: NewMemStore()}
	_, cfg := denyAll(time.Minute)
	c, err := New(store, testJWT(), WithDefaultACR(testACR), WithThrottling(cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, _, err := c.Login(ctx, "someone@example.com", "hunter2"); !errors.Is(err, ErrThrottled) {
		t.Fatalf("Login err = %v, want ErrThrottled", err)
	}
	if n := store.readCount(); n != 0 {
		t.Errorf("a throttled login read the user store %d time(s); the limiter runs "+
			"after the lookup, so a refusal already reveals the row was consulted", n)
	}
}

// TestThrottle_ErrorCarriesNoAccountDetail: the error crosses into logs
// and sometimes onto the wire. A limiter that echoes the attempted
// address into either turns a rate limit into a credential-stuffing
// receipt.
func TestThrottle_ErrorCarriesNoAccountDetail(t *testing.T) {
	ctx := context.Background()
	_, cfg := denyAll(time.Minute)
	c, _ := testCore(t, WithThrottling(cfg))

	_, _, err := c.Login(ctx, "victim@acme.example", "hunter2")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	msg := strings.ToLower(err.Error())
	for _, leak := range []string{"victim", "acme", "hunter2"} {
		if strings.Contains(msg, leak) {
			t.Errorf("the throttle error contains %q: %s", leak, err.Error())
		}
	}
}

// --- the key dimension --------------------------------------------------

// TestThrottle_LoginKeyUsesTheNormalisedEmail: a limiter keyed on the raw
// input is evaded by changing the case of one letter — a fresh bucket per
// spelling of the same account, which is no limiter at all.
func TestThrottle_LoginKeyUsesTheNormalisedEmail(t *testing.T) {
	ctx := context.Background()
	rt := &recordingThrottle{} // allow, so we only observe the key
	c, _ := testCore(t, WithThrottling(Throttling{
		Throttle:        rt,
		LoginKey:        func(tenantID, email string) string { return tenantID + "|" + email },
		SecondFactorKey: func(userID, step string) string { return step + "|" + userID },
	}))

	_, _, _ = c.Login(ctx, "  Alice@Example.COM ", "whatever")
	_, _, _ = c.Login(ctx, "alice@example.com", "whatever")

	keys := rt.seen()
	if len(keys) != 2 {
		t.Fatalf("throttle consulted %d time(s), want 2: %v", len(keys), keys)
	}
	if keys[0] != keys[1] {
		t.Errorf("case and whitespace variants got different buckets:\n %q\n %q\n"+
			"an attacker gets a fresh budget per spelling of the same address",
			keys[0], keys[1])
	}
	if !strings.Contains(keys[0], "alice@example.com") {
		t.Errorf("key %q does not carry the normalised address", keys[0])
	}
}

// TestThrottle_LoginKeyCarriesTheTenant: in a pooled process the tenant
// must be available to the key function, or one customer's login traffic
// exhausts the budget of an account that merely shares an address shape
// with theirs.
func TestThrottle_LoginKeyCarriesTheTenant(t *testing.T) {
	ctx := context.Background()
	rt := &recordingThrottle{}
	c, _ := tenantCore(t, WithThrottling(Throttling{
		Throttle:        rt,
		LoginKey:        func(tenantID, email string) string { return tenantID + "|" + email },
		SecondFactorKey: func(userID, step string) string { return step + "|" + userID },
	}))

	_, _, _ = c.LoginInTenant(ctx, "acme", "a@example.com", "whatever")
	_, _, _ = c.LoginInTenant(ctx, "globex", "a@example.com", "whatever")

	keys := rt.seen()
	if len(keys) != 2 {
		t.Fatalf("throttle consulted %d time(s), want 2: %v", len(keys), keys)
	}
	if keys[0] == keys[1] {
		t.Errorf("both tenants shared the bucket %q; one customer's login traffic "+
			"limits another's", keys[0])
	}
}

// TestThrottle_SecondFactorSurfacesDoNotShareABucket: recovery codes are
// scarce and single-use, TOTP codes are infinite and cheap. One shared
// budget lets an attacker grinding the cheap surface lock the user out of
// the expensive one — which is the account they were trying to reach.
func TestThrottle_SecondFactorSurfacesDoNotShareABucket(t *testing.T) {
	ctx := context.Background()
	rt := &recordingThrottle{}
	c, _, userID := totpCore(t)
	c.throttling = Throttling{
		Throttle:        rt,
		LoginKey:        func(tenantID, email string) string { return tenantID + "|" + email },
		SecondFactorKey: func(uid, step string) string { return step + "|" + uid },
	}

	_ = c.VerifyTOTP(ctx, userID, "000000")
	_ = c.VerifyRecoveryCode(ctx, userID, "nope")

	keys := rt.seen()
	if len(keys) != 2 {
		t.Fatalf("throttle consulted %d time(s), want 2: %v", len(keys), keys)
	}
	if keys[0] == keys[1] {
		t.Errorf("TOTP and recovery-code attempts shared the bucket %q; grinding "+
			"the cheap surface locks the user out of the scarce one", keys[0])
	}
	if !strings.HasPrefix(keys[0], ThrottleStepTOTP) {
		t.Errorf("TOTP key %q does not carry ThrottleStepTOTP", keys[0])
	}
	if !strings.HasPrefix(keys[1], ThrottleStepRecovery) {
		t.Errorf("recovery key %q does not carry ThrottleStepRecovery", keys[1])
	}
}

// TestThrottle_SecondFactorRefusalIsUniform: VerifyTOTP and
// VerifyRecoveryCode must refuse identically for an enrolled user and a
// user id that was never issued. Otherwise the throttle distinguishes
// "this account has 2FA" from "this account does not exist".
func TestThrottle_SecondFactorRefusalIsUniform(t *testing.T) {
	ctx := context.Background()
	c, _, userID := totpCore(t)
	_, cfg := denyAll(45 * time.Second)
	c.throttling = cfg

	realErr := c.VerifyTOTP(ctx, userID, "000000")
	ghostErr := c.VerifyTOTP(ctx, "user-that-never-existed", "000000")

	if realErr == nil || ghostErr == nil {
		t.Fatalf("throttling did not refuse: real %v ghost %v", realErr, ghostErr)
	}
	if realErr.Error() != ghostErr.Error() {
		t.Errorf("VerifyTOTP refusal differs by account:\n real: %q\nghost: %q",
			realErr.Error(), ghostErr.Error())
	}
	if !errors.Is(realErr, ErrThrottled) {
		t.Errorf("VerifyTOTP err = %v, want ErrThrottled", realErr)
	}

	realRec := c.VerifyRecoveryCode(ctx, userID, "nope")
	ghostRec := c.VerifyRecoveryCode(ctx, "user-that-never-existed", "nope")
	if realRec.Error() != ghostRec.Error() {
		t.Errorf("VerifyRecoveryCode refusal differs by account:\n real: %q\nghost: %q",
			realRec.Error(), ghostRec.Error())
	}
	if !errors.Is(realRec, ErrThrottled) {
		t.Errorf("VerifyRecoveryCode err = %v, want ErrThrottled", realRec)
	}
}

// TestThrottle_RecoveryCodeRefusalDoesNotConsumeTheCode: a refused
// attempt must not burn a recovery code. Otherwise an attacker who
// cannot guess them can still destroy them — the user is locked out of
// their own account by the mechanism meant to protect it.
func TestThrottle_RecoveryCodeRefusalDoesNotConsumeTheCode(t *testing.T) {
	ctx := context.Background()
	c, store, userID := totpCore(t)
	// totpCore only registers; enrol so there are codes to consume.
	if _, err := c.EnrollTOTP(ctx, userID); err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}

	before, err := store.TOTPState(ctx, userID)
	if err != nil {
		t.Fatalf("TOTPState: %v", err)
	}
	if len(before.RecoveryCodeHashes) == 0 {
		t.Fatal("fixture has no recovery codes; this test would prove nothing")
	}

	_, cfg := denyAll(time.Minute)
	c.throttling = cfg
	if err := c.VerifyRecoveryCode(ctx, userID, "nope"); !errors.Is(err, ErrThrottled) {
		t.Fatalf("VerifyRecoveryCode err = %v, want ErrThrottled", err)
	}

	after, err := store.TOTPState(ctx, userID)
	if err != nil {
		t.Fatalf("TOTPState: %v", err)
	}
	if len(after.RecoveryCodeHashes) != len(before.RecoveryCodeHashes) {
		t.Errorf("recovery codes went from %d to %d across a THROTTLED attempt; "+
			"an attacker who cannot guess them can still destroy them",
			len(before.RecoveryCodeHashes), len(after.RecoveryCodeHashes))
	}
}

// --- the boot guard -----------------------------------------------------

// TestThrottle_BootGuardFires. §6.4 and the standing rule: an
// optional-configuration upgrade ships a guard AND a test that the guard
// fires. Without it a Throttle with no key function is a nil dereference
// on the first login of the day, in production, at the one moment the
// operator most needs the login endpoint to work.
func TestThrottle_BootGuardFires(t *testing.T) {
	rt := &recordingThrottle{}
	for _, tc := range []struct {
		name string
		cfg  Throttling
		want string
	}{
		{
			name: "throttle without LoginKey",
			cfg:  Throttling{Throttle: rt, SecondFactorKey: func(string, string) string { return "k" }},
			want: "LoginKey",
		},
		{
			name: "throttle without SecondFactorKey",
			cfg:  Throttling{Throttle: rt, LoginKey: func(string, string) string { return "k" }},
			want: "SecondFactorKey",
		},
		{
			name: "throttle with neither",
			cfg:  Throttling{Throttle: rt},
			want: "LoginKey",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("WithThrottling did not panic; the misconfiguration " +
						"survives boot and surfaces as a nil dereference on the " +
						"first login attempt")
				}
				if msg, ok := r.(string); !ok || !strings.Contains(msg, tc.want) {
					t.Errorf("panic %v does not name the missing field %q", r, tc.want)
				}
			}()
			_ = WithThrottling(tc.cfg)
		})
	}
}

// TestThrottle_NilThrottleNeedsNoKeys: the compat shape. A Throttling
// with no limiter has nothing to key, so demanding key functions would
// make the zero value unconstructible and break every existing caller.
func TestThrottle_NilThrottleNeedsNoKeys(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("WithThrottling(Throttling{}) panicked: %v", r)
		}
	}()
	_ = WithThrottling(Throttling{})
}

// --- the "" path is unchanged ------------------------------------------

// TestThrottle_AbsentByDefault: a Core built without WithThrottling is
// byte-identical to pre-7k-1 behavior. The standing rule for the phase,
// and the reason nil is tolerated at all.
func TestThrottle_AbsentByDefault(t *testing.T) {
	ctx := context.Background()
	c, _ := testCore(t)
	if _, _, err := c.Register(ctx, "alice@example.com", "correct-horse"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	for i := range 50 {
		if _, _, err := c.Login(ctx, "alice@example.com", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: err = %v, want ErrInvalidCredentials — an unthrottled "+
				"Core started limiting", i+1, err)
		}
	}
	if _, _, err := c.Login(ctx, "alice@example.com", "correct-horse"); err != nil {
		t.Errorf("Login after 50 failures: %v — an unconfigured Core locked the user out", err)
	}
}

// TestThrottle_AllowedRequestsPassThroughUnchanged: a limiter that is
// consulted and says yes must not alter the outcome. Otherwise the
// throttled build and the unthrottled build disagree about a successful
// login, which is the compat break this phase forbids.
func TestThrottle_AllowedRequestsPassThroughUnchanged(t *testing.T) {
	ctx := context.Background()
	rt := &recordingThrottle{} // allows
	c, _ := testCore(t, WithThrottling(Throttling{
		Throttle:        rt,
		LoginKey:        func(tenantID, email string) string { return tenantID + "|" + email },
		SecondFactorKey: func(userID, step string) string { return step + "|" + userID },
	}))
	if _, _, err := c.Register(ctx, "alice@example.com", "correct-horse"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	user, tokens, err := c.Login(ctx, "alice@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if user.Email != "alice@example.com" || tokens.Access == "" || tokens.Refresh == "" {
		t.Errorf("an allowed login returned %+v / %+v", user, tokens)
	}
	if _, _, err := c.Login(ctx, "alice@example.com", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("a wrong password behind an allowing limiter returned %v, "+
			"want ErrInvalidCredentials", err)
	}
}
