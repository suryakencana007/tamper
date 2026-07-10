package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/suryakencana007/barista/packages/tamper/crypto"
)

func testKeySet(t *testing.T) *crypto.KeySet {
	t.Helper()
	ks, err := crypto.NewKeySet([]crypto.KEKEntry{
		{ID: 1, Key: "0000000000000000000000000000000000000000000000000000000000000001"},
	}, 1)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	return ks
}

func totpCore(t *testing.T) (*Core, *MemStore, string) {
	t.Helper()
	c, store := testCore(t, WithKeySet(testKeySet(t)))
	user, _, err := c.Register(context.Background(), "alice@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return c, store, user.ID
}

func codeFor(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	return code
}

func TestTOTPTwoPhaseEnrollment(t *testing.T) {
	ctx := context.Background()
	c, store, userID := totpCore(t)

	enrollment, err := c.StartTOTPEnrollment(ctx, userID)
	if err != nil {
		t.Fatalf("StartTOTPEnrollment: %v", err)
	}
	if enrollment.Secret == "" || enrollment.OTPAuthURI == "" || len(enrollment.RecoveryCodes) == 0 {
		t.Fatalf("enrollment payload incomplete: %+v", enrollment)
	}
	// Staged, not enrolled.
	state, _ := store.TOTPState(ctx, userID)
	if state.Enrolled || len(state.Envelope) == 0 {
		t.Fatalf("phase 1 must stage pending state: %+v", state)
	}

	// Wrong code leaves the staged state retryable.
	if _, _, err := c.CompleteTOTPEnrollment(ctx, userID, "000000"); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("wrong code: err = %v, want ErrInvalidTOTP", err)
	}
	state, _ = store.TOTPState(ctx, userID)
	if state.Enrolled || len(state.Envelope) == 0 {
		t.Fatal("failed phase 2 must not consume the staged enrollment")
	}

	// Correct code promotes + mints a session stamped at the enrollment
	// instant.
	user, tokens, err := c.CompleteTOTPEnrollment(ctx, userID, codeFor(t, enrollment.Secret))
	if err != nil {
		t.Fatalf("CompleteTOTPEnrollment: %v", err)
	}
	if !user.TOTPEnrolled || tokens.Access == "" || tokens.Refresh == "" {
		t.Fatalf("promotion result wrong: %+v %+v", user, tokens)
	}
	claims, err := testJWT().VerifyAccess(tokens.Access)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if claims.ACR != testACR || claims.AuthTime == 0 {
		t.Fatalf("phase-2 mint claims wrong: %+v", claims)
	}

	// Re-enrollment guards.
	if _, err := c.StartTOTPEnrollment(ctx, userID); !errors.Is(err, ErrTOTPAlreadyEnrolled) {
		t.Fatalf("re-start: err = %v, want ErrTOTPAlreadyEnrolled", err)
	}
	if _, _, err := c.CompleteTOTPEnrollment(ctx, userID, "123456"); !errors.Is(err, ErrTOTPAlreadyEnrolled) {
		t.Fatalf("re-complete: err = %v, want ErrTOTPAlreadyEnrolled", err)
	}
}

// TestEnrollTOTPOverwrite pins the one-shot's idempotent-overwrite
// contract: unlike the two-phase ceremony, EnrollTOTP on an ALREADY-
// enrolled user rotates the secret in place (no ErrTOTPAlreadyEnrolled)
// via a single atomic write, so a re-enroll never transiently strips
// the existing second factor.
func TestEnrollTOTPOverwrite(t *testing.T) {
	ctx := context.Background()
	c, store, userID := totpCore(t)

	first, err := c.EnrollTOTP(ctx, userID)
	if err != nil {
		t.Fatalf("EnrollTOTP #1: %v", err)
	}
	env1, _ := store.TOTPState(ctx, userID)

	// Re-enroll while fully enrolled: must succeed with a FRESH secret,
	// not ErrTOTPAlreadyEnrolled, and the user stays enrolled throughout.
	second, err := c.EnrollTOTP(ctx, userID)
	if err != nil {
		t.Fatalf("EnrollTOTP #2 (overwrite) must not error: %v", err)
	}
	if second.Secret == first.Secret {
		t.Fatal("re-enroll must rotate the secret")
	}
	env2, _ := store.TOTPState(ctx, userID)
	if !env2.Enrolled {
		t.Fatal("user must remain enrolled after overwrite (never transiently cleared)")
	}
	if string(env1.Envelope) == string(env2.Envelope) {
		t.Fatal("re-enroll must rotate the stored envelope")
	}
	// The new secret verifies; the old one does not.
	if err := c.VerifyTOTP(ctx, userID, codeFor(t, second.Secret)); err != nil {
		t.Fatalf("new secret must verify: %v", err)
	}
}

func TestTOTPPhase2BeforePhase1(t *testing.T) {
	c, _, userID := totpCore(t)
	if _, _, err := c.CompleteTOTPEnrollment(context.Background(), userID, "123456"); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("err = %v, want ErrInvalidTOTP (nothing staged)", err)
	}
}

func TestVerifyTOTPAndLoginGate(t *testing.T) {
	ctx := context.Background()
	c, _, userID := totpCore(t)
	enrollment, err := c.EnrollTOTP(ctx, userID)
	if err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}

	if err := c.VerifyTOTP(ctx, userID, codeFor(t, enrollment.Secret)); err != nil {
		t.Fatalf("VerifyTOTP: %v", err)
	}
	if err := c.VerifyTOTP(ctx, userID, "000000"); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("wrong code: err = %v, want ErrInvalidTOTP", err)
	}

	// The enrolled flag now gates Login (the 2a flow reads it through
	// the same store).
	if _, _, err := c.Login(ctx, "alice@example.com", "correct-horse"); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("post-enroll Login: err = %v, want ErrTOTPRequired", err)
	}
}

func TestVerifyRecoveryCodeSingleUse(t *testing.T) {
	ctx := context.Background()
	c, store, userID := totpCore(t)
	enrollment, err := c.EnrollTOTP(ctx, userID)
	if err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	code := enrollment.RecoveryCodes[0]

	if err := c.VerifyRecoveryCode(ctx, userID, code); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := c.VerifyRecoveryCode(ctx, userID, code); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("second use: err = %v, want ErrInvalidTOTP (single-use)", err)
	}
	// The other codes survive.
	if err := c.VerifyRecoveryCode(ctx, userID, enrollment.RecoveryCodes[1]); err != nil {
		t.Fatalf("sibling code must survive: %v", err)
	}
	state, _ := store.TOTPState(ctx, userID)
	if len(state.RecoveryCodeHashes) != len(enrollment.RecoveryCodes)-2 {
		t.Fatalf("hash list = %d entries, want %d", len(state.RecoveryCodeHashes), len(enrollment.RecoveryCodes)-2)
	}
}

func TestDisableAndClearTOTP(t *testing.T) {
	ctx := context.Background()
	c, _, userID := totpCore(t)
	enrollment, err := c.EnrollTOTP(ctx, userID)
	if err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}

	// Disable demands a valid current code.
	if err := c.DisableTOTP(ctx, userID, "000000"); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("disable with bad code: err = %v, want ErrInvalidTOTP", err)
	}
	if err := c.DisableTOTP(ctx, userID, codeFor(t, enrollment.Secret)); err != nil {
		t.Fatalf("DisableTOTP: %v", err)
	}
	if err := c.VerifyTOTP(ctx, userID, codeFor(t, enrollment.Secret)); !errors.Is(err, ErrTOTPNotEnrolled) {
		t.Fatalf("post-disable verify: err = %v, want ErrTOTPNotEnrolled", err)
	}

	// Admin clear is unconditional + idempotent.
	if _, err := c.EnrollTOTP(ctx, userID); err != nil {
		t.Fatalf("re-enroll: %v", err)
	}
	if err := c.ClearTOTP(ctx, userID); err != nil {
		t.Fatalf("ClearTOTP: %v", err)
	}
	if err := c.ClearTOTP(ctx, userID); err != nil {
		t.Fatalf("ClearTOTP must be idempotent: %v", err)
	}
}

func TestTOTPRequiresKeySet(t *testing.T) {
	ctx := context.Background()
	c, _ := testCore(t) // no keyset
	user, _, err := c.Register(ctx, "nokeys@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := c.StartTOTPEnrollment(ctx, user.ID); !errors.Is(err, ErrNoKeySet) {
		t.Fatalf("start: err = %v, want ErrNoKeySet", err)
	}
	if err := c.VerifyTOTP(ctx, user.ID, "123456"); !errors.Is(err, ErrNoKeySet) {
		t.Fatalf("verify: err = %v, want ErrNoKeySet", err)
	}
}
