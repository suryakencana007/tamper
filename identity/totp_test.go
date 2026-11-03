package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
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
	user, _, err := c.Register(context.Background(), tenant.Single, "alice@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return c, store, user.ID
}

// enrollTOTP runs the STAGED ceremony to completion: start, then prove a code.
// The one-shot EnrollTOTP it replaces enabled a secret the user had never
// demonstrated, which is the weaker of the two ways (Phase 13, D4).
func enrollTOTP(t *testing.T, c *Core, ctx context.Context, userID string) TOTPEnrollment {
	t.Helper()
	enr, err := c.StartTOTPEnrollment(ctx, tenant.Single, userID)
	if err != nil {
		t.Fatalf("StartTOTPEnrollment: %v", err)
	}
	if _, _, err := c.CompleteTOTPEnrollment(ctx, tenant.Single, userID, codeFor(t, enr.Secret)); err != nil {
		t.Fatalf("CompleteTOTPEnrollment: %v", err)
	}
	return enr
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

	enrollment, err := c.StartTOTPEnrollment(ctx, tenant.Single, userID)
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
	if _, _, err := c.CompleteTOTPEnrollment(ctx, tenant.Single, userID, "000000"); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("wrong code: err = %v, want ErrInvalidTOTP", err)
	}
	state, _ = store.TOTPState(ctx, userID)
	if state.Enrolled || len(state.Envelope) == 0 {
		t.Fatal("failed phase 2 must not consume the staged enrollment")
	}

	// Correct code promotes + mints a session stamped at the enrollment
	// instant.
	user, tokens, err := c.CompleteTOTPEnrollment(ctx, tenant.Single, userID, codeFor(t, enrollment.Secret))
	if err != nil {
		t.Fatalf("CompleteTOTPEnrollment: %v", err)
	}
	if !user.TOTPEnrolled || tokens.Access == "" || tokens.Refresh == "" {
		t.Fatalf("promotion result wrong: %+v %+v", user, tokens)
	}
	claims, err := testJWT().VerifyAccess(tokens.Access, tenant.Single)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if claims.ACR != testACR || claims.AuthTime == 0 {
		t.Fatalf("phase-2 mint claims wrong: %+v", claims)
	}

	// Re-enrollment guards.
	if _, err := c.StartTOTPEnrollment(ctx, tenant.Single, userID); !errors.Is(err, ErrTOTPAlreadyEnrolled) {
		t.Fatalf("re-start: err = %v, want ErrTOTPAlreadyEnrolled", err)
	}
	if _, _, err := c.CompleteTOTPEnrollment(ctx, tenant.Single, userID, "123456"); !errors.Is(err, ErrTOTPAlreadyEnrolled) {
		t.Fatalf("re-complete: err = %v, want ErrTOTPAlreadyEnrolled", err)
	}
}

func TestDisableAndClearTOTP(t *testing.T) {
	ctx := context.Background()
	c, store, userID := totpCore(t)
	enrollment := enrollTOTP(t, c, ctx, userID)

	// Disable demands a valid current code.
	if err := c.DisableTOTP(ctx, tenant.Single, userID, "000000"); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("disable with bad code: err = %v, want ErrInvalidTOTP", err)
	}
	if err := c.DisableTOTP(ctx, tenant.Single, userID, codeFor(t, enrollment.Secret)); err != nil {
		t.Fatalf("DisableTOTP: %v", err)
	}
	if err := c.VerifyTOTP(ctx, tenant.Single, userID, codeFor(t, enrollment.Secret)); !errors.Is(err, ErrTOTPNotEnrolled) {
		t.Fatalf("post-disable verify: err = %v, want ErrTOTPNotEnrolled", err)
	}

	// The unconditional admin/recovery reset is no longer a Core operation
	// (Phase 13, D4): it removed a second factor with NO proof, which made it the
	// weaker of two ways to do one thing. The capability still exists — asserted
	// here on the port that keeps it, and DisableTOTP above is a live caller, which
	// is why the store method did not disappear with the Core one.
	if _, err := c.StartTOTPEnrollment(ctx, tenant.Single, userID); err != nil {
		t.Fatalf("re-enroll: %v", err)
	}
	if err := store.ClearTOTP(ctx, userID); err != nil {
		t.Fatalf("store ClearTOTP: %v", err)
	}
	if state, err := store.TOTPState(ctx, userID); err != nil {
		t.Fatalf("TOTPState: %v", err)
	} else if state.Enrolled || len(state.Envelope) != 0 {
		t.Fatalf("store ClearTOTP left the factor in place: enrolled=%v envelope=%d", state.Enrolled, len(state.Envelope))
	}
	if err := store.ClearTOTP(ctx, userID); err != nil {
		t.Fatalf("store ClearTOTP must be idempotent: %v", err)
	}
}

func TestTOTPRequiresKeySet(t *testing.T) {
	ctx := context.Background()
	c, _ := testCore(t) // no keyset
	user, _, err := c.Register(ctx, tenant.Single, "nokeys@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := c.StartTOTPEnrollment(ctx, tenant.Single, user.ID); !errors.Is(err, ErrNoKeySet) {
		t.Fatalf("start: err = %v, want ErrNoKeySet", err)
	}
	if err := c.VerifyTOTP(ctx, tenant.Single, user.ID, "123456"); !errors.Is(err, ErrNoKeySet) {
		t.Fatalf("verify: err = %v, want ErrNoKeySet", err)
	}
}
