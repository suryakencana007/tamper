package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
)

// Phase 16 (TD-13): per-user second-factor policy. The three models, from the login side.

// sfPolicy adapts a closure to the port (named apart from the impersonation test's
// helper, which already owns policyFunc in this package).
type sfPolicy func(ctx context.Context, tenantID tenant.ID, userID string) (SecondFactorRequirement, error)

func (f sfPolicy) RequiredFor(ctx context.Context, tenantID tenant.ID, userID string) (SecondFactorRequirement, error) {
	return f(ctx, tenantID, userID)
}

func sfCore(t *testing.T, opts ...Option) (*Core, *MemStore) {
	t.Helper()
	store := NewMemStore()
	all := append([]Option{WithDefaultACR(testACR)}, opts...)
	c, err := New(store, testJWT(), all...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, store
}

func register(t *testing.T, c *Core, email string) User {
	t.Helper()
	u, _, err := c.Register(context.Background(), tenant.New("acme"), email, "correct-horse-battery")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return u
}

// No policy: exactly today's behaviour, including the process-wide switch.
func TestSecondFactor_NoPolicyKeepsTodaysBehaviour(t *testing.T) {
	ctx := context.Background()
	c, _ := sfCore(t)
	register(t, c, "a@acme.com")
	if _, _, err := c.Login(ctx, tenant.New("acme"), "a@acme.com", "correct-horse-battery"); err != nil {
		t.Fatalf("login without a policy: %v", err)
	}

	strict, _ := sfCore(t, WithTOTPRequired(true))
	register(t, strict, "b@acme.com")
	if _, _, err := strict.Login(ctx, tenant.New("acme"), "b@acme.com", "correct-horse-battery"); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("err = %v, want ErrTOTPRequired with WithTOTPRequired", err)
	}
}

// Model A, per user: the admin is blocked, the viewer is not, in the same tenant.
func TestSecondFactor_AtLoginIsPerUser(t *testing.T) {
	ctx := context.Background()
	admin := ""
	c, _ := sfCore(t, WithSecondFactorPolicy(sfPolicy(
		func(_ context.Context, _ tenant.ID, userID string) (SecondFactorRequirement, error) {
			return SecondFactorRequirement{AtLogin: userID == admin}, nil
		})))
	a := register(t, c, "admin@acme.com")
	admin = a.ID
	register(t, c, "viewer@acme.com")

	if _, _, err := c.Login(ctx, tenant.New("acme"), "admin@acme.com", "correct-horse-battery"); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("admin login err = %v, want ErrTOTPRequired", err)
	}
	if _, _, err := c.Login(ctx, tenant.New("acme"), "viewer@acme.com", "correct-horse-battery"); err != nil {
		t.Fatalf("viewer login err = %v, want a session", err)
	}
}

// A policy that cannot decide denies. An unreadable policy must never open a login.
func TestSecondFactor_PolicyErrorDenies(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("settings table is down")
	c, _ := sfCore(t, WithSecondFactorPolicy(sfPolicy(
		func(context.Context, tenant.ID, string) (SecondFactorRequirement, error) {
			return SecondFactorRequirement{}, boom
		})))
	register(t, c, "a@acme.com")

	if _, _, err := c.Login(ctx, tenant.New("acme"), "a@acme.com", "correct-horse-battery"); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("err = %v, want ErrTOTPRequired (deny) when the policy fails", err)
	}
}

// Model C: a grace deadline postpones the requirement, and lapses into it.
func TestSecondFactor_GraceDeadlinePostponesAndLapses(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(24 * time.Hour)
	c, _ := sfCore(t,
		WithClock(func() time.Time { return now }),
		WithSecondFactorPolicy(sfPolicy(
			func(context.Context, tenant.ID, string) (SecondFactorRequirement, error) {
				return SecondFactorRequirement{AtLogin: true, GraceUntil: deadline}, nil
			})))
	register(t, c, "a@acme.com")

	if _, _, err := c.Login(ctx, tenant.New("acme"), "a@acme.com", "correct-horse-battery"); err != nil {
		t.Fatalf("inside the grace window: %v, want a session", err)
	}
	c.now = func() time.Time { return deadline } // the deadline is inclusive: it has lapsed
	if _, _, err := c.Login(ctx, tenant.New("acme"), "a@acme.com", "correct-horse-battery"); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("at the deadline: err = %v, want ErrTOTPRequired", err)
	}
}

// The session a password login mints names the method; the enrolment ceremony names both.
func TestSecondFactor_SessionsCarryAMR(t *testing.T) {
	ctx := context.Background()
	c, _ := sfCore(t, WithKeySet(testKeySet(t)))
	register(t, c, "a@acme.com")

	_, tokens, err := c.Login(ctx, tenant.New("acme"), "a@acme.com", "correct-horse-battery")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	claims, err := testJWT().VerifyAccess(tokens.Access, tenant.New("acme"))
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if !claims.HasMethod(crypto.AMRPassword) || claims.HasMethod(crypto.AMROTP) {
		t.Fatalf("login amr = %v, want [pwd] only", claims.AMR)
	}
}

func TestSecondFactor_PanicsOnNilPolicy(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a nil policy did not panic; it would read as \"no requirement\" for everyone")
		}
	}()
	_, _ = sfCore(t, WithSecondFactorPolicy(nil))
}
