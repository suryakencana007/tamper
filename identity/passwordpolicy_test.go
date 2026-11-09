package identity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/suryakencana007/tamper/tenant"
)

// The port's contract, all four rules of it: the application's rule is consulted, an error DENIES,
// the built-in floor still applies underneath, and a Core without a policy behaves exactly as
// before.
func TestRegister_PasswordPolicy(t *testing.T) {
	const email = "policy@example.test"
	weak := strings.Repeat("a", MinPasswordLen) // passes the floor, so only a policy can refuse it

	t.Run("no policy: the floor and nothing else", func(t *testing.T) {
		core, _ := testCore(t)
		if _, _, err := core.Register(context.Background(), tenant.Single, email, weak); err != nil {
			t.Fatalf("a password at the floor was refused without a policy: %v", err)
		}
	})

	t.Run("a policy can refuse", func(t *testing.T) {
		core, _ := testCore(t, WithPasswordPolicy(PasswordPolicyFunc(
			func(context.Context, tenant.ID, string, string, string) error {
				return errors.New("seen in a breach list")
			})))
		_, _, err := core.Register(context.Background(), tenant.Single, email, weak)
		if !errors.Is(err, ErrPasswordPolicy) {
			t.Fatalf("err = %v, want ErrPasswordPolicy — a policy refusal must be catchable as one", err)
		}
	})

	t.Run("a policy error DENIES, and no user row is created", func(t *testing.T) {
		core, store := testCore(t, WithPasswordPolicy(PasswordPolicyFunc(
			func(context.Context, tenant.ID, string, string, string) error {
				return errors.New("breach list unreachable")
			})))
		if _, _, err := core.Register(context.Background(), tenant.Single, email, weak); err == nil {
			t.Fatal("a policy that could not decide let a registration through — an error must deny")
		}
		if _, err := store.UserByEmail(context.Background(), tenant.Single, email); err == nil {
			t.Error("the user was created despite the policy refusing — a deny must leave no row")
		}
	})

	t.Run("a permissive policy cannot relax the floor", func(t *testing.T) {
		core, _ := testCore(t, WithPasswordPolicy(PasswordPolicyFunc(
			func(context.Context, tenant.ID, string, string, string) error { return nil })))
		_, _, err := core.Register(context.Background(), tenant.Single, email, "short")
		if !errors.Is(err, ErrPasswordPolicy) {
			t.Fatalf("err = %v, want the floor's refusal — a policy can add rules, never remove the "+
				"library's own", err)
		}
	})

	t.Run("the policy is told the tenant and the email, with no user id yet", func(t *testing.T) {
		var got struct{ tenant, userID, email string }
		core, _ := testCore(t, WithPasswordPolicy(PasswordPolicyFunc(
			func(_ context.Context, tid tenant.ID, userID, email, _ string) error {
				got.tenant, got.userID, got.email = tid.String(), userID, email
				return nil
			})))
		if _, _, err := core.Register(context.Background(), tenant.New("acme"), email, weak); err != nil {
			t.Fatalf("Register: %v", err)
		}
		if got.userID != "" {
			t.Errorf("userID = %q, want empty — the user does not exist when the policy is asked", got.userID)
		}
		if got.tenant != "acme" || got.email != email {
			t.Errorf("policy saw tenant %q, email %q; want acme, %s", got.tenant, got.email, email)
		}
	})

	t.Run("a nil policy is refused at construction", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("WithPasswordPolicy(nil) was accepted — it would read as \"no rules\" forever")
			}
		}()
		WithPasswordPolicy(nil)
	})
}
