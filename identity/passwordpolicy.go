package identity

import (
	"context"
	"fmt"

	"github.com/suryakencana007/tamper/tenant"
)

// PasswordPolicy answers whether a password is acceptable to THIS deployment, and it is a port
// the application implements — the same shape as SecondFactorPolicy and ImpersonationPolicy, for
// the same reason: a password rule is a product decision (a breach list, a length by role, a
// rotation cadence), and identity must not guess it, nor grow a configuration surface that tries
// to express every deployment's version of "strong enough".
//
// It is asked AFTER the built-in floor (MinPasswordLen/MaxPasswordLen), never instead of it: a
// policy can add restrictions, and cannot relax the one tamper guarantees. That ordering is
// deliberate — a port whose zero value made the library's own floor optional would be a way to
// ship a weaker system than the library's minimum, which is not a choice an application should be
// able to make silently.
//
// Three rules, all load-bearing:
//
//   - An error DENIES. No error return may be read as "acceptable": a policy that cannot reach
//     its breach list, or cannot read the user's role, must not let the password through. The
//     denied registration returns the error wrapped in ErrPasswordPolicy.
//   - The user id is empty on the paths that create a user, because the user does not exist yet.
//     A policy that needs one (rotation history, per-user lockout) must treat "" as "unknown" and
//     decide for itself — refusing is always available and always safe.
//   - It is asked on every write path, and tamper does not cache the answer. A cached "acceptable"
//     is a stale security decision, which is exactly what a port is meant to keep out of here.
type PasswordPolicy interface {
	Accept(ctx context.Context, tenantID tenant.ID, userID, email, password string) error
}

// PasswordPolicyFunc adapts a closure to PasswordPolicy.
type PasswordPolicyFunc func(ctx context.Context, tenantID tenant.ID, userID, email, password string) error

// Accept implements PasswordPolicy.
func (f PasswordPolicyFunc) Accept(ctx context.Context, tenantID tenant.ID, userID, email, password string) error {
	return f(ctx, tenantID, userID, email, password)
}

// WithPasswordPolicy enables an application-defined password policy.
//
// A Core without one behaves exactly as before: the built-in floor and nothing else. A nil policy
// is refused at construction rather than accepted, because a nil one would read as "no policy" for
// every deployment that passed it by accident.
func WithPasswordPolicy(p PasswordPolicy) Option {
	if p == nil {
		panic("identity: WithPasswordPolicy requires a non-nil policy — a nil one would read as " +
			"\"no rules\" every time a password is set")
	}
	return func(c *Core) { c.passwordPolicy = p }
}

// checkPassword applies the built-in floor and then the application's policy, in that order.
//
// The order is the security property: the floor runs first so a policy can never be asked to
// approve something tamper already refuses, and the policy runs second so it can be stricter but
// never weaker.
func (c *Core) checkPassword(ctx context.Context, tenantID tenant.ID, userID, email, password string) error {
	if err := validatePassword(password); err != nil {
		return err
	}
	if c.passwordPolicy == nil {
		return nil
	}
	if err := c.passwordPolicy.Accept(ctx, tenantID, userID, email, password); err != nil {
		// Wrapped, not passed through: a caller matching ErrPasswordPolicy must catch every policy
		// refusal, whether it came from the floor or from the application's rule.
		return fmt.Errorf("%w: %v", ErrPasswordPolicy, err)
	}
	return nil
}
