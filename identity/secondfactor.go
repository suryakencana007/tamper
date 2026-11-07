package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/suryakencana007/tamper/tenant"
)

// SecondFactorRequirement is one tenant-member's answer: is a second factor owed, and where.
//
// It is a REQUIREMENT, not a permission. It says a factor is owed; it grants nothing.
// Authorization stays in authz, and satisfying this requirement cannot widen access.
type SecondFactorRequirement struct {
	// AtLogin blocks the password step until the user has enrolled: Login returns
	// ErrTOTPRequired with the user, and the caller routes them into enrolment. The
	// pending token that path needs is already minted by the auth routes, so a user is
	// never locked out of enrolling (PHASE16 sketch, invariant 3).
	AtLogin bool

	// ForActions is advisory to the transport: the application puts
	// RequireFreshAuth + StepUpRequireMethods on the routes that need a factor. tamper
	// cannot enforce it here, because "the action" is a route.
	ForActions bool

	// GraceUntil postpones AtLogin until this instant; zero means "in force now".
	//
	// A DURATION was the first shape and it does not work: tamper would have to know when
	// the requirement began, and only the application knows that. A deadline carries the
	// anchor the duration lacked.
	GraceUntil time.Time
}

// SecondFactorPolicy answers, per user, what second factor that user owes.
//
// It is a port the APPLICATION implements — the same shape as ImpersonationPolicy and for
// the same reason: "platform admins must use 2FA, customers need not" is a mapping from
// roles to policy, and identity must not learn what a role is, nor depend on authz.
//
// Two rules, both load-bearing:
//
//   - An error DENIES. No error return may be read as "not required"; a policy that
//     cannot decide must not open a login.
//   - The policy is asked once per login and tamper does not cache the answer: freshness
//     belongs to the application, and a stale "not required" is a security decision
//     tamper must not make on its behalf.
type SecondFactorPolicy interface {
	RequiredFor(ctx context.Context, tenantID tenant.ID, userID string) (SecondFactorRequirement, error)
}

// WithSecondFactorPolicy enables per-user second-factor policy.
//
// A Core without one behaves exactly as before: WithTOTPRequired still means "everyone",
// and an enrolled user still needs their code. When both are set, the STRICTER answer
// wins — a user who is enrolled always needs the code, and the process-wide switch can
// only add requirements, never remove one.
func WithSecondFactorPolicy(p SecondFactorPolicy) Option {
	if p == nil {
		panic("identity: WithSecondFactorPolicy requires a non-nil policy — a nil one would " +
			"read as \"no requirement\" for every user")
	}
	return func(c *Core) { c.secondFactor = p }
}

// secondFactorRequiredAtLogin reports whether this user must enrol before a password login
// completes. An error denies.
func (c *Core) secondFactorRequiredAtLogin(ctx context.Context, tenantID tenant.ID, userID string) bool {
	if c.secondFactor == nil {
		return c.totpRequired
	}
	req, err := c.secondFactor.RequiredFor(ctx, tenantID, userID)
	if err != nil {
		// Deny, and say so in the error chain rather than silently: this is the one
		// branch where a broken policy could otherwise read as "allowed".
		return true
	}
	if !req.AtLogin {
		return false
	}
	if req.GraceUntil.IsZero() {
		return true
	}
	return !c.now().Before(req.GraceUntil)
}

// amrForLogin and amrForSecondFactor are the method lists stamped on the two session
// shapes this package mints from a password flow. They exist as functions so a caller
// cannot invent a third spelling of the same fact.
func amrForLogin() []string { return []string{"pwd"} }

func amrForSecondFactor() []string { return []string{"pwd", "otp"} }

// secondFactorPolicySet reports whether a policy is wired, for the boot-time check that a
// deployment asking for one actually got it.
func (c *Core) secondFactorPolicySet() bool { return c.secondFactor != nil }

var errSecondFactorPolicyUnset = fmt.Errorf("identity: no SecondFactorPolicy configured")
