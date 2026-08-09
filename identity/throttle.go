package identity

import (
	"context"
	"time"

	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
)

// Slice 7k-1 — rate limiting on the credential surfaces.
//
// Login, VerifyTOTP and VerifyRecoveryCode are the three places where an
// attacker who has one of the two factors can grind for the other. A TOTP
// code is six digits: unlimited guesses is not a second factor, it is a
// delay. This wires the limiter without letting it become the very
// enumeration oracle the collapsed login errors exist to prevent.

// Throttling is the rate-limit configuration for the credential surfaces.
//
// A STRUCT rather than three options because the throttle and its key
// functions are not independently useful: a Throttle with no key function
// has nothing to limit on, and a key function with no Throttle does
// nothing. Bundling them lets New reject the incoherent combination at
// boot (§6.4) instead of discovering it as a nil dereference on the first
// login attempt.
type Throttling struct {
	// Throttle is the limiter. Nil disables throttling entirely, which is
	// the compat shape and is UNSAFE IN PRODUCTION — see WithThrottling.
	Throttle crypto.Throttle

	// LoginKey composes the throttle key for Login and LoginInTenant.
	//
	// Required when Throttle is non-nil. tamper does not compose it,
	// because whether to limit on the email, the caller's IP, the tenant
	// or some combination is deployment-dependent — and the wrong choice
	// is either useless (per-email, against an attacker spraying one
	// password across every address) or an outage (per-IP, behind a
	// corporate NAT). Only the deployment knows.
	//
	// tenantID is "" on the single-tenant path.
	LoginKey func(tenantID, email string) string

	// SecondFactorKey composes the throttle key for VerifyTOTP and
	// VerifyRecoveryCode. Required when Throttle is non-nil.
	//
	// The step is named in the key so the two surfaces do not share one
	// budget: recovery codes are single-use and scarce, TOTP codes are
	// infinite and cheap, and a shared bucket lets grinding one lock the
	// user out of the other.
	SecondFactorKey func(userID, step string) string
}

// Throttle step names passed to SecondFactorKey. Constants rather than
// inline literals so a deployment can switch on them without matching a
// string this package could later reword.
const (
	ThrottleStepTOTP     = "totp"
	ThrottleStepRecovery = "recovery"
)

// WithThrottling installs rate limiting on Login, LoginInTenant,
// VerifyTOTP and VerifyRecoveryCode.
//
// NIL IS UNSAFE IN PRODUCTION. A Core built without this option, or with
// a nil Throttle, permits unlimited password and second-factor attempts.
// It is allowed because it is the pre-7k-1 behavior and this phase does
// not break the "" path — not because it is a reasonable deployment.
//
// The in-process crypto.NewTokenBucket is PER-REPLICA: behind N replicas
// the effective limit is N times what you configured. A deployment that
// needs a true global limit backs crypto.Throttle with a shared store.
//
// Panics at construction — not at request time — if Throttle is non-nil
// and either key function is nil. §6.4: tenancy and its neighbours fail
// at New, never as a per-request denial. A missing key function is a
// misconfiguration the operator can fix in ten seconds at boot and cannot
// diagnose at all as an intermittent 500 under load.
func WithThrottling(t Throttling) Option {
	if t.Throttle != nil {
		if t.LoginKey == nil {
			panic("identity: WithThrottling has a Throttle but no LoginKey; " +
				"tamper does not choose the rate-limit dimension for you")
		}
		if t.SecondFactorKey == nil {
			panic("identity: WithThrottling has a Throttle but no SecondFactorKey; " +
				"tamper does not choose the rate-limit dimension for you")
		}
	}
	return func(c *Core) { c.throttling = t }
}

// allowLogin consults the limiter for a credential attempt.
//
// CALLED BEFORE ANY STORE LOOKUP. That ordering is the whole of the
// non-disclosure property and it is not incidental: if the limiter ran
// after the user lookup, or the key were derived from anything the store
// returned, then "throttled" would mean "this address exists" and the
// endpoint would answer a question the collapsed ErrInvalidCredentials
// spends effort refusing to answer. The key is composed from the ARGUMENT
// the caller supplied, which is attacker-known by definition.
func (c *Core) allowLogin(ctx context.Context, tenantID tenant.ID, email string) (time.Duration, bool) {
	if c.throttling.Throttle == nil {
		return 0, true
	}
	ok, retryAfter := c.throttling.Throttle.Allow(ctx, c.throttling.LoginKey(tenantID.String(), email))
	if ok {
		return 0, true
	}
	return retryAfter, false
}

// allowSecondFactor is allowLogin for the TOTP surfaces. Same ordering
// rule, same reason: userID is what the caller passed, not what the store
// confirmed, so a throttled answer does not disclose that the user is
// real or that they have a second factor enrolled.
func (c *Core) allowSecondFactor(ctx context.Context, userID, step string) (time.Duration, bool) {
	if c.throttling.Throttle == nil {
		return 0, true
	}
	ok, retryAfter := c.throttling.Throttle.Allow(ctx, c.throttling.SecondFactorKey(userID, step))
	if ok {
		return 0, true
	}
	return retryAfter, false
}
