package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
)

// ImpersonationPolicy answers the one question impersonation cannot answer for
// itself: may actorID act as targetUserID inside tenantID?
//
// The application owns the table (a support roster, a ticket reference, a
// break-glass list). tamper ships the mechanism and refuses to guess the policy:
// a Core without one cannot impersonate at all, so a deployment that has not
// thought about it has not enabled it.
//
// An error is returned, never read as a yes.
type ImpersonationPolicy interface {
	MayImpersonate(ctx context.Context, actorID string, tenantID tenant.ID, targetUserID string) (bool, error)
}

// WithImpersonation enables Core.Impersonate.
//
// It panics on a nil policy — the posture WithMemberships takes, and for the same
// reason: configuration fails at construction, never as a per-request denial that
// looks like ordinary traffic.
//
// ttl is the lifetime of an impersonated access token. It is the whole
// revocation window: an impersonated token has no refresh session, so ending an
// impersonation means waiting for the token to expire. A non-positive ttl
// panics; a ttl longer than the access token's own fails New.
func WithImpersonation(p ImpersonationPolicy, ttl time.Duration) Option {
	if p == nil {
		panic("identity: WithImpersonation requires a non-nil ImpersonationPolicy — " +
			"a nil policy would make Impersonate an open door")
	}
	if ttl <= 0 {
		panic("identity: WithImpersonation requires a positive ttl — a zero here is far more " +
			"likely a forgotten value than a choice")
	}
	return func(c *Core) {
		c.impersonation = p
		c.impersonationTTL = ttl
	}
}

// Impersonate mints an access token in which the request IS targetUserID, while
// every audit row it produces names the human behind it.
//
// session is the verified claims of the caller's own access token — what
// espresso.AccessClaimsFromContext returns behind RequireAuth. The tenant acted
// in is the session's routed tenant, and the human's home tenant is the
// session's actor tenant, so impersonation is a step INSIDE an entered session:
// a platform admin who has entered acme can act as one of acme's users.
//
// Refusals, one error built in one place, so none can be told from another:
//
//   - the session is already impersonated (no chaining);
//   - the tenant is unset or the single tenant;
//   - the human's home tenant equals the tenant acted in (same-tenant
//     impersonation is not this operation — an entered session is what puts the
//     human in another tenant);
//   - the target user does not exist, is stored in another tenant, or is stored
//     in the single tenant;
//   - the policy says no.
//
// ErrUserInactive is decided after the policy, so it is never said about a user
// the caller may not impersonate. An error from the policy is returned wrapped.
//
// The target user's password, TOTP state and sessions are untouched: this is a
// token about them, not a login as them.
func (c *Core) Impersonate(ctx context.Context, session *crypto.AccessClaims, targetUserID string) (Tokens, error) {
	if c.impersonation == nil {
		return Tokens{}, ErrNoImpersonationPolicy
	}
	if c.jwt == nil {
		return Tokens{}, ErrNoTokenService
	}
	if session == nil || session.Subject == "" || session.AuthTime <= 0 || session.ACR == "" {
		return Tokens{}, fmt.Errorf("%w: impersonating needs the claims of the current session", ErrAuthContextRequired)
	}

	actorID := session.Subject
	notFound := func() error { return fmt.Errorf("%w: user %s", ErrNotFound, targetUserID) }

	if session.Impersonated() {
		return Tokens{}, notFound()
	}
	// The tenant the request is in. A token claim is untrusted input, so it goes
	// through tenant.New: "" is "nobody said", not the single tenant.
	tenantID := tenant.New(session.TenantID)
	actorHome := tenant.New(session.ActorTenantID())
	if !tenantID.Valid() || tenantID.IsSingle() || !actorHome.Valid() || actorHome.IsSingle() || actorHome == tenantID {
		return Tokens{}, notFound()
	}

	user, err := c.store.UserByID(ctx, targetUserID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Tokens{}, fmt.Errorf("identity: lookup user to impersonate: %w", err)
	}
	if err != nil {
		return Tokens{}, notFound()
	}
	targetHome := tenant.FromStored(user.TenantID)
	if !targetHome.Valid() || targetHome.IsSingle() || targetHome != tenantID {
		// A user of another tenant, or of a single-tenant deployment: both are
		// "no such user here", deliberately.
		return Tokens{}, notFound()
	}

	allowed, err := c.impersonation.MayImpersonate(ctx, actorID, tenantID, targetUserID)
	if err != nil {
		return Tokens{}, fmt.Errorf("identity: check impersonation policy: %w", err)
	}
	if !allowed {
		return Tokens{}, notFound()
	}
	// After the policy, never before: see the doc comment.
	if !user.Active {
		return Tokens{}, ErrUserInactive
	}

	access, err := c.jwt.IssueAccessImpersonated(targetUserID, actorID, tenantID, actorHome,
		session.AuthTime, session.ACR, c.impersonationTTL)
	if err != nil {
		return Tokens{}, fmt.Errorf("identity: issue impersonated access token: %w", err)
	}
	return Tokens{Access: access}, nil
}
