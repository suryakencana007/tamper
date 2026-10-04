package identity

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/suryakencana007/tamper/tenant"
)

// MembershipStore answers one question: may this user enter this
// tenant. It is the port behind Core.EnterTenant, and it is opt-in — a
// Core built without WithMemberships has no cross-tenant path at all.
//
// A user has exactly one HOME tenant, the one on the user row. A
// membership is something else: a right, held by a user of one tenant,
// to act inside another (a platform admin inside a customer's tenant).
// It does not move the user and it does not duplicate the row.
//
// The application owns the table, like every other port here. Three
// obligations come with it:
//
//   - IsMember is deny-by-default. Unknown user, unknown tenant, a
//     revoked or expired membership: false, with a nil error. An error
//     means the lookup itself failed, and the Core treats it as a deny.
//   - A user's home tenant needs no membership row, and one that exists
//     is ignored. The Core never asks about it.
//   - Removing a membership takes effect at the next EnterTenant call.
//     A token already minted stays valid until it expires; entered
//     tokens have no refresh session, so that is one token lifetime
//     (see WithEnterTenantTTL).
type MembershipStore interface {
	// IsMember reports whether userID may enter tenantID.
	IsMember(ctx context.Context, userID string, tenantID tenant.ID) (bool, error)
	// MembershipsFor lists the tenants userID may enter. An unknown
	// user has none: an empty list and a nil error.
	MembershipsFor(ctx context.Context, userID string) ([]tenant.ID, error)
}

// WithMemberships enables EnterTenant and EnterableTenants.
//
// Panics on a nil store, for the reason WithInvitations does:
// configuration fails at construction, never as a per-request denial.
func WithMemberships(s MembershipStore) Option {
	if s == nil {
		panic("identity: WithMemberships requires a non-nil MembershipStore")
	}
	return func(c *Core) { c.memberships = s }
}

// WithEnterTenantTTL sets the lifetime of the access tokens EnterTenant
// mints. Without it they live as long as an ordinary access token. A
// value longer than the JWT service's own TTL is cut to it.
//
// This is the revocation window: an entered token has no refresh
// session, so a membership that is removed keeps working for at most
// this long.
//
// Panics on a non-positive duration. Omit the option to get the
// service TTL; a zero here is far more likely a forgotten value than a
// choice.
func WithEnterTenantTTL(d time.Duration) Option {
	if d <= 0 {
		panic("identity: WithEnterTenantTTL requires a positive duration")
	}
	return func(c *Core) { c.enterTTL = d }
}

// EnterTenant mints an access token that lets userID act inside
// target, a tenant other than the one the user is stored in. It is the
// only supported cross-tenant mint: IssueTokensForUserInTenant refuses
// every tenant but the user's own, and stays that way.
//
// The token carries tid=target, so every route of that tenant accepts
// it exactly as it accepts a token of the tenant's own users, and
// htid=<home tenant>, so the audit trail records where the actor is
// from. It is valid for target only — not for the home tenant, not for
// any other tenant the user may also enter.
//
// The result has NO refresh token and no session row is written,
// whatever WithRefreshTTL says. When the token expires the caller
// enters again, and the membership is checked again.
//
// authTime and acr describe how and when the user authenticated. Pass
// the values from the session the user is entering FROM (the claims of
// their current access token). Unlike the IssueTokensFor* family there
// is no fallback: a non-positive authTime or an empty acr is
// ErrInvalidInput. A fallback to "now" would hand a fresh step-up to
// anyone who enters a tenant.
//
// Refusals, in the order they are decided:
//
//   - ErrNoMembershipStore, ErrNoTokenService — the Core is not wired
//     for this. Programmer errors.
//   - ErrTenantRequired — target is the zero value.
//   - ErrInvalidInput — authTime or acr is missing, or target IS the
//     user's home tenant (there is nothing to enter; use the session
//     the user already has).
//   - ErrNotFound — the user does not exist, OR is not a member of
//     target, OR the single tenant is on either side. One error, built
//     in one place: "not a member" must not be distinguishable from
//     "no such user".
//   - ErrUserInactive — decided after membership, so it is only ever
//     said about a tenant the user could have entered.
//
// An error from the MembershipStore is returned wrapped, never read as
// a yes.
//
// EnterTenant decides that the user may be IN the tenant. What they may
// do there is still the application's authorization decision.
func (c *Core) EnterTenant(ctx context.Context, userID string, target tenant.ID, authTime int64, acr string) (Tokens, error) {
	if c.memberships == nil {
		return Tokens{}, ErrNoMembershipStore
	}
	if c.jwt == nil {
		return Tokens{}, ErrNoTokenService
	}
	if err := c.tenantGate(target); err != nil {
		return Tokens{}, err
	}
	if authTime <= 0 || acr == "" {
		return Tokens{}, fmt.Errorf("%w: entering a tenant needs the auth_time and acr of the current session", ErrInvalidInput)
	}

	// The one refusal for every "no": a missing user, a pair of tenants
	// that cannot be entered, and a missing membership.
	notFound := func() error { return fmt.Errorf("%w: user %s", ErrNotFound, userID) }

	user, err := c.store.UserByID(ctx, userID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Tokens{}, fmt.Errorf("identity: lookup user to enter tenant: %w", err)
	}
	if err != nil {
		return Tokens{}, notFound()
	}
	home := tenant.FromStored(user.TenantID)
	// The single tenant is "no tenancy". Nobody enters it, and a user
	// stored in it has no other tenant to go to.
	if home.IsSingle() || target.IsSingle() {
		return Tokens{}, notFound()
	}
	if home == target {
		return Tokens{}, fmt.Errorf("%w: %s is the user's own tenant", ErrInvalidInput, target)
	}

	member, err := c.memberships.IsMember(ctx, userID, target)
	if err != nil {
		return Tokens{}, fmt.Errorf("identity: check membership: %w", err)
	}
	if !member {
		return Tokens{}, notFound()
	}
	// After the membership check, never before: see the doc comment.
	if !user.Active {
		return Tokens{}, ErrUserInactive
	}

	access, err := c.jwt.IssueAccessEntered(userID, target, home, authTime, acr, c.enterTTL)
	if err != nil {
		return Tokens{}, fmt.Errorf("identity: issue entered access token: %w", err)
	}
	return Tokens{Access: access}, nil
}

// EnterableTenants lists the tenants userID may enter with EnterTenant,
// sorted. It is what a console shows in its tenant switcher.
//
// The list is the MembershipStore's answer with everything EnterTenant
// would refuse taken out: the user's home tenant, the single tenant,
// and unset ids. A user stored in the single tenant has an empty list.
//
// ErrNotFound for a user with no row, ErrUserInactive for a deactivated
// one, ErrNoMembershipStore on a Core without WithMemberships.
func (c *Core) EnterableTenants(ctx context.Context, userID string) ([]tenant.ID, error) {
	if c.memberships == nil {
		return nil, ErrNoMembershipStore
	}
	user, err := c.store.UserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("%w: user %s", ErrNotFound, userID)
		}
		return nil, fmt.Errorf("identity: lookup user to list tenants: %w", err)
	}
	if !user.Active {
		return nil, ErrUserInactive
	}
	home := tenant.FromStored(user.TenantID)
	if home.IsSingle() {
		return []tenant.ID{}, nil
	}
	all, err := c.memberships.MembershipsFor(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("identity: list memberships: %w", err)
	}
	out := make([]tenant.ID, 0, len(all))
	seen := make(map[tenant.ID]struct{}, len(all))
	for _, id := range all {
		if !id.Valid() || id.IsSingle() || id == home {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}
