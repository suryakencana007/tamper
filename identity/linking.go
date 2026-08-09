package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/suryakencana007/tamper/tenant"
)

// Multi-IdP identity linking (Phase 2d). An Identity is a (provider,
// subject) pair bound to one user. The core owns the linkage-graph
// invariants — one credential -> one user, a user keeps >=1 sign-in
// method — and the JIT federated-signup mechanics. It stays
// provider-agnostic: claim/assertion extraction and the
// email-collision veto are the caller's (see ResolveByIdentity's doc).

// ResolveByIdentity resolves within a tenant, so the
// same (provider, subject) can be federated by two tenants against the
// same IdP without either resolving to the other's user.
//
// A miss in this tenant is found=false with a NIL error — the unlinked
// signal, unchanged. It is deliberately indistinguishable from "linked,
// but to another tenant": the caller runs its own policy next and must
// not be able to learn that the credential exists elsewhere.
func (c *Core) ResolveByIdentity(ctx context.Context, tenantID tenant.ID, provider, subject string) (User, Identity, bool, error) {
	ident, err := c.identityByProviderSubject(ctx, tenantID, provider, subject)
	if err != nil {
		if errors.Is(err, ErrTenantRequired) {
			return User{}, Identity{}, false, err
		}
		if errors.Is(err, ErrNotFound) {
			return User{}, Identity{}, false, nil
		}
		return User{}, Identity{}, false, fmt.Errorf("identity: resolve by identity: %w", err)
	}
	user, err := c.store.UserByID(ctx, ident.UserID)
	if err != nil {
		return User{}, Identity{}, false, fmt.Errorf("identity: load user for identity: %w", err)
	}
	if !user.Active {
		return User{}, Identity{}, false, ErrUserInactive
	}
	now := c.now()
	if err := c.store.TouchIdentityLastLogin(ctx, ident.ID, now); err != nil {
		return User{}, Identity{}, false, fmt.Errorf("identity: touch last login: %w", err)
	}
	ident.LastLoginAt = &now // reflect the bump in the returned value
	return user, ident, true, nil
}

// ProvisionUserWithIdentity provisions within a tenant. Both rows are stamped with the SAME tenant and written by the
// SAME single store call, so atomicity is untouched: the tenant adds no
// round trip between the caller's resolve and its provision. That gap is
// where the app's email-collision veto wedges (Phase 2d), and widening it
// would reopen the lost-first-sign-in race.
//
// firstUser is counted within the tenant — blocker B2 again, on the
// federated path this time.
func (c *Core) ProvisionUserWithIdentity(ctx context.Context, tenantID tenant.ID, email, provider, subject string) (User, Identity, error) {
	count, err := c.countUsers(ctx, tenantID)
	if err != nil {
		return User{}, Identity{}, fmt.Errorf("identity: count users: %w", err)
	}
	first := count == 0
	now := c.now()
	userID := c.newID()
	nu := NewUser{ID: userID, TenantID: tenantID.String(), Email: email, PasswordHash: "", CreatedAt: now}
	// The identity's tenant is the user's, by construction rather than by
	// convention: both rows are written in one atomic call, so reading
	// nu.TenantID here is what makes it impossible for a (provider,
	// subject) to land in a tenant its user does not belong to.
	ni := NewIdentity{ID: c.newID(), UserID: userID, TenantID: nu.TenantID, Provider: provider, Subject: subject, LinkedAt: now, LastLoginAt: &now}

	user, ident, err := c.store.ProvisionUserWithIdentity(ctx, nu, ni, first)
	if err != nil {
		if errors.Is(err, ErrEmailTaken) || errors.Is(err, ErrIdentityTaken) {
			return User{}, Identity{}, err // caller folds onto its collision outcome
		}
		return User{}, Identity{}, fmt.Errorf("identity: provision user with identity: %w", err)
	}
	if c.hooks.OnProvisioned != nil {
		c.hooks.OnProvisioned(ctx, user, ident, first)
	}
	return user, ident, nil
}

// Link attaches a (provider, subject) to an ALREADY-KNOWN user (the
// explicit account-settings "link my Google/SAML account" flow, and the
// remediation for an email collision). Idempotent when the identity is
// already linked to the SAME user; ErrLinkConflict when it belongs to a
// different user. There is deliberately NO email-collision veto here —
// link-mode IS the remediation for that reject.
//
// The insert races against a concurrent link/sign-in: an ErrIdentityTaken
// on insert triggers a re-fetch to re-decide idempotent-vs-conflict.
func (c *Core) Link(ctx context.Context, userID, provider, subject string) (Identity, error) {
	// The target user must exist (link attaches to a KNOWN account; a
	// missing user is a caller error surfaced as ErrNotFound rather
	// than an opaque FK violation from the insert).
	// The user is captured, not discarded: the linked identity inherits
	// its tenant, and this lookup already happens — no extra round trip.
	target, err := c.store.UserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Identity{}, fmt.Errorf("%w: user %s", ErrNotFound, userID)
		}
		return Identity{}, fmt.Errorf("identity: link user lookup: %w", err)
	}
	existing, err := c.store.IdentityByProviderSubject(ctx, tenant.FromStored(target.TenantID), provider, subject)
	switch {
	case err == nil:
		if existing.UserID == userID {
			return existing, nil // idempotent
		}
		return Identity{}, ErrLinkConflict
	case !errors.Is(err, ErrNotFound):
		return Identity{}, fmt.Errorf("identity: link lookup: %w", err)
	}

	ni := NewIdentity{ID: c.newID(), UserID: userID, TenantID: target.TenantID, Provider: provider, Subject: subject, LinkedAt: c.now()}
	err = c.store.InsertIdentity(ctx, ni)
	if err == nil {
		return Identity{ID: ni.ID, UserID: userID, TenantID: ni.TenantID, Provider: provider, Subject: subject, LinkedAt: ni.LinkedAt}, nil
	}
	if !errors.Is(err, ErrIdentityTaken) {
		return Identity{}, fmt.Errorf("identity: link insert: %w", err)
	}
	// Lost the race — someone linked (provider,subject) between our
	// lookup and insert. Re-fetch and re-decide.
	raced, refErr := c.store.IdentityByProviderSubject(ctx, tenant.FromStored(target.TenantID), provider, subject)
	if refErr != nil {
		if errors.Is(refErr, ErrNotFound) {
			// Double race: the winner unlinked between our failed insert
			// and this refetch. Report the conflict we actually lost to —
			// a bare ErrNotFound here would read as "user not found" to
			// callers that fold ErrNotFound onto the link target.
			return Identity{}, ErrLinkConflict
		}
		return Identity{}, fmt.Errorf("identity: link race refetch: %w", refErr)
	}
	if raced.UserID == userID {
		return raced, nil // the winner was us (double-submit) — idempotent
	}
	return Identity{}, ErrLinkConflict
}

// Unlink removes userID's identity by id. The last-auth-method guard is
// PASSWORD-FIRST: only a federated-only user (empty password hash) is
// blocked from unlinking their last identity (ErrLastAuthMethod); a user
// with a password may unlink even their only identity. A cross-user
// identity id is masked as ErrNotFound (IDOR defense — never leak that
// the identity exists under another user).
func (c *Core) Unlink(ctx context.Context, userID, identityID string) error {
	ident, err := c.store.IdentityByID(ctx, identityID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("identity: unlink lookup: %w", err)
	}
	if ident.UserID != userID {
		return ErrNotFound // existence masking
	}
	user, err := c.store.UserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("identity: unlink load user: %w", err)
	}
	if user.PasswordHash == "" {
		count, err := c.store.CountIdentitiesByUserID(ctx, userID)
		if err != nil {
			return fmt.Errorf("identity: unlink count: %w", err)
		}
		if count <= 1 {
			return ErrLastAuthMethod
		}
	}
	if err := c.store.DeleteIdentity(ctx, identityID); err != nil {
		return fmt.Errorf("identity: unlink delete: %w", err)
	}
	return nil
}

// ListIdentities returns userID's linked identities, oldest first.
func (c *Core) ListIdentities(ctx context.Context, userID string) ([]Identity, error) {
	out, err := c.store.IdentitiesByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("identity: list identities: %w", err)
	}
	return out, nil
}
