package identity

import (
	"context"
	"errors"
	"fmt"
)

// Multi-IdP identity linking (Phase 2d). An Identity is a (provider,
// subject) pair bound to one user. The core owns the linkage-graph
// invariants — one credential -> one user, a user keeps >=1 sign-in
// method — and the JIT federated-signup mechanics. It stays
// provider-agnostic: claim/assertion extraction and the
// email-collision veto are the caller's (see ResolveByIdentity's doc).

// ResolveByIdentity is the REPEAT federated sign-in half: given a
// (provider, subject), return the linked user with found=true after
// gating on Active and bumping the identity's last-login. found=false
// (nil error) means the identity is unlinked — the caller then runs its
// own policy (Barista: an email-collision veto) and, if it decides to
// proceed, calls ProvisionUserWithIdentity. Keeping resolve and provision
// as two calls is deliberate: the app's policy wedges cleanly between
// them without the core ever learning it.
//
// A deactivated user gets ErrUserInactive BEFORE any last-login bump —
// deactivation gates every authentication entry point (as Login and
// Refresh already do), and a federated repeat sign-in is one more.
func (c *Core) ResolveByIdentity(ctx context.Context, provider, subject string) (User, Identity, bool, error) {
	ident, err := c.store.IdentityByProviderSubject(ctx, provider, subject)
	if err != nil {
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

// ProvisionUserWithIdentity is the FIRST federated sign-in half:
// atomically create a federated-only user (empty password hash) plus
// its first identity. Called only after the caller resolved a miss and
// cleared its own policy (e.g. no email collision). email must be
// normalised by the caller (federated emails are IdP-vouched — the core
// stores it verbatim for GetUserByEmail lookup parity). LinkedAt ==
// LastLoginAt == now (the first sign-in is the link event). The
// firstUser bootstrap signal + the OnProvisioned hook mirror Register.
//
// A lost first-sign-in race surfaces as ErrEmailTaken (users unique
// index) or ErrIdentityTaken (user_identities unique index); the caller
// folds both onto its collision outcome.
func (c *Core) ProvisionUserWithIdentity(ctx context.Context, email, provider, subject string) (User, Identity, error) {
	count, err := c.store.CountUsers(ctx)
	if err != nil {
		return User{}, Identity{}, fmt.Errorf("identity: count users: %w", err)
	}
	first := count == 0
	now := c.now()
	userID := c.newID()
	nu := NewUser{ID: userID, Email: email, PasswordHash: "", CreatedAt: now}
	ni := NewIdentity{ID: c.newID(), UserID: userID, Provider: provider, Subject: subject, LinkedAt: now, LastLoginAt: &now}

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
	if _, err := c.store.UserByID(ctx, userID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return Identity{}, fmt.Errorf("%w: user %s", ErrNotFound, userID)
		}
		return Identity{}, fmt.Errorf("identity: link user lookup: %w", err)
	}
	existing, err := c.store.IdentityByProviderSubject(ctx, provider, subject)
	switch {
	case err == nil:
		if existing.UserID == userID {
			return existing, nil // idempotent
		}
		return Identity{}, ErrLinkConflict
	case !errors.Is(err, ErrNotFound):
		return Identity{}, fmt.Errorf("identity: link lookup: %w", err)
	}

	ni := NewIdentity{ID: c.newID(), UserID: userID, Provider: provider, Subject: subject, LinkedAt: c.now()}
	err = c.store.InsertIdentity(ctx, ni)
	if err == nil {
		return Identity{ID: ni.ID, UserID: userID, Provider: provider, Subject: subject, LinkedAt: ni.LinkedAt}, nil
	}
	if !errors.Is(err, ErrIdentityTaken) {
		return Identity{}, fmt.Errorf("identity: link insert: %w", err)
	}
	// Lost the race — someone linked (provider,subject) between our
	// lookup and insert. Re-fetch and re-decide.
	raced, refErr := c.store.IdentityByProviderSubject(ctx, provider, subject)
	if refErr != nil {
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
