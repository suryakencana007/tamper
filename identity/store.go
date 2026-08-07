package identity

import (
	"context"
	"time"
)

// Store is the persistence port for the identity core. Applications
// implement it over their own tables (Barista: the users +
// refresh_tokens sqlc queries, near-verbatim); MemStore is the
// reference implementation and test double.
//
// Sentinel contract: UserByID / UserByEmail / RefreshSessionByHash
// return an error matching ErrNotFound (errors.Is) when no row exists;
// CreateUser returns one matching ErrEmailTaken on the unique-email
// violation. Other errors propagate as-is and the core fails the
// operation (deny-by-default — a degraded identity read never widens
// access).
//
// Implementations MUST be safe for concurrent use.
type Store interface {
	// CreateUser inserts the identity-core row. firstUser reports
	// whether the store was empty at the core's decision time — the
	// application's bootstrap signal (Barista assigns the cluster-admin
	// system role AT INSERT when true, preserving its at-insert
	// semantics). Implementations with no bootstrap policy ignore it.
	// The race between the emptiness check and the insert is arbitrated
	// by the unique-email index, exactly as in Barista: two concurrent
	// first registrations both see firstUser=true, one loses on
	// ErrEmailTaken.
	CreateUser(ctx context.Context, u NewUser, firstUser bool) error

	UserByID(ctx context.Context, id string) (User, error)
	UserByEmail(ctx context.Context, email string) (User, error)
	CountUsers(ctx context.Context) (int64, error)

	CreateRefreshSession(ctx context.Context, s RefreshSession) error
	RefreshSessionByHash(ctx context.Context, tokenHash string) (RefreshSession, error)
	// RevokeRefreshSession marks one session revoked at the given time.
	// Revoking an already-revoked session is not an error.
	RevokeRefreshSession(ctx context.Context, id string, at time.Time) error
	// RevokeAllRefreshSessionsForUser is the "sign out everywhere"
	// surface — marks every live session for the user revoked.
	RevokeAllRefreshSessionsForUser(ctx context.Context, userID string, at time.Time) error

	// --- TOTP sub-surface (Phase 2c). The envelope is OPAQUE sealed
	// bytes (crypto.KeySet output); how the app persists it (and any
	// legacy dual-write columns) is the adapter's concern. ---

	// TOTPState returns the user's second-factor state. A pending
	// enrollment has Envelope+hashes with Enrolled=false. ErrNotFound
	// when the user doesn't exist.
	TOTPState(ctx context.Context, userID string) (TOTPState, error)
	// SetTOTPPending stages a (re-startable) enrollment: envelope +
	// recovery hashes persisted, enrolled stays false.
	SetTOTPPending(ctx context.Context, userID string, envelope []byte, recoveryCodeHashes []string) error
	// EnableTOTP persists the enrolled state (envelope + hashes +
	// enrolledAt, enrolled=true).
	EnableTOTP(ctx context.Context, userID string, envelope []byte, recoveryCodeHashes []string, enrolledAt time.Time) error
	// SetRecoveryCodeHashes replaces the recovery-code hash list
	// (single-use consumption).
	SetRecoveryCodeHashes(ctx context.Context, userID string, hashes []string) error
	// ClearTOTP removes every TOTP column for the user (disable/admin
	// reset). Idempotent.
	ClearTOTP(ctx context.Context, userID string) error

	// --- identity linking sub-surface (Phase 2d) ---
	//
	// user_identities semantics: (Provider, Subject) is UNIQUE (one
	// external credential -> one user); the app owns the schema + unique
	// index + FK cascade. The core leans on the unique index for its
	// race handling, so InsertIdentity / ProvisionUserWithIdentity MUST
	// surface the (provider,subject) violation as ErrIdentityTaken.

	// IdentityByProviderSubject returns the identity for an exact
	// (provider, subject); ErrNotFound when unlinked — the JIT-vs-repeat
	// decision signal.
	IdentityByProviderSubject(ctx context.Context, provider, subject string) (Identity, error)
	// IdentityByID returns one identity by its own id; ErrNotFound when
	// absent (feeds the unlink ownership check).
	IdentityByID(ctx context.Context, id string) (Identity, error)
	// IdentitiesByUserID lists a user's identities, oldest LinkedAt
	// first; empty (non-nil) slice for none.
	IdentitiesByUserID(ctx context.Context, userID string) ([]Identity, error)
	// InsertIdentity links an identity to an EXISTING user;
	// ErrIdentityTaken on the (provider,subject) unique violation.
	InsertIdentity(ctx context.Context, ni NewIdentity) error
	// TouchIdentityLastLogin bumps last_login_at, keyed by identity id.
	TouchIdentityLastLogin(ctx context.Context, id string, at time.Time) error
	// DeleteIdentity removes one identity unconditionally (the
	// last-auth-method guard lives in the Core, not here).
	DeleteIdentity(ctx context.Context, id string) error
	// CountIdentitiesByUserID counts a user's linked identities.
	CountIdentitiesByUserID(ctx context.Context, userID string) (int64, error)
	// ProvisionUserWithIdentity creates a user AND its first identity
	// ATOMICALLY (both rows or neither) — the JIT federated-signup path.
	// The adapter owns the transaction; the core has no tx concept. The
	// firstUser bootstrap signal is applied at insert exactly like
	// CreateUser. Returns ErrEmailTaken on the users unique violation,
	// ErrIdentityTaken on the user_identities one — the core folds both
	// onto the "someone else won the race" outcome.
	ProvisionUserWithIdentity(ctx context.Context, u NewUser, ni NewIdentity, firstUser bool) (User, Identity, error)
}

// TenantScopedStore is the pooled-multi-tenancy upgrade of Store: the
// same surface, plus the reads and the revoke that must be constrained
// to one tenant. A Store that also satisfies this interface can back a
// deployment serving many tenants from one process; one that does not
// is single-tenant, and tamper fails at New rather than per request
// (sketch §4.2).
//
// It is an OPTIONAL interface. Implementing it is additive — existing
// Store implementations keep compiling and keep their behavior, and a
// "" tenantID selects exactly the single-tenant shape they already
// have.
//
// Declared here in slice 7a-2 so the conformance harness in
// identity/tenanttest has a contract to be written against; 7b-2
// implements it on MemStore, routes Core through it, and adds the boot
// guard. Nothing in tamper implements it yet.
//
// Implementations MUST be safe for concurrent use.
//
// PROOF OBLIGATION: run tenanttest.RunLeakSuite against your
// implementation. tamper cannot verify the isolation contract below —
// the query lives in your adapter — so the suite is the instrument that
// checks it, and it is not optional (sketch §3.3).
type TenantScopedStore interface {
	Store

	// UserByEmailInTenant resolves an email WITHIN one tenant. This is
	// the method that makes an email unique per tenant instead of
	// globally, so two customers can both have bob@acme.com.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	UserByEmailInTenant(ctx context.Context, tenantID, email string) (User, error)

	// IdentityByProviderSubjectInTenant resolves a (provider, subject)
	// WITHIN one tenant, making that pair unique per tenant rather than
	// globally — two tenants may federate with the same IdP.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	IdentityByProviderSubjectInTenant(ctx context.Context, tenantID, provider, subject string) (Identity, error)

	// CountUsersInTenant counts users WITHIN one tenant. It drives the
	// firstUser bootstrap signal, which is therefore PER TENANT: tenant
	// #2's first admin must receive firstUser=true even though tenant #1
	// is full of users. This is blocker B2, and it is the one that fails
	// silently — a global count compiles, passes, ships, and surfaces
	// months later as "the new customer's admin has no permissions".
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	CountUsersInTenant(ctx context.Context, tenantID string) (int64, error)

	// RevokeAllRefreshSessionsForTenant is "sign out this tenant" —
	// every live session belonging to tenantID, and no other tenant's.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	RevokeAllRefreshSessionsForTenant(ctx context.Context, tenantID string, at time.Time) error
}

// TOTPState is the store's projection of a user's second-factor state.
type TOTPState struct {
	Enrolled           bool
	Envelope           []byte // sealed secret; empty = nothing staged/enrolled
	RecoveryCodeHashes []string
}
