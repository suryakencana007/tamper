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

// TOTPState is the store's projection of a user's second-factor state.
type TOTPState struct {
	Enrolled           bool
	Envelope           []byte // sealed secret; empty = nothing staged/enrolled
	RecoveryCodeHashes []string
}
