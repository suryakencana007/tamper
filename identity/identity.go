// Package identity is Tamper's identity core — users, credentials, and
// refresh-session lifecycle (Phase 2a of the extraction roadmap in
// ../TAMPER-DESIGN.md; TOTP enrollment and multi-IdP identity linking
// join in later sub-phases).
//
// The Core service owns the SEMANTICS — registration, password login
// with timing-parity rejections, refresh-token rotation with step-up
// carry-forward, revocation — and delegates persistence to a Store
// interface the application implements over its own tables, and
// cryptography to the already-extracted tamper/crypto primitives.
//
// App-specific policy stays app-side by construction:
//
//   - the first-user bootstrap decision (Barista: cluster-admin) is the
//     Store's CreateUser firstUser signal + the OnRegistered hook;
//   - post-registration side effects (Barista: default-org enrollment)
//     are the OnRegistered hook;
//   - ACR values are caller-supplied (WithDefaultACR) because they are
//     PERSISTED in refresh-session rows and must survive extraction
//     byte-identical (Barista: urn:barista:auth:local-password);
//   - roles/authz are not identity — see tamper/authz.
package identity

import (
	"context"
	"time"
)

// User is the identity-core projection of an account. Applications
// typically carry more columns on the same row (roles, profile,
// preferences); the Store maps between its wide row and this struct,
// and the core never learns about the rest.
type User struct {
	ID           string
	Email        string
	PasswordHash string // "" = federated-only account: password login always rejects
	Active       bool   // false gates login AND refresh (deactivation bites on next rotation)
	TOTPEnrolled bool
	CreatedAt    time.Time
}

// NewUser is the row the core asks the Store to create on Register.
type NewUser struct {
	ID           string
	Email        string // already normalised (lowercase, trimmed, shape-checked)
	PasswordHash string
	CreatedAt    time.Time
}

// RefreshSession is one refresh-token row. Sessions ARE refresh rows —
// there is no separate session table (Barista precedent).
type RefreshSession struct {
	ID        string
	UserID    string
	TokenHash string // sha-based hash from crypto.HashRefreshToken; plaintext never stored
	IssuedAt  time.Time
	ExpiresAt time.Time
	RevokedAt time.Time // zero = live
	// AuthTime + ACR are the step-up carry-forward pair: rotation copies
	// them UNCHANGED onto the successor row and the new access JWT. If
	// rotation advanced AuthTime, a fresh-auth gate would silently re-arm
	// every access-token TTL, defeating the step-up promise. A zero
	// AuthTime marks a legacy row: rotation falls back to now + the
	// configured default ACR (one forced re-auth, then carried forward).
	AuthTime time.Time
	ACR      string
}

// Revoked reports whether the session has been revoked.
func (s RefreshSession) Revoked() bool { return !s.RevokedAt.IsZero() }

// Tokens is the mint result. Refresh is "" when session continuity is
// disabled (refresh TTL 0) or when the flow doesn't grant it.
type Tokens struct {
	Access           string
	Refresh          string // plaintext, shown once; only its hash is stored
	RefreshExpiresAt time.Time
}

// Identity is one linked external credential: a (Provider, Subject)
// pair bound to exactly one user. Provider is an opaque app-defined
// string (Barista uses OIDC provider ids and saml_providers ids in the
// same space). LastLoginAt is nil for an identity that has been linked
// but never used to sign in.
type Identity struct {
	ID          string
	UserID      string
	Provider    string
	Subject     string
	LinkedAt    time.Time
	LastLoginAt *time.Time
}

// NewIdentity is the row the core asks the Store to insert. For an
// explicit link LastLoginAt is nil; for a JIT provision it equals
// LinkedAt (the first sign-in is the link event).
type NewIdentity struct {
	ID          string
	UserID      string
	Provider    string
	Subject     string
	LinkedAt    time.Time
	LastLoginAt *time.Time
}

// Hooks are the app-side extension points. All hooks are optional.
type Hooks struct {
	// OnRegistered runs after a local (password) user row is created and
	// before tokens are minted. firstUser reports whether the store was
	// empty at decision time — the bootstrap signal (Barista promotes
	// the first user to cluster-admin and enrolls everyone into the
	// default org). Best-effort by contract: the hook owns its own error
	// handling and logging; registration does not roll back on hook
	// failure.
	OnRegistered func(ctx context.Context, user User, firstUser bool)

	// OnProvisioned runs after a FEDERATED user is JIT-created with its
	// first identity (ProvisionUserWithIdentity), post-commit. Same
	// firstUser bootstrap signal + best-effort contract as OnRegistered;
	// the two exist separately so the app can distinguish a
	// password-registration side effect from a federated-provision one
	// (Barista runs the same default-org enroll from both).
	OnProvisioned func(ctx context.Context, user User, identity Identity, firstUser bool)
}
