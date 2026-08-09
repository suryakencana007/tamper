package identity

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/suryakencana007/tamper/tenant"
)

// MemStore is an in-memory Store — the reference implementation and
// test double. Linear/map lookups; fine for tests and small embedded
// uses, not a production store.
type MemStore struct {
	mu        sync.RWMutex
	usersByID map[string]User
	// emailToID is keyed by (tenant, email), not by email alone. That is
	// what makes an address unique PER TENANT rather than globally, so two
	// customers can both have bob@acme.com — blocker B1. Single-tenant
	// rows all carry tenant "", so their keys and their collision
	// behaviour are byte-identical to the pre-tenancy map.
	emailToID  map[string]string
	sessions   map[string]RefreshSession // by session id
	hashToID   map[string]string         // token hash -> session id
	totp       map[string]TOTPState      // by user id
	identities map[string]Identity       // by identity id
	// invitations is keyed by invitation id; invHashToID indexes the
	// token hash. Two maps rather than one so MarkAccepted can address a
	// row by id without holding the token.
	invitations map[string]Invitation
	invHashToID map[string]string
}

var (
	_ Store           = (*MemStore)(nil)
	_ InvitationStore = (*MemStore)(nil)
)

// tenantKey composes a per-tenant index key. NUL cannot appear in an
// email or a provider subject, so it is an unambiguous separator: no
// (tenant, value) pair can collide with a different one by concatenation.
func tenantKey(tenantID, value string) string { return tenantID + "\x00" + value }

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{
		usersByID:   make(map[string]User),
		emailToID:   make(map[string]string),
		sessions:    make(map[string]RefreshSession),
		hashToID:    make(map[string]string),
		totp:        make(map[string]TOTPState),
		identities:  make(map[string]Identity),
		invitations: make(map[string]Invitation),
		invHashToID: make(map[string]string),
	}
}

// CreateUser implements Store. firstUser is accepted and ignored — the
// reference store has no bootstrap policy.
func (m *MemStore) CreateUser(_ context.Context, u NewUser, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, taken := m.emailToID[tenantKey(u.TenantID, u.Email)]; taken {
		return fmt.Errorf("%w: %s", ErrEmailTaken, u.Email)
	}
	m.usersByID[u.ID] = User{
		ID:           u.ID,
		TenantID:     u.TenantID,
		Email:        u.Email,
		PasswordHash: u.PasswordHash,
		Active:       true,
		CreatedAt:    u.CreatedAt,
	}
	m.emailToID[tenantKey(u.TenantID, u.Email)] = u.ID
	return nil
}

// Seed inserts a fully-specified user (tests: federated-only accounts,
// pre-enrolled TOTP, deactivated users).
func (m *MemStore) Seed(u User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.usersByID[u.ID] = u
	m.emailToID[tenantKey(u.TenantID, u.Email)] = u.ID
}

// SetActive flips a user's active flag (tests: deactivation mid-session).
func (m *MemStore) SetActive(id string, active bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.usersByID[id]; ok {
		u.Active = active
		m.usersByID[id] = u
	}
}

// UserByID implements Store.
func (m *MemStore) UserByID(_ context.Context, id string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.usersByID[id]
	if !ok {
		return User{}, fmt.Errorf("%w: user %s", ErrNotFound, id)
	}
	return u, nil
}

// --- TenantScopedStore (Phase 7). The isolation contract is on the
// interface; these are the reference implementation of it. ---

// UserByEmail implements Store.
func (m *MemStore) UserByEmail(_ context.Context, tenantID tenant.ID, email string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.emailToID[tenantKey(tenantID.String(), email)]
	if !ok {
		// ErrNotFound, never a permission error: a miss and a
		// wrong-tenant hit must be indistinguishable (§6.3).
		return User{}, fmt.Errorf("%w: email %s", ErrNotFound, email)
	}
	return m.usersByID[id], nil
}

// IdentityByProviderSubject implements Store.
func (m *MemStore) IdentityByProviderSubject(_ context.Context, tenantID tenant.ID, provider, subject string) (Identity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, id := range m.identities {
		if id.TenantID == tenantID.String() && id.Provider == provider && id.Subject == subject {
			return id, nil
		}
	}
	return Identity{}, fmt.Errorf("%w: identity %s/%s", ErrNotFound, provider, subject)
}

// CountUsers implements Store. This is the count the
// firstUser bootstrap signal reads, so it must exclude other tenants or
// tenant #2's first admin silently gets firstUser=false (blocker B2).
func (m *MemStore) CountUsers(_ context.Context, tenantID tenant.ID) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var n int64
	for _, u := range m.usersByID {
		if u.TenantID == tenantID.String() {
			n++
		}
	}
	return n, nil
}

// RevokeAllRefreshSessionsForTenant implements Store.
func (m *MemStore) RevokeAllRefreshSessionsForTenant(_ context.Context, tenantID tenant.ID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if s.TenantID == tenantID.String() && !s.Revoked() {
			s.RevokedAt = at
			m.sessions[id] = s
		}
	}
	return nil
}

// CreateRefreshSession implements Store.
func (m *MemStore) CreateRefreshSession(_ context.Context, s RefreshSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.ID] = s
	m.hashToID[s.TokenHash] = s.ID
	return nil
}

// RefreshSessionByHash implements Store.
func (m *MemStore) RefreshSessionByHash(_ context.Context, tokenHash string) (RefreshSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.hashToID[tokenHash]
	if !ok {
		return RefreshSession{}, fmt.Errorf("%w: session", ErrNotFound)
	}
	return m.sessions[id], nil
}

// RevokeRefreshSession implements Store (idempotent).
func (m *MemStore) RevokeRefreshSession(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || s.Revoked() {
		return nil
	}
	s.RevokedAt = at
	m.sessions[id] = s
	return nil
}

// RevokeAllRefreshSessionsForUser implements Store.
func (m *MemStore) RevokeAllRefreshSessionsForUser(_ context.Context, userID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if s.UserID == userID && !s.Revoked() {
			s.RevokedAt = at
			m.sessions[id] = s
		}
	}
	return nil
}

// SessionByHash exposes a raw session row for test assertions (e.g. the
// carry-forward pin needs to inspect the successor row's ACR/AuthTime).
func (m *MemStore) SessionByHash(tokenHash string) (RefreshSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.hashToID[tokenHash]
	if !ok {
		return RefreshSession{}, false
	}
	return m.sessions[id], true
}

// TOTPState implements Store.
func (m *MemStore) TOTPState(_ context.Context, userID string) (TOTPState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.usersByID[userID]; !ok {
		return TOTPState{}, fmt.Errorf("%w: user %s", ErrNotFound, userID)
	}
	return m.totp[userID], nil
}

// SetTOTPPending implements Store.
func (m *MemStore) SetTOTPPending(_ context.Context, userID string, envelope []byte, hashes []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totp[userID] = TOTPState{Enrolled: false, Envelope: envelope, RecoveryCodeHashes: hashes}
	return nil
}

// EnableTOTP implements Store.
func (m *MemStore) EnableTOTP(_ context.Context, userID string, envelope []byte, hashes []string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totp[userID] = TOTPState{Enrolled: true, Envelope: envelope, RecoveryCodeHashes: hashes}
	if u, ok := m.usersByID[userID]; ok {
		u.TOTPEnrolled = true
		m.usersByID[userID] = u
	}
	return nil
}

// SetRecoveryCodeHashes implements Store.
func (m *MemStore) SetRecoveryCodeHashes(_ context.Context, userID string, hashes []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.totp[userID]
	s.RecoveryCodeHashes = hashes
	m.totp[userID] = s
	return nil
}

// ClearTOTP implements Store (idempotent).
func (m *MemStore) ClearTOTP(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.totp, userID)
	if u, ok := m.usersByID[userID]; ok {
		u.TOTPEnrolled = false
		m.usersByID[userID] = u
	}
	return nil
}

// --- identity linking (Phase 2d) ---

// IdentityByID implements Store.
func (m *MemStore) IdentityByID(_ context.Context, id string) (Identity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ident, ok := m.identities[id]
	if !ok {
		return Identity{}, fmt.Errorf("%w: identity %s", ErrNotFound, id)
	}
	return ident, nil
}

// IdentitiesByUserID implements Store (oldest LinkedAt first, non-nil).
func (m *MemStore) IdentitiesByUserID(_ context.Context, userID string) ([]Identity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Identity, 0)
	for _, id := range m.identities {
		if id.UserID == userID {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LinkedAt.Before(out[j].LinkedAt) })
	return out, nil
}

// InsertIdentity implements Store (ErrIdentityTaken on collision).
func (m *MemStore) InsertIdentity(_ context.Context, ni NewIdentity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.insertIdentityLocked(ni)
}

// insertIdentityLocked is the shared insert used by InsertIdentity and
// the provision tx; caller holds the write lock.
func (m *MemStore) insertIdentityLocked(ni NewIdentity) error {
	for _, id := range m.identities {
		// Uniqueness is per (tenant, provider, subject). Two tenants
		// federating against the SAME IdP must not collide — otherwise
		// the second one to link is rejected as a duplicate of a row it
		// cannot see. Single-tenant rows all carry tenant "", so this is
		// the pre-tenancy global uniqueness unchanged.
		if id.TenantID == ni.TenantID && id.Provider == ni.Provider && id.Subject == ni.Subject {
			return fmt.Errorf("%w: %s/%s", ErrIdentityTaken, ni.Provider, ni.Subject)
		}
	}
	// Explicit map, NOT Identity(ni). NewIdentity is a COMMAND (the row
	// the core asks the Store to insert); Identity is the persisted
	// ENTITY. Their fields coincide today, which is why staticcheck
	// S1016 suggests a conversion — but they have different lifecycles
	// (an entity may later grow a version/updated-at the command lacks),
	// and collapsing them via conversion asserts they are one type.
	m.identities[ni.ID] = Identity{ //nolint:staticcheck // S1016: command->entity map, kept explicit on purpose
		ID: ni.ID, UserID: ni.UserID, TenantID: ni.TenantID, Provider: ni.Provider, Subject: ni.Subject,
		LinkedAt: ni.LinkedAt, LastLoginAt: ni.LastLoginAt,
	}
	return nil
}

// TouchIdentityLastLogin implements Store.
func (m *MemStore) TouchIdentityLastLogin(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ident, ok := m.identities[id]
	if !ok {
		return fmt.Errorf("%w: identity %s", ErrNotFound, id)
	}
	t := at
	ident.LastLoginAt = &t
	m.identities[id] = ident
	return nil
}

// DeleteIdentity implements Store (unconditional, idempotent).
func (m *MemStore) DeleteIdentity(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.identities, id)
	return nil
}

// CountIdentitiesByUserID implements Store.
func (m *MemStore) CountIdentitiesByUserID(_ context.Context, userID string) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var n int64
	for _, id := range m.identities {
		if id.UserID == userID {
			n++
		}
	}
	return n, nil
}

// ProvisionUserWithIdentity implements Store — atomic both-or-neither
// under the single mutex (the in-memory analogue of the adapter's tx).
func (m *MemStore) ProvisionUserWithIdentity(_ context.Context, u NewUser, ni NewIdentity, _ bool) (User, Identity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, taken := m.emailToID[tenantKey(u.TenantID, u.Email)]; taken {
		return User{}, Identity{}, fmt.Errorf("%w: %s", ErrEmailTaken, u.Email)
	}
	// Insert the identity first (into a copy-checked map); if it
	// collides, nothing is committed. Per (tenant, provider, subject),
	// matching insertIdentityLocked.
	for _, id := range m.identities {
		if id.TenantID == ni.TenantID && id.Provider == ni.Provider && id.Subject == ni.Subject {
			return User{}, Identity{}, fmt.Errorf("%w: %s/%s", ErrIdentityTaken, ni.Provider, ni.Subject)
		}
	}
	user := User{ID: u.ID, TenantID: u.TenantID, Email: u.Email, PasswordHash: u.PasswordHash, Active: true, CreatedAt: u.CreatedAt}
	// Explicit map, NOT Identity(ni) — see the note in AddIdentity:
	// NewIdentity is a command, Identity is the entity; the coinciding
	// field sets (S1016) are incidental, not an invitation to couple them.
	ident := Identity{ID: ni.ID, UserID: ni.UserID, TenantID: ni.TenantID, Provider: ni.Provider, Subject: ni.Subject, LinkedAt: ni.LinkedAt, LastLoginAt: ni.LastLoginAt} //nolint:staticcheck // S1016: command->entity map, kept explicit
	m.usersByID[u.ID] = user
	m.emailToID[tenantKey(u.TenantID, u.Email)] = u.ID
	m.identities[ni.ID] = ident
	return user, ident, nil
}

// LiveSessionCount reports the user's unrevoked sessions (tests).
func (m *MemStore) LiveSessionCount(userID string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, s := range m.sessions {
		if s.UserID == userID && !s.Revoked() {
			n++
		}
	}
	return n
}

// --- invitations (7j-1) ------------------------------------------------

// CreateInvitation implements InvitationStore.
func (m *MemStore) CreateInvitation(_ context.Context, inv Invitation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.invHashToID[inv.TokenHash]; dup {
		// Astronomically improbable with a 256-bit token, and a hard
		// error rather than an overwrite: silently replacing a row would
		// mean one invitation quietly invalidating another.
		return fmt.Errorf("%w: invitation token hash", ErrInvitationConsumed)
	}
	m.invitations[inv.ID] = inv
	m.invHashToID[inv.TokenHash] = inv.ID
	return nil
}

// InvitationByHash implements InvitationStore.
//
// Returns pending, expired and accepted rows alike. Filtering here would
// turn "already accepted" into a not-found and "expired" into something
// else, and the core needs both to reach one collapsed error.
func (m *MemStore) InvitationByHash(_ context.Context, hash string) (Invitation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.invHashToID[hash]
	if !ok {
		return Invitation{}, fmt.Errorf("%w: invitation", ErrNotFound)
	}
	inv, ok := m.invitations[id]
	if !ok {
		return Invitation{}, fmt.Errorf("%w: invitation", ErrNotFound)
	}
	return inv, nil
}

// MarkAccepted implements InvitationStore as a COMPARE-AND-SET.
//
// The whole write — read the row, test AcceptedAt, set it — happens
// under a single exclusive lock. That is the in-memory equivalent of
//
//	UPDATE invitations SET accepted_at = $2
//	 WHERE id = $1 AND accepted_at IS NULL
//
// and it is the reason the check cannot be hoisted into the core: split
// the read from the write and two concurrent accepts both see a pending
// invitation. An RLock here instead of a Lock would reintroduce exactly
// that race.
func (m *MemStore) MarkAccepted(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invitations[id]
	if !ok {
		return fmt.Errorf("%w: invitation %s", ErrNotFound, id)
	}
	if !inv.AcceptedAt.IsZero() {
		return fmt.Errorf("%w: invitation %s", ErrInvitationConsumed, id)
	}
	inv.AcceptedAt = at
	m.invitations[id] = inv
	return nil
}
