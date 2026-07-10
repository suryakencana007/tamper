package identity

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// MemStore is an in-memory Store — the reference implementation and
// test double. Linear/map lookups; fine for tests and small embedded
// uses, not a production store.
type MemStore struct {
	mu         sync.RWMutex
	usersByID  map[string]User
	emailToID  map[string]string
	sessions   map[string]RefreshSession // by session id
	hashToID   map[string]string         // token hash -> session id
	totp       map[string]TOTPState      // by user id
	identities map[string]Identity       // by identity id
}

var _ Store = (*MemStore)(nil)

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{
		usersByID:  make(map[string]User),
		emailToID:  make(map[string]string),
		sessions:   make(map[string]RefreshSession),
		hashToID:   make(map[string]string),
		totp:       make(map[string]TOTPState),
		identities: make(map[string]Identity),
	}
}

// CreateUser implements Store. firstUser is accepted and ignored — the
// reference store has no bootstrap policy.
func (m *MemStore) CreateUser(_ context.Context, u NewUser, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, taken := m.emailToID[u.Email]; taken {
		return fmt.Errorf("%w: %s", ErrEmailTaken, u.Email)
	}
	m.usersByID[u.ID] = User{
		ID:           u.ID,
		Email:        u.Email,
		PasswordHash: u.PasswordHash,
		Active:       true,
		CreatedAt:    u.CreatedAt,
	}
	m.emailToID[u.Email] = u.ID
	return nil
}

// Seed inserts a fully-specified user (tests: federated-only accounts,
// pre-enrolled TOTP, deactivated users).
func (m *MemStore) Seed(u User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.usersByID[u.ID] = u
	m.emailToID[u.Email] = u.ID
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

// UserByEmail implements Store.
func (m *MemStore) UserByEmail(_ context.Context, email string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.emailToID[email]
	if !ok {
		return User{}, fmt.Errorf("%w: email %s", ErrNotFound, email)
	}
	return m.usersByID[id], nil
}

// CountUsers implements Store.
func (m *MemStore) CountUsers(_ context.Context) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return int64(len(m.usersByID)), nil
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

// IdentityByProviderSubject implements Store.
func (m *MemStore) IdentityByProviderSubject(_ context.Context, provider, subject string) (Identity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, id := range m.identities {
		if id.Provider == provider && id.Subject == subject {
			return id, nil
		}
	}
	return Identity{}, fmt.Errorf("%w: identity %s/%s", ErrNotFound, provider, subject)
}

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
		if id.Provider == ni.Provider && id.Subject == ni.Subject {
			return fmt.Errorf("%w: %s/%s", ErrIdentityTaken, ni.Provider, ni.Subject)
		}
	}
	m.identities[ni.ID] = Identity{
		ID: ni.ID, UserID: ni.UserID, Provider: ni.Provider, Subject: ni.Subject,
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
	if _, taken := m.emailToID[u.Email]; taken {
		return User{}, Identity{}, fmt.Errorf("%w: %s", ErrEmailTaken, u.Email)
	}
	// Insert the identity first (into a copy-checked map); if it
	// collides, nothing is committed.
	for _, id := range m.identities {
		if id.Provider == ni.Provider && id.Subject == ni.Subject {
			return User{}, Identity{}, fmt.Errorf("%w: %s/%s", ErrIdentityTaken, ni.Provider, ni.Subject)
		}
	}
	user := User{ID: u.ID, Email: u.Email, PasswordHash: u.PasswordHash, Active: true, CreatedAt: u.CreatedAt}
	ident := Identity{ID: ni.ID, UserID: ni.UserID, Provider: ni.Provider, Subject: ni.Subject, LinkedAt: ni.LinkedAt, LastLoginAt: ni.LastLoginAt}
	m.usersByID[u.ID] = user
	m.emailToID[u.Email] = u.ID
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
