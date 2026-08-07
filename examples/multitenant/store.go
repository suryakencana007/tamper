package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/suryakencana007/tamper/identity"
)

// tenantStore is the app-side adapter for a POOLED deployment: one
// store, many tenants, every row carrying its tenant. It is written out
// by hand rather than reusing identity.MemStore because that is what an
// adapter author actually does, and because this store does the one
// thing MemStore deliberately does not — it acts on the firstUser
// bootstrap signal at insert, exactly as Barista assigns its
// cluster-admin role AT INSERT.
//
// It implements identity.TenantScopedStore, so tamper.New accepts it
// with Tenancy.Enabled. The isolation contract on that interface is the
// obligation this type is signing up to; examples/multitenant's test
// runs tenanttest.RunLeakSuite against it as the proof.
//
// A real deployment swaps the maps for SQL. Nothing about the shape
// changes: every scoped method constrains its query to tenantID and
// returns identity.ErrNotFound — never a permission error — when the
// addressed row belongs to someone else.
type tenantStore struct {
	mu       sync.RWMutex
	users    map[string]identity.User
	sessions map[string]identity.RefreshSession
	byHash   map[string]string
	idents   map[string]identity.Identity

	// bootstrapped records the firstUser signal as the store SAW it at
	// insert. A real app would grant an owner/admin role here instead.
	// Keeping it lets the test assert on the signal itself rather than on
	// a proxy for it.
	bootstrapped map[string]bool
}

var _ identity.TenantScopedStore = (*tenantStore)(nil)

func newTenantStore() *tenantStore {
	return &tenantStore{
		users: map[string]identity.User{}, sessions: map[string]identity.RefreshSession{},
		byHash: map[string]string{}, idents: map[string]identity.Identity{},
		bootstrapped: map[string]bool{},
	}
}

// key scopes an index by tenant. NUL cannot appear in an email or a
// provider subject, so no (tenant, value) pair can collide with another
// by concatenation.
func key(tenantID, value string) string { return tenantID + "\x00" + value }

// wasBootstrapped reports the firstUser signal the store recorded for a
// user at insert (test support).
func (s *tenantStore) wasBootstrapped(userID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bootstrapped[userID]
}

// --- tenant-scoped surface ---

func (s *tenantStore) UserByEmailInTenant(_ context.Context, tenantID, email string) (identity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.TenantID == tenantID && u.Email == email {
			return u, nil
		}
	}
	// ErrNotFound, never a permission error: a miss and a wrong-tenant
	// hit must be indistinguishable, or the error is an existence oracle.
	return identity.User{}, fmt.Errorf("%w: email %s", identity.ErrNotFound, email)
}

func (s *tenantStore) IdentityByProviderSubjectInTenant(_ context.Context, tenantID, provider, subject string) (identity.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, i := range s.idents {
		if i.TenantID == tenantID && i.Provider == provider && i.Subject == subject {
			return i, nil
		}
	}
	return identity.Identity{}, fmt.Errorf("%w: identity %s/%s", identity.ErrNotFound, provider, subject)
}

func (s *tenantStore) CountUsersInTenant(_ context.Context, tenantID string) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var n int64
	for _, u := range s.users {
		if u.TenantID == tenantID {
			n++
		}
	}
	return n, nil
}

func (s *tenantStore) RevokeAllRefreshSessionsForTenant(_ context.Context, tenantID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, x := range s.sessions {
		if x.TenantID == tenantID && !x.Revoked() {
			x.RevokedAt = at
			s.sessions[id] = x
		}
	}
	return nil
}

// --- base Store surface ---

func (s *tenantStore) CreateUser(_ context.Context, u identity.NewUser, firstUser bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.emailIndexLocked()[key(u.TenantID, u.Email)]; taken {
		return fmt.Errorf("%w: %s", identity.ErrEmailTaken, u.Email)
	}
	s.users[u.ID] = identity.User{
		ID: u.ID, TenantID: u.TenantID, Email: u.Email,
		PasswordHash: u.PasswordHash, Active: true, CreatedAt: u.CreatedAt,
	}
	// The bootstrap decision is applied AT INSERT, in the same write —
	// this is the signal's whole point, and it is per tenant because the
	// Core counted within the tenant.
	s.bootstrapped[u.ID] = firstUser
	return nil
}

func (s *tenantStore) emailIndexLocked() map[string]string {
	idx := make(map[string]string, len(s.users))
	for _, u := range s.users {
		idx[key(u.TenantID, u.Email)] = u.ID
	}
	return idx
}

func (s *tenantStore) UserByID(_ context.Context, id string) (identity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return identity.User{}, fmt.Errorf("%w: user %s", identity.ErrNotFound, id)
	}
	return u, nil
}

// UserByEmail is the SINGLE-TENANT lookup — the "" tenant. A pooled
// deployment never reaches it (the Core routes to the scoped method
// whenever tenancy is on); it stays correct rather than convenient.
func (s *tenantStore) UserByEmail(ctx context.Context, email string) (identity.User, error) {
	return s.UserByEmailInTenant(ctx, "", email)
}

func (s *tenantStore) CountUsers(ctx context.Context) (int64, error) {
	return s.CountUsersInTenant(ctx, "")
}

func (s *tenantStore) CreateRefreshSession(_ context.Context, x identity.RefreshSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[x.ID] = x
	s.byHash[x.TokenHash] = x.ID
	return nil
}

func (s *tenantStore) RefreshSessionByHash(_ context.Context, h string) (identity.RefreshSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byHash[h]
	if !ok {
		return identity.RefreshSession{}, fmt.Errorf("%w: session", identity.ErrNotFound)
	}
	return s.sessions[id], nil
}

func (s *tenantStore) RevokeRefreshSession(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if x, ok := s.sessions[id]; ok && !x.Revoked() {
		x.RevokedAt = at
		s.sessions[id] = x
	}
	return nil
}

func (s *tenantStore) RevokeAllRefreshSessionsForUser(_ context.Context, uid string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, x := range s.sessions {
		if x.UserID == uid && !x.Revoked() {
			x.RevokedAt = at
			s.sessions[id] = x
		}
	}
	return nil
}

func (s *tenantStore) IdentityByProviderSubject(ctx context.Context, p, sub string) (identity.Identity, error) {
	return s.IdentityByProviderSubjectInTenant(ctx, "", p, sub)
}

func (s *tenantStore) IdentityByID(_ context.Context, id string) (identity.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i, ok := s.idents[id]
	if !ok {
		return identity.Identity{}, fmt.Errorf("%w: identity %s", identity.ErrNotFound, id)
	}
	return i, nil
}

func (s *tenantStore) IdentitiesByUserID(_ context.Context, uid string) ([]identity.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]identity.Identity, 0)
	for _, i := range s.idents {
		if i.UserID == uid {
			out = append(out, i)
		}
	}
	return out, nil
}

func (s *tenantStore) InsertIdentity(_ context.Context, ni identity.NewIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.insertIdentityLocked(ni)
}

func (s *tenantStore) insertIdentityLocked(ni identity.NewIdentity) error {
	for _, i := range s.idents {
		// Unique per (tenant, provider, subject): two tenants may federate
		// against the SAME IdP without colliding.
		if i.TenantID == ni.TenantID && i.Provider == ni.Provider && i.Subject == ni.Subject {
			return fmt.Errorf("%w: %s/%s", identity.ErrIdentityTaken, ni.Provider, ni.Subject)
		}
	}
	// Explicit map, NOT identity.Identity(ni) — the same reasoning
	// identity/memstore.go records: NewIdentity is a COMMAND, Identity is
	// the persisted ENTITY, and their coinciding field sets are
	// incidental rather than an invitation to couple the two types.
	s.idents[ni.ID] = identity.Identity{ //nolint:staticcheck // S1016: command->entity map, kept explicit on purpose
		ID: ni.ID, UserID: ni.UserID, TenantID: ni.TenantID,
		Provider: ni.Provider, Subject: ni.Subject,
		LinkedAt: ni.LinkedAt, LastLoginAt: ni.LastLoginAt,
	}
	return nil
}

func (s *tenantStore) TouchIdentityLastLogin(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.idents[id]
	if !ok {
		return fmt.Errorf("%w: identity %s", identity.ErrNotFound, id)
	}
	t := at
	i.LastLoginAt = &t
	s.idents[id] = i
	return nil
}

func (s *tenantStore) DeleteIdentity(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.idents, id)
	return nil
}

func (s *tenantStore) CountIdentitiesByUserID(_ context.Context, uid string) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var n int64
	for _, i := range s.idents {
		if i.UserID == uid {
			n++
		}
	}
	return n, nil
}

// ProvisionUserWithIdentity writes both rows or neither, under one lock
// — the in-memory analogue of the adapter's transaction. The tenant adds
// no round trip: the Core hands both records in one call.
func (s *tenantStore) ProvisionUserWithIdentity(_ context.Context, u identity.NewUser, ni identity.NewIdentity, firstUser bool) (identity.User, identity.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.emailIndexLocked()[key(u.TenantID, u.Email)]; taken {
		return identity.User{}, identity.Identity{}, fmt.Errorf("%w: %s", identity.ErrEmailTaken, u.Email)
	}
	for _, i := range s.idents {
		if i.TenantID == ni.TenantID && i.Provider == ni.Provider && i.Subject == ni.Subject {
			return identity.User{}, identity.Identity{}, fmt.Errorf("%w: %s/%s", identity.ErrIdentityTaken, ni.Provider, ni.Subject)
		}
	}
	user := identity.User{
		ID: u.ID, TenantID: u.TenantID, Email: u.Email,
		PasswordHash: u.PasswordHash, Active: true, CreatedAt: u.CreatedAt,
	}
	ident := identity.Identity{ //nolint:staticcheck // S1016: command->entity map, kept explicit on purpose
		ID: ni.ID, UserID: ni.UserID, TenantID: ni.TenantID,
		Provider: ni.Provider, Subject: ni.Subject,
		LinkedAt: ni.LinkedAt, LastLoginAt: ni.LastLoginAt,
	}
	s.users[u.ID] = user
	s.idents[ni.ID] = ident
	s.bootstrapped[u.ID] = firstUser
	return user, ident, nil
}

// --- TOTP sub-surface: not exercised by this example ---

func (s *tenantStore) TOTPState(_ context.Context, uid string) (identity.TOTPState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.users[uid]; !ok {
		return identity.TOTPState{}, fmt.Errorf("%w: user %s", identity.ErrNotFound, uid)
	}
	return identity.TOTPState{}, nil
}

func (s *tenantStore) SetTOTPPending(context.Context, string, []byte, []string) error { return nil }
func (s *tenantStore) EnableTOTP(context.Context, string, []byte, []string, time.Time) error {
	return nil
}
func (s *tenantStore) SetRecoveryCodeHashes(context.Context, string, []string) error { return nil }
func (s *tenantStore) ClearTOTP(context.Context, string) error                       { return nil }
