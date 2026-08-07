package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

)

// This file is the local stand-in for `moon run barista:ci`, which
// cannot run from this repository. It exists because slice 7b-2 removed
// the module's ability to model a pre-Phase-7 adapter at all: MemStore
// now implements TenantScopedStore, so EVERY store in the module —
// production, examples and every test double — is *MemStore or embeds
// one. The compatibility path stopped having an independent witness.
//
// legacyStore is that witness. Two properties are load-bearing:
//
//  1. It does NOT embed MemStore. The other single-tenant stand-ins
//     (plainStore, singleTenantStore) satisfy Store by PROMOTION, so if
//     Store ever widens they are auto-satisfied and stay green while a
//     real hand-written adapter fails to compile. This one breaks, which
//     is the point.
//  2. It has no tenant column. It drops TenantID on every write and
//     always reads back "", modelling Barista's schema literally — so a
//     tenant value leaking into the compatibility path is observable
//     here and nowhere else.
//
// It does not replace Barista CI. Consumer-side lint and unkeyed
// composite literals in a separate repo remain out of reach.

// legacyStore is a hand-written, globally-keyed, single-tenant Store —
// the shape of an adapter written before Phase 7 existed.
type legacyStore struct {
	mu       sync.Mutex
	users    map[string]User
	sessions map[string]RefreshSession
	byHash   map[string]string
	idents   map[string]Identity
	totp     map[string]TOTPState

	// calls is the port call trace: every method the Core invokes, in
	// order. Golden-comparing it is what catches a change in the SHAPE
	// of the conversation — an extra read, a reordered lookup — that no
	// behavioural assertion notices because the outcome is unchanged.
	calls []string
	// tenantWrites records any non-empty TenantID that crossed the port
	// on a write. On the compatibility path this must stay empty.
	tenantWrites []string
}

// Store is satisfied by hand, not by promotion.
var _ Store = (*legacyStore)(nil)

func newLegacyStore() *legacyStore {
	return &legacyStore{
		users: map[string]User{}, sessions: map[string]RefreshSession{},
		byHash: map[string]string{}, idents: map[string]Identity{}, totp: map[string]TOTPState{},
	}
}

func (s *legacyStore) note(method string) { s.calls = append(s.calls, method) }

func (s *legacyStore) noteTenant(tenantID string) {
	if tenantID != "" {
		s.tenantWrites = append(s.tenantWrites, tenantID)
	}
}

func (s *legacyStore) trace() []string { return s.calls }

func (s *legacyStore) reset() { s.calls = nil }

func (s *legacyStore) CreateUser(_ context.Context, u NewUser, _ bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("CreateUser")
	s.noteTenant(u.TenantID)
	for _, e := range s.users { // UNIQUE(email), globally
		if e.Email == u.Email {
			return fmt.Errorf("%w: %s", ErrEmailTaken, u.Email)
		}
	}
	// No tenant column: the value is dropped on write, as Barista's
	// INSERT would drop a field its schema has never heard of.
	s.users[u.ID] = User{ID: u.ID, Email: u.Email, PasswordHash: u.PasswordHash, Active: true, CreatedAt: u.CreatedAt}
	return nil
}

func (s *legacyStore) UserByID(_ context.Context, id string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("UserByID")
	u, ok := s.users[id]
	if !ok {
		return User{}, fmt.Errorf("%w: user %s", ErrNotFound, id)
	}
	return u, nil
}

// UserByEmail is `WHERE email = ?` across every row — no tenant filter,
// because there is no tenant column.
func (s *legacyStore) UserByEmail(_ context.Context, email string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("UserByEmail")
	for _, u := range s.users {
		if u.Email == email {
			return u, nil
		}
	}
	return User{}, fmt.Errorf("%w: email %s", ErrNotFound, email)
}

func (s *legacyStore) CountUsers(context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("CountUsers")
	return int64(len(s.users)), nil
}

func (s *legacyStore) CreateRefreshSession(_ context.Context, x RefreshSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("CreateRefreshSession")
	s.noteTenant(x.TenantID)
	x.TenantID = "" // no column
	s.sessions[x.ID] = x
	s.byHash[x.TokenHash] = x.ID
	return nil
}

func (s *legacyStore) RefreshSessionByHash(_ context.Context, h string) (RefreshSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("RefreshSessionByHash")
	id, ok := s.byHash[h]
	if !ok {
		return RefreshSession{}, fmt.Errorf("%w: session", ErrNotFound)
	}
	return s.sessions[id], nil
}

func (s *legacyStore) RevokeRefreshSession(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("RevokeRefreshSession")
	if x, ok := s.sessions[id]; ok && !x.Revoked() {
		x.RevokedAt = at
		s.sessions[id] = x
	}
	return nil
}

func (s *legacyStore) RevokeAllRefreshSessionsForUser(_ context.Context, uid string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("RevokeAllRefreshSessionsForUser")
	for id, x := range s.sessions {
		if x.UserID == uid && !x.Revoked() {
			x.RevokedAt = at
			s.sessions[id] = x
		}
	}
	return nil
}

func (s *legacyStore) IdentityByProviderSubject(_ context.Context, p, sub string) (Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("IdentityByProviderSubject")
	for _, i := range s.idents {
		if i.Provider == p && i.Subject == sub {
			return i, nil
		}
	}
	return Identity{}, fmt.Errorf("%w: identity %s/%s", ErrNotFound, p, sub)
}

func (s *legacyStore) IdentityByID(_ context.Context, id string) (Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("IdentityByID")
	i, ok := s.idents[id]
	if !ok {
		return Identity{}, fmt.Errorf("%w: identity %s", ErrNotFound, id)
	}
	return i, nil
}

func (s *legacyStore) IdentitiesByUserID(_ context.Context, uid string) ([]Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("IdentitiesByUserID")
	out := make([]Identity, 0)
	for _, i := range s.idents {
		if i.UserID == uid {
			out = append(out, i)
		}
	}
	return out, nil
}

func (s *legacyStore) InsertIdentity(_ context.Context, ni NewIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("InsertIdentity")
	s.noteTenant(ni.TenantID)
	for _, i := range s.idents { // UNIQUE(provider, subject), globally
		if i.Provider == ni.Provider && i.Subject == ni.Subject {
			return fmt.Errorf("%w: %s/%s", ErrIdentityTaken, ni.Provider, ni.Subject)
		}
	}
	s.idents[ni.ID] = Identity{ID: ni.ID, UserID: ni.UserID, Provider: ni.Provider, Subject: ni.Subject, LinkedAt: ni.LinkedAt, LastLoginAt: ni.LastLoginAt}
	return nil
}

func (s *legacyStore) TouchIdentityLastLogin(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("TouchIdentityLastLogin")
	i, ok := s.idents[id]
	if !ok {
		return fmt.Errorf("%w: identity %s", ErrNotFound, id)
	}
	t := at
	i.LastLoginAt = &t
	s.idents[id] = i
	return nil
}

func (s *legacyStore) DeleteIdentity(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("DeleteIdentity")
	delete(s.idents, id)
	return nil
}

func (s *legacyStore) CountIdentitiesByUserID(_ context.Context, uid string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("CountIdentitiesByUserID")
	var n int64
	for _, i := range s.idents {
		if i.UserID == uid {
			n++
		}
	}
	return n, nil
}

func (s *legacyStore) ProvisionUserWithIdentity(_ context.Context, u NewUser, ni NewIdentity, _ bool) (User, Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("ProvisionUserWithIdentity")
	s.noteTenant(u.TenantID)
	s.noteTenant(ni.TenantID)
	for _, e := range s.users {
		if e.Email == u.Email {
			return User{}, Identity{}, fmt.Errorf("%w: %s", ErrEmailTaken, u.Email)
		}
	}
	for _, i := range s.idents {
		if i.Provider == ni.Provider && i.Subject == ni.Subject {
			return User{}, Identity{}, fmt.Errorf("%w: %s/%s", ErrIdentityTaken, ni.Provider, ni.Subject)
		}
	}
	user := User{ID: u.ID, Email: u.Email, PasswordHash: u.PasswordHash, Active: true, CreatedAt: u.CreatedAt}
	ident := Identity{ID: ni.ID, UserID: ni.UserID, Provider: ni.Provider, Subject: ni.Subject, LinkedAt: ni.LinkedAt, LastLoginAt: ni.LastLoginAt}
	s.users[u.ID] = user
	s.idents[ni.ID] = ident
	return user, ident, nil
}

func (s *legacyStore) TOTPState(_ context.Context, uid string) (TOTPState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("TOTPState")
	if _, ok := s.users[uid]; !ok {
		return TOTPState{}, fmt.Errorf("%w: user %s", ErrNotFound, uid)
	}
	return s.totp[uid], nil
}

func (s *legacyStore) SetTOTPPending(_ context.Context, uid string, env []byte, hashes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("SetTOTPPending")
	s.totp[uid] = TOTPState{Envelope: env, RecoveryCodeHashes: hashes}
	return nil
}

func (s *legacyStore) EnableTOTP(_ context.Context, uid string, env []byte, hashes []string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("EnableTOTP")
	s.totp[uid] = TOTPState{Enrolled: true, Envelope: env, RecoveryCodeHashes: hashes}
	if u, ok := s.users[uid]; ok {
		u.TOTPEnrolled = true
		s.users[uid] = u
	}
	return nil
}

func (s *legacyStore) SetRecoveryCodeHashes(_ context.Context, uid string, hashes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("SetRecoveryCodeHashes")
	st := s.totp[uid]
	st.RecoveryCodeHashes = hashes
	s.totp[uid] = st
	return nil
}

func (s *legacyStore) ClearTOTP(_ context.Context, uid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note("ClearTOTP")
	delete(s.totp, uid)
	return nil
}

func legacyCore(t *testing.T, s *legacyStore, opts ...Option) *Core {
	t.Helper()
	base := []Option{WithRefreshTTL(30 * 24 * time.Hour), WithDefaultACR(testACR)}
	c, err := New(s, testJWT(), append(base, opts...)...)
	if err != nil {
		t.Fatalf("New over the legacy adapter: %v", err)
	}
	return c
}

// TestLegacyStore_IsNotTenantScoped guards the fixture itself. The day
// someone "simplifies" legacyStore by embedding MemStore, it silently
// becomes tenant-scoped and stops modelling anything — this fails first
// and says why.
func TestLegacyStore_IsNotTenantScoped(t *testing.T) {
	if _, ok := any(newLegacyStore()).(TenantScopedStore); ok {
		t.Fatal("legacyStore implements TenantScopedStore; it must model a PRE-Phase-7 adapter, " +
			"or the compatibility path has no independent witness left in this module")
	}
}

// TestLegacyAdapter_BaristaFlowsUnchanged drives the flow list Barista
// drives, against a store that has never heard of a tenant.
func TestLegacyAdapter_BaristaFlowsUnchanged(t *testing.T) {
	ctx := context.Background()
	s := newLegacyStore()
	c := legacyCore(t, s, WithKeySet(testKeySet(t)))

	// Register: first user gets the bootstrap signal.
	var firstSeen bool
	c.hooks.OnRegistered = func(_ context.Context, _ User, first bool) { firstSeen = first }
	alice, tokens, err := c.Register(ctx, "alice@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !firstSeen {
		t.Error("first user did not receive firstUser=true")
	}
	if _, _, err := c.Register(ctx, "bob@example.com", "correct-horse"); err != nil {
		t.Fatalf("Register second: %v", err)
	}

	// Duplicate email still collides on the adapter's global index.
	if _, _, err := c.Register(ctx, "alice@example.com", "correct-horse"); !errors.Is(err, ErrEmailTaken) {
		t.Errorf("duplicate register err = %v, want ErrEmailTaken", err)
	}

	// Login: success and the collapsed rejections.
	if _, _, err := c.Login(ctx, "alice@example.com", "correct-horse"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	for _, tc := range []struct{ name, email, pw string }{
		{"wrong password", "alice@example.com", "nope"},
		{"unknown email", "nobody@example.com", "correct-horse"},
	} {
		if _, _, err := c.Login(ctx, tc.email, tc.pw); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s: err = %v, want ErrInvalidCredentials", tc.name, err)
		}
	}

	// Refresh rotation, then Logout, then RevokeAllSessions.
	_, rotated, err := c.Refresh(ctx, tokens.Refresh)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if err := c.Logout(ctx, rotated.Refresh); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if err := c.RevokeAllSessions(ctx, alice.ID); err != nil {
		t.Fatalf("RevokeAllSessions: %v", err)
	}

	// Federated: resolve miss, provision, resolve hit, link, unlink.
	if _, _, found, err := c.ResolveByIdentity(ctx, "google", "sub-1"); err != nil || found {
		t.Fatalf("ResolveByIdentity(miss) = (%v, %v), want (false, nil)", found, err)
	}
	fed, ident, err := c.ProvisionUserWithIdentity(ctx, "carol@example.com", "google", "sub-1")
	if err != nil {
		t.Fatalf("ProvisionUserWithIdentity: %v", err)
	}
	if _, _, found, err := c.ResolveByIdentity(ctx, "google", "sub-1"); err != nil || !found {
		t.Fatalf("ResolveByIdentity(hit) = (%v, %v), want (true, nil)", found, err)
	}
	if _, err := c.Link(ctx, alice.ID, "saml", "sub-2"); err != nil {
		t.Fatalf("Link: %v", err)
	}
	if err := c.Unlink(ctx, alice.ID, mustIdentityID(t, c, ctx, alice.ID)); err != nil {
		t.Fatalf("Unlink: %v", err)
	}
	// A federated-only user cannot unlink their last method.
	if err := c.Unlink(ctx, fed.ID, ident.ID); !errors.Is(err, ErrLastAuthMethod) {
		t.Errorf("Unlink last method err = %v, want ErrLastAuthMethod", err)
	}

	// THE TRIPWIRE. Nothing on the compatibility path may push a tenant
	// across the port. A non-empty value here means the "" path started
	// inventing tenants — the failure Barista would surface as a column
	// that does not exist.
	if len(s.tenantWrites) != 0 {
		t.Errorf("tenant ids crossed the port on the compatibility path: %v", s.tenantWrites)
	}
}

func mustIdentityID(t *testing.T, c *Core, ctx context.Context, userID string) string {
	t.Helper()
	list, err := c.ListIdentities(ctx, userID)
	if err != nil || len(list) == 0 {
		t.Fatalf("ListIdentities: %v (%d)", err, len(list))
	}
	return list[0].ID
}

// TestLegacyAdapter_ProvisionPortTrace is the guard for 7b-2's atomicity
// invariant: "ProvisionUserWithIdentity stays atomic. The tenant does not
// introduce a second round trip between resolve and provision."
//
// No behavioural assertion can see that. A JIT provision uses a fresh
// email, so an extra pre-flight read MISSES and the flow still succeeds —
// which is why an added read compiled and left the whole suite green. The
// only observable is the SHAPE of the port conversation, so this pins it
// exactly: count, then the single atomic write. Nothing between them.
func TestLegacyAdapter_ProvisionPortTrace(t *testing.T) {
	ctx := context.Background()
	s := newLegacyStore()
	c := legacyCore(t, s)

	s.reset()
	if _, _, err := c.ProvisionUserWithIdentity(ctx, "dave@example.com", "google", "sub-9"); err != nil {
		t.Fatalf("ProvisionUserWithIdentity: %v", err)
	}

	want := []string{"CountUsers", "ProvisionUserWithIdentity"}
	got := s.trace()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("provision port trace = %v, want %v\n"+
			"An extra read here widens the window between the caller's resolve and its provision — "+
			"which is where the app's email-collision veto wedges, and widening it reopens the "+
			"lost-first-sign-in race (7b-2 invariant).", got, want)
	}
}

// TestLegacyAdapter_LoginPortTrace pins that the compatibility path uses
// the UNSCOPED lookup and reads the user exactly once. A Core that
// consulted a scoped method here would not compile against this adapter
// — which is the whole reason the fixture does not embed MemStore.
func TestLegacyAdapter_LoginPortTrace(t *testing.T) {
	ctx := context.Background()
	s := newLegacyStore()
	c := legacyCore(t, s)
	if _, _, err := c.Register(ctx, "erin@example.com", "correct-horse"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	s.reset()
	if _, _, err := c.Login(ctx, "erin@example.com", "correct-horse"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	want := []string{"UserByEmail", "CreateRefreshSession"}
	if got := s.trace(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("login port trace = %v, want %v", got, want)
	}
}

// TestLegacyAdapter_SentinelParity pins the error vocabulary an app maps
// onto its own wire errors. A changed sentinel is invisible here and a
// 500 in production.
func TestLegacyAdapter_SentinelParity(t *testing.T) {
	ctx := context.Background()
	s := newLegacyStore()
	c := legacyCore(t, s)

	if _, _, err := c.Register(ctx, "frank@example.com", "correct-horse"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, _, err := c.Register(ctx, "frank@example.com", "correct-horse"); !errors.Is(err, ErrEmailTaken) {
		t.Errorf("ErrEmailTaken not surfaced: %v", err)
	}
	if _, _, err := c.Login(ctx, "frank@example.com", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("ErrInvalidCredentials not surfaced: %v", err)
	}
	if _, _, err := c.Refresh(ctx, "not-a-token"); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("ErrInvalidSession not surfaced: %v", err)
	}
	if err := c.Unlink(ctx, "nobody", "nothing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ErrNotFound not surfaced: %v", err)
	}
	// Cross-user link conflict keeps its pre-delegation message.
	if _, _, err := c.ProvisionUserWithIdentity(ctx, "gina@example.com", "google", "sub-x"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	u, err := c.store.UserByEmail(ctx, "frank@example.com")
	if err != nil {
		t.Fatalf("UserByEmail: %v", err)
	}
	if _, err := c.Link(ctx, u.ID, "google", "sub-x"); !errors.Is(err, ErrLinkConflict) {
		t.Errorf("ErrLinkConflict not surfaced: %v", err)
	}
}

