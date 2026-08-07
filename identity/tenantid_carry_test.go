package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/crypto"
)

// Slice 7b-1 carries TenantID through mint / rotate / link without ever
// branching on it. These tests pin the CARRY. Nothing here asserts a
// tenant-scoped decision — that is 7b-2's work, behind its own mutation
// proofs.

// TestRefresh_PreservesTenantIDOnSuccessor is the headline guard. The
// rotation carry-forward already protects AuthTime and ACR; TenantID
// joins them for a sharper reason. Dropping it does not merely lose a
// value: the successor lands with "", which every tenant-scoped read
// treats as the single-tenant shape. A session silently widens from one
// tenant to no tenant, and no test that only checks "refresh works"
// would ever notice.
func TestRefresh_PreservesTenantIDOnSuccessor(t *testing.T) {
	ctx := context.Background()
	c, store := testCore(t)

	user, _, err := c.Register(ctx, "bob@acme.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Register cannot supply a tenant in 7b-1, so seed a tenant-bearing
	// session directly — the shape a pooled deployment produces once
	// 7b-2 routes it.
	plaintext, err := crypto.NewRefreshToken()
	if err != nil {
		t.Fatalf("NewRefreshToken: %v", err)
	}
	hash, err := crypto.HashRefreshToken(plaintext)
	if err != nil {
		t.Fatalf("HashRefreshToken: %v", err)
	}
	now := time.Now()
	if err := store.CreateRefreshSession(ctx, RefreshSession{
		ID:        "sess-tenant",
		UserID:    user.ID,
		TenantID:  "acme",
		TokenHash: hash,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		AuthTime:  now,
		ACR:       testACR,
	}); err != nil {
		t.Fatalf("CreateRefreshSession: %v", err)
	}

	_, tokens, err := c.Refresh(ctx, plaintext)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	succHash, err := crypto.HashRefreshToken(tokens.Refresh)
	if err != nil {
		t.Fatalf("HashRefreshToken(successor): %v", err)
	}
	succ, ok := store.SessionByHash(succHash)
	if !ok {
		t.Fatal("successor session not persisted")
	}
	if succ.TenantID != "acme" {
		t.Errorf("successor TenantID = %q, want %q — rotation dropped the tenant", succ.TenantID, "acme")
	}
	// The successor is a genuinely new row, not the one we seeded.
	if succ.ID == "sess-tenant" {
		t.Error("expected a rotated successor row, got the original")
	}
}

// TestRefresh_EmptyTenantStaysEmpty is the parity half: a pre-7b-1 row
// carries no tenant, and rotation must not invent one.
func TestRefresh_EmptyTenantStaysEmpty(t *testing.T) {
	ctx := context.Background()
	c, store := testCore(t)

	_, tokens, err := c.Register(ctx, "carol@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, rotated, err := c.Refresh(ctx, tokens.Refresh)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	h, err := crypto.HashRefreshToken(rotated.Refresh)
	if err != nil {
		t.Fatalf("HashRefreshToken: %v", err)
	}
	succ, ok := store.SessionByHash(h)
	if !ok {
		t.Fatal("successor session not persisted")
	}
	if succ.TenantID != "" {
		t.Errorf("successor TenantID = %q, want empty — rotation invented a tenant", succ.TenantID)
	}
}

// provisionSpy records the command pair the core hands the store.
// Embedding *MemStore supplies the rest of the Store surface.
type provisionSpy struct {
	*MemStore
	gotUser  NewUser
	gotIdent NewIdentity
}

func (s *provisionSpy) ProvisionUserWithIdentity(ctx context.Context, u NewUser, ni NewIdentity, first bool) (User, Identity, error) {
	s.gotUser, s.gotIdent = u, ni
	return s.MemStore.ProvisionUserWithIdentity(ctx, u, ni, first)
}

// TestProvisionUserWithIdentity_CouplesTenantAcrossBothRows pins that the
// core hands ONE tenant to both rows of the atomic pair. If the two ever
// diverge, a (provider, subject) resolves into a tenant its user does not
// belong to — a cross-tenant bind created at signup, by construction.
func TestProvisionUserWithIdentity_CouplesTenantAcrossBothRows(t *testing.T) {
	ctx := context.Background()
	spy := &provisionSpy{MemStore: NewMemStore()}
	c, err := New(spy, testJWT(), WithRefreshTTL(time.Hour), WithDefaultACR(testACR))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, _, err := c.ProvisionUserWithIdentity(ctx, "dave@acme.com", "google", "sub-1"); err != nil {
		t.Fatalf("ProvisionUserWithIdentity: %v", err)
	}
	if spy.gotUser.TenantID != spy.gotIdent.TenantID {
		t.Errorf("tenant diverged across the atomic pair: user %q vs identity %q",
			spy.gotUser.TenantID, spy.gotIdent.TenantID)
	}
}

// TestMemStore_ProvisionUserWithIdentity_PersistsTenantOnBothRows proves
// the store MAPPING carries the field, with a real value — the half the
// core-level coupling test cannot reach while nothing supplies a tenant.
func TestMemStore_ProvisionUserWithIdentity_PersistsTenantOnBothRows(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	now := time.Now()

	user, ident, err := store.ProvisionUserWithIdentity(ctx,
		NewUser{ID: "u1", TenantID: "acme", Email: "erin@acme.com", CreatedAt: now},
		NewIdentity{ID: "i1", UserID: "u1", TenantID: "acme", Provider: "google", Subject: "sub-1", LinkedAt: now},
		false)
	if err != nil {
		t.Fatalf("ProvisionUserWithIdentity: %v", err)
	}
	if user.TenantID != "acme" {
		t.Errorf("user TenantID = %q, want %q", user.TenantID, "acme")
	}
	if ident.TenantID != "acme" {
		t.Errorf("identity TenantID = %q, want %q", ident.TenantID, "acme")
	}

	// And it survives a re-read, not just the return value.
	got, err := store.UserByID(ctx, "u1")
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if got.TenantID != "acme" {
		t.Errorf("re-read user TenantID = %q, want %q", got.TenantID, "acme")
	}
	gotIdent, err := store.IdentityByID(ctx, "i1")
	if err != nil {
		t.Fatalf("IdentityByID: %v", err)
	}
	if gotIdent.TenantID != "acme" {
		t.Errorf("re-read identity TenantID = %q, want %q", gotIdent.TenantID, "acme")
	}
}

// TestLink_InheritsTenantFromTargetUser: linking an external credential
// to an existing account must place the identity in THAT account's
// tenant. The core already loads the target user for its existence
// check, so the value is free — the risk is that it stays discarded.
func TestLink_InheritsTenantFromTargetUser(t *testing.T) {
	ctx := context.Background()
	c, store := testCore(t)

	store.Seed(User{ID: "u-acme", TenantID: "acme", Email: "frank@acme.com", PasswordHash: "x", Active: true})

	ident, err := c.Link(ctx, "u-acme", "google", "sub-9")
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	if ident.TenantID != "acme" {
		t.Errorf("returned identity TenantID = %q, want %q", ident.TenantID, "acme")
	}
	stored, err := store.IdentityByID(ctx, ident.ID)
	if err != nil {
		t.Fatalf("IdentityByID: %v", err)
	}
	if stored.TenantID != "acme" {
		t.Errorf("persisted identity TenantID = %q, want %q", stored.TenantID, "acme")
	}
}

// TestMemStore_CreateUser_PersistsTenant pins the remaining store
// mapping: CreateUser rebuilds the entity field by field, so a new field
// is exactly the kind that gets forgotten there.
func TestMemStore_CreateUser_PersistsTenant(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()

	if err := store.CreateUser(ctx, NewUser{
		ID: "u2", TenantID: "globex", Email: "gina@globex.com", CreatedAt: time.Now(),
	}, false); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, err := store.UserByID(ctx, "u2")
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if got.TenantID != "globex" {
		t.Errorf("TenantID = %q, want %q", got.TenantID, "globex")
	}

	// The tenant-scoped read finds them...
	scoped, err := store.UserByEmailInTenant(ctx, "globex", "gina@globex.com")
	if err != nil {
		t.Fatalf("UserByEmailInTenant: %v", err)
	}
	if scoped.ID != "u2" {
		t.Errorf("UserByEmailInTenant returned %q, want %q", scoped.ID, "u2")
	}

	// ...and the UNSCOPED read does not. This is the 7b-2 rule, pinned
	// here because it is easy to read as a regression: "" is a tenant
	// like any other, and Store.UserByEmail is the ""-tenant lookup. If
	// it could reach into a tenant, a tenancy-OFF caller would resolve
	// tenant-owned rows — cross-tenant access by omission, which is the
	// fail-open shape deny-by-default exists to prevent (§6.2).
	if _, err := store.UserByEmail(ctx, "gina@globex.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unscoped UserByEmail found a tenant-owned user: err = %v, want ErrNotFound", err)
	}
}
