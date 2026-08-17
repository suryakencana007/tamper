package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
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

	user, _, err := c.Register(ctx, tenant.Single, "bob@acme.com", "correct-horse")
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

	_, tokens, err := c.Register(ctx, tenant.Single, "carol@example.com", "correct-horse")
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

	if _, _, err := c.ProvisionUserWithIdentity(ctx, tenant.Single, "dave@acme.com", "google", "sub-1"); err != nil {
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

	user, ident, err := store.ProvisionUserWithIdentity(ctx, NewUser{ID: "u1", TenantID: "acme", Email: "erin@acme.com", CreatedAt: now},
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
	scoped, err := store.UserByEmail(ctx, tenant.New("globex"), "gina@globex.com")
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
	if _, err := store.UserByEmail(ctx, tenant.Single, "gina@globex.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unscoped UserByEmail found a tenant-owned user: err = %v, want ErrNotFound", err)
	}
}

// --- v0.5.0 (M2 slice 1): the tenant-aware mint entry point ----------
//
// 7b-1 carried a tenant that nothing could supply; the tests above had
// to hand-seed a session row to observe the carry at all. These pin the
// entry point that closes that gap, and the deny that keeps it honest.

// TestIssueTokensForUserInTenant_DeniesUnsetTenant is the fence. An
// unset tenant must NOT fall back to Single: a caller reaching for this
// method is asserting it has a tenant, so an unset one is a wiring bug,
// and minting a Single-scoped session for it would hand back a token
// authorising the wrong scope.
//
// Mutation check: replace the tenantGate call with a Single fallback and
// this fails.
func TestIssueTokensForUserInTenant_DeniesUnsetTenant(t *testing.T) {
	ctx := context.Background()
	c, store := testCore(t)

	user, _, err := c.Register(ctx, tenant.Single, "zoe@acme.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Register already minted a session, so count the delta rather than
	// asserting the store is empty.
	before := len(store.sessions)

	var unset tenant.ID // the zero value -- "I forgot", not "single"
	if _, err := c.IssueTokensForUserInTenant(ctx, user.ID, unset, 0, ""); !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("err = %v, want ErrTenantRequired", err)
	}

	// And it denied BEFORE writing anything: a refused mint must not
	// leave a session behind for the caller to stumble onto later.
	if after := len(store.sessions); after != before {
		t.Fatalf("sessions %d -> %d: a REFUSED mint persisted a session", before, after)
	}
}

// TestIssueTokensForUserInTenant_CarriesTenantIntoJWTAndSession pins the
// two places the tenant must land, and then that rotation preserves it.
// Losing it in either place is silent: the token still verifies, the
// refresh still works, and the session has quietly widened to the
// single-tenant shape.
func TestIssueTokensForUserInTenant_CarriesTenantIntoJWTAndSession(t *testing.T) {
	ctx := context.Background()
	c, store := testCore(t)

	user, _, err := c.Register(ctx, tenant.Single, "acme-user@acme.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	acme := tenant.New("acme")
	tokens, err := c.IssueTokensForUserInTenant(ctx, user.ID, acme, 0, "")
	if err != nil {
		t.Fatalf("IssueTokensForUserInTenant: %v", err)
	}

	// 1. the access JWT's tid claim -- verifying against the WRONG
	//    tenant must fail, which is what makes the claim load-bearing.
	if _, err := c.jwt.VerifyAccess(tokens.Access, acme); err != nil {
		t.Errorf("VerifyAccess against the minting tenant: %v", err)
	}
	if _, err := c.jwt.VerifyAccess(tokens.Access, tenant.Single); err == nil {
		t.Error("token minted for \"acme\" verified against Single -- the tid claim is not binding")
	}

	// 2. the refresh session row.
	// Register minted a Single session first, so look for the acme one
	// specifically rather than asserting every row carries it.
	var acmeSessions int
	for _, s := range store.sessions {
		if s.UserID == user.ID && s.TenantID == "acme" {
			acmeSessions++
		}
	}
	if acmeSessions != 1 {
		t.Fatalf("sessions carrying TenantID=acme = %d, want 1 (of %d total)", acmeSessions, len(store.sessions))
	}

	// 3. rotation inherits it. This is the end-to-end shape 7b-1 could
	//    only fake by hand-seeding a row.
	_, rotated, err := c.Refresh(ctx, tokens.Refresh)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if _, err := c.jwt.VerifyAccess(rotated.Access, acme); err != nil {
		t.Errorf("rotated token lost the tenant: %v", err)
	}
}

// TestIssueTokensForUserInTenant_SingleMatchesTheShim pins the
// compatibility claim in the method's doc: passing Single explicitly is
// the same session the pre-v0.5.0 shim produces. If these ever diverge,
// a single-tenant deployment migrating onto the new entry point would
// change behaviour while reading as a no-op.
func TestIssueTokensForUserInTenant_SingleMatchesTheShim(t *testing.T) {
	ctx := context.Background()
	c, store := testCore(t)

	user, _, err := c.Register(ctx, tenant.Single, "single@acme.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	emptyBefore := 0
	for _, s := range store.sessions {
		if s.UserID == user.ID && s.TenantID == "" {
			emptyBefore++
		}
	}

	viaShim, err := c.IssueTokensForUserWithACR(ctx, user.ID, 0, "")
	if err != nil {
		t.Fatalf("shim mint: %v", err)
	}
	viaTenant, err := c.IssueTokensForUserInTenant(ctx, user.ID, tenant.Single, 0, "")
	if err != nil {
		t.Fatalf("tenant mint: %v", err)
	}

	for _, tok := range []string{viaShim.Access, viaTenant.Access} {
		claims, err := c.jwt.ParseAccess(tok)
		if err != nil {
			t.Fatalf("ParseAccess: %v", err)
		}
		if claims.TenantID != "" {
			t.Errorf("tid = %q, want empty for Single", claims.TenantID)
		}
	}
	var emptyAfter int
	for _, s := range store.sessions {
		if s.UserID == user.ID && s.TenantID == "" {
			emptyAfter++
		}
	}
	if got := emptyAfter - emptyBefore; got != 2 {
		t.Errorf("empty-tenant sessions added by the two mints = %d, want 2 (one per path)", got)
	}
}
