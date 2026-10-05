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

	// The user is stored in acme, so the session Register mints carries
	// acme, and that is the session rotated here.
	_, tokens, err := c.Register(ctx, tenant.New("acme"), "bob@acme.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	origHash, err := crypto.HashRefreshToken(tokens.Refresh)
	if err != nil {
		t.Fatalf("HashRefreshToken: %v", err)
	}
	orig, ok := store.SessionByHash(origHash)
	if !ok || orig.TenantID != "acme" {
		t.Fatalf("fixture: the registered session should carry acme, got %+v (found=%v)", orig, ok)
	}

	_, rotated, err := c.Refresh(ctx, tokens.Refresh)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	succHash, err := crypto.HashRefreshToken(rotated.Refresh)
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
	// The successor is a genuinely new row, not the one Register minted.
	if succ.ID == orig.ID {
		t.Error("expected a rotated successor row, got the original")
	}
}

// seedSession writes a live refresh session for userID in tenantID
// straight into the store, the way an application (or an older version
// of this package) could have, and returns its plaintext token.
func seedSession(t *testing.T, store *MemStore, id, userID, tenantID string) string {
	t.Helper()
	plaintext, err := crypto.NewRefreshToken()
	if err != nil {
		t.Fatalf("NewRefreshToken: %v", err)
	}
	hash, err := crypto.HashRefreshToken(plaintext)
	if err != nil {
		t.Fatalf("HashRefreshToken: %v", err)
	}
	now := time.Now()
	if err := store.CreateRefreshSession(context.Background(), RefreshSession{
		ID: id, UserID: userID, TenantID: tenantID, TokenHash: hash,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), AuthTime: now, ACR: testACR,
	}); err != nil {
		t.Fatalf("CreateRefreshSession: %v", err)
	}
	return plaintext
}

// TestRefresh_DeniesSessionInAnotherTenant (TD-19): a session whose
// tenant is not the one its user is stored in must not rotate. Rotation
// would copy the session's tenant into a new access token, so the user
// would keep getting tokens for a tenant they do not belong to.
func TestRefresh_DeniesSessionInAnotherTenant(t *testing.T) {
	acme, globex := tenant.New("acme"), tenant.New("globex")
	for _, tc := range []struct {
		name          string
		userTenant    tenant.ID
		sessionTenant string
	}{
		{"tenant user, session in another tenant", globex, "acme"},
		{"single-tenant user, session in a tenant", tenant.Single, "acme"},
		{"tenant user, session with no tenant", acme, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c, store := testCore(t)
			user, _, err := c.Register(ctx, tc.userTenant, "bob@example.com", "correct-horse")
			if err != nil {
				t.Fatalf("Register: %v", err)
			}
			token := seedSession(t, store, "sess-cross", user.ID, tc.sessionTenant)
			before := sessionsFor(store, user.ID)

			_, tokens, err := c.Refresh(ctx, token)
			if !errors.Is(err, ErrInvalidSession) {
				t.Fatalf("Refresh of a session in %q for a user stored in %q: err = %v, want ErrInvalidSession",
					tc.sessionTenant, tc.userTenant.String(), err)
			}
			if tokens != (Tokens{}) {
				t.Errorf("a REFUSED refresh returned tokens: %+v", tokens)
			}
			if after := sessionsFor(store, user.ID); after != before {
				t.Fatalf("sessions %d -> %d: a refused refresh minted a successor", before, after)
			}
			// Revoked, so the same token cannot be tried again.
			hash, _ := crypto.HashRefreshToken(token)
			if s, ok := store.SessionByHash(hash); !ok || !s.Revoked() {
				t.Errorf("the refused session was left live: %+v (found=%v)", s, ok)
			}
		})
	}
}

// TestRefresh_CrossTenantSessionDoesNotDiscloseInactive: ErrUserInactive
// is the one refresh failure that says something about the user. It must
// not be said through a session bound to another tenant.
func TestRefresh_CrossTenantSessionDoesNotDiscloseInactive(t *testing.T) {
	ctx := context.Background()
	c, store := testCore(t)
	user, _, err := c.Register(ctx, tenant.New("globex"), "bob@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	store.SetActive(user.ID, false)

	if _, _, err := c.Refresh(ctx, seedSession(t, store, "sess-cross", user.ID, "acme")); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("cross-tenant session of an inactive user: err = %v, want ErrInvalidSession "+
			"(ErrUserInactive here tells acme that the user exists in another tenant)", err)
	}
	// In the user's own tenant the inactive answer is unchanged.
	if _, _, err := c.Refresh(ctx, seedSession(t, store, "sess-own", user.ID, "globex")); !errors.Is(err, ErrUserInactive) {
		t.Fatalf("own-tenant session of an inactive user: err = %v, want ErrUserInactive", err)
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

	// The user is registered IN acme. This test used to register in
	// tenant.Single and then mint into acme — which is the cross-tenant
	// mint TD-10 closed, so the fixture, not the assertions, had to move.
	acme := tenant.New("acme")
	user, _, err := c.Register(ctx, acme, "acme-user@acme.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Register already minted an acme session of its own, so count the
	// delta rather than the total.
	acmeSessionsFor := func() int {
		var n int
		for _, s := range store.sessions {
			if s.UserID == user.ID && s.TenantID == "acme" {
				n++
			}
		}
		return n
	}
	before := acmeSessionsFor()

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
	if got := acmeSessionsFor() - before; got != 1 {
		t.Fatalf("sessions carrying TenantID=acme added by the mint = %d, want 1 (of %d total)", got, len(store.sessions))
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

// --- TD-10: the tenant-aware mint checks the user's STORED tenant ----
//
// The entry point above denied an unset tenant and nothing else: it
// minted for any user in any tenant, so the rights check lived entirely
// with the caller. The TOTP second leg is the caller that could not make
// it — it holds a bare user id — and an adapter that minted with the
// ROUTED tenant handed a globex user a session with tid=acme. These pin
// the check that moved into the Core.

// sessionsFor counts the refresh sessions persisted for one user.
func sessionsFor(store *MemStore, userID string) int {
	var n int
	for _, s := range store.sessions {
		if s.UserID == userID {
			n++
		}
	}
	return n
}

// TestIssueTokensForUserInTenant_DeniesMismatchedTenant is the fence.
// Every pairing of a stored tenant with a DIFFERENT requested one is
// refused, including the two that involve tenant.Single — "" is a tenant
// like any other, not a wildcard in either direction.
//
// The second half is standing rule 3. The refusal is compared, text and
// all, against the error the SAME call returns once the user's row is
// gone: a deny and a miss that differ by a word are an oracle for which
// user ids exist in another tenant.
//
// Mutation check: delete the FromStored comparison in
// IssueTokensForUserInTenant and every case here mints.
func TestIssueTokensForUserInTenant_DeniesMismatchedTenant(t *testing.T) {
	acme, globex := tenant.New("acme"), tenant.New("globex")
	for _, tc := range []struct {
		name      string
		stored    tenant.ID
		requested tenant.ID
	}{
		// TD-10 as reported: a globex user, minted for at acme.
		{"tenant user into another tenant", globex, acme},
		{"single-tenant user into a tenant", tenant.Single, acme},
		{"tenant user into the single tenant", acme, tenant.Single},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c, store := testCore(t)

			user, _, err := c.Register(ctx, tc.stored, "bob@example.com", "correct-horse")
			if err != nil {
				t.Fatalf("Register: %v", err)
			}
			before := sessionsFor(store, user.ID)

			tokens, denyErr := c.IssueTokensForUserInTenant(ctx, user.ID, tc.requested, 0, "")
			if !errors.Is(denyErr, ErrNotFound) {
				t.Fatalf("a user stored in %q minted into %q: err = %v, want ErrNotFound",
					tc.stored.String(), tc.requested.String(), denyErr)
			}
			if tokens != (Tokens{}) {
				t.Errorf("a REFUSED mint returned tokens: %+v", tokens)
			}
			// Denied BEFORE writing: a refused mint that left a refresh
			// session behind would still be a cross-tenant grant, just one
			// the caller has to find.
			if after := sessionsFor(store, user.ID); after != before {
				t.Fatalf("sessions %d -> %d: a REFUSED mint persisted a session", before, after)
			}

			// The control: the same user id with no row at all.
			store.mu.Lock()
			delete(store.usersByID, user.ID)
			store.mu.Unlock()
			_, missErr := c.IssueTokensForUserInTenant(ctx, user.ID, tc.requested, 0, "")
			if !errors.Is(missErr, ErrNotFound) {
				t.Fatalf("missing user: err = %v, want ErrNotFound", missErr)
			}
			if denyErr.Error() != missErr.Error() {
				t.Errorf("wrong-tenant error %q differs from missing-user error %q — the difference "+
					"is an oracle for which users exist in another tenant", denyErr, missErr)
			}
			if after := sessionsFor(store, user.ID); after != before {
				t.Fatalf("sessions %d -> %d: a mint for a missing user persisted a session", before, after)
			}
		})
	}
}

// TestIssueTokensForUserInTenant_PendingTokenCannotMintIntoAnotherTenant
// walks TD-10 end to end, the way the proof that found it did: a globex
// user clears the password step, and the pending token is replayed at
// acme's totp-verify.
//
// Two fences stand in the way now, and the test takes them one at a
// time because either alone would have been enough. The pending token is
// bound to globex, so acme's verify refuses it. And an adapter that
// never got that far — one still on the unbound pair, minting with the
// ROUTED tenant — is refused by the Core.
// TestIssueTokensForUserInTenant_DeniesInactiveUser: the user is
// deactivated between the password step and the mint. Login and Refresh
// both refuse an inactive account; the mint that follows a second factor
// must not be the one path that still hands out a session.
func TestIssueTokensForUserInTenant_DeniesInactiveUser(t *testing.T) {
	ctx := context.Background()
	c, store := testCore(t)
	acme, globex := tenant.New("acme"), tenant.New("globex")

	user, _, err := c.Register(ctx, acme, "bob@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	store.SetActive(user.ID, false)
	before := sessionsFor(store, user.ID)

	tokens, err := c.IssueTokensForUserInTenant(ctx, user.ID, acme, 0, "")
	if !errors.Is(err, ErrUserInactive) {
		t.Fatalf("mint for a deactivated user: err = %v, want ErrUserInactive", err)
	}
	if tokens != (Tokens{}) {
		t.Errorf("a REFUSED mint returned tokens: %+v", tokens)
	}
	if after := sessionsFor(store, user.ID); after != before {
		t.Fatalf("sessions %d -> %d: a REFUSED mint persisted a session", before, after)
	}

	// The tenant is checked FIRST. From another tenant the answer stays
	// not-found, so "inactive" is never disclosed across the boundary.
	if _, err := c.IssueTokensForUserInTenant(ctx, user.ID, globex, 0, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("inactive user addressed from another tenant: err = %v, want ErrNotFound "+
			"(an ErrUserInactive here tells globex that the user exists in acme)", err)
	}

	// Reactivated, the same call mints: the refusal was the flag, not
	// something the test set up wrong.
	store.SetActive(user.ID, true)
	if _, err := c.IssueTokensForUserInTenant(ctx, user.ID, acme, 0, ""); err != nil {
		t.Fatalf("mint after reactivation: %v", err)
	}
}

func TestIssueTokensForUserInTenant_PendingTokenCannotMintIntoAnotherTenant(t *testing.T) {
	ctx := context.Background()
	c, store := testCore(t)
	acme, globex := tenant.New("acme"), tenant.New("globex")

	user, _, err := c.Register(ctx, globex, "bob@globex.test", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Password step done in globex.
	pending, err := c.jwt.IssueTOTPPending(user.ID, globex)
	if err != nil {
		t.Fatalf("IssueTOTPPending: %v", err)
	}

	// Fence 1: the token is replayed at ACME's verify.
	if uid, err := c.jwt.VerifyTOTPPending(pending, acme); !errors.Is(err, crypto.ErrInvalidToken) {
		t.Errorf("acme accepted a globex pending token: uid=%q err=%v", uid, err)
	}

	// Fence 2: the adapter that mints with the routed tenant without
	// comparing it to the user's stored tenant. Globex's own verify
	// accepts the token and hands back a bare user id; the mint is asked
	// for acme with it.
	uid, err := c.jwt.VerifyTOTPPending(pending, globex)
	if err != nil {
		t.Fatalf("VerifyTOTPPending: %v", err)
	}
	before := sessionsFor(store, user.ID)
	tokens, err := c.IssueTokensForUserInTenant(ctx, uid, acme, 0, "")
	if !errors.Is(err, ErrNotFound) {
		claims, _ := c.jwt.ParseAccess(tokens.Access)
		t.Fatalf("a user stored in tenant %q received a session with tid=%q (refresh issued=%v): err = %v, want ErrNotFound",
			user.TenantID, claims.TenantID, tokens.Refresh != "", err)
	}
	if after := sessionsFor(store, user.ID); after != before {
		t.Fatalf("sessions %d -> %d: the refused mint left a refresh session to rotate", before, after)
	}

	// The honest path: the same verified user id, minted for globex,
	// carries the user's tenant.
	tokens, err = c.IssueTokensForUserInTenant(ctx, uid, globex, 0, "")
	if err != nil {
		t.Fatalf("IssueTokensForUserInTenant(globex user, globex): %v", err)
	}
	claims, err := c.jwt.VerifyAccess(tokens.Access, globex)
	if err != nil {
		t.Fatalf("VerifyAccess(globex): %v", err)
	}
	if claims.TenantID != "globex" || claims.Subject != user.ID {
		t.Errorf("claims = tid %q sub %q, want tid %q sub %q", claims.TenantID, claims.Subject, "globex", user.ID)
	}
	if _, err := c.jwt.VerifyAccess(tokens.Access, acme); err == nil {
		t.Error("the globex session verified at acme")
	}
	// And the session it persisted rotates inside globex.
	_, rotated, err := c.Refresh(ctx, tokens.Refresh)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if _, err := c.jwt.VerifyAccess(rotated.Access, globex); err != nil {
		t.Errorf("rotated token lost the tenant: %v", err)
	}
}

// userLookupFails is a Store whose UserByID fails with an error that is
// NOT ErrNotFound — the database being down, not the row being absent.
type userLookupFails struct {
	*MemStore
	err error
}

func (s *userLookupFails) UserByID(context.Context, string) (User, error) { return User{}, s.err }

// TestIssueTokensForUserInTenant_StoreFailureDoesNotMint: the tenant
// check rests on a store read, so a read that fails must deny. No error
// return may be read as allow — and it must not be dressed up as
// ErrNotFound either, or an outage reads as "no such user".
func TestIssueTokensForUserInTenant_StoreFailureDoesNotMint(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("store: connection refused")
	store := &userLookupFails{MemStore: NewMemStore(), err: boom}
	c, err := New(store, testJWT(), WithRefreshTTL(time.Hour), WithDefaultACR(testACR))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tokens, err := c.IssueTokensForUserInTenant(ctx, "u-1", tenant.New("acme"), 0, "")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the store failure", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Errorf("a store failure was reported as ErrNotFound: %v", err)
	}
	if tokens != (Tokens{}) {
		t.Errorf("a failed lookup still returned tokens: %+v", tokens)
	}
	if n := len(store.sessions); n != 0 {
		t.Errorf("a failed lookup persisted %d session(s)", n)
	}
}

// TestIssueTokensForUserInTenant_SingleIsByteIdenticalToTheShim is
// standing rule 1 for the new read. For a user stored in the single
// tenant, passing tenant.Single must still produce the access token the
// shim produces — the shim was not touched by TD-10 and reads nothing,
// so it is the fixed point. Both clocks are frozen so the comparison can
// be on the encoded token rather than on parsed claims.
func TestIssueTokensForUserInTenant_SingleIsByteIdenticalToTheShim(t *testing.T) {
	ctx := context.Background()
	clock := time.Unix(1700000000, 0).UTC()
	c, _ := testCore(t, WithClock(func() time.Time { return clock }))
	c.jwt.Testing().SetNow(func() time.Time { return clock })

	user, _, err := c.Register(ctx, tenant.Single, "single@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	viaShim, err := c.IssueTokensForUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("shim mint: %v", err)
	}
	viaTenant, err := c.IssueTokensForUserInTenant(ctx, user.ID, tenant.Single, 0, "")
	if err != nil {
		t.Fatalf("tenant mint: %v", err)
	}
	if viaTenant.Access != viaShim.Access {
		t.Errorf("Single mint drifted from the shim:\n  shim:   %s\n  tenant: %s", viaShim.Access, viaTenant.Access)
	}
	if !viaTenant.RefreshExpiresAt.Equal(viaShim.RefreshExpiresAt) {
		t.Errorf("refresh expiry drifted: shim %v, tenant %v", viaShim.RefreshExpiresAt, viaTenant.RefreshExpiresAt)
	}
}

// issueTokens is the one place every session mint goes through. An
// unset tenant there is identity's own ErrTenantRequired, so a caller
// that maps that error to "wiring bug" sees it, and it is not the
// crypto error of the same name wrapped as a signing failure. No
// exported method reaches it with an unset tenant today; this pins what
// a future one would get.
func TestIssueTokens_UnsetTenantIsIdentitysError(t *testing.T) {
	c, store := testCore(t)
	before := len(store.sessions)

	tok, err := c.issueTokens(context.Background(), "u-1", tenant.ID{}, time.Now().Unix(), testACR)
	if !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("err = %v, want identity.ErrTenantRequired", err)
	}
	if tok.Access != "" || tok.Refresh != "" {
		t.Error("a refused mint returned tokens")
	}
	if after := len(store.sessions); after != before {
		t.Errorf("sessions %d -> %d: a refused mint wrote a session", before, after)
	}
}
