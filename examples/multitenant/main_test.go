package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/identity/tenanttest"
	"github.com/suryakencana007/tamper/tenant"
)

// This example registers a lot of users, and every registration is a
// real bcrypt hash. At the default cost the suite takes ~2 minutes under
// -race; at cost 4 it takes seconds. Test-only — the example binary is
// untouched and still hashes at full cost. Same reasoning, same knob, as
// identity/core_test.go.
func TestMain(m *testing.M) {
	crypto.Cost = 4
	os.Exit(m.Run())
}

// authResp mirrors the AuthRes envelope the auth routes return.
type authResp struct {
	Token string          `json:"token"`
	User  json.RawMessage `json:"user"`
}

type userDTO struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Email    string `json:"email"`
}

const password = "correct-horse-battery"

func newServer(t *testing.T) (*httptest.Server, *tenantStore) {
	t.Helper()
	store := newTenantStore()
	handler, provider, err := buildHandler(store, "multitenant-test-secret")
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, store
}

func post(t *testing.T, url, body string) (*http.Response, authResp) {
	t.Helper()
	//nolint:noctx // test helper against a local httptest server
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out authResp
	_ = json.Unmarshal(raw, &out)
	return resp, out
}

func register(t *testing.T, srv *httptest.Server, tenant, email string) authResp {
	t.Helper()
	resp, out := post(t, srv.URL+"/t/"+tenant+"/auth/register",
		`{"email":"`+email+`","password":"`+password+`"}`)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Fatalf("register %s into %s: status %d", email, tenant, resp.StatusCode)
	}
	if out.Token == "" {
		t.Fatalf("register %s into %s: no access token", email, tenant)
	}
	return out
}

func login(t *testing.T, srv *httptest.Server, tenant, email string) (int, authResp) {
	t.Helper()
	resp, out := post(t, srv.URL+"/t/"+tenant+"/auth/login",
		`{"email":"`+email+`","password":"`+password+`"}`)
	return resp.StatusCode, out
}

func getMe(t *testing.T, srv *httptest.Server, tenant, bearer string) (int, userDTO) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/t/"+tenant+"/auth/me", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET me: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var env struct {
		User json.RawMessage `json:"user"`
	}
	_ = json.Unmarshal(raw, &env)
	var u userDTO
	if len(env.User) > 0 {
		_ = json.Unmarshal(env.User, &u)
	} else {
		_ = json.Unmarshal(raw, &u)
	}
	return resp.StatusCode, u
}

func dto(t *testing.T, raw json.RawMessage) userDTO {
	t.Helper()
	var u userDTO
	if err := json.Unmarshal(raw, &u); err != nil {
		t.Fatalf("decode user: %v", err)
	}
	return u
}

// --- assertion 1 + 2 --------------------------------------------------

// TestBothTenantsLogInThroughOneProcess covers the first two required
// assertions together, because they are the same fact seen twice: the
// SAME address in two tenants is two different people, and each tenant's
// login lands on its own.
//
// Before blocker B1 this could not be expressed at all —
// identity.Store.UserByEmail resolved an address globally, so the second
// registration collided with the first.
func TestBothTenantsLogInThroughOneProcess(t *testing.T) {
	srv, _ := newServer(t)
	const shared = "bob@example.com"

	acme := dto(t, register(t, srv, tenantAcme, shared).User)
	globex := dto(t, register(t, srv, tenantGlobex, shared).User)

	if acme.ID == globex.ID {
		t.Fatalf("one process resolved %s to a single user (%s) across both tenants", shared, acme.ID)
	}
	if acme.TenantID != tenantAcme || globex.TenantID != tenantGlobex {
		t.Errorf("tenants not stamped: %q / %q", acme.TenantID, globex.TenantID)
	}

	// Both log in, and each lands on its OWN user.
	for _, tc := range []struct{ tenant, wantID string }{
		{tenantAcme, acme.ID},
		{tenantGlobex, globex.ID},
	} {
		code, out := login(t, srv, tc.tenant, shared)
		if code != http.StatusOK {
			t.Fatalf("login into %s: status %d", tc.tenant, code)
		}
		if got := dto(t, out.User); got.ID != tc.wantID {
			t.Errorf("login into %s landed on %s, want %s", tc.tenant, got.ID, tc.wantID)
		}
	}
}

// --- assertion 3 ------------------------------------------------------

// TestTokenFromOneTenantIsRejectedOnAnother is the cross-tenant denial —
// the assertion this whole example exists to make, and the one Barista
// structurally cannot make.
//
// The token is genuine: correct signature, unexpired, real user id. What
// makes it invalid is only WHERE it was presented. Note the status is
// the same one an unknown user gets — a deny and a miss are
// indistinguishable, so the response cannot be used to discover that a
// user exists in another tenant.
func TestTokenFromOneTenantIsRejectedOnAnother(t *testing.T) {
	srv, store := newServer(t)

	acme := register(t, srv, tenantAcme, "alice@acme.example")
	register(t, srv, tenantGlobex, "carol@globex.example")

	// Sanity: the token works on its OWN tenant's route.
	code, me := getMe(t, srv, tenantAcme, acme.Token)
	if code != http.StatusOK {
		t.Fatalf("acme token on acme route: status %d, want 200", code)
	}
	if me.TenantID != tenantAcme {
		t.Errorf("me returned tenant %q, want %q", me.TenantID, tenantAcme)
	}

	// The same token on globex's route must not work.
	crossCode, crossBody := getMe(t, srv, tenantGlobex, acme.Token)
	if crossCode == http.StatusOK {
		t.Fatalf("acme's token was ACCEPTED on the globex route — the tenant boundary is not "+
			"enforced in the request path (got user %+v)", crossBody)
	}
	if crossBody.ID != "" || crossBody.Email != "" {
		t.Errorf("cross-tenant response disclosed a user: %+v", crossBody)
	}

	// And it is indistinguishable from a token for a user that does not
	// exist at all — same status, no extra signal.
	unknownCode, _ := getMe(t, srv, tenantGlobex, mintForMissingUser(t, srv, store))
	if crossCode != unknownCode {
		t.Errorf("cross-tenant status %d differs from unknown-user status %d — the difference "+
			"is an oracle for which users exist in another tenant", crossCode, unknownCode)
	}
}

// mintForMissingUser returns a bearer token that is valid on its face —
// correct signature, unexpired, well-formed subject — for a user whose
// row no longer exists. It is the control for the cross-tenant case: the
// ONLY difference between the two is why the lookup fails, so any
// difference in the response is a signal an attacker can read.
func mintForMissingUser(t *testing.T, srv *httptest.Server, store *tenantStore) string {
	t.Helper()
	ghost := register(t, srv, tenantGlobex, "ghost@globex.example")
	u := dto(t, ghost.User)
	store.mu.Lock()
	delete(store.users, u.ID)
	store.mu.Unlock()
	return ghost.Token
}

// --- assertion 4 ------------------------------------------------------

// TestSecondTenantGetsTheBootstrapSignal is blocker B2, and it is the one
// that deserves the fear. Every other blocker fails to compile the moment
// a consumer tries pooled tenancy. This one compiles, passes, ships, and
// surfaces months later as "the new customer's admin has no permissions".
//
// The signal is read from the STORE, at insert, which is where an app
// acts on it (Barista assigns its cluster-admin role in the same write).
func TestSecondTenantGetsTheBootstrapSignal(t *testing.T) {
	srv, store := newServer(t)

	// acme fills up first.
	first := dto(t, register(t, srv, tenantAcme, "a1@acme.example").User)
	second := dto(t, register(t, srv, tenantAcme, "a2@acme.example").User)
	// Then globex's very first user arrives.
	newTenant := dto(t, register(t, srv, tenantGlobex, "g1@globex.example").User)

	if !store.wasBootstrapped(first.ID) {
		t.Error("acme's first user did not receive the bootstrap signal")
	}
	if store.wasBootstrapped(second.ID) {
		t.Error("acme's SECOND user received the bootstrap signal")
	}
	if !store.wasBootstrapped(newTenant.ID) {
		t.Error("globex's first user received firstUser=FALSE because acme already had users. " +
			"This is blocker B2: the new customer's admin gets no permissions, and nothing " +
			"fails until someone notices months later.")
	}
}

// --- the store honours the isolation contract -------------------------

// TestStoreSatisfiesTheLeakSuite runs the exported conformance harness
// against this example's own adapter. It is the proof obligation that
// comes with implementing identity.Store, and running it here
// is the example demonstrating what every adapter author should do.
func TestStoreSatisfiesTheLeakSuite(t *testing.T) {
	tenanttest.RunLeakSuite(t, func() identity.Store { return newTenantStore() })
}

// --- the federated path is tenant-scoped too --------------------------

// TestFederatedProvisionIsPerTenant exercises the JIT federated-signup
// path that 7b-2 made tenant-aware. The OIDC leg itself (a per-tenant
// provider on an embedded fake IdP) needs the tenant-keyed registry from
// 7e-1, so this drives the Core methods an OIDC callback would call —
// which is the half that carries the tenant.
func TestFederatedProvisionIsPerTenant(t *testing.T) {
	ctx := context.Background()
	store := newTenantStore()
	_, provider, err := buildHandler(store, "multitenant-test-secret")
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	defer func() { _ = provider.Close() }()
	core := provider.Identity

	const provider0, subject = "shared-idp", "sub-123"

	// The SAME (provider, subject) federates into both tenants — two
	// different people, exactly as with the shared email.
	a, _, err := core.ProvisionUserWithIdentity(ctx, tenant.New(tenantAcme), "dev@shared.example", provider0, subject)
	if err != nil {
		t.Fatalf("provision into %s: %v", tenantAcme, err)
	}
	b, _, err := core.ProvisionUserWithIdentity(ctx, tenant.New(tenantGlobex), "dev@shared.example", provider0, subject)
	if err != nil {
		t.Fatalf("provision the same identity into %s: %v — (provider, subject) is still unique "+
			"globally, so two tenants cannot federate with one IdP", tenantGlobex, err)
	}
	if a.ID == b.ID {
		t.Fatal("both tenants provisioned into a single user")
	}

	// Repeat sign-in resolves within the tenant, never across it.
	got, _, found, err := core.ResolveByIdentity(ctx, tenant.New(tenantAcme), provider0, subject)
	if err != nil || !found {
		t.Fatalf("resolve in %s: (%v, %v)", tenantAcme, found, err)
	}
	if got.ID != a.ID {
		t.Errorf("resolve in %s landed on %s, want %s", tenantAcme, got.ID, a.ID)
	}

	// And an unknown tenant resolves to nothing — not to someone else's.
	if _, _, found, err := core.ResolveByIdentity(ctx, tenant.New("stranger"), provider0, subject); err != nil || found {
		t.Errorf("resolve in an unknown tenant = (%v, %v), want (false, nil)", found, err)
	}
}

// --- the TOTP second leg is tenant-bound ------------------------------

// TestTOTPSecondLegIsTenantBound drives the three port methods the
// totp-verify route calls, in the order it calls them, on the adapters
// the routes are mounted with. It is TD-10 at the level an app owns.
//
// The leg used to fail in one of two directions, and both are asserted
// here because fixing one by hand is how the other gets introduced:
//
//   - closed: the post-TOTP mint went through Core.IssueTokensForUser,
//     so the token carried no tid and the refresh session no tenant — a
//     user with 2FA got a session no tenant-pinned verifier accepts, and
//     one this adapter's own Refresh refused;
//   - open: nothing tied the pending token to a tenant, so a globex
//     user's token could be presented under acme's prefix.
//
// The code check itself (VerifyTOTP) sits between steps 2 and 3 on the
// real route and is skipped: this example's store does not persist TOTP
// state, and that check is keyed by user id alone — it is not what
// stands between the two tenants.
func TestTOTPSecondLegIsTenantBound(t *testing.T) {
	ctx := context.Background()
	store := newTenantStore()
	_, provider, err := buildHandler(store, "multitenant-test-secret")
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	defer func() { _ = provider.Close() }()

	// The same constructor buildHandler mounts the routes with.
	acme := newTenantIdentity(provider, store, tenantAcme)
	globex := newTenantIdentity(provider, store, tenantGlobex)

	reg, err := globex.Register(ctx, "bob@globex.example", password)
	if err != nil {
		t.Fatalf("register into %s: %v", tenantGlobex, err)
	}
	bob := reg.User

	// 1. Password step done under globex's prefix: the routes mint the
	//    pending token through globex's adapter.
	pending, err := globex.IssueTOTPPending(bob.ID)
	if err != nil {
		t.Fatalf("IssueTOTPPending: %v", err)
	}

	// 2. The token is replayed under ACME's prefix. It must die here,
	//    at the first thing the route does.
	if uid, err := acme.VerifyTOTPPending(pending); !errors.Is(err, crypto.ErrInvalidToken) {
		t.Fatalf("%s accepted a pending token minted under %s: uid=%q err=%v", tenantAcme, tenantGlobex, uid, err)
	}
	// A pending token that names NO tenant is refused too: absence is
	// not a match, and it is what an unbound mint would have produced.
	unbound, err := provider.JWT.IssueTOTPPending(bob.ID)
	if err != nil {
		t.Fatalf("IssueTOTPPending (unbound): %v", err)
	}
	for _, a := range []tenantIdentity{acme, globex} {
		if uid, err := a.VerifyTOTPPending(unbound); !errors.Is(err, crypto.ErrInvalidToken) {
			t.Errorf("%s accepted a pending token bound to no tenant: uid=%q err=%v", a.tenantID, uid, err)
		}
	}

	// And if acme's adapter is asked to mint for bob anyway, it reports
	// a user that does not exist — the same answer as for one that
	// really does not.
	_, crossErr := acme.IssueTokensForUser(ctx, bob.ID)
	_, missErr := acme.IssueTokensForUser(ctx, "no-such-user")
	if !errors.Is(crossErr, identity.ErrNotFound) || !errors.Is(missErr, identity.ErrNotFound) {
		t.Fatalf("cross-tenant mint err = %v, missing-user err = %v; want ErrNotFound for both", crossErr, missErr)
	}

	// 3. The honest path, under globex's prefix.
	uid, err := globex.VerifyTOTPPending(pending)
	if err != nil {
		t.Fatalf("%s refused its own pending token: %v", tenantGlobex, err)
	}
	if uid != bob.ID {
		t.Fatalf("pending token resolved to %q, want %q", uid, bob.ID)
	}
	res, err := globex.IssueTokensForUser(ctx, uid)
	if err != nil {
		t.Fatalf("IssueTokensForUser: %v", err)
	}
	if res.User == nil || res.User.ID != bob.ID {
		t.Fatalf("post-TOTP result carries user %+v, want %s", res.User, bob.ID)
	}

	// The post-TOTP access token carries the tenant...
	claims, err := provider.JWT.VerifyAccess(res.Tokens.Access, tenant.New(tenantGlobex))
	if err != nil {
		t.Fatalf("the post-TOTP token does not verify for %s: %v — a user with 2FA cannot sign in", tenantGlobex, err)
	}
	if claims.TenantID != tenantGlobex {
		t.Errorf("post-TOTP token tid = %q, want %q", claims.TenantID, tenantGlobex)
	}
	// ...and only that one.
	if _, err := provider.JWT.VerifyAccess(res.Tokens.Access, tenant.New(tenantAcme)); err == nil {
		t.Errorf("the post-TOTP token for %s verified for %s", tenantGlobex, tenantAcme)
	}

	// So does the refresh session: it rotates under globex and is
	// refused under acme. With the tid-less mint it rotated nowhere.
	if _, err := acme.Refresh(ctx, res.Tokens.Refresh); !errors.Is(err, identity.ErrInvalidSession) {
		t.Errorf("%s rotated a %s session: err = %v, want ErrInvalidSession", tenantAcme, tenantGlobex, err)
	}
	rotated, err := globex.Refresh(ctx, res.Tokens.Refresh)
	if err != nil {
		t.Fatalf("the post-TOTP session does not refresh under %s: %v", tenantGlobex, err)
	}
	if _, err := provider.JWT.VerifyAccess(rotated.Tokens.Access, tenant.New(tenantGlobex)); err != nil {
		t.Errorf("the rotated token lost the tenant: %v", err)
	}
}
