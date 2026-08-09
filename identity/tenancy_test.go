package identity

import (
	"context"
	"errors"
	"github.com/suryakencana007/tamper/tenant"
	"testing"
	"time"
)

// Slice 7b-2 — the semantic change. Tenancy ON routes every scoped read
// through the *InTenant methods; tenancy OFF is byte-identical to
// before, which the pre-existing suite proves by passing unchanged.

const (
	tenantA = "acme"
	tenantB = "globex"
)

func tenantCore(t *testing.T, opts ...Option) (*Core, *MemStore) {
	t.Helper()
	store := NewMemStore()
	base := []Option{
		WithRefreshTTL(30 * 24 * time.Hour),
		WithDefaultACR(testACR),
	}
	c, err := New(store, testJWT(), append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, store
}

// plainStore implements Store and NOT TenantScopedStore — Barista's
// exact shape, and the store the boot guard must reject.

// --- B1: the same email in two tenants --------------------------------

func TestRegisterInTenant_SameEmailInTwoTenants(t *testing.T) {
	ctx := context.Background()
	c, _ := tenantCore(t)
	const email = "bob@example.com"

	ua, _, err := c.Register(ctx, tenant.New(tenantA), email, "correct-horse")
	if err != nil {
		t.Fatalf("register into %s: %v", tenantA, err)
	}
	ub, _, err := c.Register(ctx, tenant.New(tenantB), email, "correct-horse")
	if err != nil {
		t.Fatalf("register the SAME email into %s: %v — email is still globally unique (B1)", tenantB, err)
	}
	if ua.ID == ub.ID {
		t.Fatal("both tenants resolved to one user")
	}
	if ua.TenantID != tenantA || ub.TenantID != tenantB {
		t.Errorf("tenants not stamped: %q / %q", ua.TenantID, ub.TenantID)
	}

	// Both can log in, and each gets its OWN user.
	gotA, _, err := c.Login(ctx, tenant.New(tenantA), email, "correct-horse")
	if err != nil {
		t.Fatalf("login %s: %v", tenantA, err)
	}
	gotB, _, err := c.Login(ctx, tenant.New(tenantB), email, "correct-horse")
	if err != nil {
		t.Fatalf("login %s: %v", tenantB, err)
	}
	if gotA.ID != ua.ID || gotB.ID != ub.ID {
		t.Errorf("login crossed tenants: %q/%q want %q/%q", gotA.ID, gotB.ID, ua.ID, ub.ID)
	}
}

// TestLoginInTenant_CrossTenantIsRejected is the CORE-level leak guard,
// and it is the test M-B1 has to turn red. RunLeakSuite cannot do that
// job: it asserts at the STORE boundary and never constructs a Core, so
// a Core that calls the unscoped UserByEmail leaves every store
// assertion satisfied.
// It runs over globalEmailStore rather than a bare MemStore, and that
// choice is load-bearing. MemStore's UNSCOPED UserByEmail keys on
// (tenant "", email), so it cannot see a tenant's rows either — which
// means a Core that wrongly called it would still fail to find the user,
// and this test would pass while the routing was broken. A real SQL
// adapter's unscoped read is `WHERE email = ?` across the whole table.
// globalEmailStore models that, so the assertion depends on the CORE's
// choice of method rather than on the store's luck.
func TestLoginInTenant_CrossTenantIsRejected(t *testing.T) {
	ctx := context.Background()
	store := &globalEmailStore{MemStore: NewMemStore()}
	c, err := New(store, testJWT(), WithRefreshTTL(time.Hour), WithDefaultACR(testACR))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, _, err := c.Register(ctx, tenant.New(tenantA), "alice@acme.com", "correct-horse"); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Tenant B asks for tenant A's user, with A's correct password.
	_, _, err = c.Login(ctx, tenant.New(tenantB), "alice@acme.com", "correct-horse")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("cross-tenant login err = %v, want ErrInvalidCredentials — tenant %s reached "+
			"tenant %s's user", err, tenantB, tenantA)
	}
}

// globalEmailStore is a MemStore whose UNSCOPED UserByEmail scans every
// tenant, the way a pre-tenancy SQL adapter's `WHERE email = ?` does.
// Before v0.4.0 it overrode the UNSCOPED read to model a legacy SQL
// adapter, so the test could catch a Core that chose the wrong method.
// The fold removed the wrong method, so the override went with it: what
// remains guards that the Core passes the CALLER's tenant through, which
// a mutation pinning it to Single would still break.
type globalEmailStore struct{ *MemStore }

// --- B2: firstUser is per tenant --------------------------------------

// TestRegisterInTenant_FirstUserIsPerTenant is the B2 guard and the test
// M-B2 must turn red. B2 is the blocker that fails SILENTLY: a global
// count compiles, passes every existing test, ships, and surfaces months
// later as "the new customer's admin has no permissions".
func TestRegisterInTenant_FirstUserIsPerTenant(t *testing.T) {
	ctx := context.Background()

	var seen []struct {
		tenant string
		first  bool
	}
	record := Hooks{OnRegistered: func(_ context.Context, u User, first bool) {
		seen = append(seen, struct {
			tenant string
			first  bool
		}{u.TenantID, first})
	}}
	c, _ := tenantCore(t, WithHooks(record))

	// Tenant A fills up first.
	for _, e := range []string{"a1@acme.com", "a2@acme.com"} {
		if _, _, err := c.Register(ctx, tenant.New(tenantA), e, "correct-horse"); err != nil {
			t.Fatalf("register %s: %v", e, err)
		}
	}
	// Then tenant B's very first user arrives.
	if _, _, err := c.Register(ctx, tenant.New(tenantB), "b1@globex.com", "correct-horse"); err != nil {
		t.Fatalf("register into %s: %v", tenantB, err)
	}

	if len(seen) != 3 {
		t.Fatalf("hook fired %d times, want 3", len(seen))
	}
	if !seen[0].first {
		t.Errorf("%s's first user did not get the bootstrap signal", tenantA)
	}
	if seen[1].first {
		t.Errorf("%s's SECOND user got firstUser=true", tenantA)
	}
	if !seen[2].first {
		t.Errorf("%s's first user got firstUser=FALSE because tenant %s already had users — "+
			"this is blocker B2, and it is why the new customer's admin has no permissions",
			tenantB, tenantA)
	}
}

func TestProvisionUserWithIdentityInTenant_FirstUserIsPerTenant(t *testing.T) {
	ctx := context.Background()
	var provisioned []bool
	c, _ := tenantCore(t, WithHooks(Hooks{
		OnProvisioned: func(_ context.Context, _ User, _ Identity, first bool) {
			provisioned = append(provisioned, first)
		},
	}))

	if _, _, err := c.Register(ctx, tenant.New(tenantA), "a1@acme.com", "correct-horse"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, _, err := c.ProvisionUserWithIdentity(ctx, tenant.New(tenantB), "b1@globex.com", "google", "sub-b"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if len(provisioned) != 1 || !provisioned[0] {
		t.Errorf("federated first user in %s got firstUser=%v, want true (B2 on the federated path)",
			tenantB, provisioned)
	}
}

// --- deny-by-default on the tenant argument ---------------------------

func TestUnsetTenantIsAnError(t *testing.T) {
	ctx := context.Background()
	c, _ := tenantCore(t)
	if _, _, err := c.Register(ctx, tenant.New(tenantA), "alice@acme.com", "correct-horse"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The ZERO ID is what a caller who forgot to thread the tenant
	// produces. It must never behave as a wildcard matching the row we
	// just created in tenant A.
	//
	// This used to assert on "". After the v0.4.0 flip "" is tenant.Single
	// — a LEGAL, explicit single-tenant value — so asserting on it here
	// would test the opposite of the intended property and pass for the
	// wrong reason. The distinction only exists because tenant.ID has an
	// invalid zero value; a bare string could not express this test.
	var unset tenant.ID
	if _, _, err := c.Login(ctx, unset, "alice@acme.com", "correct-horse"); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("Login with an unset tenant: err = %v, want ErrTenantRequired", err)
	}
	if _, _, err := c.Register(ctx, unset, "new@acme.com", "correct-horse"); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("Register with an unset tenant: err = %v, want ErrTenantRequired", err)
	}
}

// TestSingleTenantIsAccepted is the other half, and the two must be read
// together: "" stays legal when it is SAID, which is the §5 M6 invariant.
// Without this, a gate that rejected everything would satisfy the test
// above and look correct.
func TestSingleTenantIsAccepted(t *testing.T) {
	ctx := context.Background()
	c, _ := tenantCore(t)
	if _, _, err := c.Register(ctx, tenant.Single, "solo@example.com", "correct-horse"); err != nil {
		t.Fatalf("Register with tenant.Single must be accepted, got: %v", err)
	}
	if _, _, err := c.Login(ctx, tenant.Single, "solo@example.com", "correct-horse"); err != nil {
		t.Fatalf("Login with tenant.Single must be accepted, got: %v", err)
	}
}

// --- timing parity ----------------------------------------------------

// callRecorder wraps a MemStore and records which lookup the Core chose.
// This is how the timing-parity property is asserted STRUCTURALLY rather
// than statistically: the dangerous implementation of a tenant check is
// "read globally with UserByEmail, then compare TenantID", which both
// discloses the row and returns before the hash comparison, making a
// wrong tenant cheaper than a wrong password. If the Core ever does
// that, the unscoped method shows up here.
type callRecorder struct {
	*MemStore
	calls []string
}

func (r *callRecorder) UserByEmail(ctx context.Context, tenantID tenant.ID, email string) (User, error) {
	r.calls = append(r.calls, "UserByEmail")
	return r.MemStore.UserByEmail(ctx, tenantID, email)
}

func TestLoginInTenant_TimingParityIsStructural(t *testing.T) {
	ctx := context.Background()
	rec := &callRecorder{MemStore: NewMemStore()}
	c, err := New(rec, testJWT(), WithRefreshTTL(time.Hour), WithDefaultACR(testACR))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := c.Register(ctx, tenant.New(tenantA), "alice@acme.com", "correct-horse"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Every rejection shape converges on the SAME collapsed sentinel —
	// the repo's established structural device (see TestLogin's
	// "every rejection collapses to ErrInvalidCredentials").
	for _, tc := range []struct{ name, tenant, email, password string }{
		{"wrong password", tenantA, "alice@acme.com", "wrong-password"},
		{"wrong tenant", tenantB, "alice@acme.com", "correct-horse"},
		{"unknown email", tenantA, "nobody@acme.com", "correct-horse"},
		{"wrong tenant AND wrong password", tenantB, "alice@acme.com", "wrong-password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec.calls = nil
			_, _, err := c.Login(ctx, tenant.New(tc.tenant), tc.email, tc.password)
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("err = %v, want ErrInvalidCredentials", err)
			}
			// Structural half: EXACTLY ONE lookup. Before v0.4.0 this also
			// asserted the unscoped twin was untouched; the fold deleted that
			// twin, so what is left to guard is the call COUNT — a second
			// read here would mean a post-hoc TenantID comparison, which
			// returns before the hash comparison and leaks timing.
			if len(rec.calls) != 1 || rec.calls[0] != "UserByEmail" {
				t.Errorf("lookup calls = %v, want exactly [UserByEmail]", rec.calls)
			}
		})
	}
}

// --- the tenant-wide revoke is NOT the per-user one -------------------

// TestRevokeAllSessionsForTenant_IsNotThePerUserRevoke is the guard for
// the routing-rule defect recorded in the PR body: routing
// RevokeAllSessions onto RevokeAllRefreshSessionsForTenant compiles, is
// a one-line diff, and leaves TestRevokeAllSessions passing — because
// that test asserts the target user has zero live sessions, which is
// still true after signing out every user in the tenant.
func TestRevokeAllSessionsForTenant_IsNotThePerUserRevoke(t *testing.T) {
	ctx := context.Background()
	c, store := tenantCore(t)

	alice, _, err := c.Register(ctx, tenant.New(tenantA), "alice@acme.com", "correct-horse")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	bob, _, err := c.Register(ctx, tenant.New(tenantA), "bob@acme.com", "correct-horse")
	if err != nil {
		t.Fatalf("register bob: %v", err)
	}
	carol, _, err := c.Register(ctx, tenant.New(tenantB), "carol@globex.com", "correct-horse")
	if err != nil {
		t.Fatalf("register carol: %v", err)
	}

	// Alice signs out everywhere. That is HER sessions, nobody else's.
	if err := c.RevokeAllSessions(ctx, alice.ID); err != nil {
		t.Fatalf("RevokeAllSessions: %v", err)
	}
	if n := store.LiveSessionCount(alice.ID); n != 0 {
		t.Errorf("alice live sessions = %d, want 0", n)
	}
	if n := store.LiveSessionCount(bob.ID); n != 1 {
		t.Errorf("bob (same tenant) live sessions = %d, want 1 — one user's sign-out revoked "+
			"a co-tenant's sessions", n)
	}
	if n := store.LiveSessionCount(carol.ID); n != 1 {
		t.Errorf("carol (other tenant) live sessions = %d, want 1", n)
	}

	// The tenant-wide revoke is the separate, deliberately-named one.
	if err := c.RevokeAllSessionsForTenant(ctx, tenant.New(tenantA)); err != nil {
		t.Fatalf("RevokeAllSessionsForTenant: %v", err)
	}
	if n := store.LiveSessionCount(bob.ID); n != 0 {
		t.Errorf("bob live sessions after tenant-wide revoke = %d, want 0", n)
	}
	if n := store.LiveSessionCount(carol.ID); n != 1 {
		t.Errorf("carol (tenant %s) live sessions = %d, want 1 — the tenant revoke crossed "+
			"the boundary", tenantB, n)
	}
}

// --- compatibility ----------------------------------------------------
