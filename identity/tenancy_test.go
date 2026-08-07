package identity

import (
	"context"
	"errors"
	"strings"
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
		WithTenancy(true),
	}
	c, err := New(store, testJWT(), append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, store
}

// plainStore implements Store and NOT TenantScopedStore — Barista's
// exact shape, and the store the boot guard must reject.
type plainStore struct{ *MemStore }

func (plainStore) UserByEmailInTenant() {} // deliberately the wrong signature

// --- the boot guard ---------------------------------------------------

func TestNew_TenancyRequiresTenantScopedStore(t *testing.T) {
	_, err := New(plainStore{NewMemStore()}, testJWT(), WithDefaultACR(testACR), WithTenancy(true))
	if err == nil {
		t.Fatal("New accepted a Store that does not implement TenantScopedStore")
	}
	// The message must name the CONCRETE type. Without it, "tenancy
	// doesn't work" is a debugging session instead of one line.
	if !strings.Contains(err.Error(), "plainStore") {
		t.Errorf("error does not name the concrete type: %v", err)
	}
	if !strings.Contains(err.Error(), "TenantScopedStore") {
		t.Errorf("error does not name the interface: %v", err)
	}
}

func TestNew_TenancyOffAcceptsPlainStore(t *testing.T) {
	// The compatibility path: a single-tenant app's store keeps working
	// untouched. This is the local stand-in for Barista's adapter.
	if _, err := New(plainStore{NewMemStore()}, testJWT(), WithDefaultACR(testACR)); err != nil {
		t.Fatalf("tenancy OFF rejected a plain Store: %v", err)
	}
}

// --- B1: the same email in two tenants --------------------------------

func TestRegisterInTenant_SameEmailInTwoTenants(t *testing.T) {
	ctx := context.Background()
	c, _ := tenantCore(t)
	const email = "bob@example.com"

	ua, _, err := c.RegisterInTenant(ctx, tenantA, email, "correct-horse")
	if err != nil {
		t.Fatalf("register into %s: %v", tenantA, err)
	}
	ub, _, err := c.RegisterInTenant(ctx, tenantB, email, "correct-horse")
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
	gotA, _, err := c.LoginInTenant(ctx, tenantA, email, "correct-horse")
	if err != nil {
		t.Fatalf("login %s: %v", tenantA, err)
	}
	gotB, _, err := c.LoginInTenant(ctx, tenantB, email, "correct-horse")
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
	c, err := New(store, testJWT(), WithRefreshTTL(time.Hour), WithDefaultACR(testACR), WithTenancy(true))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, _, err := c.RegisterInTenant(ctx, tenantA, "alice@acme.com", "correct-horse"); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Tenant B asks for tenant A's user, with A's correct password.
	_, _, err = c.LoginInTenant(ctx, tenantB, "alice@acme.com", "correct-horse")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("cross-tenant login err = %v, want ErrInvalidCredentials — tenant %s reached "+
			"tenant %s's user", err, tenantB, tenantA)
	}
}

// globalEmailStore is a MemStore whose UNSCOPED UserByEmail scans every
// tenant, the way a pre-tenancy SQL adapter's `WHERE email = ?` does.
// Its scoped method is correct; only the legacy read is global. That is
// exactly the store against which calling the wrong method leaks.
type globalEmailStore struct{ *MemStore }

func (g *globalEmailStore) UserByEmail(_ context.Context, email string) (User, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, u := range g.usersByID {
		if u.Email == email {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}

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
		if _, _, err := c.RegisterInTenant(ctx, tenantA, e, "correct-horse"); err != nil {
			t.Fatalf("register %s: %v", e, err)
		}
	}
	// Then tenant B's very first user arrives.
	if _, _, err := c.RegisterInTenant(ctx, tenantB, "b1@globex.com", "correct-horse"); err != nil {
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

	if _, _, err := c.RegisterInTenant(ctx, tenantA, "a1@acme.com", "correct-horse"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, _, err := c.ProvisionUserWithIdentityInTenant(ctx, tenantB, "b1@globex.com", "google", "sub-b"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if len(provisioned) != 1 || !provisioned[0] {
		t.Errorf("federated first user in %s got firstUser=%v, want true (B2 on the federated path)",
			tenantB, provisioned)
	}
}

// --- deny-by-default on the tenant argument ---------------------------

func TestTenancyOn_EmptyTenantIsAnError(t *testing.T) {
	ctx := context.Background()
	c, _ := tenantCore(t)
	if _, _, err := c.RegisterInTenant(ctx, tenantA, "alice@acme.com", "correct-horse"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// An empty tenant must never behave as a wildcard that matches the
	// row we just created in tenant A.
	if _, _, err := c.LoginInTenant(ctx, "", "alice@acme.com", "correct-horse"); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("LoginInTenant with empty tenant: err = %v, want ErrTenantRequired", err)
	}
	if _, _, err := c.RegisterInTenant(ctx, "", "new@acme.com", "correct-horse"); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("RegisterInTenant with empty tenant: err = %v, want ErrTenantRequired", err)
	}
	// The un-suffixed methods delegate with "", so with tenancy ON they
	// are the same deny — there is no path to an unscoped read.
	if _, _, err := c.Login(ctx, "alice@acme.com", "correct-horse"); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("Login (un-suffixed) with tenancy ON: err = %v, want ErrTenantRequired", err)
	}
}

func TestTenancyOff_TenantArgumentIsAnError(t *testing.T) {
	ctx := context.Background()
	c, _ := testCore(t) // tenancy OFF
	// Honouring a tenant here would run an UNSCOPED query while the
	// caller believes it is scoped — fail-open, so it must deny.
	if _, _, err := c.LoginInTenant(ctx, tenantA, "alice@acme.com", "correct-horse"); !errors.Is(err, ErrTenancyDisabled) {
		t.Errorf("err = %v, want ErrTenancyDisabled", err)
	}
	if err := c.RevokeAllSessionsForTenant(ctx, tenantA); !errors.Is(err, ErrTenancyDisabled) {
		t.Errorf("RevokeAllSessionsForTenant with tenancy OFF: err = %v, want ErrTenancyDisabled", err)
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

func (r *callRecorder) UserByEmail(ctx context.Context, email string) (User, error) {
	r.calls = append(r.calls, "UserByEmail")
	return r.MemStore.UserByEmail(ctx, email)
}

func (r *callRecorder) UserByEmailInTenant(ctx context.Context, tenantID, email string) (User, error) {
	r.calls = append(r.calls, "UserByEmailInTenant")
	return r.MemStore.UserByEmailInTenant(ctx, tenantID, email)
}

func TestLoginInTenant_TimingParityIsStructural(t *testing.T) {
	ctx := context.Background()
	rec := &callRecorder{MemStore: NewMemStore()}
	c, err := New(rec, testJWT(), WithRefreshTTL(time.Hour), WithDefaultACR(testACR), WithTenancy(true))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := c.RegisterInTenant(ctx, tenantA, "alice@acme.com", "correct-horse"); err != nil {
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
			_, _, err := c.LoginInTenant(ctx, tc.tenant, tc.email, tc.password)
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("err = %v, want ErrInvalidCredentials", err)
			}
			// Structural half: the scoped lookup was used, and the
			// unscoped one was never touched.
			for _, call := range rec.calls {
				if call == "UserByEmail" {
					t.Errorf("Core used the UNSCOPED UserByEmail; a post-hoc TenantID comparison "+
						"leaks the row and returns before the hash comparison (calls: %v)", rec.calls)
				}
			}
			if len(rec.calls) != 1 || rec.calls[0] != "UserByEmailInTenant" {
				t.Errorf("lookup calls = %v, want exactly [UserByEmailInTenant]", rec.calls)
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

	alice, _, err := c.RegisterInTenant(ctx, tenantA, "alice@acme.com", "correct-horse")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	bob, _, err := c.RegisterInTenant(ctx, tenantA, "bob@acme.com", "correct-horse")
	if err != nil {
		t.Fatalf("register bob: %v", err)
	}
	carol, _, err := c.RegisterInTenant(ctx, tenantB, "carol@globex.com", "correct-horse")
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
	if err := c.RevokeAllSessionsForTenant(ctx, tenantA); err != nil {
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

// TestTenancyOff_UsesUnscopedLookups pins the byte-identical claim at
// the point it could silently stop being true: with tenancy OFF the Core
// must call the ORIGINAL Store methods, not the scoped ones.
func TestTenancyOff_UsesUnscopedLookups(t *testing.T) {
	ctx := context.Background()
	rec := &callRecorder{MemStore: NewMemStore()}
	c, err := New(rec, testJWT(), WithRefreshTTL(time.Hour), WithDefaultACR(testACR))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := c.Register(ctx, "alice@example.com", "correct-horse"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	rec.calls = nil
	if _, _, err := c.Login(ctx, "alice@example.com", "correct-horse"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if len(rec.calls) != 1 || rec.calls[0] != "UserByEmail" {
		t.Errorf("tenancy OFF lookup calls = %v, want exactly [UserByEmail]", rec.calls)
	}
}
