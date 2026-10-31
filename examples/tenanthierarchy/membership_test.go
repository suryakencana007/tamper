package tenanthierarchy

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

// org3 completes the three-child tg-acme fixture used in the membership tests.
var org3 = tenant.New("org-3")

func ids(xs []tenant.ID) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = x.String()
	}
	return out
}

func newCore(t *testing.T, m *Membership) (*identity.Core, *crypto.JWTService) {
	t.Helper()
	jwt := crypto.NewJWTService(crypto.JWTConfig{
		Secret: "tenanthierarchy-membership-test-secret",
		TTL:    time.Hour,
		Issuer: "tenanthierarchy-test",
	})
	idStore := identity.NewMemStore()
	// bob's home tenant is the tenant-group he administers.
	idStore.Seed(identity.User{ID: "bob", TenantID: tg.String(), Email: "bob@example.com", Active: true})

	core, err := identity.New(idStore, jwt, identity.WithMemberships(m))
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	return core, jwt
}

func homeClaims(t *testing.T, jwt *crypto.JWTService) *crypto.AccessClaims {
	t.Helper()
	tok, err := jwt.IssueAccess("bob", tg, time.Now().Unix(), crypto.ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	claims, err := jwt.ParseAccess(tok)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	return claims
}

// ---------------------------------------------------------------------
// IsMember is derived from the intent rows plus parentage.
// ---------------------------------------------------------------------

func TestIsMember_CoversEveryChildOrg(t *testing.T) {
	h := newHierarchy()
	p, s := newP(t, h, roleMap())
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	m := NewMembership(s, h)
	for _, org := range []tenant.ID{org1, org2, org3} {
		ok, err := m.IsMember(ctx, "bob", org)
		if err != nil {
			t.Fatalf("IsMember(bob, %s): %v", org, err)
		}
		if !ok {
			t.Fatalf("IsMember(bob, %s) = false, want true", org)
		}
	}
}

func TestIsMember_FalseOutsideTheGroup(t *testing.T) {
	h := newHierarchy()
	p, s := newP(t, h, roleMap())
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	m := NewMembership(s, h)

	// org-9 belongs to tg-other; bob administers only tg-acme.
	if ok, err := m.IsMember(ctx, "bob", org9); err != nil || ok {
		t.Fatalf("IsMember(bob, org-9) = (%v, %v), want false", ok, err)
	}
	// An unknown org has no parent, so there is no group to be a member of.
	if ok, err := m.IsMember(ctx, "bob", tenant.New("org-unknown")); err != nil || ok {
		t.Fatalf("IsMember(bob, unknown) = (%v, %v), want false", ok, err)
	}
	// A user with no intent anywhere.
	if ok, err := m.IsMember(ctx, "erin", org1); err != nil || ok {
		t.Fatalf("IsMember(erin, org-1) = (%v, %v), want false", ok, err)
	}
}

func TestIsMember_HierarchyErrorPropagates(t *testing.T) {
	h := newHierarchy()
	p, s := newP(t, h, roleMap())
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	m := NewMembership(s, h)
	boom := errors.New("hierarchy down")
	h.err = boom

	if _, err := m.IsMember(ctx, "bob", org1); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the hierarchy error", err)
	}
}

func TestMembershipsFor_ListsChildOrgs(t *testing.T) {
	h := newHierarchy()
	p, s := newP(t, h, roleMap())
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant bob: %v", err)
	}
	if err := p.GrantGroupAdmin(ctx, erin, tgOther, groupRole()); err != nil {
		t.Fatalf("grant erin: %v", err)
	}
	m := NewMembership(s, h)

	got, err := m.MembershipsFor(ctx, "bob")
	if err != nil {
		t.Fatalf("MembershipsFor(bob): %v", err)
	}
	if !reflect.DeepEqual(ids(got), []string{"org-1", "org-2", "org-3"}) {
		t.Fatalf("MembershipsFor(bob) = %v", ids(got))
	}

	got, err = m.MembershipsFor(ctx, "erin")
	if err != nil {
		t.Fatalf("MembershipsFor(erin): %v", err)
	}
	if !reflect.DeepEqual(ids(got), []string{"org-9"}) {
		t.Fatalf("MembershipsFor(erin) = %v", ids(got))
	}

	if got, err := m.MembershipsFor(ctx, "nobody"); err != nil || len(got) != 0 {
		t.Fatalf("MembershipsFor(nobody) = (%v, %v), want empty", ids(got), err)
	}
}

// ---------------------------------------------------------------------
// EnterTenant end to end: bob's home session (tid = group) enters org-1, and
// the token it returns says tid=org-1, htid=tg-acme.
// ---------------------------------------------------------------------

func TestEnterTenant_GroupAdminEntersChildOrg(t *testing.T) {
	h := newHierarchy()
	p, s := newP(t, h, roleMap())
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	core, jwt := newCore(t, NewMembership(s, h))

	tokens, err := core.EnterTenant(ctx, homeClaims(t, jwt), org1)
	if err != nil {
		t.Fatalf("EnterTenant: %v", err)
	}
	entered, err := jwt.ParseAccess(tokens.Access)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	if entered.TenantID != org1.String() || entered.HomeTenantID != tg.String() {
		t.Fatalf("entered token tid=%q htid=%q, want %q/%q",
			entered.TenantID, entered.HomeTenantID, org1.String(), tg.String())
	}
}

func TestEnterTenant_RefusedAfterRevoke(t *testing.T) {
	h := newHierarchy()
	p, s := newP(t, h, roleMap())
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	core, jwt := newCore(t, NewMembership(s, h))
	claims := homeClaims(t, jwt)

	if _, err := core.EnterTenant(ctx, claims, org1); err != nil {
		t.Fatalf("enter while a member: %v", err)
	}

	if err := p.RevokeGroupAdmin(ctx, bob, tg); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := core.EnterTenant(ctx, claims, org1); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("enter after revoke: err = %v, want ErrNotFound", err)
	}
}

func TestEnterTenant_DoesNotMintOnHierarchyError(t *testing.T) {
	h := newHierarchy()
	p, s := newP(t, h, roleMap())
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	core, jwt := newCore(t, NewMembership(s, h))
	claims := homeClaims(t, jwt)

	boom := errors.New("hierarchy down")
	h.err = boom
	if _, err := core.EnterTenant(ctx, claims, org1); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the hierarchy error (no mint)", err)
	}
}

// ---------------------------------------------------------------------
// Membership is user-scoped: a subject of another type that shares the id
// is not a user membership, and the user type is configurable.
// ---------------------------------------------------------------------

func TestIsMember_MatchesTheUserSubjectTypeOnly(t *testing.T) {
	h := newHierarchy()
	s := newStore()
	sa := authz.Subject{Tenant: tg, Type: "service_account", ID: "bob"}
	if err := s.GrantFrom(ctx, intentBinding(sa, tg, groupRole()), GroupOrigin(tg)); err != nil {
		t.Fatalf("seed service-account intent: %v", err)
	}

	m := NewMembership(s, h)
	if ok, err := m.IsMember(ctx, "bob", org1); err != nil || ok {
		t.Fatalf("IsMember(bob) = (%v, %v) — a service_account named bob is not a user membership", ok, err)
	}
	if got, err := m.MembershipsFor(ctx, "bob"); err != nil || len(got) != 0 {
		t.Fatalf("MembershipsFor(bob) = (%v, %v), want empty", ids(got), err)
	}

	// The app's own taxonomy may name users something else.
	m2 := NewMembership(s, h, WithUserSubjectType("staff"))
	staff := authz.Subject{Tenant: tg, Type: "staff", ID: "bob"}
	if err := s.GrantFrom(ctx, intentBinding(staff, tg, groupRole()), GroupOrigin(tg)); err != nil {
		t.Fatalf("seed staff intent: %v", err)
	}
	if ok, err := m2.IsMember(ctx, "bob", org1); err != nil || !ok {
		t.Fatalf("IsMember(bob) with staff user type = (%v, %v), want true", ok, err)
	}
}

func TestNewMembership_PanicsOnMisconfiguration(t *testing.T) {
	mustPanic := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Fatalf("%s: want panic, got none", name)
			}
		}()
		fn()
	}

	mustPanic("nil store", func() { NewMembership(nil, newHierarchy()) })
	mustPanic("nil hierarchy", func() { NewMembership(newStore(), nil) })
	mustPanic("empty user type", func() { NewMembership(newStore(), newHierarchy(), WithUserSubjectType("")) })
}
