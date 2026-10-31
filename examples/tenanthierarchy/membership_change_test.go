package tenanthierarchy

import (
	"errors"
	"testing"

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/tenant"
)

var (
	tgOther = tenant.New("tg-other")
	org9    = tenant.New("org-9")
)

// roleMapTwo maps both a group admin and a group viewer role, so a membership
// change can be shown to carry each admin's OWN translated role.
func roleMapTwo() RoleMap {
	return RoleMap{"tenant_group_admin": "org_admin", "tenant_group_viewer": "org_viewer"}
}

// newHierarchy is the two-group fixture: tg-acme owns org-1/2/3, tg-other owns
// org-9.
func newHierarchy() *fakeHierarchy {
	return &fakeHierarchy{
		parent: map[string]string{
			"org-1": "tg-acme", "org-2": "tg-acme", "org-3": "tg-acme", "org-9": "tg-other",
		},
		children: map[string][]string{
			"tg-acme":  {"org-1", "org-2", "org-3"},
			"tg-other": {"org-9"},
		},
	}
}

// setParent simulates the app's own parentage change, which must precede the
// provisioner call (AddOrg/MoveOrg/RemoveOrg verify it).
func (f *fakeHierarchy) setParent(org, group string) { f.parent[org] = group }

func newP(t *testing.T, h OrgHierarchy, roles RoleMap) (*Provisioner, *Store) {
	t.Helper()
	s := newStore()
	p, err := NewProvisioner(s, h, roles)
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	return p, s
}

func orgRes(id string) authz.Resource { return authz.Resource{Type: ResourceOrganization, ID: id} }

// ---------------------------------------------------------------------
// AddOrg extends every current grant of the group onto the new org.
// ---------------------------------------------------------------------

func TestAddOrg_ExtendsEveryGroupAdminWithItsOwnRole(t *testing.T) {
	h := newHierarchy()
	p, s := newP(t, h, roleMapTwo())
	carol := authz.Subject{Tenant: tg, Type: "user", ID: "carol"}
	if err := p.GrantGroupAdmin(ctx, bob, tg, "tenant_group_admin"); err != nil {
		t.Fatalf("grant bob: %v", err)
	}
	if err := p.GrantGroupAdmin(ctx, carol, tg, "tenant_group_viewer"); err != nil {
		t.Fatalf("grant carol: %v", err)
	}

	newOrg := tenant.New("org-4")
	h.setParent("org-4", "tg-acme") // the app attaches first
	if err := p.AddOrg(ctx, tg, newOrg); err != nil {
		t.Fatalf("AddOrg: %v", err)
	}

	adminRole, err := s.BindingsForSubject(ctx, newOrg, bob, ResourceOrganization)
	if err != nil {
		t.Fatalf("BindingsForSubject(bob): %v", err)
	}
	if len(adminRole) != 1 || adminRole[0].Role != "org_admin" {
		t.Fatalf("bob in org-4 = %+v, want one org_admin", adminRole)
	}
	viewerRole, err := s.BindingsForSubject(ctx, newOrg, carol, ResourceOrganization)
	if err != nil {
		t.Fatalf("BindingsForSubject(carol): %v", err)
	}
	if len(viewerRole) != 1 || viewerRole[0].Role != "org_viewer" {
		t.Fatalf("carol in org-4 = %+v, want one org_viewer", viewerRole)
	}
}

func TestAddOrg_NoAdminsIsANoOp(t *testing.T) {
	h := newHierarchy()
	p, s := newP(t, h, roleMapTwo())
	h.setParent("org-4", "tg-acme")
	if err := p.AddOrg(ctx, tg, tenant.New("org-4")); err != nil {
		t.Fatalf("AddOrg: %v", err)
	}
	if len(s.rows) != 0 {
		t.Fatalf("rows = %d, want 0", len(s.rows))
	}
}

func TestAddOrg_IsIdempotent(t *testing.T) {
	h := newHierarchy()
	p, s := newP(t, h, roleMap())
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	newOrg := tenant.New("org-4")
	h.setParent("org-4", "tg-acme")
	for i := 0; i < 2; i++ {
		if err := p.AddOrg(ctx, tg, newOrg); err != nil {
			t.Fatalf("AddOrg #%d: %v", i+1, err)
		}
	}
	got, err := s.BindingsForSubject(ctx, newOrg, bob, ResourceOrganization)
	if err != nil {
		t.Fatalf("BindingsForSubject: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("bob in org-4 = %d rows, want 1", len(got))
	}
}

func TestAddOrg_UnmappedRoleFailsClosed(t *testing.T) {
	h := newHierarchy()
	p, s := newP(t, h, roleMap()) // only admin -> org_admin
	// Seed an intent whose role the map cannot translate.
	if err := s.GrantFrom(ctx, intentBinding(bob, tg, "tenant_group_viewer"), GroupOrigin(tg)); err != nil {
		t.Fatalf("seed intent: %v", err)
	}
	newOrg := tenant.New("org-4")
	h.setParent("org-4", "tg-acme")

	if err := p.AddOrg(ctx, tg, newOrg); !errors.Is(err, ErrUnmappedRole) {
		t.Fatalf("err = %v, want ErrUnmappedRole", err)
	}
	got, err := s.BindingsForSubject(ctx, newOrg, bob, ResourceOrganization)
	if err != nil {
		t.Fatalf("BindingsForSubject: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("org-4 got %+v — an unmapped role must write nothing", got)
	}
}

func TestAddOrg_RejectsWrongParent(t *testing.T) {
	p, _ := newP(t, newHierarchy(), roleMap())
	// org-9's parent is tg-other; AddOrg names tg-acme.
	if err := p.AddOrg(ctx, tg, org9); !errors.Is(err, ErrParentMismatch) {
		t.Fatalf("err = %v, want ErrParentMismatch", err)
	}
}

func TestAddOrg_RejectsSameTenant(t *testing.T) {
	p, _ := newP(t, newHierarchy(), roleMap())
	if err := p.AddOrg(ctx, tg, tg); !errors.Is(err, ErrBadMembership) {
		t.Fatalf("err = %v, want ErrBadMembership", err)
	}
}

func TestAddOrg_RejectsUnsetOrg(t *testing.T) {
	p, _ := newP(t, newHierarchy(), roleMap())
	if err := p.AddOrg(ctx, tg, tenant.ID{}); !errors.Is(err, ErrBadMembership) {
		t.Fatalf("err = %v, want ErrBadMembership", err)
	}
}

func TestAddOrg_RejectsSingleTenantGroup(t *testing.T) {
	p, _ := newP(t, newHierarchy(), roleMap())
	err := p.AddOrg(ctx, tenant.Single, org1)
	if !errors.Is(err, ErrBadMembership) {
		t.Fatalf("err = %v, want ErrBadMembership", err)
	}
}

// ---------------------------------------------------------------------
// MoveOrg does both halves in one operation.
// ---------------------------------------------------------------------

func TestMoveOrg_LosesFromAndGainsTo(t *testing.T) {
	h := newHierarchy()
	p, s := newP(t, h, roleMap())
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant bob: %v", err)
	}
	if err := p.GrantGroupAdmin(ctx, erin, tgOther, groupRole()); err != nil {
		t.Fatalf("grant erin: %v", err)
	}
	h.setParent("org-9", "tg-acme") // the app reparents first

	if err := p.MoveOrg(ctx, org9, tgOther, tg); err != nil {
		t.Fatalf("MoveOrg: %v", err)
	}

	gained, err := s.BindingsForSubject(ctx, org9, bob, ResourceOrganization)
	if err != nil {
		t.Fatalf("BindingsForSubject(bob): %v", err)
	}
	if len(gained) != 1 {
		t.Fatal("to-group admin did not gain access to the moved org")
	}
	lost, err := s.BindingsForSubject(ctx, org9, erin, ResourceOrganization)
	if err != nil {
		t.Fatalf("BindingsForSubject(erin): %v", err)
	}
	if len(lost) != 0 {
		t.Fatalf("from-group admin still has access: %+v", lost)
	}
}

func TestMoveOrg_RejectsWrongParent(t *testing.T) {
	p, _ := newP(t, newHierarchy(), roleMap())
	// org-9's parent is still tg-other, not the destination tg-acme.
	if err := p.MoveOrg(ctx, org9, tgOther, tg); !errors.Is(err, ErrParentMismatch) {
		t.Fatalf("err = %v, want ErrParentMismatch", err)
	}
}

func TestMoveOrg_RejectsSameGroup(t *testing.T) {
	p, _ := newP(t, newHierarchy(), roleMap())
	if err := p.MoveOrg(ctx, org9, tg, tg); !errors.Is(err, ErrBadMembership) {
		t.Fatalf("err = %v, want ErrBadMembership", err)
	}
}

// ---------------------------------------------------------------------
// RemoveOrg clears the group's contribution and nothing else.
// ---------------------------------------------------------------------

func TestRemoveOrg_ClearsOnlyThatOrg(t *testing.T) {
	p, s := newP(t, newHierarchy(), roleMap())
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := p.RemoveOrg(ctx, org1, tg); err != nil {
		t.Fatalf("RemoveOrg: %v", err)
	}

	cleared, err := s.BindingsOnResource(ctx, org1, resOrg1)
	if err != nil {
		t.Fatalf("BindingsOnResource(org-1): %v", err)
	}
	if len(cleared) != 0 {
		t.Fatalf("org-1 scope = %+v, want empty", cleared)
	}
	kept, err := s.BindingsOnResource(ctx, org2, orgRes("org-2"))
	if err != nil {
		t.Fatalf("BindingsOnResource(org-2): %v", err)
	}
	if len(kept) != 1 {
		t.Fatalf("org-2 scope = %+v, want bob's binding untouched", kept)
	}
}

func TestRemoveOrg_KeepsDirectGrantOnSameBinding(t *testing.T) {
	p, s := newP(t, newHierarchy(), roleMap())
	direct := materializedBinding(bob, "org-1", "org_admin")
	if err := s.Grant(ctx, direct); err != nil {
		t.Fatalf("direct grant: %v", err)
	}
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant group: %v", err)
	}
	if err := p.RemoveOrg(ctx, org1, tg); err != nil {
		t.Fatalf("RemoveOrg: %v", err)
	}
	if _, ok := s.rows[keyOf(direct)]; !ok {
		t.Fatal("the DIRECT org-1 grant was removed by RemoveOrg")
	}
	// RemoveOrg names only org-1; another child is untouched.
	kept, err := s.BindingsOnResource(ctx, org2, orgRes("org-2"))
	if err != nil {
		t.Fatalf("BindingsOnResource(org-2): %v", err)
	}
	if len(kept) != 1 {
		t.Fatalf("org-2 scope = %+v, want bob's group binding untouched", kept)
	}
}

func TestRemoveOrg_RejectsWrongParent(t *testing.T) {
	p, _ := newP(t, newHierarchy(), roleMap())
	// org-9's parent is tg-other; RemoveOrg names tg-acme.
	if err := p.RemoveOrg(ctx, org9, tg); !errors.Is(err, ErrParentMismatch) {
		t.Fatalf("err = %v, want ErrParentMismatch", err)
	}
}

// ---------------------------------------------------------------------
// GroupAdmins reads intent rows by origin, not direct grants on the group.
// ---------------------------------------------------------------------

func TestGroupAdmins_ReturnsIntentRowsOnly(t *testing.T) {
	p, s := newP(t, newHierarchy(), roleMapTwo())
	if err := p.GrantGroupAdmin(ctx, bob, tg, "tenant_group_admin"); err != nil {
		t.Fatalf("grant bob: %v", err)
	}
	// A direct grant on the group resource, a different subject: it must not
	// be read as an intent row.
	dave := authz.Subject{Tenant: tg, Type: "user", ID: "dave"}
	if err := s.Grant(ctx, intentBinding(dave, tg, "tenant_group_admin")); err != nil {
		t.Fatalf("direct grant: %v", err)
	}

	admins, err := s.GroupAdmins(ctx, tg)
	if err != nil {
		t.Fatalf("GroupAdmins: %v", err)
	}
	if len(admins) != 1 || admins[0].Subject != bob {
		t.Fatalf("GroupAdmins = %+v, want only bob's intent row", admins)
	}
}

// ---------------------------------------------------------------------
// The row cap applies to membership changes too, and rolls back.
// ---------------------------------------------------------------------

func TestAddOrg_RespectsTheCap(t *testing.T) {
	h := newHierarchy()
	s := newStore()
	p, err := NewProvisioner(s, h, roleMap(), WithMaxProvisionRows(2))
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	// Three intent rows, cap two.
	for _, id := range []string{"a", "b", "c"} {
		sub := authz.Subject{Tenant: tg, Type: "user", ID: id}
		if err := s.GrantFrom(ctx, intentBinding(sub, tg, groupRole()), GroupOrigin(tg)); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	h.setParent("org-4", "tg-acme")
	newOrg := tenant.New("org-4")
	if err := p.AddOrg(ctx, tg, newOrg); !errors.Is(err, ErrTooManyRows) {
		t.Fatalf("err = %v, want ErrTooManyRows", err)
	}
	got, err := s.BindingsForSubject(ctx, newOrg, authz.Subject{Tenant: tg, Type: "user", ID: "a"}, ResourceOrganization)
	if err != nil {
		t.Fatalf("BindingsForSubject: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("org-4 got %+v despite the cap", got)
	}
}

func TestMoveOrg_RespectsTheCap(t *testing.T) {
	h := newHierarchy()
	s := newStore()
	if err := s.GrantFrom(ctx, materializedBinding(erin, "org-9", "org_admin"), GroupOrigin(tgOther)); err != nil {
		t.Fatalf("seed from-binding: %v", err)
	}
	for _, id := range []string{"a", "b"} {
		sub := authz.Subject{Tenant: tg, Type: "user", ID: id}
		if err := s.GrantFrom(ctx, intentBinding(sub, tg, groupRole()), GroupOrigin(tg)); err != nil {
			t.Fatalf("seed intent %s: %v", id, err)
		}
	}
	p, err := NewProvisioner(s, h, roleMap(), WithMaxProvisionRows(2))
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	h.setParent("org-9", "tg-acme")
	// fromRows(1) + toAdmins(2) = 3 > cap 2.
	if err := p.MoveOrg(ctx, org9, tgOther, tg); !errors.Is(err, ErrTooManyRows) {
		t.Fatalf("err = %v, want ErrTooManyRows", err)
	}
	kept, err := s.BindingsForSubject(ctx, org9, erin, ResourceOrganization)
	if err != nil {
		t.Fatalf("BindingsForSubject(erin): %v", err)
	}
	if len(kept) != 1 {
		t.Fatalf("org-9 = %+v, want erin's binding untouched by the failed move", kept)
	}
}

func TestRemoveOrg_RespectsTheCap(t *testing.T) {
	h := newHierarchy()
	s := newStore()
	seed, err := NewProvisioner(s, h, roleMap())
	if err != nil {
		t.Fatalf("NewProvisioner(seed): %v", err)
	}
	carol := authz.Subject{Tenant: tg, Type: "user", ID: "carol"}
	if err := seed.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant bob: %v", err)
	}
	if err := seed.GrantGroupAdmin(ctx, carol, tg, groupRole()); err != nil {
		t.Fatalf("grant carol: %v", err)
	}

	p, err := NewProvisioner(s, h, roleMap(), WithMaxProvisionRows(1))
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	if err := p.RemoveOrg(ctx, org1, tg); !errors.Is(err, ErrTooManyRows) {
		t.Fatalf("err = %v, want ErrTooManyRows", err)
	}
	kept, err := s.BindingsOnResource(ctx, org1, resOrg1)
	if err != nil {
		t.Fatalf("BindingsOnResource(org-1): %v", err)
	}
	if len(kept) != 2 {
		t.Fatalf("org-1 = %d rows, want 2 untouched by the failed remove", len(kept))
	}
}

// ---------------------------------------------------------------------
// A hierarchy read that errors fails the membership change, never a silent
// success.
// ---------------------------------------------------------------------

func TestMembership_HierarchyErrorPropagates(t *testing.T) {
	h := newHierarchy()
	p, _ := newP(t, h, roleMap())
	boom := errors.New("hierarchy down")
	h.err = boom

	cases := []struct {
		name string
		call func() error
	}{
		{"AddOrg", func() error { return p.AddOrg(ctx, tg, tenant.New("org-4")) }},
		{"MoveOrg", func() error { return p.MoveOrg(ctx, org9, tgOther, tg) }},
		{"RemoveOrg", func() error { return p.RemoveOrg(ctx, org1, tg) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, boom) {
				t.Fatalf("err = %v, want the hierarchy error", err)
			}
		})
	}
}
