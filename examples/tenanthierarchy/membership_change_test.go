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
// org-9. Org membership changes are driven by the caller (here, the test), so
// a fresh org like org-4 needs no hierarchy entry.
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
	p, s := newP(t, newHierarchy(), roleMapTwo())
	carol := authz.Subject{Tenant: tg, Type: "user", ID: "carol"}
	if err := p.GrantGroupAdmin(ctx, bob, tg, "tenant_group_admin"); err != nil {
		t.Fatalf("grant bob: %v", err)
	}
	if err := p.GrantGroupAdmin(ctx, carol, tg, "tenant_group_viewer"); err != nil {
		t.Fatalf("grant carol: %v", err)
	}

	newOrg := tenant.New("org-4")
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
	p, s := newP(t, newHierarchy(), roleMapTwo())
	if err := p.AddOrg(ctx, tg, tenant.New("org-4")); err != nil {
		t.Fatalf("AddOrg: %v", err)
	}
	if len(s.rows) != 0 {
		t.Fatalf("rows = %d, want 0", len(s.rows))
	}
}

func TestAddOrg_IsIdempotent(t *testing.T) {
	p, s := newP(t, newHierarchy(), roleMap())
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	newOrg := tenant.New("org-4")
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
	p, s := newP(t, newHierarchy(), roleMap()) // only admin -> org_admin
	// Seed an intent whose role the map cannot translate.
	if err := s.GrantFrom(ctx, intentBinding(bob, tg, "tenant_group_viewer"), GroupOrigin(tg)); err != nil {
		t.Fatalf("seed intent: %v", err)
	}
	newOrg := tenant.New("org-4")
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

func TestAddOrg_RejectsSameTenant(t *testing.T) {
	p, _ := newP(t, newHierarchy(), roleMap())
	if err := p.AddOrg(ctx, tg, tg); !errors.Is(err, ErrBadMembership) {
		t.Fatalf("err = %v, want ErrBadMembership", err)
	}
}

// ---------------------------------------------------------------------
// MoveOrg does both halves in one operation.
// ---------------------------------------------------------------------

func TestMoveOrg_LosesFromAndGainsTo(t *testing.T) {
	p, s := newP(t, newHierarchy(), roleMap())
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant bob: %v", err)
	}
	if err := p.GrantGroupAdmin(ctx, erin, tgOther, groupRole()); err != nil {
		t.Fatalf("grant erin: %v", err)
	}

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
