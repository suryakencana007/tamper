package tenanthierarchy

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/tenant"
)

// fakeHierarchy is an in-memory OrgHierarchy: the app-owned port tamper's
// tenant.Store deliberately does not provide.
type fakeHierarchy struct {
	parent   map[string]string
	children map[string][]string
	err      error // when set, every method returns it
}

func newFakeHierarchy() *fakeHierarchy {
	return &fakeHierarchy{
		parent: map[string]string{"org-1": "tg-acme", "org-2": "tg-acme", "org-3": "tg-acme"},
		children: map[string][]string{
			"tg-acme": {"org-1", "org-2", "org-3"},
		},
	}
}

func (f *fakeHierarchy) ParentOf(_ context.Context, orgID string) (string, bool, error) {
	if f.err != nil {
		return "", false, f.err
	}
	g, ok := f.parent[orgID]
	return g, ok, nil
}

func (f *fakeHierarchy) ChildrenOf(_ context.Context, groupID string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.children[groupID], nil
}

func roleMap() RoleMap { return RoleMap{"tenant_group_admin": "org_admin"} }

func newProvisioner(t *testing.T) (*Provisioner, *Store, *fakeHierarchy) {
	t.Helper()
	s := newStore()
	h := newFakeHierarchy()
	p, err := NewProvisioner(s, h, roleMap())
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	return p, s, h
}

func groupRole() authz.Role { return "tenant_group_admin" }

// ---------------------------------------------------------------------
// Construction: misconfiguration fails at New, never as a per-request deny.
// ---------------------------------------------------------------------

func TestNewProvisioner_Validation(t *testing.T) {
	h := newFakeHierarchy()
	rm := roleMap()
	cases := []struct {
		name string
		call func() error
	}{
		{"nil source", func() error { _, err := NewProvisioner(nil, h, rm); return err }},
		{"nil hierarchy", func() error { _, err := NewProvisioner(newStore(), nil, rm); return err }},
		{"empty role map", func() error { _, err := NewProvisioner(newStore(), h, RoleMap{}); return err }},
		{"zero cap", func() error { _, err := NewProvisioner(newStore(), h, rm, WithMaxProvisionRows(0)); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err == nil {
				t.Fatal("want construction error, got nil")
			}
		})
	}
}

// ---------------------------------------------------------------------
// Grant: intent + one materialized binding per child, translated.
// ---------------------------------------------------------------------

func TestGrantGroupAdmin_WritesIntentAndEveryChild(t *testing.T) {
	p, s, _ := newProvisioner(t)
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("GrantGroupAdmin: %v", err)
	}

	if len(s.rows) != 4 {
		t.Fatalf("rows = %d, want 4 (1 intent + 3 children): %+v", len(s.rows), s.rows)
	}

	intent := intentBinding(bob, tg, groupRole())
	if _, ok := s.rows[keyOf(intent)]; !ok {
		t.Fatalf("intent row missing: %+v", intent)
	}

	for _, id := range []string{"org-1", "org-2", "org-3"} {
		want := materializedBinding(bob, id, "org_admin")
		if _, ok := s.rows[keyOf(want)]; !ok {
			t.Fatalf("materialized row missing for %s: %+v", id, want)
		}
	}
}

func TestGrantGroupAdmin_UnmappedRoleFailsClosed(t *testing.T) {
	p, s, _ := newProvisioner(t)
	err := p.GrantGroupAdmin(ctx, bob, tg, "tenant_group_viewer")
	if !errors.Is(err, ErrUnmappedRole) {
		t.Fatalf("err = %v, want ErrUnmappedRole", err)
	}
	if len(s.rows) != 0 {
		t.Fatalf("rows = %d, want 0 — an unmapped role writes nothing", len(s.rows))
	}
}

func TestGrantGroupAdmin_IsIdempotent(t *testing.T) {
	p, s, _ := newProvisioner(t)
	for i := 0; i < 2; i++ {
		if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
			t.Fatalf("GrantGroupAdmin #%d: %v", i+1, err)
		}
	}
	if len(s.rows) != 4 {
		t.Fatalf("rows = %d, want 4 — granting twice is idempotent", len(s.rows))
	}
}

func TestGrantGroupAdmin_SubjectHomeTenantMustBeGroup(t *testing.T) {
	p, s, _ := newProvisioner(t)
	outsider := authz.Subject{Tenant: tenant.New("tg-other"), Type: "user", ID: "erin"}
	if err := p.GrantGroupAdmin(ctx, outsider, tg, groupRole()); !errors.Is(err, ErrSubjectNotInGroup) {
		t.Fatalf("err = %v, want ErrSubjectNotInGroup", err)
	}
	if len(s.rows) != 0 {
		t.Fatalf("rows = %d, want 0", len(s.rows))
	}
}

func TestGrantGroupAdmin_HierarchyErrorPropagates(t *testing.T) {
	p, s, h := newProvisioner(t)
	h.err = errors.New("hierarchy down")
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err == nil {
		t.Fatal("want error, got nil")
	}
	if len(s.rows) != 0 {
		t.Fatalf("rows = %d, want 0", len(s.rows))
	}
}

// ---------------------------------------------------------------------
// Revoke: intent and every materialized row go, in one apply.
// ---------------------------------------------------------------------

func TestRevokeGroupAdmin_RemovesIntentAndChildren(t *testing.T) {
	p, s, _ := newProvisioner(t)
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("GrantGroupAdmin: %v", err)
	}
	if err := p.RevokeGroupAdmin(ctx, bob, tg); err != nil {
		t.Fatalf("RevokeGroupAdmin: %v", err)
	}
	if len(s.rows) != 0 {
		t.Fatalf("rows = %d, want 0 after revoke: %+v", len(s.rows), s.rows)
	}

	// And a fresh grant works again (revoke did not wedge the store).
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("re-grant: %v", err)
	}
	if len(s.rows) != 4 {
		t.Fatalf("rows = %d, want 4 after re-grant", len(s.rows))
	}
}

func TestRevokeGroupAdmin_LeavesOtherSubjectsAlone(t *testing.T) {
	p, s, _ := newProvisioner(t)
	other := authz.Subject{Tenant: tg, Type: "user", ID: "carol"}
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant bob: %v", err)
	}
	if err := p.GrantGroupAdmin(ctx, other, tg, groupRole()); err != nil {
		t.Fatalf("grant carol: %v", err)
	}
	if err := p.RevokeGroupAdmin(ctx, bob, tg); err != nil {
		t.Fatalf("revoke bob: %v", err)
	}
	if len(s.rows) != 4 {
		t.Fatalf("rows = %d, want 4 — only bob's rows go", len(s.rows))
	}
	for _, id := range []string{"org-1", "org-2", "org-3"} {
		if _, ok := s.rows[keyOf(materializedBinding(other, id, "org_admin"))]; !ok {
			t.Fatalf("carol's binding in %s was removed", id)
		}
	}
}

// ---------------------------------------------------------------------
// Reverse query: a child scope sees the materialized binding, never the
// intent row (which lives in the group scope).
// ---------------------------------------------------------------------

func TestReverseQuery_SeesMaterializedNotIntent(t *testing.T) {
	p, s, _ := newProvisioner(t)
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("GrantGroupAdmin: %v", err)
	}

	bySubject, err := s.BindingsForSubject(ctx, org1, bob, ResourceOrganization)
	if err != nil {
		t.Fatalf("BindingsForSubject: %v", err)
	}
	if len(bySubject) != 1 || bySubject[0].Role != "org_admin" || bySubject[0].Resource != resOrg1 {
		t.Fatalf("BindingsForSubject(org1, bob) = %+v, want bob's org_admin on org-1", bySubject)
	}

	exact, err := s.BindingsFor(ctx, org1, bob, resOrg1)
	if err != nil {
		t.Fatalf("BindingsFor: %v", err)
	}
	if len(exact) != 1 || exact[0].Role != "org_admin" {
		t.Fatalf("BindingsFor(org1, bob, org-1) = %+v", exact)
	}

	// The intent row lives in the group's scope; it is not visible in the
	// child's.
	inOrg, err := s.BindingsOnResource(ctx, org1, resTg)
	if err != nil {
		t.Fatalf("BindingsOnResource: %v", err)
	}
	if len(inOrg) != 0 {
		t.Fatalf("child scope returned %+v — the intent row must not be visible there", inOrg)
	}
	inGroup, err := s.BindingsOnResource(ctx, tg, resTg)
	if err != nil {
		t.Fatalf("BindingsOnResource(group): %v", err)
	}
	if len(inGroup) != 1 || inGroup[0].Subject != bob {
		t.Fatalf("group scope = %+v, want the intent row", inGroup)
	}
}

// ---------------------------------------------------------------------
// The cap is a loud stop, never a silent split.
// ---------------------------------------------------------------------

func TestMaxProvisionRows_CapsTheOperation(t *testing.T) {
	s := newStore()
	h := &fakeHierarchy{children: map[string][]string{}}
	var kids []string
	for i := 0; i < 10; i++ {
		kids = append(kids, fmt.Sprintf("org-%d", i))
	}
	h.children["tg-acme"] = kids

	p, err := NewProvisioner(s, h, roleMap(), WithMaxProvisionRows(3))
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); !errors.Is(err, ErrTooManyRows) {
		t.Fatalf("err = %v, want ErrTooManyRows", err)
	}
	if len(s.rows) != 0 {
		t.Fatalf("rows = %d, want 0 — the cap writes nothing", len(s.rows))
	}
}

// ---------------------------------------------------------------------
// Provenance: a group revoke must not remove a direct grant that lands on
// the same binding (review B1).
// ---------------------------------------------------------------------

func TestRevokeGroupAdmin_KeepsDirectGrantOnSameBinding(t *testing.T) {
	p, s, _ := newProvisioner(t)
	direct := authz.Binding{Tenant: org1, Subject: bob, Resource: resOrg1, Role: "org_admin"}
	if err := s.Grant(ctx, direct); err != nil {
		t.Fatalf("direct grant: %v", err)
	}
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("GrantGroupAdmin: %v", err)
	}
	if err := p.RevokeGroupAdmin(ctx, bob, tg); err != nil {
		t.Fatalf("RevokeGroupAdmin: %v", err)
	}

	if _, ok := s.rows[keyOf(direct)]; !ok {
		t.Fatal("the DIRECT org-1 grant was removed by the group revoke")
	}
	// org-2 and org-3 were justified by the group alone, so they are gone.
	if _, ok := s.rows[keyOf(materializedBinding(bob, "org-2", "org_admin"))]; ok {
		t.Fatal("org-2's group binding survived the revoke")
	}
	// The direct grant is the last origin on org-1; revoking it clears the row.
	if err := s.Revoke(ctx, keyOf(direct)); err != nil {
		t.Fatalf("Revoke(direct): %v", err)
	}
	if len(s.rows) != 0 {
		t.Fatalf("rows = %d, want 0", len(s.rows))
	}
}

func TestRevokeGroupAdmin_KeepsDirectGrantOnGroupResource(t *testing.T) {
	p, s, _ := newProvisioner(t)
	// Same key as the intent row, so only provenance tells them apart.
	direct := intentBinding(bob, tg, groupRole())
	if err := s.Grant(ctx, direct); err != nil {
		t.Fatalf("direct grant: %v", err)
	}
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("GrantGroupAdmin: %v", err)
	}
	if err := p.RevokeGroupAdmin(ctx, bob, tg); err != nil {
		t.Fatalf("RevokeGroupAdmin: %v", err)
	}
	if _, ok := s.rows[keyOf(direct)]; !ok {
		t.Fatal("the DIRECT grant on the group resource was removed by the revoke")
	}
}
