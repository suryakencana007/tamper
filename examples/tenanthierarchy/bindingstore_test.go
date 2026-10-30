package tenanthierarchy

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/suryakencana007/tamper/authz"
)

// ---------------------------------------------------------------------
// Fixtures — mirror the ADR-0001 example: one tenant-group "tg-acme"
// with three organization children, plus a lone root org with no
// parent (the single-tenant-deployment-shaped edge case).
// ---------------------------------------------------------------------

var (
	alice = authz.Subject{Type: "user", ID: "alice"} // org-1 direct admin only
	bob   = authz.Subject{Type: "user", ID: "bob"}   // tenant-group admin on tg-acme
	carol = authz.Subject{Type: "user", ID: "carol"} // platform admin (system, global)
	dave  = authz.Subject{Type: "user", ID: "dave"}  // tenant-group VIEWER (unmapped role)
	erin  = authz.Subject{Type: "user", ID: "erin"}  // admin of a DIFFERENT tenant-group

	org1 = authz.Resource{Type: "organization", ID: "org-1"}
	org2 = authz.Resource{Type: "organization", ID: "org-2"}
	org3 = authz.Resource{Type: "organization", ID: "org-3"}
	org4 = authz.Resource{Type: "organization", ID: "org-4"}    // child of tg-other (erin's group)
	root = authz.Resource{Type: "organization", ID: "org-root"} // no parent

	tgAcme  = authz.Resource{Type: "tenant_group", ID: "tg-acme"}
	tgOther = authz.Resource{Type: "tenant_group", ID: "tg-other"} // erin's group; owns org-4

	system = authz.Resource{Type: "system"}
)

// roleMap mirrors ADR-0001 §3: tenant_group admin expands to org admin;
// tenant_group viewer is deliberately left UNMAPPED to exercise fail-
// closed (ADR-0001's RoleMap doc: "a role absent from the map does NOT
// expand").
func roleMap() RoleMap {
	return RoleMap{
		"tenant_group_admin": "org_admin",
	}
}

// fakeHierarchy is a tiny in-memory OrgHierarchy test double — the
// app-owned port tamper's own tenant.Store deliberately does not
// provide (ParentID stays reserved there).
type fakeHierarchy struct {
	mu       sync.Mutex
	parent   map[string]string // orgID -> tenantGroupID
	children map[string][]string
	err      error // when set, every method returns this error
	calls    int   // call counter, for cache-worthiness assertions
}

func newFakeHierarchy() *fakeHierarchy {
	return &fakeHierarchy{
		parent: map[string]string{
			"org-1": "tg-acme",
			"org-2": "tg-acme",
			"org-3": "tg-acme",
			"org-4": "tg-other",
			// "org-root" intentionally absent: no parent.
		},
		children: map[string][]string{
			"tg-acme":  {"org-1", "org-2", "org-3"},
			"tg-other": {"org-4"}, // erin's group has a child of its own
		},
	}
}

func (f *fakeHierarchy) ParentOf(_ context.Context, orgID string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return "", false, f.err
	}
	tg, ok := f.parent[orgID]
	return tg, ok, nil
}

func (f *fakeHierarchy) ChildrenOf(_ context.Context, tenantGroupID string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.children[tenantGroupID], nil
}

// baseBindings seeds the raw, un-expanded bindings exactly as ADR-0001
// §1 describes the three scopes being stored.
func baseBindings() *authz.MemStore {
	return authz.NewMemStore(
		// alice: direct organization admin on org-1 only. No tenant-group binding.
		authz.Binding{Subject: alice, Resource: org1, Role: "org_admin"},
		// bob: tenant-group admin on tg-acme — should expand to org-1/2/3.
		authz.Binding{Subject: bob, Resource: tgAcme, Role: "tenant_group_admin"},
		// carol: platform admin, global system binding. NOT expanded by
		// this Store at all — system scope is a passthrough (ADR-0001 §3:
		// "platform and tenant_group bindings are never themselves
		// expanded further").
		authz.Binding{Subject: carol, Resource: system, Role: "platform_admin"},
		// dave: tenant-group VIEWER on tg-acme — role has no RoleMap
		// entry, must expand to NOTHING (fail closed).
		authz.Binding{Subject: dave, Resource: tgAcme, Role: "tenant_group_viewer"},
		// erin: tenant-group admin on a DIFFERENT group (tg-other, which
		// now owns org-4) — the cross-tenant-group leak probe: erin must
		// reach org-4 and MUST NOT reach tg-acme's org-1/2/3.
		authz.Binding{Subject: erin, Resource: tgOther, Role: "tenant_group_admin"},
	)
}

func newTestStore(t *testing.T) (*Store, *fakeHierarchy, *authz.MemStore) {
	t.Helper()
	base := baseBindings()
	hier := newFakeHierarchy()
	s, err := New(base, hier, roleMap())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, hier, base
}

// ---------------------------------------------------------------------
// Construction — fail at New, never as a per-request denial (ADR-0001
// mirrors tamper's own RequireTenant/PinTenant posture here).
// ---------------------------------------------------------------------

func TestNewValidation(t *testing.T) {
	base := baseBindings()
	hier := newFakeHierarchy()
	rm := roleMap()

	cases := []struct {
		name  string
		base  authz.BindingStore
		hier  OrgHierarchy
		roles RoleMap
	}{
		{"nil base", nil, hier, rm},
		{"nil hierarchy", base, nil, rm},
		{"nil roles", base, hier, nil},
		{"empty roles", base, hier, RoleMap{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.base, tc.hier, tc.roles); err == nil {
				t.Fatal("want construction error, got nil")
			}
		})
	}
}

func TestNewValid(t *testing.T) {
	s, _, _ := newTestStore(t)
	if s == nil {
		t.Fatal("New returned nil Store with nil error")
	}
}

// ---------------------------------------------------------------------
// BindingsFor — the per-resource expand path (ADR-0001 §4a / diagram 3).
// ---------------------------------------------------------------------

func TestBindingsFor_DirectOrgBindingUnaffected(t *testing.T) {
	s, _, _ := newTestStore(t)
	bs, err := s.BindingsFor(context.Background(), alice, org1)
	if err != nil {
		t.Fatalf("BindingsFor: %v", err)
	}
	if len(bs) != 1 || bs[0].Role != "org_admin" || bs[0].Resource != org1 {
		t.Fatalf("got %+v, want exactly alice's direct org_admin binding on org1", bs)
	}
}

func TestBindingsFor_TenantGroupAdminExpandsOntoChildOrg(t *testing.T) {
	s, _, _ := newTestStore(t)
	for _, org := range []authz.Resource{org1, org2, org3} {
		t.Run(org.ID, func(t *testing.T) {
			bs, err := s.BindingsFor(context.Background(), bob, org)
			if err != nil {
				t.Fatalf("BindingsFor: %v", err)
			}
			if len(bs) != 1 {
				t.Fatalf("got %+v, want exactly one expanded binding", bs)
			}
			got := bs[0]
			if got.Resource != org {
				t.Fatalf("resource = %+v, want re-stamped to %+v (not tenant_group)", got.Resource, org)
			}
			if got.Subject != bob {
				t.Fatalf("subject = %+v, want %+v", got.Subject, bob)
			}
			if got.Role != "org_admin" {
				t.Fatalf("role = %q, want translated %q", got.Role, "org_admin")
			}
		})
	}
}

func TestBindingsFor_UnmappedRoleExpandsToNothing(t *testing.T) {
	// dave holds tenant_group_viewer on tg-acme, which has no RoleMap
	// entry — must deny, not pass the role through verbatim.
	s, _, _ := newTestStore(t)
	bs, err := s.BindingsFor(context.Background(), dave, org1)
	if err != nil {
		t.Fatalf("BindingsFor: %v", err)
	}
	if len(bs) != 0 {
		t.Fatalf("got %+v, want empty — unmapped role must fail closed", bs)
	}
}

func TestBindingsFor_CrossTenantGroupLeak(t *testing.T) {
	// THE cross-tenant-group leak suite ADR-0001's mitigations section
	// requires: erin is admin of tg-other (a DIFFERENT tenant-group),
	// and must get NOTHING on org-1/2/3 — those belong to tg-acme.
	s, _, _ := newTestStore(t)
	for _, org := range []authz.Resource{org1, org2, org3} {
		t.Run(org.ID, func(t *testing.T) {
			bs, err := s.BindingsFor(context.Background(), erin, org)
			if err != nil {
				t.Fatalf("BindingsFor: %v", err)
			}
			if len(bs) != 0 {
				t.Fatalf("cross-tenant-group leak: erin (tg-other admin) got %+v on %s (belongs to tg-acme)", bs, org.ID)
			}
		})
	}

	// ...but the probe must not be a blanket "erin sees nothing": erin's
	// OWN group's child (org-4) must still be reachable, and re-stamped
	// to the org with the translated role. Without this half, a store
	// that dropped all expansion would pass the loop above vacuously.
	bs, err := s.BindingsFor(context.Background(), erin, org4)
	if err != nil {
		t.Fatalf("BindingsFor(org-4): %v", err)
	}
	if len(bs) != 1 || bs[0].Resource != org4 || bs[0].Subject != erin || bs[0].Role != "org_admin" {
		t.Fatalf("got %+v, want erin's tg-other binding expanded onto org-4 as org_admin", bs)
	}
}

func TestBindingsFor_OrgWithNoParentIsPassthrough(t *testing.T) {
	// org-root has no tenant-group parent (fakeHierarchy.parent has no
	// entry for it) — ParentOf reports ok=false, and bob's tenant-group
	// binding must not leak onto an unrelated, parent-less org.
	s, _, _ := newTestStore(t)
	bs, err := s.BindingsFor(context.Background(), bob, root)
	if err != nil {
		t.Fatalf("BindingsFor: %v", err)
	}
	if len(bs) != 0 {
		t.Fatalf("got %+v, want empty — org with no parent must not inherit any tenant-group binding", bs)
	}
}

func TestBindingsFor_NonOrganizationTypeIsPassthrough(t *testing.T) {
	// Resource types other than "organization" (tenant_group, system)
	// must never themselves be expanded further — ADR-0001 §3: "no
	// reseller-of-reseller in this draft".
	s, _, _ := newTestStore(t)

	bs, err := s.BindingsFor(context.Background(), bob, tgAcme)
	if err != nil {
		t.Fatalf("BindingsFor(tenant_group): %v", err)
	}
	if len(bs) != 1 || bs[0].Role != "tenant_group_admin" {
		t.Fatalf("tenant_group binding must pass through unexpanded, got %+v", bs)
	}

	bs, err = s.BindingsFor(context.Background(), carol, system)
	if err != nil {
		t.Fatalf("BindingsFor(system): %v", err)
	}
	if len(bs) != 1 || bs[0].Role != "platform_admin" {
		t.Fatalf("system binding must pass through unexpanded, got %+v", bs)
	}
}

func TestBindingsFor_GlobalOrgQueryIsPassthrough(t *testing.T) {
	// Resource{"organization", ""} is the type-level / global query —
	// ParentOf has no concrete org id to resolve against, so this must
	// skip expansion rather than panic or error.
	s, _, _ := newTestStore(t)
	bs, err := s.BindingsFor(context.Background(), bob, authz.Resource{Type: "organization", ID: ""})
	if err != nil {
		t.Fatalf("BindingsFor(global org): %v", err)
	}
	if len(bs) != 0 {
		t.Fatalf("got %+v, want empty — bob has no direct global org binding", bs)
	}
}

func TestBindingsFor_HierarchyErrorPropagates(t *testing.T) {
	base := baseBindings()
	hier := newFakeHierarchy()
	hier.err = errors.New("hierarchy store down")
	s, err := New(base, hier, roleMap())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.BindingsFor(context.Background(), bob, org1); err == nil {
		t.Fatal("want error when OrgHierarchy fails, got nil")
	}
}

func TestBindingsFor_BaseErrorPropagates(t *testing.T) {
	s, err := New(errBase{}, newFakeHierarchy(), roleMap())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.BindingsFor(context.Background(), bob, org1); err == nil {
		t.Fatal("want error when base BindingStore fails, got nil")
	}
}

// ---------------------------------------------------------------------
// BindingsForSubject — the reverse-query expand path, fuel for
// authz.Authorizer.ListResources (ADR-0001 §4b).
// ---------------------------------------------------------------------

func TestBindingsForSubject_TenantGroupAdminListsAllChildOrgs(t *testing.T) {
	s, _, _ := newTestStore(t)
	bs, err := s.BindingsForSubject(context.Background(), bob, "organization")
	if err != nil {
		t.Fatalf("BindingsForSubject: %v", err)
	}
	if len(bs) != 3 {
		t.Fatalf("got %d bindings, want 3 (org-1, org-2, org-3): %+v", len(bs), bs)
	}
	seen := map[string]bool{}
	for _, b := range bs {
		if b.Resource.Type != "organization" {
			t.Fatalf("unexpected resource type %q", b.Resource.Type)
		}
		if b.Role != "org_admin" {
			t.Fatalf("role = %q, want translated org_admin", b.Role)
		}
		seen[b.Resource.ID] = true
	}
	for _, id := range []string{"org-1", "org-2", "org-3"} {
		if !seen[id] {
			t.Fatalf("missing expanded binding for %s in %+v", id, bs)
		}
	}
}

func TestBindingsForSubject_DirectAndExpandedDeduped(t *testing.T) {
	// alice holds BOTH a direct org_admin binding on org1 AND (for this
	// test) a tenant-group binding whose expansion would also cover
	// org1 — the direct one must win without duplication.
	base := authz.NewMemStore(
		authz.Binding{Subject: alice, Resource: org1, Role: "org_admin"},
		authz.Binding{Subject: alice, Resource: tgAcme, Role: "tenant_group_admin"},
	)
	s, err := New(base, newFakeHierarchy(), roleMap())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	bs, err := s.BindingsForSubject(context.Background(), alice, "organization")
	if err != nil {
		t.Fatalf("BindingsForSubject: %v", err)
	}
	count := map[string]int{}
	for _, b := range bs {
		count[b.Resource.ID]++
	}
	for id, n := range count {
		if n != 1 {
			t.Fatalf("resource %s appeared %d times, want exactly 1 (deduped): %+v", id, n, bs)
		}
	}
	if len(bs) != 3 {
		t.Fatalf("got %d bindings, want 3 (org-1 direct + org-2/org-3 expanded): %+v", len(bs), bs)
	}
}

func TestBindingsForSubject_UnmappedRoleContributesNothing(t *testing.T) {
	s, _, _ := newTestStore(t)
	bs, err := s.BindingsForSubject(context.Background(), dave, "organization")
	if err != nil {
		t.Fatalf("BindingsForSubject: %v", err)
	}
	if len(bs) != 0 {
		t.Fatalf("got %+v, want empty — dave's unmapped tenant_group_viewer must not expand", bs)
	}
}

func TestBindingsForSubject_CrossTenantGroupLeak(t *testing.T) {
	// erin is admin of tg-other, which has its OWN child (org-4). This
	// is what makes the probe meaningful: with a childless tg-other the
	// assertion below would pass vacuously even if the store returned
	// the WRONG group's children. erin must see exactly org-4 and none
	// of tg-acme's org-1/2/3 (the leak that matters for §4b listings).
	s, _, _ := newTestStore(t)
	bs, err := s.BindingsForSubject(context.Background(), erin, "organization")
	if err != nil {
		t.Fatalf("BindingsForSubject: %v", err)
	}
	if len(bs) != 1 || bs[0].Resource != org4 {
		t.Fatalf("got %+v, want exactly erin's own org-4 binding", bs)
	}
	for _, b := range bs {
		if b.Resource != org4 {
			t.Fatalf("cross-tenant-group leak: erin (tg-other admin) got %+v on %s", b, b.Resource.ID)
		}
	}
}

func TestBindingsForSubject_NonOrganizationTypeIsPassthrough(t *testing.T) {
	s, _, _ := newTestStore(t)
	bs, err := s.BindingsForSubject(context.Background(), bob, "tenant_group")
	if err != nil {
		t.Fatalf("BindingsForSubject(tenant_group): %v", err)
	}
	// BindingsForSubject only returns CONCRETE resources (ID != "");
	// bob's own tenant_group binding IS concrete (tg-acme).
	if len(bs) != 1 || bs[0].Resource != tgAcme {
		t.Fatalf("got %+v, want exactly bob's own tg-acme binding, unexpanded", bs)
	}
}

// ---------------------------------------------------------------------
// BindingsOnResource — "who can act on this org", fuel for ListSubjects.
// ---------------------------------------------------------------------

func TestBindingsOnResource_IncludesExpandedTenantGroupAdmins(t *testing.T) {
	s, _, _ := newTestStore(t)
	bs, err := s.BindingsOnResource(context.Background(), org1)
	if err != nil {
		t.Fatalf("BindingsOnResource: %v", err)
	}
	subs := map[string]bool{}
	for _, b := range bs {
		if b.Resource != org1 {
			t.Fatalf("binding resource must be re-stamped to org1, got %+v", b.Resource)
		}
		subs[b.Subject.ID] = true
	}
	if !subs["alice"] {
		t.Fatalf("missing alice (direct org admin) in %+v", bs)
	}
	if !subs["bob"] {
		t.Fatalf("missing bob (expanded tenant-group admin) in %+v", bs)
	}
	if subs["dave"] {
		t.Fatal("dave (unmapped tenant_group_viewer) must not appear")
	}
	if subs["erin"] {
		t.Fatal("erin (different tenant-group) must not appear — cross-tenant-group leak")
	}
}

func TestBindingsOnResource_DirectAndExpandedDeduped(t *testing.T) {
	base := authz.NewMemStore(
		authz.Binding{Subject: bob, Resource: org1, Role: "org_admin"}, // direct, same role bob would get via expansion
		authz.Binding{Subject: bob, Resource: tgAcme, Role: "tenant_group_admin"},
	)
	s, err := New(base, newFakeHierarchy(), roleMap())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	bs, err := s.BindingsOnResource(context.Background(), org1)
	if err != nil {
		t.Fatalf("BindingsOnResource: %v", err)
	}
	count := 0
	for _, b := range bs {
		if b.Subject == bob {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("bob appeared %d times, want exactly 1 (deduped): %+v", count, bs)
	}
}

func TestBindingsOnResource_OrgWithNoParentOnlyDirect(t *testing.T) {
	s, _, _ := newTestStore(t)
	bs, err := s.BindingsOnResource(context.Background(), root)
	if err != nil {
		t.Fatalf("BindingsOnResource: %v", err)
	}
	if len(bs) != 0 {
		t.Fatalf("got %+v, want empty — org-root has no parent and no direct bindings", bs)
	}
}

// ---------------------------------------------------------------------
// errBase — fails every query, exercises error-means-deny plumbing
// through the wrapper (mirrors authz/rbac_test.go's own errStore).
// ---------------------------------------------------------------------

type errBase struct{}

func (errBase) BindingsFor(context.Context, authz.Subject, authz.Resource) ([]authz.Binding, error) {
	return nil, errors.New("base store down")
}
func (errBase) BindingsForSubject(context.Context, authz.Subject, string) ([]authz.Binding, error) {
	return nil, errors.New("base store down")
}
func (errBase) BindingsOnResource(context.Context, authz.Resource) ([]authz.Binding, error) {
	return nil, errors.New("base store down")
}

func TestBaseErrorsPropagateThroughAllMethods(t *testing.T) {
	s, err := New(errBase{}, newFakeHierarchy(), roleMap())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := s.BindingsFor(ctx, bob, org1); err == nil {
		t.Fatal("BindingsFor must propagate base store error")
	}
	if _, err := s.BindingsForSubject(ctx, bob, "organization"); err == nil {
		t.Fatal("BindingsForSubject must propagate base store error")
	}
	if _, err := s.BindingsOnResource(ctx, org1); err == nil {
		t.Fatal("BindingsOnResource must propagate base store error")
	}
}

// ---------------------------------------------------------------------
// End-to-end: wire into the REAL authz.RBAC engine, exactly as
// ADR-0001 §5 promises — zero changes to the engine or the espresso
// DecisionGate call-site. This is the proof that the RBAC engine never
// learns a hierarchy exists.
// ---------------------------------------------------------------------

func testHierarchyLadder() authz.Hierarchy {
	return authz.Hierarchy{
		"organization": {"org_admin"},
		"system":       {"platform_admin"},
	}
}

func testPolicy() authz.Policy {
	return authz.Policy{
		"org:manage": {
			{Type: "organization", Min: "org_admin"},
			{Type: "system", Min: "platform_admin"}, // platform bypass
		},
	}
}

func TestEndToEnd_RBACEngineNeverLearnsHierarchyExists(t *testing.T) {
	store, _, _ := newTestStore(t)
	engine, err := authz.NewRBAC(store, testHierarchyLadder(), testPolicy())
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}
	ctx := context.Background()

	cases := []struct {
		name string
		sub  authz.Subject
		res  authz.Resource
		want bool
	}{
		{"org admin direct on own org", alice, org1, true},
		{"org admin direct, wrong org", alice, org2, false},
		{"tenant-group admin reaches child org-1", bob, org1, true},
		{"tenant-group admin reaches child org-2", bob, org2, true},
		{"tenant-group admin reaches child org-3", bob, org3, true},
		{"tenant-group admin does NOT reach parentless org", bob, root, false},
		{"tenant-group admin does NOT reach another group's org", bob, org4, false},
		{"platform admin bypasses everything", carol, org1, true},
		{"platform admin bypasses everything, other org", carol, org3, true},
		{"unmapped tenant-group role denies", dave, org1, false},
		{"cross-tenant-group admin denied on unrelated org", erin, org1, false},
		{"cross-tenant-group admin denied on unrelated org 2", erin, org2, false},
		{"cross-tenant-group admin denied on unrelated org 3", erin, org3, false},
		{"cross-tenant-group admin reaches its OWN child org-4", erin, org4, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := engine.Check(ctx, tc.sub, "org:manage", tc.res)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if d.Allowed != tc.want {
				t.Fatalf("Allowed = %v, want %v (reason: %s)", d.Allowed, tc.want, d.Reason)
			}
		})
	}
}

func TestEndToEnd_ListResourcesViaExpandedBindingStore(t *testing.T) {
	store, _, _ := newTestStore(t)
	engine, err := authz.NewRBAC(store, testHierarchyLadder(), testPolicy())
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}
	ctx := context.Background()

	t.Run("tenant-group admin lists all child orgs, not unbounded", func(t *testing.T) {
		rs, unbounded, err := engine.ListResources(ctx, bob, "org:manage", "organization")
		if err != nil {
			t.Fatalf("ListResources: %v", err)
		}
		if unbounded {
			t.Fatal("bob has no global/system grant; must not be unbounded")
		}
		if len(rs) != 3 {
			t.Fatalf("got %v, want org-1/2/3", rs)
		}
	})

	t.Run("platform admin is unbounded — app must skip filtering entirely", func(t *testing.T) {
		_, unbounded, err := engine.ListResources(ctx, carol, "org:manage", "organization")
		if err != nil {
			t.Fatalf("ListResources: %v", err)
		}
		if !unbounded {
			t.Fatal("platform admin (system bypass) must report unbounded=true")
		}
	})

	t.Run("cross-tenant-group admin sees only its own org", func(t *testing.T) {
		rs, unbounded, err := engine.ListResources(ctx, erin, "org:manage", "organization")
		if err != nil {
			t.Fatalf("ListResources: %v", err)
		}
		if unbounded {
			t.Fatal("erin has no global/system grant; must not be unbounded")
		}
		if len(rs) != 1 || rs[0] != org4 {
			t.Fatalf("erin must see exactly org-4 and nothing from tg-acme: rs=%v unbounded=%v", rs, unbounded)
		}
	})
}

// ---------------------------------------------------------------------
// Dedup correctness: a subject holding a LOW-ranked DIRECT org role and
// a HIGHER-ranked role INHERITED from its tenant-group must keep both.
// Deduping on resource/subject alone (the old bug) kept the direct, lower
// one and dropped the inherited higher one, so ListResources/ListSubjects
// under-reported. See ADR-0001 §4a.
// ---------------------------------------------------------------------

// roleMapWithViewer adds a second, lower org role plus its tenant_group
// source so a rank distinction exists to be deduped away.
func roleMapWithViewer() RoleMap {
	return RoleMap{
		"tenant_group_admin":  "org_admin",
		"tenant_group_viewer": "org_viewer",
	}
}

// testHierarchyWithViewer is testHierarchyLadder plus the lower org_viewer
// rung, so rank filtering actually discriminates.
func testHierarchyWithViewer() authz.Hierarchy {
	return authz.Hierarchy{
		"organization": {"org_viewer", "org_admin"},
		"system":       {"platform_admin"},
	}
}

// testPolicyWithViewer requires org_admin for the managed action — a role
// only the inherited binding can supply in these fixtures.
func testPolicyWithViewer() authz.Policy {
	return authz.Policy{
		"org:manage": {{Type: "organization", Min: "org_admin"}},
	}
}

func TestBindingsForSubject_KeepsHigherInheritedRoleAlongsideLowerDirect(t *testing.T) {
	base := authz.NewMemStore(
		authz.Binding{Subject: alice, Resource: org1, Role: "org_viewer"}, // direct, LOW
		authz.Binding{Subject: alice, Resource: tgAcme, Role: "tenant_group_admin"},
	)
	s, err := New(base, newFakeHierarchy(), roleMapWithViewer())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	bs, err := s.BindingsForSubject(context.Background(), alice, "organization")
	if err != nil {
		t.Fatalf("BindingsForSubject: %v", err)
	}
	var org1Roles []authz.Role
	for _, b := range bs {
		if b.Resource == org1 {
			org1Roles = append(org1Roles, b.Role)
		}
	}
	if len(org1Roles) != 2 {
		t.Fatalf("org-1 roles = %v, want BOTH org_viewer (direct) and org_admin (inherited)", org1Roles)
	}
}

func TestBindingsOnResource_KeepsHigherInheritedRoleAlongsideLowerDirect(t *testing.T) {
	base := authz.NewMemStore(
		authz.Binding{Subject: bob, Resource: org1, Role: "org_viewer"}, // direct, LOW
		authz.Binding{Subject: bob, Resource: tgAcme, Role: "tenant_group_admin"},
	)
	s, err := New(base, newFakeHierarchy(), roleMapWithViewer())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	bs, err := s.BindingsOnResource(context.Background(), org1)
	if err != nil {
		t.Fatalf("BindingsOnResource: %v", err)
	}
	var bobRoles []authz.Role
	for _, b := range bs {
		if b.Subject == bob {
			bobRoles = append(bobRoles, b.Role)
		}
	}
	if len(bobRoles) != 2 {
		t.Fatalf("bob roles on org-1 = %v, want BOTH org_viewer (direct) and org_admin (inherited)", bobRoles)
	}
}

func TestEndToEnd_ReverseQueriesKeepHigherInheritedRole(t *testing.T) {
	// Engine-level proof that the store-level dedup fix matters: the
	// higher inherited role is what satisfies "org:manage".
	base := authz.NewMemStore(
		authz.Binding{Subject: bob, Resource: org1, Role: "org_viewer"}, // direct, LOW
		authz.Binding{Subject: bob, Resource: tgAcme, Role: "tenant_group_admin"},
	)
	s, err := New(base, newFakeHierarchy(), roleMapWithViewer())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	engine, err := authz.NewRBAC(s, testHierarchyWithViewer(), testPolicyWithViewer())
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}
	ctx := context.Background()

	t.Run("ListResources includes org-1 via the inherited org_admin", func(t *testing.T) {
		rs, _, err := engine.ListResources(ctx, bob, "org:manage", "organization")
		if err != nil {
			t.Fatalf("ListResources: %v", err)
		}
		found := false
		for _, r := range rs {
			if r == org1 {
				found = true
			}
		}
		if !found {
			t.Fatalf("org-1 missing from %v — the inherited org_admin was deduped away", rs)
		}
	})

	t.Run("ListSubjects includes bob via the inherited org_admin", func(t *testing.T) {
		subs, _, err := engine.ListSubjects(ctx, "org:manage", org1)
		if err != nil {
			t.Fatalf("ListSubjects: %v", err)
		}
		for _, sub := range subs {
			if sub == bob {
				return
			}
		}
		t.Fatalf("bob missing from %v — the inherited org_admin was deduped away", subs)
	})
}

// ---------------------------------------------------------------------
// Concurrency — Store must be safe for concurrent use whenever base and
// hier are, same posture as authz.RBAC itself (rbac_test.go's own
// TestConcurrentUse).
// ---------------------------------------------------------------------

func TestConcurrentUse(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if _, err := s.BindingsFor(ctx, bob, org1); err != nil {
					t.Errorf("goroutine %d: BindingsFor: %v", g, err)
					return
				}
				if _, err := s.BindingsForSubject(ctx, bob, "organization"); err != nil {
					t.Errorf("goroutine %d: BindingsForSubject: %v", g, err)
					return
				}
				if _, err := s.BindingsOnResource(ctx, org1); err != nil {
					t.Errorf("goroutine %d: BindingsOnResource: %v", g, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------
// RoleMap unit coverage — isolated from the Store, since translate is
// where "fail closed on unmapped role" actually lives.
// ---------------------------------------------------------------------

func TestRoleMapTranslate(t *testing.T) {
	rm := roleMap()
	if got, ok := rm.translate("tenant_group_admin"); !ok || got != "org_admin" {
		t.Fatalf("translate(tenant_group_admin) = (%q, %v), want (org_admin, true)", got, ok)
	}
	if _, ok := rm.translate("tenant_group_viewer"); ok {
		t.Fatal("translate(tenant_group_viewer) must report ok=false — unmapped")
	}
	if _, ok := rm.translate(""); ok {
		t.Fatal("translate(\"\") must report ok=false")
	}
}
