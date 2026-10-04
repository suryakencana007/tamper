package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/suryakencana007/tamper/tenant"
)

// Phase 8b: the tenant contract. Every question has a scope (whose
// resources) and every subject has a home tenant (where it is stored).

var (
	tAcme     = tenant.New("acme")
	tGlobex   = tenant.New("globex")
	tPlatform = tenant.New("platform")

	// The same {Type, ID} in two tenants: two different people.
	acmeU1   = Subject{Tenant: tAcme, Type: "user", ID: "u-1"}
	globexU1 = Subject{Tenant: tGlobex, Type: "user", ID: "u-1"}
	// A platform admin: stored in platform, may be a guest elsewhere.
	guest = Subject{Tenant: tPlatform, Type: "user", ID: "a-9"}
)

// tenantEngines builds both engines over the same grants, so every case
// below runs against RBAC and against PermissionSet.
//
//   - acme's u-1 is cluster-admin on c1 in acme.
//   - the guest is system cluster-admin (global) AT HOME, in platform.
func tenantEngines(t *testing.T) (map[string]Authorizer, *MemStore, *MemPermissionStore) {
	t.Helper()
	bs := NewMemStore(
		Binding{Tenant: tAcme, Subject: acmeU1, Resource: c1, Role: "cluster-admin"},
		Binding{Tenant: tPlatform, Subject: guest, Resource: system, Role: "cluster-admin"},
	)
	rbac, err := NewRBAC(bs, testHierarchy(), testPolicy())
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}
	ps := NewMemPermissionStore()
	ps.Grant(tAcme, acmeU1, c1, "cluster.view", "cluster.deploy", "cluster.acl.grant")
	ps.GrantSuperuser(tPlatform, guest)
	pset, err := NewPermissionSet(ps)
	if err != nil {
		t.Fatalf("NewPermissionSet: %v", err)
	}
	return map[string]Authorizer{"RBAC": rbac, "PermissionSet": pset}, bs, ps
}

func allowed(t *testing.T, a Authorizer, scope tenant.ID, sub Subject, act Action, res Resource) bool {
	t.Helper()
	d, err := a.Check(context.Background(), scope, sub, act, res)
	if err != nil {
		t.Fatalf("Check(%s, %v, %s): %v", scope, sub, act, err)
	}
	return d.Allowed
}

// A binding answers in its own scope, for its own subject, and for
// nothing else.
func TestTenant_BindingStaysInItsScopeAndWithItsSubject(t *testing.T) {
	engines, _, _ := tenantEngines(t)
	for name, a := range engines {
		t.Run(name, func(t *testing.T) {
			if !allowed(t, a, tAcme, acmeU1, "cluster.deploy", c1) {
				t.Fatal("fixture: acme's u-1 cannot deploy to c1 in acme")
			}
			for what, q := range map[string]struct {
				scope tenant.ID
				sub   Subject
			}{
				"the same subject asked in another scope":          {tGlobex, acmeU1},
				"another tenant's user with the same id":           {tAcme, globexU1},
				"that user in their own scope":                     {tGlobex, globexU1},
				"the same subject asked in the single scope":       {tenant.Single, acmeU1},
				"a single-tenant subject with the same id in acme": {tAcme, Subject{Tenant: tenant.Single, Type: "user", ID: "u-1"}},
			} {
				if allowed(t, a, q.scope, q.sub, "cluster.deploy", c1) {
					t.Errorf("%s was allowed by a binding granted to %v in %s", what, acmeU1, tAcme)
				}
			}
		})
	}
}

// A guest gets what was granted to them in the tenant they entered, and
// nothing from home — not even a global role or a superuser flag.
func TestTenant_GuestNeedsABindingInTheScope(t *testing.T) {
	engines, bs, ps := tenantEngines(t)
	for name, a := range engines {
		t.Run(name, func(t *testing.T) {
			// At home the guest can do everything.
			if !allowed(t, a, tPlatform, guest, "cluster.acl.grant", c1) {
				t.Fatal("fixture: the platform admin is not an admin at home")
			}
			// In acme, nothing.
			for _, act := range []Action{"cluster.view", "cluster.deploy", "cluster.acl.grant", "cluster.create"} {
				if allowed(t, a, tAcme, guest, act, c1) {
					t.Errorf("the guest's HOME role allowed %q in acme", act)
				}
			}
		})
	}

	// Grant the guest view, and only view, inside acme.
	bs.Grant(Binding{Tenant: tAcme, Subject: guest, Resource: c1, Role: "cluster-viewer"})
	ps.Grant(tAcme, guest, c1, "cluster.view")
	for name, a := range engines {
		t.Run(name+" after a grant in acme", func(t *testing.T) {
			if !allowed(t, a, tAcme, guest, "cluster.view", c1) {
				t.Error("the guest cannot view c1 in acme although it was granted there")
			}
			if allowed(t, a, tAcme, guest, "cluster.deploy", c1) {
				t.Error("a view grant in acme let the guest deploy")
			}
			// The grant is acme's. It does not follow the guest to globex.
			if allowed(t, a, tGlobex, guest, "cluster.view", c1) {
				t.Error("a grant in acme allowed the guest in globex")
			}
		})
	}
}

// The reverse queries are scoped too, and a guest is listed with the
// tenant they are from.
func TestTenant_ListsAreScoped(t *testing.T) {
	engines, bs, ps := tenantEngines(t)
	bs.Grant(Binding{Tenant: tAcme, Subject: guest, Resource: c1, Role: "cluster-viewer"})
	ps.Grant(tAcme, guest, c1, "cluster.view")
	ctx := context.Background()

	for name, a := range engines {
		t.Run(name, func(t *testing.T) {
			subs, _, err := a.ListSubjects(ctx, tAcme, "cluster.view", c1)
			if err != nil {
				t.Fatalf("ListSubjects(acme): %v", err)
			}
			if len(subs) != 2 || subs[0] != guest || subs[1] != acmeU1 {
				t.Errorf("ListSubjects(acme) = %v, want the guest (from platform) and acme's u-1", subs)
			}
			other, _, err := a.ListSubjects(ctx, tGlobex, "cluster.view", c1)
			if err != nil {
				t.Fatalf("ListSubjects(globex): %v", err)
			}
			if len(other) != 0 {
				t.Errorf("ListSubjects(globex) = %v, want nobody: every grant is in another scope", other)
			}

			res, unbounded, err := a.ListResources(ctx, tAcme, acmeU1, "cluster.view", "cluster")
			if err != nil {
				t.Fatalf("ListResources(acme): %v", err)
			}
			if unbounded || len(res) != 1 || res[0] != c1 {
				t.Errorf("ListResources(acme, u-1) = %v unbounded=%v, want [c1]", res, unbounded)
			}
			for what, q := range map[string]struct {
				scope tenant.ID
				sub   Subject
			}{
				"acme's u-1 asked in globex":          {tGlobex, acmeU1},
				"globex's u-1 asked in acme":          {tAcme, globexU1},
				"the guest, admin at home, in globex": {tGlobex, guest},
			} {
				res, unbounded, err := a.ListResources(ctx, q.scope, q.sub, "cluster.view", "cluster")
				if err != nil {
					t.Fatalf("ListResources: %v", err)
				}
				if unbounded || len(res) != 0 {
					t.Errorf("%s: resources=%v unbounded=%v, want none", what, res, unbounded)
				}
			}
		})
	}
}

// A question that names no tenant is an error, never a decision.
func TestTenant_UnsetTenantIsRefused(t *testing.T) {
	engines, _, _ := tenantEngines(t)
	ctx := context.Background()
	var unset tenant.ID
	noHome := Subject{Type: "user", ID: "u-1"}

	for name, a := range engines {
		t.Run(name, func(t *testing.T) {
			check := func(what string, err error) {
				t.Helper()
				if !errors.Is(err, ErrTenantRequired) {
					t.Errorf("%s: err = %v, want ErrTenantRequired", what, err)
				}
			}
			d, err := a.Check(ctx, unset, acmeU1, "cluster.view", c1)
			check("Check, unset scope", err)
			if d.Allowed {
				t.Error("Check with an unset scope allowed")
			}
			d, err = a.Check(ctx, tAcme, noHome, "cluster.view", c1)
			check("Check, subject without a home tenant", err)
			if d.Allowed {
				t.Error("Check with a subject that has no home tenant allowed")
			}
			// Before the action is looked at: an unknown action is a
			// quiet deny, and must not hide the wiring bug.
			_, err = a.Check(ctx, unset, acmeU1, "no.such.action", c1)
			check("Check, unset scope and unknown action", err)

			_, err = a.CheckBulk(ctx, unset, []CheckRequest{{acmeU1, "cluster.view", c1}})
			check("CheckBulk, unset scope", err)
			_, err = a.CheckBulk(ctx, tAcme, []CheckRequest{{acmeU1, "cluster.view", c1}, {noHome, "cluster.view", c1}})
			check("CheckBulk, one subject without a home tenant", err)

			_, _, err = a.ListResources(ctx, unset, acmeU1, "cluster.view", "cluster")
			check("ListResources, unset scope", err)
			_, _, err = a.ListResources(ctx, tAcme, noHome, "cluster.view", "cluster")
			check("ListResources, subject without a home tenant", err)
			_, _, err = a.ListSubjects(ctx, unset, "cluster.view", c1)
			check("ListSubjects, unset scope", err)
		})
	}
}

// leakyBindings is a BindingStore that forgot the tenant: it answers
// every question from every scope. Its bindings are stamped truthfully,
// which is what a real store reading a tenant column would return.
type leakyBindings struct{ all []Binding }

func (l leakyBindings) BindingsFor(_ context.Context, _ tenant.ID, sub Subject, res Resource) ([]Binding, error) {
	var out []Binding
	for _, b := range l.all {
		// Matches on the bare id too: the other half of the same bug.
		if b.Subject.Type == sub.Type && b.Subject.ID == sub.ID && b.Resource == res {
			out = append(out, b)
		}
	}
	return out, nil
}

func (l leakyBindings) BindingsForSubject(_ context.Context, _ tenant.ID, sub Subject, resourceType string) ([]Binding, error) {
	var out []Binding
	for _, b := range l.all {
		if b.Subject.Type == sub.Type && b.Subject.ID == sub.ID && b.Resource.Type == resourceType && b.Resource.ID != "" {
			out = append(out, b)
		}
	}
	return out, nil
}

func (l leakyBindings) BindingsOnResource(_ context.Context, _ tenant.ID, res Resource) ([]Binding, error) {
	var out []Binding
	for _, b := range l.all {
		if b.Resource == res {
			out = append(out, b)
		}
	}
	return out, nil
}

// The RBAC engine does not trust the store. Bindings of another scope,
// and bindings of another tenant's subject, are dropped even when the
// store hands them over.
func TestRBAC_DropsWhatALeakyStoreReturns(t *testing.T) {
	ctx := context.Background()
	store := leakyBindings{all: []Binding{
		{Tenant: tAcme, Subject: acmeU1, Resource: c1, Role: "cluster-admin"},
		{Tenant: tAcme, Subject: acmeU1, Resource: system, Role: "cluster-admin"},
	}}
	e, err := NewRBAC(store, testHierarchy(), testPolicy())
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}
	if !allowed(t, e, tAcme, acmeU1, "cluster.deploy", c1) {
		t.Fatal("fixture: the rightful subject is denied in the rightful scope")
	}

	for what, q := range map[string]struct {
		scope tenant.ID
		sub   Subject
	}{
		"another scope":                        {tGlobex, acmeU1},
		"another tenant's user, same bare id":  {tAcme, globexU1},
		"another tenant's user in their scope": {tGlobex, globexU1},
	} {
		for _, act := range []Action{"cluster.deploy", "cluster.create"} {
			if allowed(t, e, q.scope, q.sub, act, c1) {
				t.Errorf("%s: %q allowed from a binding the store should not have returned", what, act)
			}
		}
		res, unbounded, err := e.ListResources(ctx, q.scope, q.sub, "cluster.view", "cluster")
		if err != nil {
			t.Fatalf("ListResources: %v", err)
		}
		if unbounded || len(res) != 0 {
			t.Errorf("%s: ListResources = %v unbounded=%v, want none", what, res, unbounded)
		}
	}
	subs, _, err := e.ListSubjects(ctx, tGlobex, "cluster.view", c1)
	if err != nil {
		t.Fatalf("ListSubjects: %v", err)
	}
	if len(subs) != 0 {
		t.Errorf("ListSubjects(globex) = %v, want nobody: the bindings are acme's", subs)
	}
}

// A superuser is a superuser of one scope.
func TestMemPermissionStore_SuperuserIsPerScope(t *testing.T) {
	ctx := context.Background()
	ps := NewMemPermissionStore()
	ps.GrantSuperuser(tAcme, acmeU1)

	for what, q := range map[string]struct {
		scope tenant.ID
		sub   Subject
		want  bool
	}{
		"in its own scope":               {tAcme, acmeU1, true},
		"in another scope":               {tGlobex, acmeU1, false},
		"another tenant's user, same id": {tAcme, globexU1, false},
	} {
		got, err := ps.PermissionsFor(ctx, q.scope, q.sub, c1)
		if err != nil {
			t.Fatalf("PermissionsFor: %v", err)
		}
		if got.Superuser != q.want {
			t.Errorf("%s: Superuser = %v, want %v", what, got.Superuser, q.want)
		}
		_, unbounded, err := ps.ResourcesWithPermission(ctx, q.scope, q.sub, "cluster.view", "cluster")
		if err != nil {
			t.Fatalf("ResourcesWithPermission: %v", err)
		}
		if unbounded != q.want {
			t.Errorf("%s: unbounded = %v, want %v", what, unbounded, q.want)
		}
	}
	subs, err := ps.SubjectsWithPermission(ctx, tGlobex, "cluster.view", c1)
	if err != nil {
		t.Fatalf("SubjectsWithPermission: %v", err)
	}
	if len(subs) != 0 {
		t.Errorf("acme's superuser is listed in globex: %v", subs)
	}
}

// An empty batch does not hide an unset scope.
func TestTenant_CheckBulkRefusesAnUnsetScopeEvenWhenEmpty(t *testing.T) {
	engines, _, _ := tenantEngines(t)
	for name, a := range engines {
		out, err := a.CheckBulk(context.Background(), tenant.ID{}, nil)
		if !errors.Is(err, ErrTenantRequired) || out != nil {
			t.Errorf("%s: CheckBulk(unset, nil) = %v, %v; want nil and ErrTenantRequired", name, out, err)
		}
	}
}

// An access review does not list a subject that Check would refuse.
func TestTenant_ListSubjectsSkipsASubjectWithNoHomeTenant(t *testing.T) {
	engines, bs, ps := tenantEngines(t)
	noHome := Subject{Type: "user", ID: "orphan"}
	bs.Grant(Binding{Tenant: tAcme, Subject: noHome, Resource: c1, Role: "cluster-admin"})
	ps.Grant(tAcme, noHome, c1, "cluster.view")

	for name, a := range engines {
		subs, _, err := a.ListSubjects(context.Background(), tAcme, "cluster.view", c1)
		if err != nil {
			t.Fatalf("%s: ListSubjects: %v", name, err)
		}
		for _, s := range subs {
			if s == noHome {
				t.Errorf("%s: ListSubjects lists %+v, which Check refuses with ErrTenantRequired", name, s)
			}
		}
		if len(subs) != 1 || subs[0] != acmeU1 {
			t.Errorf("%s: ListSubjects = %v, want only acme's u-1", name, subs)
		}
	}
}

// The reference stores return nothing for the unset scope, even when a
// row was stored with one.
func TestMemStores_ReturnNothingForTheUnsetScope(t *testing.T) {
	ctx := context.Background()
	var unset tenant.ID

	bs := NewMemStore(Binding{Subject: acmeU1, Resource: c1, Role: "cluster-admin"}) // Tenant unset
	if got, _ := bs.BindingsFor(ctx, unset, acmeU1, c1); len(got) != 0 {
		t.Errorf("MemStore.BindingsFor(unset) = %v", got)
	}
	if got, _ := bs.BindingsForSubject(ctx, unset, acmeU1, "cluster"); len(got) != 0 {
		t.Errorf("MemStore.BindingsForSubject(unset) = %v", got)
	}
	if got, _ := bs.BindingsOnResource(ctx, unset, c1); len(got) != 0 {
		t.Errorf("MemStore.BindingsOnResource(unset) = %v", got)
	}

	ps := NewMemPermissionStore()
	ps.Grant(unset, acmeU1, c1, "cluster.view")
	ps.GrantSuperuser(unset, acmeU1)
	if got, _ := ps.PermissionsFor(ctx, unset, acmeU1, c1); got.Superuser || len(got.Keys) != 0 {
		t.Errorf("MemPermissionStore.PermissionsFor(unset) = %+v", got)
	}
	if got, unbounded, _ := ps.ResourcesWithPermission(ctx, unset, acmeU1, "cluster.view", "cluster"); unbounded || len(got) != 0 {
		t.Errorf("MemPermissionStore.ResourcesWithPermission(unset) = %v unbounded=%v", got, unbounded)
	}
	if got, _ := ps.SubjectsWithPermission(ctx, unset, "cluster.view", c1); len(got) != 0 {
		t.Errorf("MemPermissionStore.SubjectsWithPermission(unset) = %v", got)
	}
}
