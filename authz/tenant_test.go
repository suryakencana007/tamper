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
	ok(t, ps.Grant(tAcme, acmeU1, c1, "cluster.view", "cluster.deploy", "cluster.acl.grant"))
	ok(t, ps.GrantSuperuser(tPlatform, guest))
	pset, err := NewPermissionSet(ps)
	if err != nil {
		t.Fatalf("NewPermissionSet: %v", err)
	}
	// The third engine: PermissionSet over the RBAC-backed store. That
	// store cannot be run through authz/tenanttest (a role ladder cannot
	// grant the suite's two independent keys), so its isolation is
	// proved here, by every case in this file.
	rps, err := NewRBACPermissionStore(bs, testHierarchy(), testPolicy())
	if err != nil {
		t.Fatalf("NewRBACPermissionStore: %v", err)
	}
	overRBAC, err := NewPermissionSet(rps)
	if err != nil {
		t.Fatalf("NewPermissionSet: %v", err)
	}
	return map[string]Authorizer{"RBAC": rbac, "PermissionSet": pset, "PermissionSet over RBAC": overRBAC}, bs, ps
}

// ok fails the test when a seed write is refused.
func ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
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
	ok(t, bs.Grant(Binding{Tenant: tAcme, Subject: guest, Resource: c1, Role: "cluster-viewer"}))
	ok(t, ps.Grant(tAcme, guest, c1, "cluster.view"))
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
	ok(t, bs.Grant(Binding{Tenant: tAcme, Subject: guest, Resource: c1, Role: "cluster-viewer"}))
	ok(t, ps.Grant(tAcme, guest, c1, "cluster.view"))
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
	ok(t, ps.GrantSuperuser(tAcme, acmeU1))

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

// orphanSubjects is a PermissionStore that lists a subject with no home
// tenant beside a real one.
type orphanSubjects struct{ PermissionStore }

func (orphanSubjects) SubjectsWithPermission(context.Context, tenant.ID, string, Resource) ([]Subject, error) {
	return []Subject{{Type: "user", ID: "orphan"}, acmeU1}, nil
}

// An access review does not list a subject that Check would refuse,
// and it does not hide the problem either: a store that returns a
// subject with no home tenant gets the error Check gives. An empty list
// would read as "nobody has access". The reference stores cannot hold
// such a subject, so the stores here are ones that hand it over anyway.
func TestTenant_ListSubjectsRefusesASubjectWithNoHomeTenant(t *testing.T) {
	noHome := Subject{Type: "user", ID: "orphan"}
	rbac, err := NewRBAC(leakyBindings{all: []Binding{
		{Tenant: tAcme, Subject: noHome, Resource: c1, Role: "cluster-admin"},
		{Tenant: tAcme, Subject: acmeU1, Resource: c1, Role: "cluster-admin"},
		// Another scope's broken row is not this scope's problem.
		{Tenant: tGlobex, Subject: noHome, Resource: c2, Role: "cluster-admin"},
	}}, testHierarchy(), testPolicy())
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}
	pset, err := NewPermissionSet(orphanSubjects{})
	if err != nil {
		t.Fatalf("NewPermissionSet: %v", err)
	}
	for name, a := range map[string]Authorizer{"RBAC": rbac, "PermissionSet": pset} {
		subs, _, err := a.ListSubjects(context.Background(), tAcme, "cluster.view", c1)
		if !errors.Is(err, ErrTenantRequired) {
			t.Errorf("%s: ListSubjects err = %v, want ErrTenantRequired", name, err)
		}
		if len(subs) != 0 {
			t.Errorf("%s: ListSubjects returned %v beside its error", name, subs)
		}
	}
	// The broken row is on c1 in acme. A review of c2 in acme is clean.
	if subs, _, err := rbac.ListSubjects(context.Background(), tAcme, "cluster.view", c2); err != nil || len(subs) != 0 {
		t.Errorf("RBAC: ListSubjects(acme, c2) = %v, %v; want nobody and no error", subs, err)
	}

	// A broken row that would NOT be listed does not fail the review:
	// a viewer with no home tenant is not an answer to "who may grant".
	viewerOnly, err := NewRBAC(leakyBindings{all: []Binding{
		{Tenant: tAcme, Subject: noHome, Resource: c1, Role: "cluster-viewer"},
		{Tenant: tAcme, Subject: acmeU1, Resource: c1, Role: "cluster-admin"},
	}}, testHierarchy(), testPolicy())
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}
	subs, _, err := viewerOnly.ListSubjects(context.Background(), tAcme, "cluster.acl.grant", c1)
	if err != nil || len(subs) != 1 || subs[0] != acmeU1 {
		t.Errorf("ListSubjects(cluster.acl.grant) = %v, %v; want acme's u-1 and no error", subs, err)
	}
}

// The reference stores say ErrTenantRequired for the unset scope. A
// quiet empty answer would read as "nobody has access".
func TestMemStores_RefuseTheUnsetScope(t *testing.T) {
	ctx := context.Background()
	var unset tenant.ID
	bs := NewMemStore(Binding{Tenant: tAcme, Subject: acmeU1, Resource: c1, Role: "cluster-admin"})
	ps := NewMemPermissionStore()
	ok(t, ps.Grant(tAcme, acmeU1, c1, "cluster.view"))
	rps, err := NewRBACPermissionStore(bs, testHierarchy(), testPolicy())
	if err != nil {
		t.Fatalf("NewRBACPermissionStore: %v", err)
	}
	noHome := Subject{Type: "user", ID: "u-1"}

	for what, call := range map[string]func() error{
		"MemStore.BindingsFor":              func() error { _, err := bs.BindingsFor(ctx, unset, acmeU1, c1); return err },
		"MemStore.BindingsForSubject":       func() error { _, err := bs.BindingsForSubject(ctx, unset, acmeU1, "cluster"); return err },
		"MemStore.BindingsOnResource":       func() error { _, err := bs.BindingsOnResource(ctx, unset, c1); return err },
		"MemPermissionStore.PermissionsFor": func() error { _, err := ps.PermissionsFor(ctx, unset, acmeU1, c1); return err },
		"MemPermissionStore.ResourcesWithPermission": func() error {
			_, _, err := ps.ResourcesWithPermission(ctx, unset, acmeU1, "cluster.view", "cluster")
			return err
		},
		"MemPermissionStore.SubjectsWithPermission": func() error { _, err := ps.SubjectsWithPermission(ctx, unset, "cluster.view", c1); return err },
		// The RBAC-backed store, called without the engine in front.
		"rbacPermissionStore.PermissionsFor, unset scope":        func() error { _, err := rps.PermissionsFor(ctx, unset, acmeU1, c1); return err },
		"rbacPermissionStore.PermissionsFor, subject, no tenant": func() error { _, err := rps.PermissionsFor(ctx, tAcme, noHome, c1); return err },
		"rbacPermissionStore.PermissionsFor, neither":            func() error { _, err := rps.PermissionsFor(ctx, unset, noHome, c1); return err },
	} {
		if err := call(); !errors.Is(err, ErrTenantRequired) {
			t.Errorf("%s: err = %v, want ErrTenantRequired", what, err)
		}
	}
}

// A grant or a revoke that names no scope, or a subject with no home
// tenant, is refused with ErrTenantRequired and changes nothing. It
// could never be read back, and a literal written before these fields
// existed still compiles. It is an error and not a panic: the binding
// may come from a request.
func TestMemStores_WritesRefuseMissingTenants(t *testing.T) {
	ctx := context.Background()
	noHome := Subject{Type: "user", ID: "u-1"}
	good := Binding{Tenant: tAcme, Subject: acmeU1, Resource: c1, Role: "cluster-admin"}

	bs := NewMemStore(good)
	ps := NewMemPermissionStore()
	for what, err := range map[string]error{
		"MemStore.Grant, no scope":                     bs.Grant(Binding{Subject: acmeU1, Resource: c1, Role: "cluster-admin"}),
		"MemStore.Grant, subject without tenant":       bs.Grant(Binding{Tenant: tAcme, Subject: noHome, Resource: c1, Role: "cluster-admin"}),
		"MemStore.Revoke, no scope":                    bs.Revoke(Binding{Subject: acmeU1, Resource: c1, Role: "cluster-admin"}),
		"MemStore.Revoke, subject without tenant":      bs.Revoke(Binding{Tenant: tAcme, Subject: noHome, Resource: c1, Role: "cluster-admin"}),
		"MemPermissionStore.Grant, no scope":           ps.Grant(tenant.ID{}, acmeU1, c1, "cluster.view"),
		"MemPermissionStore.Grant, subject, no tenant": ps.Grant(tAcme, noHome, c1, "cluster.view"),
		"MemPermissionStore.GrantSuperuser, no scope":  ps.GrantSuperuser(tenant.ID{}, acmeU1),
		"MemPermissionStore.GrantSuperuser, no tenant": ps.GrantSuperuser(tAcme, noHome),
	} {
		if !errors.Is(err, ErrTenantRequired) {
			t.Errorf("%s: err = %v, want ErrTenantRequired", what, err)
		}
	}
	// The refused revokes removed nothing.
	if got, err := bs.BindingsOnResource(ctx, tAcme, c1); err != nil || len(got) != 1 || got[0] != good {
		t.Errorf("bindings after refused writes = %v, %v; want only the one seeded", got, err)
	}

	// A seed literal is a construction error.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("NewMemStore accepted a seed binding with no scope")
			}
		}()
		NewMemStore(Binding{Subject: acmeU1, Resource: c1, Role: "cluster-admin"})
	}()
}

// The reference stores refuse a subject with no home tenant on reads
// too, not only an unset scope: called without an engine in front, a
// forgotten Tenant must not come back as a quiet empty answer.
func TestMemStores_ReadsRefuseASubjectWithNoHomeTenant(t *testing.T) {
	ctx := context.Background()
	noHome := Subject{Type: "user", ID: "u-1"}
	bs, ps := NewMemStore(), NewMemPermissionStore()
	for what, call := range map[string]func() error{
		"MemStore.BindingsFor":              func() error { _, err := bs.BindingsFor(ctx, tAcme, noHome, c1); return err },
		"MemStore.BindingsForSubject":       func() error { _, err := bs.BindingsForSubject(ctx, tAcme, noHome, "cluster"); return err },
		"MemPermissionStore.PermissionsFor": func() error { _, err := ps.PermissionsFor(ctx, tAcme, noHome, c1); return err },
		"MemPermissionStore.ResourcesWithPermission": func() error {
			_, _, err := ps.ResourcesWithPermission(ctx, tAcme, noHome, "cluster.view", "cluster")
			return err
		},
	} {
		if err := call(); !errors.Is(err, ErrTenantRequired) {
			t.Errorf("%s: err = %v, want ErrTenantRequired", what, err)
		}
	}
}
