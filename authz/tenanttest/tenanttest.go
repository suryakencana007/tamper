// Package tenanttest is the cross-tenant leak conformance harness for
// the authz stores: authz.BindingStore and authz.PermissionStore.
//
// tamper cannot enforce tenant isolation in a store: the query lives in
// the application's adapter. What it can do is state the obligation on
// the port (the isolation contract on each interface) and ship the
// instrument that checks it. This package is that instrument. It is the
// authz sibling of identity/tenanttest.
//
// Adapter authors run it against their own store:
//
//	func TestMyBindingStoreIsolation(t *testing.T) {
//	    tenanttest.RunBindingStoreLeakSuite(t, func() tenanttest.BindingHarness {
//	        s := newMyStore(t) // fresh and EMPTY on every call
//	        return tenanttest.BindingHarness{Store: s, Grant: s.insertBinding}
//	    })
//	}
//
// The ports are read-only — how a binding is created is outside the
// policy decision point — so the suite cannot seed through them. The
// harness carries the store and the function that writes to it.
//
// For the PermissionStore the suite is the ONLY guard. The RBAC engine
// drops a binding of the wrong tenant when a store returns one; the
// PermissionSet engine cannot, because a PermissionSetResult carries no
// tenant.
//
// It never skips, and there is no single-tenant opt-out, for the reason
// identity/tenanttest gives: nothing the suite can observe tells a
// single-tenant store from a pooled one that leaks.
package tenanttest

import (
	"context"
	"testing"

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/tenant"
)

// The tenants every case is built from. Opaque values, as tamper
// requires of any tenant id.
var (
	tenantA = tenant.New("tenanttest-a")
	tenantB = tenant.New("tenanttest-b")
	// tenantP is where the guest is stored: a subject of one tenant
	// holding grants inside another.
	tenantP = tenant.New("tenanttest-p")
)

// The subjects. userA and userB share a Type and an ID on purpose: an
// id is unique inside one tenant only, and a store that matches on the
// bare id confuses them.
var (
	userA = authz.Subject{Tenant: tenantA, Type: "user", ID: "same-id"}
	userB = authz.Subject{Tenant: tenantB, Type: "user", ID: "same-id"}
	guest = authz.Subject{Tenant: tenantP, Type: "user", ID: "guest-id"}

	// The same resource id exists in both tenants, as ids chosen by
	// customers do.
	res    = authz.Resource{Type: "thing", ID: "t-1"}
	global = authz.Resource{Type: "thing"}
	// resHome exists only where the guest is stored. A Resource carries
	// no tenant, so a different id is the only way to see that a store
	// answered from the wrong scope.
	resHome = authz.Resource{Type: "thing", ID: "t-home"}
)

const (
	roleA = authz.Role("role-of-a")
	roleB = authz.Role("role-of-b")
	keyA  = "thing.a"
	keyB  = "thing.b"
)

// harnessT is the slice of *testing.T the suites use. It exists so this
// package's own tests can drive a suite with a recorder and assert that
// a deliberately leaky store FAILS it.
type harnessT interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Run(name string, f func(harnessT)) bool
}

type realT struct{ *testing.T }

func (r realT) Run(name string, f func(harnessT)) bool {
	return r.T.Run(name, func(sub *testing.T) { f(realT{sub}) })
}

// --- BindingStore --------------------------------------------------------

// BindingHarness is a BindingStore and the way to put a binding in it.
type BindingHarness struct {
	Store authz.BindingStore
	// Grant stores b. b.Tenant is the scope the binding lives in.
	Grant func(b authz.Binding) error
}

// RunBindingStoreLeakSuite asserts the isolation contract on a
// BindingStore. newHarness must return a FRESH, EMPTY store on each
// call.
func RunBindingStoreLeakSuite(t *testing.T, newHarness func() BindingHarness) {
	t.Helper()
	runBindingSuite(realT{t}, newHarness)
}

func runBindingSuite(t harnessT, newHarness func() BindingHarness) {
	t.Helper()
	t.Run("BindingsFor", func(t harnessT) { bindingsFor(t, seedBindings(t, newHarness())) })
	t.Run("BindingsForSubject", func(t harnessT) { bindingsForSubject(t, seedBindings(t, newHarness())) })
	t.Run("BindingsOnResource", func(t harnessT) { bindingsOnResource(t, seedBindings(t, newHarness())) })
}

// seedBindings writes the same shape into every store under test:
//
//	scope A: userA has roleA on res and on the global resource;
//	         the guest has roleA on res
//	scope B: userB has roleB on res and on the global resource
//	scope P: the guest has roleB on res and roleA on resHome (AT HOME)
func seedBindings(t harnessT, h BindingHarness) authz.BindingStore {
	t.Helper()
	for _, b := range []authz.Binding{
		{Tenant: tenantA, Subject: userA, Resource: res, Role: roleA},
		{Tenant: tenantA, Subject: userA, Resource: global, Role: roleA},
		{Tenant: tenantA, Subject: guest, Resource: res, Role: roleA},
		{Tenant: tenantB, Subject: userB, Resource: res, Role: roleB},
		{Tenant: tenantB, Subject: userB, Resource: global, Role: roleB},
		{Tenant: tenantP, Subject: guest, Resource: res, Role: roleB},
		{Tenant: tenantP, Subject: guest, Resource: resHome, Role: roleA},
	} {
		if err := h.Grant(b); err != nil {
			t.Fatalf("seed %+v: %v", b, err)
		}
	}
	return h.Store
}

// wantBindings fails unless got is exactly the bindings want lists,
// each stamped with the scope asked for.
func wantBindings(t harnessT, what string, scope tenant.ID, got []authz.Binding, err error, want ...authz.Binding) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	for _, b := range got {
		if b.Tenant != scope {
			t.Errorf("%s returned a binding of scope %q (%+v); the scope asked for was %q", what, b.Tenant, b, scope)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%s returned %d binding(s) %+v, want %d %+v", what, len(got), got, len(want), want)
		return
	}
	left := append([]authz.Binding(nil), got...)
	for _, w := range want {
		found := false
		for i, g := range left {
			if g == w {
				left = append(left[:i], left[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s did not return %+v; got %+v", what, w, got)
		}
	}
}

func bindingsFor(t harnessT, s authz.BindingStore) {
	ctx := context.Background()

	got, err := s.BindingsFor(ctx, tenantA, userA, res)
	wantBindings(t, "BindingsFor(A, userA)", tenantA, got, err,
		authz.Binding{Tenant: tenantA, Subject: userA, Resource: res, Role: roleA})

	// The scope: userA holds nothing in B, although a subject with the
	// same bare id does.
	got, err = s.BindingsFor(ctx, tenantB, userA, res)
	wantBindings(t, "BindingsFor(B, userA) — a subject asked about another scope", tenantB, got, err)

	// The subject: userB is not userA, although the id is the same.
	got, err = s.BindingsFor(ctx, tenantA, userB, res)
	wantBindings(t, "BindingsFor(A, userB) — another tenant's subject with the same id", tenantA, got, err)

	// The guest: one binding in A, a different one at home. Each scope
	// returns its own.
	got, err = s.BindingsFor(ctx, tenantA, guest, res)
	wantBindings(t, "BindingsFor(A, guest)", tenantA, got, err,
		authz.Binding{Tenant: tenantA, Subject: guest, Resource: res, Role: roleA})
	got, err = s.BindingsFor(ctx, tenantB, guest, res)
	wantBindings(t, "BindingsFor(B, guest) — the guest holds nothing in B", tenantB, got, err)

	// The global resource is global inside its scope only.
	got, err = s.BindingsFor(ctx, tenantB, userA, global)
	wantBindings(t, "BindingsFor(B, userA, global)", tenantB, got, err)
}

func bindingsForSubject(t harnessT, s authz.BindingStore) {
	ctx := context.Background()

	got, err := s.BindingsForSubject(ctx, tenantA, userA, res.Type)
	wantBindings(t, "BindingsForSubject(A, userA)", tenantA, got, err,
		authz.Binding{Tenant: tenantA, Subject: userA, Resource: res, Role: roleA})

	got, err = s.BindingsForSubject(ctx, tenantB, userA, res.Type)
	wantBindings(t, "BindingsForSubject(B, userA) — a subject asked about another scope", tenantB, got, err)

	got, err = s.BindingsForSubject(ctx, tenantA, userB, res.Type)
	wantBindings(t, "BindingsForSubject(A, userB) — another tenant's subject with the same id", tenantA, got, err)

	// The guest: exactly the one binding of the scope asked. A store
	// that finds a guest's bindings through the home tenant returns the
	// home ones here.
	got, err = s.BindingsForSubject(ctx, tenantA, guest, res.Type)
	wantBindings(t, "BindingsForSubject(A, guest)", tenantA, got, err,
		authz.Binding{Tenant: tenantA, Subject: guest, Resource: res, Role: roleA})
	got, err = s.BindingsForSubject(ctx, tenantP, guest, res.Type)
	wantBindings(t, "BindingsForSubject(P, guest) — the guest at home", tenantP, got, err,
		authz.Binding{Tenant: tenantP, Subject: guest, Resource: res, Role: roleB},
		authz.Binding{Tenant: tenantP, Subject: guest, Resource: resHome, Role: roleA})
	got, err = s.BindingsForSubject(ctx, tenantB, guest, res.Type)
	wantBindings(t, "BindingsForSubject(B, guest) — the guest holds nothing in B", tenantB, got, err)
}

func bindingsOnResource(t harnessT, s authz.BindingStore) {
	ctx := context.Background()

	// Everyone with a binding on res IN A: A's own user and the guest.
	// Not B's user, and not the guest's binding at home.
	got, err := s.BindingsOnResource(ctx, tenantA, res)
	wantBindings(t, "BindingsOnResource(A)", tenantA, got, err,
		authz.Binding{Tenant: tenantA, Subject: userA, Resource: res, Role: roleA},
		authz.Binding{Tenant: tenantA, Subject: guest, Resource: res, Role: roleA})

	got, err = s.BindingsOnResource(ctx, tenantB, res)
	wantBindings(t, "BindingsOnResource(B)", tenantB, got, err,
		authz.Binding{Tenant: tenantB, Subject: userB, Resource: res, Role: roleB})

	got, err = s.BindingsOnResource(ctx, tenantB, global)
	wantBindings(t, "BindingsOnResource(B, global)", tenantB, got, err,
		authz.Binding{Tenant: tenantB, Subject: userB, Resource: global, Role: roleB})
}

// --- PermissionStore -----------------------------------------------------

// PermissionHarness is a PermissionStore and the ways to write to it.
type PermissionHarness struct {
	Store authz.PermissionStore
	// Grant gives sub the keys on res inside the scope tenantID.
	Grant func(tenantID tenant.ID, sub authz.Subject, res authz.Resource, keys ...string) error
	// GrantSuperuser makes sub a superuser of the scope tenantID. Leave
	// it nil if the store has no superusers; the superuser case is then
	// not run.
	GrantSuperuser func(tenantID tenant.ID, sub authz.Subject) error
}

// RunPermissionStoreLeakSuite asserts the isolation contract on a
// PermissionStore. newHarness must return a FRESH, EMPTY store on each
// call.
func RunPermissionStoreLeakSuite(t *testing.T, newHarness func() PermissionHarness) {
	t.Helper()
	runPermissionSuite(realT{t}, newHarness)
}

func runPermissionSuite(t harnessT, newHarness func() PermissionHarness) {
	t.Helper()
	t.Run("PermissionsFor", func(t harnessT) { permissionsFor(t, seedPermissions(t, newHarness())) })
	t.Run("ResourcesWithPermission", func(t harnessT) { resourcesWithPermission(t, seedPermissions(t, newHarness())) })
	t.Run("SubjectsWithPermission", func(t harnessT) { subjectsWithPermission(t, seedPermissions(t, newHarness())) })
	// One harness, built inside the case: a store without superusers
	// passes it by having nothing to check.
	t.Run("Superuser", func(t harnessT) {
		if h := newHarness(); h.GrantSuperuser != nil {
			superuser(t, h)
		}
	})
}

// seedPermissions mirrors seedBindings:
//
//	scope A: userA holds keyA on res; the guest holds keyA on res
//	scope B: userB holds keyB on res
//	scope P: the guest holds keyB on res and keyA on resHome (at home)
func seedPermissions(t harnessT, h PermissionHarness) authz.PermissionStore {
	t.Helper()
	for _, g := range []struct {
		scope tenant.ID
		sub   authz.Subject
		res   authz.Resource
		key   string
	}{
		{tenantA, userA, res, keyA},
		{tenantA, guest, res, keyA},
		{tenantB, userB, res, keyB},
		{tenantP, guest, res, keyB},
		{tenantP, guest, resHome, keyA},
	} {
		if err := h.Grant(g.scope, g.sub, g.res, g.key); err != nil {
			t.Fatalf("seed %s %v %s: %v", g.scope, g.sub, g.key, err)
		}
	}
	return h.Store
}

// wantKeys fails unless the set is exactly want, with no superuser.
func wantKeys(t harnessT, what string, got authz.PermissionSetResult, err error, want ...string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if got.Superuser {
		t.Errorf("%s reported a superuser; nobody was made one", what)
	}
	if len(got.Keys) != len(want) {
		t.Errorf("%s returned keys %v, want %v", what, keysOf(got), want)
		return
	}
	for _, k := range want {
		if _, ok := got.Keys[k]; !ok {
			t.Errorf("%s returned keys %v, want %v", what, keysOf(got), want)
		}
	}
}

func keysOf(r authz.PermissionSetResult) []string {
	out := make([]string, 0, len(r.Keys))
	for k := range r.Keys {
		out = append(out, k)
	}
	return out
}

func permissionsFor(t harnessT, s authz.PermissionStore) {
	ctx := context.Background()

	got, err := s.PermissionsFor(ctx, tenantA, userA, res)
	wantKeys(t, "PermissionsFor(A, userA)", got, err, keyA)

	got, err = s.PermissionsFor(ctx, tenantB, userA, res)
	wantKeys(t, "PermissionsFor(B, userA) — a subject asked about another scope", got, err)

	got, err = s.PermissionsFor(ctx, tenantA, userB, res)
	wantKeys(t, "PermissionsFor(A, userB) — another tenant's subject with the same id", got, err)

	// The guest: keyA in A, keyB at home, and each scope answers its own.
	got, err = s.PermissionsFor(ctx, tenantA, guest, res)
	wantKeys(t, "PermissionsFor(A, guest)", got, err, keyA)
	got, err = s.PermissionsFor(ctx, tenantP, guest, res)
	wantKeys(t, "PermissionsFor(P, guest)", got, err, keyB)
	got, err = s.PermissionsFor(ctx, tenantB, guest, res)
	wantKeys(t, "PermissionsFor(B, guest) — the guest holds nothing in B", got, err)
}

func resourcesWithPermission(t harnessT, s authz.PermissionStore) {
	ctx := context.Background()
	// want is the exact set: a store that returns the right NUMBER of
	// resources from the wrong scope must not pass.
	check := func(what string, scope tenant.ID, sub authz.Subject, key string, want ...authz.Resource) {
		t.Helper()
		got, unbounded, err := s.ResourcesWithPermission(ctx, scope, sub, key, res.Type)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if unbounded {
			t.Errorf("%s reported unbounded access; nobody was granted it", what)
		}
		if len(got) != len(want) {
			t.Errorf("%s returned %v, want %v", what, got, want)
			return
		}
		for _, w := range want {
			found := false
			for _, g := range got {
				if g == w {
					found = true
				}
			}
			if !found {
				t.Errorf("%s returned %v, want %v", what, got, want)
			}
		}
	}
	check("ResourcesWithPermission(A, userA, keyA)", tenantA, userA, keyA, res)
	check("ResourcesWithPermission(B, userA, keyA) — another scope", tenantB, userA, keyA)
	// keyA, the key A's user really holds in A: a store that matches on
	// the bare id hands it to B's user.
	check("ResourcesWithPermission(A, userB, keyA) — another tenant's subject with the same id", tenantA, userB, keyA)
	check("ResourcesWithPermission(A, userA, keyB) — a key granted only in B", tenantA, userA, keyB)
	check("ResourcesWithPermission(A, guest, keyB) — the guest's key at home", tenantA, guest, keyB)
	// The guest holds keyA on one resource in A and on another at home.
	// Each scope returns its own.
	check("ResourcesWithPermission(A, guest, keyA)", tenantA, guest, keyA, res)
	check("ResourcesWithPermission(P, guest, keyA) — the guest at home", tenantP, guest, keyA, resHome)
}

func subjectsWithPermission(t harnessT, s authz.PermissionStore) {
	ctx := context.Background()
	check := func(what string, scope tenant.ID, key string, want ...authz.Subject) {
		t.Helper()
		got, err := s.SubjectsWithPermission(ctx, scope, key, res)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if len(got) != len(want) {
			t.Errorf("%s returned %v, want %v", what, got, want)
			return
		}
		for _, w := range want {
			found := false
			for _, g := range got {
				if g == w {
					found = true
				}
			}
			if !found {
				t.Errorf("%s returned %v, want %v", what, got, want)
			}
		}
	}
	// In A: A's user and the guest, each with the tenant they are from.
	check("SubjectsWithPermission(A, keyA)", tenantA, keyA, userA, guest)
	check("SubjectsWithPermission(B, keyA) — a key granted only in A", tenantB, keyA)
	check("SubjectsWithPermission(B, keyB)", tenantB, keyB, userB)
	check("SubjectsWithPermission(A, keyB) — keys of B and of the guest's home", tenantA, keyB)
}

func superuser(t harnessT, h PermissionHarness) {
	ctx := context.Background()
	if err := h.GrantSuperuser(tenantA, userA); err != nil {
		t.Fatalf("seed superuser: %v", err)
	}
	got, err := h.Store.PermissionsFor(ctx, tenantA, userA, res)
	if err != nil {
		t.Fatalf("PermissionsFor(A, userA): %v", err)
	}
	if !got.Superuser {
		t.Fatalf("PermissionsFor(A, userA) is not a superuser after GrantSuperuser(A, userA)")
	}
	for what, q := range map[string]struct {
		scope tenant.ID
		sub   authz.Subject
	}{
		"the superuser of A asked about B":               {tenantB, userA},
		"another tenant's subject with the same id in A": {tenantA, userB},
		"that subject in its own scope":                  {tenantB, userB},
	} {
		got, err := h.Store.PermissionsFor(ctx, q.scope, q.sub, res)
		if err != nil {
			t.Fatalf("PermissionsFor (%s): %v", what, err)
		}
		if got.Superuser {
			t.Errorf("%s is a superuser; only userA in A was made one", what)
		}
		_, unbounded, err := h.Store.ResourcesWithPermission(ctx, q.scope, q.sub, keyA, res.Type)
		if err != nil {
			t.Fatalf("ResourcesWithPermission (%s): %v", what, err)
		}
		if unbounded {
			t.Errorf("%s has unbounded access; only userA in A was made a superuser", what)
		}
	}
	subs, err := h.Store.SubjectsWithPermission(ctx, tenantB, keyA, res)
	if err != nil {
		t.Fatalf("SubjectsWithPermission(B): %v", err)
	}
	for _, s := range subs {
		if s == userA {
			t.Errorf("SubjectsWithPermission(B) lists A's superuser")
		}
	}
}
