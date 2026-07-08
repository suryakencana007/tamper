package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// The fixture mirrors Barista's production taxonomy: four independent
// ladders, cluster actions satisfiable by a per-cluster role OR the global
// system role (the system-admin bypass), and a system-only action
// (cluster.create).
func testHierarchy() Hierarchy {
	return Hierarchy{
		"system":  {"user", "cluster-admin"},
		"org":     {"member", "admin", "owner"},
		"project": {"member", "admin", "owner"},
		"cluster": {"cluster-viewer", "cluster-deployer", "cluster-admin"},
	}
}

func testPolicy() Policy {
	return Policy{
		"cluster.view":      {{Type: "cluster", Min: "cluster-viewer"}, {Type: "system", Min: "cluster-admin"}},
		"cluster.deploy":    {{Type: "cluster", Min: "cluster-deployer"}, {Type: "system", Min: "cluster-admin"}},
		"cluster.acl.grant": {{Type: "cluster", Min: "cluster-admin"}, {Type: "system", Min: "cluster-admin"}},
		"cluster.create":    {{Type: "system", Min: "cluster-admin"}},
		"org.update":        {{Type: "org", Min: "admin"}, {Type: "system", Min: "cluster-admin"}},
		"project.delete":    {{Type: "project", Min: "owner"}},
	}
}

var (
	alice = Subject{Type: "user", ID: "alice"} // per-cluster roles only
	bob   = Subject{Type: "user", ID: "bob"}   // system cluster-admin (global)
	carol = Subject{Type: "user", ID: "carol"} // mixed direct + group-derived ranks
	dave  = Subject{Type: "user", ID: "dave"}  // stale enum value binding

	c1     = Resource{Type: "cluster", ID: "c1"}
	c2     = Resource{Type: "cluster", ID: "c2"}
	c3     = Resource{Type: "cluster", ID: "c3"}
	org1   = Resource{Type: "org", ID: "org1"}
	system = Resource{Type: "system"}
)

func testStore() *MemStore {
	return NewMemStore(
		// alice: deployer on c1 only.
		Binding{Subject: alice, Resource: c1, Role: "cluster-deployer"},
		// bob: global system cluster-admin AND a direct viewer row on c1
		// (exercises ListSubjects dedup).
		Binding{Subject: bob, Resource: system, Role: "cluster-admin"},
		Binding{Subject: bob, Resource: c1, Role: "cluster-viewer"},
		// carol: viewer directly on c1 plus deployer on c1 via a group
		// grant — the store resolves indirection, the engine takes max.
		// Also deployer on c2 and admin on c3 for reverse queries.
		Binding{Subject: carol, Resource: c1, Role: "cluster-viewer"},
		Binding{Subject: carol, Resource: c1, Role: "cluster-deployer"},
		Binding{Subject: carol, Resource: c2, Role: "cluster-deployer"},
		Binding{Subject: carol, Resource: c3, Role: "cluster-admin"},
		Binding{Subject: carol, Resource: org1, Role: "member"},
		// dave: a role value not in the cluster ladder (stale enum) —
		// must rank 0 and satisfy nothing.
		Binding{Subject: dave, Resource: c1, Role: "superadmin"},
	)
}

func testEngine(t *testing.T) *RBAC {
	t.Helper()
	e, err := NewRBAC(testStore(), testHierarchy(), testPolicy())
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}
	return e
}

func TestCheck(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()

	cases := []struct {
		name string
		sub  Subject
		act  Action
		res  Resource
		want bool
	}{
		{"direct role at exact rank", alice, "cluster.deploy", c1, true},
		{"direct role above min (deployer >= viewer)", alice, "cluster.view", c1, true},
		{"direct role below min (deployer < admin)", alice, "cluster.acl.grant", c1, false},
		{"no binding on other cluster", alice, "cluster.deploy", c2, false},
		{"system bypass on any cluster", bob, "cluster.acl.grant", c2, true},
		{"system bypass on org action", bob, "org.update", org1, true},
		{"max of direct + group-derived wins", carol, "cluster.deploy", c1, true},
		{"org member below admin", carol, "org.update", org1, false},
		{"type-level check denied without global role", alice, "cluster.create", Resource{Type: "cluster"}, false},
		{"type-level check allowed via global role", bob, "cluster.create", Resource{Type: "cluster"}, true},
		{"stale enum ranks zero (fail closed)", dave, "cluster.view", c1, false},
		{"subject with no bindings at all", Subject{Type: "user", ID: "nobody"}, "cluster.view", c1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := e.Check(ctx, tc.sub, tc.act, tc.res)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if d.Allowed != tc.want {
				t.Fatalf("Allowed = %v, want %v (reason: %s)", d.Allowed, tc.want, d.Reason)
			}
			if d.Reason == "" {
				t.Fatalf("Reason must be filled on both allow and deny")
			}
		})
	}
}

func TestCheckUnknownActionDenies(t *testing.T) {
	e := testEngine(t)
	d, err := e.Check(context.Background(), alice, "cluster.destroy", c1)
	if err != nil {
		t.Fatalf("unknown action must deny, not error: %v", err)
	}
	if d.Allowed {
		t.Fatal("unknown action must deny")
	}
	if !strings.Contains(d.Reason, "unknown action") {
		t.Fatalf("reason should say unknown action, got %q", d.Reason)
	}
}

func TestCheckGlobalBindingDoesNotLeakToInstances(t *testing.T) {
	// A binding on the SAME type's global singleton must not satisfy an
	// instance check — only different-type requirements consult globals.
	store := NewMemStore(Binding{Subject: alice, Resource: Resource{Type: "cluster"}, Role: "cluster-admin"})
	e, err := NewRBAC(store, testHierarchy(), testPolicy())
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}
	d, err := e.Check(context.Background(), alice, "cluster.deploy", c1)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if d.Allowed {
		t.Fatal("same-type global binding must not satisfy an instance check")
	}
}

func TestCheckBulk(t *testing.T) {
	e := testEngine(t)
	reqs := []CheckRequest{
		{Subject: alice, Action: "cluster.deploy", Resource: c1},
		{Subject: alice, Action: "cluster.deploy", Resource: c2},
		{Subject: bob, Action: "cluster.create", Resource: Resource{Type: "cluster"}},
	}
	ds, err := e.CheckBulk(context.Background(), reqs)
	if err != nil {
		t.Fatalf("CheckBulk: %v", err)
	}
	if len(ds) != 3 {
		t.Fatalf("got %d decisions, want 3", len(ds))
	}
	for i, want := range []bool{true, false, true} {
		if ds[i].Allowed != want {
			t.Fatalf("decision[%d].Allowed = %v, want %v", i, ds[i].Allowed, want)
		}
	}
}

func TestListResources(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()

	t.Run("concrete set at min rank, sorted, deduped", func(t *testing.T) {
		rs, unbounded, err := e.ListResources(ctx, carol, "cluster.deploy", "cluster")
		if err != nil {
			t.Fatalf("ListResources: %v", err)
		}
		if unbounded {
			t.Fatal("carol has no global grant; unbounded must be false")
		}
		want := []Resource{c1, c2, c3}
		if len(rs) != len(want) {
			t.Fatalf("got %v, want %v", rs, want)
		}
		for i := range want {
			if rs[i] != want[i] {
				t.Fatalf("got %v, want %v", rs, want)
			}
		}
	})

	t.Run("higher min shrinks the set", func(t *testing.T) {
		rs, _, err := e.ListResources(ctx, carol, "cluster.acl.grant", "cluster")
		if err != nil {
			t.Fatalf("ListResources: %v", err)
		}
		if len(rs) != 1 || rs[0] != c3 {
			t.Fatalf("got %v, want [c3]", rs)
		}
	})

	t.Run("global role reports unbounded", func(t *testing.T) {
		rs, unbounded, err := e.ListResources(ctx, bob, "cluster.deploy", "cluster")
		if err != nil {
			t.Fatalf("ListResources: %v", err)
		}
		if !unbounded {
			t.Fatal("system cluster-admin must be unbounded")
		}
		// bob's direct viewer row on c1 is below deployer — not listed.
		if len(rs) != 0 {
			t.Fatalf("expected no concrete rows, got %v", rs)
		}
	})

	t.Run("unknown action errors loudly", func(t *testing.T) {
		if _, _, err := e.ListResources(ctx, alice, "cluster.destroy", "cluster"); err == nil {
			t.Fatal("unknown action must error on list queries")
		}
	})

	t.Run("action with no same-type requirement yields empty", func(t *testing.T) {
		rs, unbounded, err := e.ListResources(ctx, alice, "cluster.create", "cluster")
		if err != nil {
			t.Fatalf("ListResources: %v", err)
		}
		if len(rs) != 0 || unbounded {
			t.Fatalf("alice: got %v unbounded=%v, want empty + false", rs, unbounded)
		}
	})
}

func TestListSubjects(t *testing.T) {
	e := testEngine(t)
	subs, unbounded, err := e.ListSubjects(context.Background(), "cluster.deploy", c1)
	if err != nil {
		t.Fatalf("ListSubjects: %v", err)
	}
	if unbounded {
		t.Fatal("RBAC enumerates global holders; unbounded must be false")
	}
	// alice (direct deployer), carol (max rank deployer), bob (global
	// system-admin; his direct c1 viewer row alone would NOT qualify —
	// and he must appear exactly once).
	want := []Subject{alice, bob, carol}
	if len(subs) != len(want) {
		t.Fatalf("got %v, want %v", subs, want)
	}
	for i := range want {
		if subs[i] != want[i] {
			t.Fatalf("got %v, want %v", subs, want)
		}
	}
}

func TestNewRBACValidation(t *testing.T) {
	h := testHierarchy()
	cases := []struct {
		name  string
		store BindingStore
		h     Hierarchy
		p     Policy
	}{
		{"nil store", nil, h, testPolicy()},
		{"unknown requirement type", NewMemStore(), h, Policy{"x": {{Type: "volume", Min: "admin"}}}},
		{"min not in ladder", NewMemStore(), h, Policy{"x": {{Type: "cluster", Min: "owner"}}}},
		{"empty requirements", NewMemStore(), h, Policy{"x": {}}},
		{"empty action", NewMemStore(), h, Policy{"": {{Type: "cluster", Min: "cluster-admin"}}}},
		{"empty ladder", NewMemStore(), Hierarchy{"cluster": {}}, Policy{}},
		{"duplicate role in ladder", NewMemStore(), Hierarchy{"cluster": {"a", "a"}}, Policy{}},
		{"empty role in ladder", NewMemStore(), Hierarchy{"cluster": {""}}, Policy{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRBAC(tc.store, tc.h, tc.p); err == nil {
				t.Fatal("want construction error, got nil")
			}
		})
	}
}

// errStore fails every query — exercises the error-means-deny plumbing.
type errStore struct{}

func (errStore) BindingsFor(context.Context, Subject, Resource) ([]Binding, error) {
	return nil, errors.New("store down")
}
func (errStore) BindingsForSubject(context.Context, Subject, string) ([]Binding, error) {
	return nil, errors.New("store down")
}
func (errStore) BindingsOnResource(context.Context, Resource) ([]Binding, error) {
	return nil, errors.New("store down")
}

func TestStoreErrorsPropagate(t *testing.T) {
	e, err := NewRBAC(errStore{}, testHierarchy(), testPolicy())
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}
	ctx := context.Background()
	if d, err := e.Check(ctx, alice, "cluster.deploy", c1); err == nil || d.Allowed {
		t.Fatalf("Check must error and deny on store failure, got %+v err=%v", d, err)
	}
	if _, err := e.CheckBulk(ctx, []CheckRequest{{Subject: alice, Action: "cluster.deploy", Resource: c1}}); err == nil {
		t.Fatal("CheckBulk must fail the whole call on store failure")
	}
	if _, _, err := e.ListResources(ctx, alice, "cluster.deploy", "cluster"); err == nil {
		t.Fatal("ListResources must error on store failure")
	}
	if _, _, err := e.ListSubjects(ctx, "cluster.deploy", c1); err == nil {
		t.Fatal("ListSubjects must error on store failure")
	}
}

func TestConcurrentUse(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if _, err := e.Check(ctx, carol, "cluster.deploy", c1); err != nil {
					t.Errorf("goroutine %d: %v", g, err)
					return
				}
				if _, _, err := e.ListResources(ctx, carol, "cluster.view", "cluster"); err != nil {
					t.Errorf("goroutine %d: %v", g, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// Example-shaped smoke: the end-state integration sketch from
// TAMPER-DESIGN.md compiles against the real API.
func ExampleRBAC() {
	store := NewMemStore(
		Binding{Subject: Subject{Type: "user", ID: "u1"}, Resource: Resource{Type: "doc", ID: "d1"}, Role: "editor"},
	)
	authz, _ := NewRBAC(store,
		Hierarchy{"doc": {"viewer", "editor"}},
		Policy{"doc.delete": {{Type: "doc", Min: "editor"}}},
	)
	d, _ := authz.Check(context.Background(), Subject{Type: "user", ID: "u1"}, "doc.delete", Resource{Type: "doc", ID: "d1"})
	fmt.Println(d.Allowed)
	// Output: true
}
