package authz

import (
	"context"
	"errors"
	"testing"
)

func ps(t *testing.T, store PermissionStore) *PermissionSet {
	t.Helper()
	e, err := NewPermissionSet(store)
	if err != nil {
		t.Fatalf("NewPermissionSet: %v", err)
	}
	return e
}

func mustAllow(t *testing.T, e Authorizer, sub Subject, act Action, res Resource, want bool) {
	t.Helper()
	d, err := e.Check(context.Background(), sub, act, res)
	if err != nil {
		t.Fatalf("Check(%s, %q, %s): unexpected error %v", sub.ID, act, res.ID, err)
	}
	if d.Allowed != want {
		t.Errorf("Check(%s, %q, %s) = %v (%s), want %v", sub.ID, act, res.ID, d.Allowed, d.Reason, want)
	}
}

func TestPermissionSet_NilStore(t *testing.T) {
	if _, err := NewPermissionSet(nil); err == nil {
		t.Fatal("NewPermissionSet(nil) must error")
	}
}

func TestPermissionSet_DenyByDefault(t *testing.T) {
	e := ps(t, NewMemPermissionStore())
	alice := Subject{"user", "alice"}
	c1 := Resource{"cluster", "c1"}
	// No grants at all — every action denies, nil error.
	mustAllow(t, e, alice, "cluster.view", c1, false)
	mustAllow(t, e, alice, "anything.at.all", c1, false)
}

func TestPermissionSet_ExactKeyMembership(t *testing.T) {
	st := NewMemPermissionStore()
	alice := Subject{"user", "alice"}
	c1 := Resource{"cluster", "c1"}
	st.Grant(alice, c1, "cluster.view")
	e := ps(t, st)

	mustAllow(t, e, alice, "cluster.view", c1, true)
	mustAllow(t, e, alice, "cluster.deploy", c1, false)
	// A key held on c1 does not carry to c2.
	mustAllow(t, e, alice, "cluster.view", Resource{"cluster", "c2"}, false)
}

// TestPermissionSet_NonDownwardClosedRole is the capability a rank ladder
// CANNOT express: view + manage but NOT deploy. This is the whole point of the
// set engine.
func TestPermissionSet_NonDownwardClosedRole(t *testing.T) {
	st := NewMemPermissionStore()
	frank := Subject{"user", "frank"}
	c1 := Resource{"cluster", "c1"}
	st.Grant(frank, c1, "cluster.view", "cluster.manage") // note: no cluster.deploy
	e := ps(t, st)

	mustAllow(t, e, frank, "cluster.view", c1, true)
	mustAllow(t, e, frank, "cluster.deploy", c1, false) // the skipped middle rung
	mustAllow(t, e, frank, "cluster.manage", c1, true)
}

func TestPermissionSet_Superuser(t *testing.T) {
	st := NewMemPermissionStore()
	root := Subject{"user", "root"}
	st.GrantSuperuser(root)
	e := ps(t, st)

	// Allowed every KNOWN action on every resource, with no per-resource grant.
	mustAllow(t, e, root, "cluster.manage", Resource{"cluster", "c1"}, true)
	mustAllow(t, e, root, "cluster.manage", Resource{"cluster", "c2"}, true)
	mustAllow(t, e, root, "system.admin", Resource{"system", ""}, true)
}

func TestPermissionSet_EmptyActionDenies(t *testing.T) {
	e := ps(t, NewMemPermissionStore())
	d, err := e.Check(context.Background(), Subject{"user", "a"}, "", Resource{"cluster", "c1"})
	if err != nil || d.Allowed {
		t.Fatalf("empty action must deny with nil error, got allowed=%v err=%v", d.Allowed, err)
	}
}

// errPermStore is a PermissionStore that always fails — proves store errors surface
// as errors (which callers must treat as deny), never as a silent allow.
type errPermStore struct{ err error }

func (s errPermStore) PermissionsFor(context.Context, Subject, Resource) (PermissionSetResult, error) {
	return PermissionSetResult{}, s.err
}
func (s errPermStore) ResourcesWithPermission(context.Context, Subject, string, string) ([]Resource, bool, error) {
	return nil, false, s.err
}
func (s errPermStore) SubjectsWithPermission(context.Context, string, Resource) ([]Subject, error) {
	return nil, s.err
}

func TestPermissionSet_StoreErrorSurfaces(t *testing.T) {
	boom := errors.New("store down")
	e := ps(t, errPermStore{err: boom})
	d, err := e.Check(context.Background(), Subject{"user", "a"}, "cluster.view", Resource{"cluster", "c1"})
	if err == nil {
		t.Fatal("store error must surface as a Check error")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error must wrap the store error, got %v", err)
	}
	if d.Allowed {
		t.Error("a failed evaluation must not report Allowed=true")
	}
}

// fixedStore returns a fixed result — used to prove the wildcard fail-closed
// path and the explicit-Superuser path.
type fixedStore struct{ r PermissionSetResult }

func (s fixedStore) PermissionsFor(context.Context, Subject, Resource) (PermissionSetResult, error) {
	return s.r, nil
}
func (s fixedStore) ResourcesWithPermission(context.Context, Subject, string, string) ([]Resource, bool, error) {
	return nil, false, nil
}
func (s fixedStore) SubjectsWithPermission(context.Context, string, Resource) ([]Subject, error) {
	return nil, nil
}

func TestPermissionSet_WildcardInKeysDoesNotEscalate(t *testing.T) {
	// A stray "*" in Keys (WITHOUT the Superuser flag) must NOT grant superuser
	// — it is treated as the literal key "*", which matches no real action, so a
	// wildcard leaking in via a bug fails CLOSED rather than escalating to root.
	e := ps(t, fixedStore{r: PermissionSetResult{Keys: map[string]struct{}{SuperuserKey: {}}}})
	mustAllow(t, e, Subject{"user", "a"}, "cluster.manage", Resource{"cluster", "c1"}, false)

	// The explicit Superuser flag is the ONLY way to grant everything.
	su := ps(t, fixedStore{r: PermissionSetResult{Superuser: true}})
	mustAllow(t, su, Subject{"user", "a"}, "cluster.manage", Resource{"cluster", "c1"}, true)
}

func TestPermissionSet_CheckBulk(t *testing.T) {
	st := NewMemPermissionStore()
	alice := Subject{"user", "alice"}
	c1 := Resource{"cluster", "c1"}
	st.Grant(alice, c1, "cluster.view")
	e := ps(t, st)

	reqs := []CheckRequest{
		{alice, "cluster.view", c1},
		{alice, "cluster.deploy", c1},
	}
	out, err := e.CheckBulk(context.Background(), reqs)
	if err != nil {
		t.Fatalf("CheckBulk: %v", err)
	}
	if len(out) != 2 || !out[0].Allowed || out[1].Allowed {
		t.Errorf("CheckBulk = %+v, want [allow, deny]", out)
	}
}

func TestPermissionSet_CheckBulkErrorFailsWhole(t *testing.T) {
	e := ps(t, errPermStore{err: errors.New("boom")})
	if _, err := e.CheckBulk(context.Background(), []CheckRequest{{Subject{"user", "a"}, "x", Resource{"cluster", "c1"}}}); err == nil {
		t.Fatal("CheckBulk must fail the whole call on a store error")
	}
}

func TestPermissionSet_ListResources(t *testing.T) {
	st := NewMemPermissionStore()
	alice := Subject{"user", "alice"}
	st.Grant(alice, Resource{"cluster", "c2"}, "cluster.view")
	st.Grant(alice, Resource{"cluster", "c1"}, "cluster.view", "cluster.deploy")
	e := ps(t, st)

	// view held on both, returned sorted by ID.
	rs, unbounded, err := e.ListResources(context.Background(), alice, "cluster.view", "cluster")
	if err != nil || unbounded {
		t.Fatalf("ListResources view: err=%v unbounded=%v", err, unbounded)
	}
	if len(rs) != 2 || rs[0].ID != "c1" || rs[1].ID != "c2" {
		t.Errorf("ListResources view = %+v, want [c1, c2] sorted", rs)
	}
	// deploy held only on c1.
	rs, _, _ = e.ListResources(context.Background(), alice, "cluster.deploy", "cluster")
	if len(rs) != 1 || rs[0].ID != "c1" {
		t.Errorf("ListResources deploy = %+v, want [c1]", rs)
	}
}

func TestPermissionSet_ListResources_SuperuserUnbounded(t *testing.T) {
	st := NewMemPermissionStore()
	root := Subject{"user", "root"}
	st.GrantSuperuser(root)
	e := ps(t, st)
	_, unbounded, err := e.ListResources(context.Background(), root, "cluster.manage", "cluster")
	if err != nil || !unbounded {
		t.Fatalf("superuser ListResources must be unbounded, got unbounded=%v err=%v", unbounded, err)
	}
}

func TestPermissionSet_ListSubjects(t *testing.T) {
	st := NewMemPermissionStore()
	c1 := Resource{"cluster", "c1"}
	st.Grant(Subject{"user", "bob"}, c1, "cluster.view")
	st.Grant(Subject{"user", "amy"}, c1, "cluster.view")
	st.GrantSuperuser(Subject{"user", "root"})
	e := ps(t, st)

	subs, unbounded, err := e.ListSubjects(context.Background(), "cluster.view", c1)
	if err != nil || unbounded {
		t.Fatalf("ListSubjects: err=%v unbounded=%v", err, unbounded)
	}
	// amy, bob (scoped) + root (superuser), sorted by (Type, ID).
	if len(subs) != 3 || subs[0].ID != "amy" || subs[1].ID != "bob" || subs[2].ID != "root" {
		t.Errorf("ListSubjects = %+v, want [amy, bob, root] sorted", subs)
	}
}
