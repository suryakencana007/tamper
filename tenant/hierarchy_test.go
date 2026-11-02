package tenant

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// spyStore records whether the store was touched at all, so "no store call" is
// an assertion rather than an inference from an empty result.
type spyStore struct {
	inner *MemStore
	calls int
}

func newSpyStore() *spyStore { return &spyStore{inner: NewMemStore()} }

func (s *spyStore) ByID(ctx context.Context, id string) (Descriptor, error) {
	s.calls++
	return s.inner.ByID(ctx, id)
}

func (s *spyStore) BySlug(ctx context.Context, slug string) (Descriptor, error) {
	s.calls++
	return s.inner.BySlug(ctx, slug)
}

// chain seeds id_n with id_{n+1} as its parent, for n in [0, depth).
func chain(t *testing.T, s *MemStore, depth int) {
	t.Helper()
	for n := 0; n < depth; n++ {
		d := Descriptor{ID: fmt.Sprintf("t-%d", n), Status: StatusActive}
		if n+1 < depth {
			d.ParentID = fmt.Sprintf("t-%d", n+1)
		}
		s.Seed(d)
	}
}

func ids(t *testing.T, list []ID) []string {
	t.Helper()
	out := make([]string, 0, len(list))
	for _, id := range list {
		out = append(out, id.String())
	}
	return out
}

func TestAncestors_NearestFirstAndExcludesItself(t *testing.T) {
	s := NewMemStore()
	s.Seed(Descriptor{ID: "group", Status: StatusActive})
	s.Seed(Descriptor{ID: "org", ParentID: "group", Status: StatusActive})
	s.Seed(Descriptor{ID: "team", ParentID: "org", Status: StatusActive})

	got, err := Ancestors(context.Background(), s, New("team"))
	if err != nil {
		t.Fatalf("Ancestors: %v", err)
	}
	if want := []string{"org", "group"}; !equalStrings(ids(t, got), want) {
		t.Fatalf("Ancestors = %v, want %v (nearest first, self excluded)", ids(t, got), want)
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestAncestors_RootHasNone(t *testing.T) {
	s := NewMemStore()
	s.Seed(Descriptor{ID: "root", Status: StatusActive})

	got, err := Ancestors(context.Background(), s, New("root"))
	if err != nil {
		t.Fatalf("Ancestors: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Ancestors(root) = %v, want empty", ids(t, got))
	}
	if got == nil {
		t.Error("Ancestors returned a nil slice; the house contract for \"none\" is non-nil empty")
	}
}

func TestAncestors_UnsetAndSingleNeverTouchTheStore(t *testing.T) {
	for name, id := range map[string]ID{"zero": {}, "single": Single} {
		t.Run(name, func(t *testing.T) {
			s := newSpyStore()
			s.inner.Seed(Descriptor{ID: "root", Status: StatusActive})

			got, err := Ancestors(context.Background(), s, id)
			if err != nil {
				t.Fatalf("Ancestors: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("Ancestors(%v) = %v, want empty", name, ids(t, got))
			}
			if s.calls != 0 {
				t.Fatalf("store was read %d times; unset and single-tenant must not read it "+
					"at all (a read returns ErrNotFound and turns every such call into an error)", s.calls)
			}
		})
	}
}

// An empty ParentID mid-chain is a root, and it must stop the walk without ever
// producing Single — the unreachable branch of FromStored. This breaks the day a
// refactor converts before checking.
func TestAncestors_EmptyParentIDStopsTheWalkAndNeverYieldsSingle(t *testing.T) {
	s := NewMemStore()
	s.Seed(Descriptor{ID: "group", Status: StatusActive}) // ParentID "" — a root
	s.Seed(Descriptor{ID: "org", ParentID: "group", Status: StatusActive})
	s.Seed(Descriptor{ID: "team", ParentID: "org", Status: StatusActive})

	got, err := Ancestors(context.Background(), s, New("team"))
	if err != nil {
		t.Fatalf("Ancestors: %v", err)
	}
	if want := []string{"org", "group"}; !equalStrings(ids(t, got), want) {
		t.Fatalf("Ancestors = %v, want %v", ids(t, got), want)
	}
	for _, id := range got {
		if id.IsSingle() {
			t.Fatal("the single-tenant value appeared in an ancestor chain")
		}
		if !id.Valid() {
			t.Fatalf("%q is unset; every returned id must carry validity", id.String())
		}
	}
}

func TestAncestors_UnknownStartIsAnError(t *testing.T) {
	s := NewMemStore()
	_, err := Ancestors(context.Background(), s, New("ghost"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Ancestors(unknown) err = %v, want ErrNotFound", err)
	}
}

// A parent that does not resolve is corrupt data, not a root.
func TestAncestors_DanglingParentIsAnError(t *testing.T) {
	s := NewMemStore()
	s.Seed(Descriptor{ID: "team", ParentID: "vanished", Status: StatusActive})

	_, err := Ancestors(context.Background(), s, New("team"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Ancestors with a dangling parent err = %v, want ErrNotFound", err)
	}
}

func TestAncestors_Cycle(t *testing.T) {
	t.Run("two nodes", func(t *testing.T) {
		s := NewMemStore()
		s.Seed(Descriptor{ID: "a", ParentID: "b", Status: StatusActive})
		s.Seed(Descriptor{ID: "b", ParentID: "a", Status: StatusActive})

		if _, err := Ancestors(context.Background(), s, New("a")); !errors.Is(err, ErrHierarchyCycle) {
			t.Fatalf("err = %v, want ErrHierarchyCycle", err)
		}
	})
	t.Run("its own parent", func(t *testing.T) {
		s := NewMemStore()
		s.Seed(Descriptor{ID: "a", ParentID: "a", Status: StatusActive})

		if _, err := Ancestors(context.Background(), s, New("a")); !errors.Is(err, ErrHierarchyCycle) {
			t.Fatalf("err = %v, want ErrHierarchyCycle (self-parent)", err)
		}
	})
}

// The bound is pinned on both sides of the edge: n nodes with a root yield n-1
// ancestors, so maxHierarchyDepth+1 nodes is exactly the limit and one more node
// is one too many.
func TestAncestors_ExactlyTheLimitResolves(t *testing.T) {
	s := NewMemStore()
	chain(t, s, maxHierarchyDepth+1)

	got, err := Ancestors(context.Background(), s, New("t-0"))
	if err != nil {
		t.Fatalf("Ancestors at exactly the limit: %v", err)
	}
	if len(got) != maxHierarchyDepth {
		t.Fatalf("got %d ancestors, want exactly %d (the bound must not fire early)", len(got), maxHierarchyDepth)
	}
}

func TestAncestors_OneOverTheLimitIsAnError(t *testing.T) {
	s := NewMemStore()
	chain(t, s, maxHierarchyDepth+2)

	if _, err := Ancestors(context.Background(), s, New("t-0")); !errors.Is(err, ErrHierarchyDepth) {
		t.Fatalf("err = %v, want ErrHierarchyDepth at %d ancestors", err, maxHierarchyDepth+1)
	}
}

// The store's own error must survive the walk, not merely cause one: a caller
// distinguishes "the hierarchy is corrupt" from "the database is unreachable" by
// errors.Is, and a wrapper that dropped the sentinel would collapse them.
func TestAncestors_StoreErrorPropagates(t *testing.T) {
	s := newSpyStore()
	s.inner.Seed(Descriptor{ID: "a", ParentID: "boom", Status: StatusActive})

	_, err := Ancestors(context.Background(), errStore{Store: s}, New("a"))
	if !errors.Is(err, errStoreDown) {
		t.Fatalf("err = %v, want the store's own error to survive (errors.Is errStoreDown)", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatal("the fake store's error masquerades as ErrNotFound; this test would then prove nothing")
	}
}

// errStoreDown is deliberately NOT one of tenant's sentinels, so the assertion
// above can only pass if the walk propagated rather than invented an error.
var errStoreDown = errors.New("store is down")

// errStore serves the first row and fails every other lookup, so the failure
// lands mid-walk rather than on the start id.
type errStore struct{ Store }

func (errStore) ByID(_ context.Context, id string) (Descriptor, error) {
	if id == "a" {
		return Descriptor{ID: "a", ParentID: "boom", Status: StatusActive}, nil
	}
	return Descriptor{}, errStoreDown
}

func TestAncestors_PanicsOnNilStore(t *testing.T) {
	for name, id := range map[string]ID{"valid": New("a"), "single": Single, "zero": {}} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("Ancestors(nil store) did not panic; nil is a wiring bug, and it must not " +
						"pass for a hierarchy that happens to inherit nothing")
				}
			}()
			// Not even the cases that never read the store get to skip the guard.
			_, _ = Ancestors(context.Background(), nil, id)
		})
	}
}
