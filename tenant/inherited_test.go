package tenant

import (
	"context"
	"errors"
	"testing"
)

// The inheritance policy rules, tested where they live. The engine suites prove
// their managers delegate here; these prove the rules themselves.

// axis is a tiny inheritance axis: a map from tenant to its own items.
type axis struct {
	items map[string][]string
	err   error
}

func (a *axis) own(_ context.Context, id ID) ([]string, error) {
	if a.err != nil {
		return nil, a.err
	}
	return a.items[id.String()], nil
}

type switchSpy struct {
	ask []string
	yes map[string]bool
	err error
}

func (s *switchSpy) allow(_ context.Context, id ID) (bool, error) {
	s.ask = append(s.ask, id.String())
	if s.err != nil {
		return false, s.err
	}
	return s.yes[id.String()], nil
}

func inhTree(t *testing.T) *MemStore {
	t.Helper()
	h := NewMemStore()
	h.Seed(Descriptor{ID: "group", Status: StatusActive})
	h.Seed(Descriptor{ID: "org", ParentID: "group", Status: StatusActive})
	h.Seed(Descriptor{ID: "team", ParentID: "org", Status: StatusActive})
	return h
}

func TestInherited_OwnItemsWinEntirelyAndNothingMerges(t *testing.T) {
	a := &axis{items: map[string][]string{"team": {"team-x"}, "group": {"group-x"}}}
	spy := &switchSpy{yes: map[string]bool{"group": true}}

	got, err := Inherited(context.Background(), inhTree(t), spy.allow, New("team"), a.own)
	if err != nil {
		t.Fatalf("Inherited: %v", err)
	}
	if len(got) != 1 || got[0] != "team-x" {
		t.Fatalf("got %v, want only the tenant's own — a merge would make an id lookup ambiguous", got)
	}
	if len(spy.ask) != 0 {
		t.Fatalf("the switch was asked about %v for a tenant with its own items", spy.ask)
	}
}

func TestInherited_AProviderlessAncestorIsSkippedWithoutAsking(t *testing.T) {
	a := &axis{items: map[string][]string{"group": {"group-x"}}} // org has nothing
	spy := &switchSpy{yes: map[string]bool{"group": true}}

	got, err := Inherited(context.Background(), inhTree(t), spy.allow, New("team"), a.own)
	if err != nil {
		t.Fatalf("Inherited: %v", err)
	}
	if len(got) != 1 || got[0] != "group-x" {
		t.Fatalf("got %v, want the group's through a providerless org", got)
	}
	if len(spy.ask) != 1 || spy.ask[0] != "group" {
		t.Fatalf("switch asked about %v, want exactly [group] — a silent middle layer must not "+
			"block a decision made above it", spy.ask)
	}
}

func TestInherited_ARefusalStopsTheWalk(t *testing.T) {
	a := &axis{items: map[string][]string{"group": {"group-x"}, "org": {"org-x"}}}
	spy := &switchSpy{yes: map[string]bool{"group": true}} // org has items and has NOT opted in

	got, err := Inherited(context.Background(), inhTree(t), spy.allow, New("team"), a.own)
	if err != nil {
		t.Fatalf("Inherited: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v; the nearest ancestor with items refused, so a grandparent's must not "+
			"be substituted", got)
	}
	if len(spy.ask) != 1 || spy.ask[0] != "org" {
		t.Fatalf("switch asked about %v, want exactly [org]", spy.ask)
	}
}

func TestInherited_PolicyErrorAbortsEitherWayRound(t *testing.T) {
	boom := errors.New("settings table is down")
	a := &axis{items: map[string][]string{"org": {"org-x"}}}

	for _, yes := range []bool{false, true} {
		spy := &switchSpy{err: boom, yes: map[string]bool{"org": yes}}
		got, err := Inherited(context.Background(), inhTree(t), spy.allow, New("team"), a.own)
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the policy's error — (false, err) read as a refusal would make "+
				"an outage look like a switched-off group, and (true, err) read as permission is the "+
				"obvious bug", err)
		}
		if got != nil {
			t.Fatalf("got %v alongside an error", got)
		}
	}
}

func TestInherited_UnwiredKeepsTheTenantsOwnAnswer(t *testing.T) {
	a := &axis{items: map[string][]string{"team": {"team-x"}, "group": {"group-x"}}}
	h := inhTree(t)

	for name, tc := range map[string]struct {
		store Store
		allow Inheritance
	}{
		"nil store":  {nil, func(context.Context, ID) (bool, error) { return true, nil }},
		"nil policy": {h, nil},
		"both nil":   {nil, nil},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Inherited(context.Background(), tc.store, tc.allow, New("team"), a.own)
			if err != nil {
				t.Fatalf("Inherited: %v", err)
			}
			if len(got) != 1 || got[0] != "team-x" {
				t.Fatalf("got %v, want the tenant's own", got)
			}
		})
	}
}

func TestInherited_UnknownAndCorruptParentage(t *testing.T) {
	a := &axis{}
	allow := func(context.Context, ID) (bool, error) { return true, nil }

	t.Run("unknown id is empty, not an error", func(t *testing.T) {
		got, err := Inherited(context.Background(), inhTree(t), allow, New("ghost"), a.own)
		if err != nil || len(got) != 0 {
			t.Fatalf("got (%v, %v), want (empty, nil)", got, err)
		}
	})

	t.Run("dangling parent propagates", func(t *testing.T) {
		h := NewMemStore()
		h.Seed(Descriptor{ID: "team", ParentID: "vanished", Status: StatusActive})
		if _, err := Inherited(context.Background(), h, allow, New("team"), a.own); !errors.Is(err, ErrHierarchyDangling) {
			t.Fatalf("err = %v, want ErrHierarchyDangling — corrupt parentage must not read as "+
				"\"nothing to inherit\"", err)
		}
	})

	t.Run("unset and single never walk", func(t *testing.T) {
		h := newSpyStore()
		for _, id := range []ID{{}, Single} {
			if _, err := Inherited(context.Background(), h, allow, id, a.own); err != nil {
				t.Fatalf("Inherited: %v", err)
			}
		}
		if h.calls != 0 {
			t.Fatalf("the hierarchy store was read %d times; unset and single-tenant walk nothing", h.calls)
		}
	})
}

func TestInherited_LookupErrorsPropagate(t *testing.T) {
	boom := errors.New("provider store is down")
	allow := func(context.Context, ID) (bool, error) { return true, nil }

	t.Run("own lookup", func(t *testing.T) {
		a := &axis{err: boom}
		if _, err := Inherited(context.Background(), inhTree(t), allow, New("team"), a.own); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the lookup's own error", err)
		}
	})

	t.Run("ancestor lookup", func(t *testing.T) {
		a := &axis{items: map[string][]string{}, err: boom}
		if _, err := Inherited(context.Background(), inhTree(t), allow, New("team"), a.own); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the lookup's own error", err)
		}
	})
}

func TestInherited_NoAncestorsIsEmpty(t *testing.T) {
	a := &axis{items: map[string][]string{"group": {"group-x"}}}
	spy := &switchSpy{yes: map[string]bool{"group": true}}

	got, err := Inherited(context.Background(), inhTree(t), spy.allow, New("group"), a.own)
	if err != nil {
		t.Fatalf("Inherited: %v", err)
	}
	if len(got) != 1 || got[0] != "group-x" {
		t.Fatalf("got %v, want the root's own", got)
	}
	if len(spy.ask) != 0 {
		t.Fatalf("a root has no ancestors to ask about, got %v", spy.ask)
	}
}

func TestInherited_PanicsOnNilLookup(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a nil lookup did not panic; it would resolve every tenant to nothing")
		}
	}()
	allow := func(context.Context, ID) (bool, error) { return true, nil }
	_, _ = Inherited[string](context.Background(), inhTree(t), allow, New("team"), nil)
}

// The helper is generic over the axis's own type, which is the reason it can live
// here at all: an entitlement record and a provider record share no shape.
func TestInherited_IsNotSpecificToAnyRecordType(t *testing.T) {
	a := map[string][]int{"group": {7}}
	own := func(_ context.Context, id ID) ([]int, error) { return a[id.String()], nil }
	allow := func(context.Context, ID) (bool, error) { return true, nil }

	got, err := Inherited(context.Background(), inhTree(t), allow, New("team"), own)
	if err != nil {
		t.Fatalf("Inherited: %v", err)
	}
	if len(got) != 1 || got[0] != 7 {
		t.Fatalf("got %v, want [7]", got)
	}
}
