package tenant

import (
	"context"
	"errors"
	"testing"
)

// planStore is a plan lookup keyed by tenant id, plus a call counter so the
// "1+depth reads" contract is asserted rather than assumed.
type planStore struct {
	plans map[string]Entitlements
	calls []ID
	err   error
}

func newPlanStore(plans map[string]Entitlements) *planStore {
	return &planStore{plans: plans}
}

func (p *planStore) ForTenant(_ context.Context, tenantID ID) (Entitlements, error) {
	p.calls = append(p.calls, tenantID)
	if p.err != nil {
		return Entitlements{}, p.err
	}
	return p.plans[tenantID.String()], nil
}

// hierarchy seeds group → org → team, so a child has two ancestors.
func hierarchy(t *testing.T) *MemStore {
	t.Helper()
	s := NewMemStore()
	s.Seed(Descriptor{ID: "group", Status: StatusActive})
	s.Seed(Descriptor{ID: "org", ParentID: "group", Status: StatusActive})
	s.Seed(Descriptor{ID: "team", ParentID: "org", Status: StatusActive})
	return s
}

func TestInheritingEntitlements_UnionsTheWholeChain(t *testing.T) {
	plans := newPlanStore(map[string]Entitlements{
		"team":  {},
		"org":   {SCIMEnabled: true, MaxIdPConnections: 2},
		"group": {SSOEnabled: true, MaxIdPConnections: 5},
	})
	store := InheritingEntitlements(plans, hierarchy(t))

	got, err := store.ForTenant(context.Background(), New("team"))
	if err != nil {
		t.Fatalf("ForTenant: %v", err)
	}
	want := Entitlements{SSOEnabled: true, SCIMEnabled: true, MaxIdPConnections: 5}
	if got != want {
		t.Fatalf("effective = %+v, want %+v", got, want)
	}
}

// The child's own purchase is never given away.
func TestInheritingEntitlements_KeepsWhatTheChildBought(t *testing.T) {
	plans := newPlanStore(map[string]Entitlements{
		"org":  {SSOEnabled: true, MaxIdPConnections: 3},
		"team": {SCIMEnabled: true, MaxIdPConnections: 40},
	})
	store := InheritingEntitlements(plans, hierarchy(t))

	got, err := store.ForTenant(context.Background(), New("team"))
	if err != nil {
		t.Fatalf("ForTenant: %v", err)
	}
	if !got.SCIMEnabled || !got.SSOEnabled {
		t.Fatalf("effective = %+v, want both capabilities", got)
	}
	if got.MaxIdPConnections != 40 {
		t.Fatalf("cap = %d, want the child's own 40", got.MaxIdPConnections)
	}
}

// The pair the sketch got wrong, end to end through the decorator: a child that
// bought a capped plan keeps its cap when the ancestor bought nothing, and loses
// it to UNLIMITED when the ancestor actually bought an uncapped one.
func TestInheritingEntitlements_CapDependsOnWhetherTheAncestorBoughtAnything(t *testing.T) {
	t.Run("ancestor bought nothing: the child's cap stands", func(t *testing.T) {
		plans := newPlanStore(map[string]Entitlements{
			"team": {SSOEnabled: true, MaxIdPConnections: 3},
			"org":  {}, // no plan row: the zero record
		})
		got, err := InheritingEntitlements(plans, hierarchy(t)).ForTenant(context.Background(), New("team"))
		if err != nil {
			t.Fatalf("ForTenant: %v", err)
		}
		if got.MaxIdPConnections != 3 {
			t.Fatalf("cap = %d, want 3 — a parent that bought nothing must not lift the child's cap "+
				"to unlimited", got.MaxIdPConnections)
		}
	})

	t.Run("ancestor bought unlimited: the child gets unlimited", func(t *testing.T) {
		plans := newPlanStore(map[string]Entitlements{
			"team": {MaxIdPConnections: 3},
			"org":  {SSOEnabled: true, MaxIdPConnections: 0}, // bought something, uncapped
		})
		got, err := InheritingEntitlements(plans, hierarchy(t)).ForTenant(context.Background(), New("team"))
		if err != nil {
			t.Fatalf("ForTenant: %v", err)
		}
		if got.MaxIdPConnections != 0 {
			t.Fatalf("cap = %d, want 0 (unlimited) — an ancestor that bought unlimited widens", got.MaxIdPConnections)
		}
		if !got.SSOEnabled {
			t.Fatal("the ancestor's capability did not carry")
		}
	})
}

// A root tenant has nothing to inherit: the decorator returns exactly what the
// inner store said.
func TestInheritingEntitlements_RootTenantIsPassthrough(t *testing.T) {
	own := Entitlements{SSOEnabled: true, MaxIdPConnections: 7}
	plans := newPlanStore(map[string]Entitlements{"group": own})
	store := InheritingEntitlements(plans, hierarchy(t))

	got, err := store.ForTenant(context.Background(), New("group"))
	if err != nil {
		t.Fatalf("ForTenant: %v", err)
	}
	if got != own {
		t.Fatalf("effective = %+v, want the tenant's own %+v", got, own)
	}
	if len(plans.calls) != 1 {
		t.Fatalf("inner store read %d times, want 1 (a root has no ancestors to read)", len(plans.calls))
	}
}

// The uncached contract, asserted so nobody assumes a cache that is not there.
func TestInheritingEntitlements_ReadsOnePlusDepthTimesAndCachesNothing(t *testing.T) {
	plans := newPlanStore(map[string]Entitlements{"group": {SSOEnabled: true}})
	store := InheritingEntitlements(plans, hierarchy(t))

	if _, err := store.ForTenant(context.Background(), New("team")); err != nil {
		t.Fatalf("ForTenant: %v", err)
	}
	if len(plans.calls) != 3 {
		t.Fatalf("reads = %d, want 3 (own + 2 ancestors)", len(plans.calls))
	}
	if _, err := store.ForTenant(context.Background(), New("team")); err != nil {
		t.Fatalf("ForTenant (second): %v", err)
	}
	if len(plans.calls) != 6 {
		t.Fatalf("reads after a second call = %d, want 6 — the decorator caches nothing, "+
			"and a gated deployment wraps it in its own cache", len(plans.calls))
	}
}

func TestInheritingEntitlements_UnsetAndSingleOnlyAskTheInnerStore(t *testing.T) {
	for name, id := range map[string]ID{"zero": {}, "single": Single} {
		t.Run(name, func(t *testing.T) {
			plans := newPlanStore(map[string]Entitlements{"": {SSOEnabled: true}})
			spy := newSpyStore()
			store := InheritingEntitlements(plans, spy)

			got, err := store.ForTenant(context.Background(), id)
			if err != nil {
				t.Fatalf("ForTenant: %v", err)
			}
			if !got.SSOEnabled {
				t.Fatalf("effective = %+v, want the inner store's answer untouched", got)
			}
			if spy.calls != 0 {
				t.Fatalf("the hierarchy store was read %d times; unset and single-tenant must not walk", spy.calls)
			}
			if len(plans.calls) != 1 {
				t.Fatalf("inner reads = %d, want exactly 1", len(plans.calls))
			}
		})
	}
}

// Every error fails the lookup. Nothing is read as "inherited nothing", because
// the gate denies on error and an empty answer would look like a tenant that
// bought nothing.
func TestInheritingEntitlements_ErrorsFailTheLookup(t *testing.T) {
	t.Run("inner store", func(t *testing.T) {
		boom := errors.New("billing is down")
		plans := newPlanStore(map[string]Entitlements{})
		plans.err = boom
		store := InheritingEntitlements(plans, hierarchy(t))

		if _, err := store.ForTenant(context.Background(), New("team")); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the inner store's error", err)
		}
	})

	t.Run("corrupt parentage", func(t *testing.T) {
		s := NewMemStore()
		s.Seed(Descriptor{ID: "team", ParentID: "vanished", Status: StatusActive})
		store := InheritingEntitlements(newPlanStore(nil), s)

		_, err := store.ForTenant(context.Background(), New("team"))
		if !errors.Is(err, ErrHierarchyDangling) {
			t.Fatalf("err = %v, want ErrHierarchyDangling to propagate rather than read as \"no ancestors\"", err)
		}
	})

	t.Run("unknown tenant", func(t *testing.T) {
		store := InheritingEntitlements(newPlanStore(nil), NewMemStore())

		if _, err := store.ForTenant(context.Background(), New("ghost")); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})
}

func TestInheritingEntitlements_PanicsOnMisconfiguration(t *testing.T) {
	t.Run("nil inner", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("a nil inner store did not panic; it would report every tenant as having bought nothing")
			}
		}()
		InheritingEntitlements(nil, hierarchy(t))
	})
	t.Run("nil hierarchy", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("a nil hierarchy store did not panic; it would silently inherit nothing")
			}
		}()
		InheritingEntitlements(newPlanStore(nil), nil)
	})
}
