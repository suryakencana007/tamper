package tenant

import "context"

// Entitlement inheritance: a tenant's effective plan is its own, widened by what
// its ancestors bought (../docs/phases/PHASE12-TENANT-INHERITANCE-SKETCH.md §4.1, decision D2).
//
// This is the first consumer of [Ancestors], and it is deliberately the smallest
// one: no engine, no cache, no lock — a decorator over the port the gate already
// takes.

// InheritingEntitlements wraps a tenant's own entitlement lookup so that it also
// sees what its ancestors purchased.
//
// It is a DECORATOR, and that is the whole design. `espresso.RequireEntitlement`
// takes an [EntitlementStore] and calls [EntitlementStore.ForTenant]; nothing in
// it changes, and opting in is literal — pass the plain store and get today's
// behaviour, pass this and get inheritance.
//
// The result is the EFFECT, not the PURCHASE. A tenant's own record remains what
// it bought, and an admin screen that shows "your plan" must call the inner store
// or it will show a customer a plan they never paid for. The decorator can only
// widen: every answer it returns grants at least what the wrapped store granted.
//
// Three properties a caller should know before wiring it:
//
//   - It is UNCACHED. A call is 1+depth reads — the tenant's own, then one per
//     ancestor. [EntitlementStore]'s contract already says an implementation
//     should be cheap or cached "because a gate consults this on every gated
//     request", and this one is neither; a deployment that gates per request
//     wraps it in its own cache, exactly as it would the plain store.
//   - Any error fails the lookup: the inner store's, the walk's, or an
//     ancestor's. Nothing is read as "inherited nothing", because a gate denies
//     on error and a silent empty answer would be indistinguishable from a
//     tenant that bought nothing.
//   - An unset ID and [Single] reach the inner store through
//     [Ancestors]'s no-walk cases: no ancestors are added, and what the inner
//     store answers for them is what goes to the gate. Whether that denies is the
//     inner store's decision, not this one's.
//
// Both arguments are required and a nil either way panics: a nil store would
// silently inherit nothing, and a nil inner would silently report every tenant as
// having bought nothing.
func InheritingEntitlements(inner EntitlementStore, s Store) EntitlementStore {
	if inner == nil {
		panic("tenant: InheritingEntitlements requires an inner EntitlementStore — " +
			"a nil one would report every tenant as having bought nothing")
	}
	if s == nil {
		panic("tenant: InheritingEntitlements requires a Store — a nil one would resolve " +
			"no ancestors, a hierarchy that silently never inherits")
	}
	return inheriting{inner: inner, store: s}
}

type inheriting struct {
	inner EntitlementStore
	store Store
}

var _ EntitlementStore = inheriting{}

// ForTenant implements EntitlementStore: the tenant's own record, unioned with
// each ancestor's, nearest first.
//
// Order does not change the result — [Entitlements.Union] is commutative — but it
// fixes which ancestor's store error surfaces first, and nearest-first is the one
// an operator debugging a chain expects to see.
func (i inheriting) ForTenant(ctx context.Context, tenantID ID) (Entitlements, error) {
	own, err := i.inner.ForTenant(ctx, tenantID)
	if err != nil {
		return Entitlements{}, err
	}
	chain, err := Ancestors(ctx, i.store, tenantID)
	if err != nil {
		return Entitlements{}, err
	}
	effective := own
	for _, ancestor := range chain {
		inherited, err := i.inner.ForTenant(ctx, ancestor)
		if err != nil {
			return Entitlements{}, err
		}
		effective = effective.Union(inherited)
	}
	return effective, nil
}
