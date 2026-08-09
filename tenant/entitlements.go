package tenant

import "context"

// Entitlements are what a tenant has PURCHASED — the plan tier, expressed
// as capabilities rather than as a plan name.
//
// Capabilities, not tiers, on purpose. "enterprise" means nothing to a
// gate; SSOEnabled does. A tenant moved between plans, or given one
// feature as a trial, changes a boolean here and no gate anywhere has to
// learn a new plan name.
//
// This is NOT authorization. authz answers "may this subject do this to
// this resource"; this answers "did this customer buy the feature at
// all". A tenant admin with every permission in the system still cannot
// use SSO their plan does not include, and a gate that conflated the two
// would report one as the other.
type Entitlements struct {
	// SSOEnabled allows federated login (OIDC/SAML) for the tenant.
	SSOEnabled bool

	// SCIMEnabled allows directory provisioning for the tenant.
	SCIMEnabled bool

	// MaxIdPConnections caps how many identity providers the tenant may
	// configure. ZERO MEANS UNLIMITED, not zero-allowed — the zero value
	// of this struct is a tenant with nothing purchased and no cap, which
	// is the safe combination: the booleans deny on their own, so an
	// unset cap cannot be the thing that accidentally permits.
	MaxIdPConnections int
}

// AllowsAnotherIdP reports whether a tenant already holding `current`
// identity providers may configure one more.
//
// The check is deliberately a method on the record rather than logic at
// each call site: "is 0 unlimited?" is exactly the question two call
// sites answer differently, and one of those answers locks every tenant
// out of SSO.
func (e Entitlements) AllowsAnotherIdP(current int) bool {
	if e.MaxIdPConnections <= 0 {
		return true
	}
	return current < e.MaxIdPConnections
}

// EntitlementStore is the plan-lookup port. The application implements it
// over its own billing or plan table; tamper names no column.
//
// Sentinel contract: there ISN'T one, deliberately. A tenant with no plan
// row is not a not-found to be signalled — it is a tenant that has bought
// nothing, and returning the zero Entitlements says exactly that. An
// implementation that returns an error for a missing row is also correct,
// because callers DENY on error; both readings fail closed.
//
// Implementations MUST be safe for concurrent use, and should be cheap or
// cached: a gate consults this on every gated request.
type EntitlementStore interface {
	// ForTenant returns the tenant's purchased capabilities.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	ForTenant(ctx context.Context, tenantID ID) (Entitlements, error)
}
