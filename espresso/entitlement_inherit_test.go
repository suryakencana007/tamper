package espresso

import (
	"net/http"
	"strings"
	"testing"

	"github.com/suryakencana007/tamper/tenant"
)

// Slice 12b — entitlement inheritance, proved at the surface it is meant to
// serve. The point of choosing a decorator was that RequireEntitlement needs no
// change at all, so the test that matters is the one where only the store handed
// to the unchanged gate differs.

func TestEntitlement_InheritedPlanOpensTheSameGate(t *testing.T) {
	plans := &entStore{byTenant: map[string]tenant.Entitlements{
		"group": {SSOEnabled: true},
		// "org" bought nothing, so it has no row at all — the commonest shape
		// in a reseller deployment.
	}}
	hierarchy := tenant.NewMemStore()
	hierarchy.Seed(tenant.Descriptor{ID: "group", Status: tenant.StatusActive})
	hierarchy.Seed(tenant.Descriptor{ID: "org", ParentID: "group", Status: tenant.StatusActive})

	t.Run("the plain store denies, as it does today", func(t *testing.T) {
		var ran bool
		rec := callAsTenant(gatedRoute(plans, CapabilitySSO, &ran), "org", true)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 — the child itself bought nothing", rec.Code)
		}
		if ran {
			t.Fatal("the gated route ran for a tenant with no plan")
		}
	})

	t.Run("the decorator opens it", func(t *testing.T) {
		var ran bool
		inherited := tenant.InheritingEntitlements(plans, hierarchy)
		rec := callAsTenant(gatedRoute(inherited, CapabilitySSO, &ran), "org", true)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 — the group bought SSO", rec.Code)
		}
		if !ran {
			t.Fatal("the gated route did not run; the inherited plan did not open the gate")
		}
	})
}

// A capability the chain does not hold is still refused, and still with the
// FEATURE_NOT_ENABLED code — inheritance must not turn a 403 into a 404 or make
// an unpurchased feature look like a miss.
func TestEntitlement_InheritanceDoesNotWidenBeyondTheChain(t *testing.T) {
	plans := &entStore{byTenant: map[string]tenant.Entitlements{"group": {SCIMEnabled: true}}}
	hierarchy := tenant.NewMemStore()
	hierarchy.Seed(tenant.Descriptor{ID: "group", Status: tenant.StatusActive})
	hierarchy.Seed(tenant.Descriptor{ID: "org", ParentID: "group", Status: tenant.StatusActive})

	var ran bool
	inherited := tenant.InheritingEntitlements(plans, hierarchy)
	rec := callAsTenant(gatedRoute(inherited, CapabilitySSO, &ran), "org", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — the group bought SCIM, not SSO", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), EntitlementDeniedCode) {
		t.Fatalf("body = %s, want the stable %q code", rec.Body.String(), EntitlementDeniedCode)
	}
}
