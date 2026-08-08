package espresso

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/suryakencana007/tamper/tenant"
)

// Slice 7h-1 — entitlements. Gated at the route surface, never at boot,
// because a pooled process serves every plan tier at once.

type entStore struct {
	byTenant map[string]tenant.Entitlements
	err      error
}

var _ tenant.EntitlementStore = (*entStore)(nil)

func (s *entStore) ForTenant(_ context.Context, tenantID string) (tenant.Entitlements, error) {
	if s.err != nil {
		return tenant.Entitlements{}, s.err
	}
	return s.byTenant[tenantID], nil
}

// gatedRoute wraps a handler that records whether it ran.
func gatedRoute(store tenant.EntitlementStore, c Capability, ran *bool, opts ...EntitlementOption) http.Handler {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*ran = true
		w.WriteHeader(http.StatusOK)
	})
	return RequireEntitlement(store, c, TenantFromRoutedContext, opts...)(inner)
}

// callAsTenant drives the gate with a tenant pinned the way RequireTenant
// pins it.
func callAsTenant(h http.Handler, tenantID string, pinned bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/start/okta", nil)
	if pinned {
		req = req.WithContext(context.WithValue(req.Context(), tenantCtxKey{}, tenantID))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// --- the deny is 403 with a stable code -------------------------------

// TestEntitlement_DisabledCapabilityIs403NotFound is the invariant, and
// the inversion worth being explicit about. Everywhere else in this phase
// a deny is 404 so it cannot be told from a miss. Here the caller IS the
// tenant, the tenant exists, and the feature is simply not purchased —
// answering 404 would send an operator hunting a broken route when the
// real answer is "upgrade your plan".
func TestEntitlement_DisabledCapabilityIs403NotFound(t *testing.T) {
	store := &entStore{byTenant: map[string]tenant.Entitlements{
		"paid": {SSOEnabled: true},
		"free": {SSOEnabled: false},
	}}

	var ran bool
	h := gatedRoute(store, CapabilitySSO, &ran)

	rec := callAsTenant(h, "free", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — a disabled capability is not a missing route", rec.Code)
	}
	if rec.Code == http.StatusNotFound {
		t.Error("the gate answered 404; the tenant exists and needs to know why it was refused")
	}
	if ran {
		t.Error("the handler ran behind a denied gate")
	}
	if body := rec.Body.String(); !strings.Contains(body, EntitlementDeniedCode) {
		t.Errorf("deny body does not carry the stable code %q: %s", EntitlementDeniedCode, body)
	}
}

func TestEntitlement_EnabledCapabilityPasses(t *testing.T) {
	store := &entStore{byTenant: map[string]tenant.Entitlements{"paid": {SSOEnabled: true}}}
	var ran bool
	h := gatedRoute(store, CapabilitySSO, &ran)

	rec := callAsTenant(h, "paid", true)
	if rec.Code != http.StatusOK || !ran {
		t.Errorf("status = %d ran = %v, want 200/true — the gate denies everything", rec.Code, ran)
	}
}

// TestEntitlement_CapabilitiesAreIndependent: buying SCIM does not buy
// SSO. A gate that checked "any entitlement" would pass both.
func TestEntitlement_CapabilitiesAreIndependent(t *testing.T) {
	store := &entStore{byTenant: map[string]tenant.Entitlements{
		"scim-only": {SCIMEnabled: true, SSOEnabled: false},
	}}
	var ranSSO, ranSCIM bool

	if rec := callAsTenant(gatedRoute(store, CapabilitySSO, &ranSSO), "scim-only", true); rec.Code != http.StatusForbidden {
		t.Errorf("SSO gate status = %d, want 403 — SCIM entitlement opened the SSO route", rec.Code)
	}
	if rec := callAsTenant(gatedRoute(store, CapabilitySCIM, &ranSCIM), "scim-only", true); rec.Code != http.StatusOK {
		t.Errorf("SCIM gate status = %d, want 200", rec.Code)
	}
}

// --- every failure denies ---------------------------------------------

// TestEntitlement_StoreErrorDenies: an outage must not become a free
// upgrade. §6.2 — no error return may be read as allow.
func TestEntitlement_StoreErrorDenies(t *testing.T) {
	store := &entStore{
		byTenant: map[string]tenant.Entitlements{"paid": {SSOEnabled: true}},
		err:      errors.New("billing database is down"),
	}
	var ran bool
	rec := callAsTenant(gatedRoute(store, CapabilitySSO, &ran), "paid", true)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 — a store failure was read as permission", rec.Code)
	}
	if ran {
		t.Error("the handler ran despite the entitlement store failing")
	}
	if body := rec.Body.String(); strings.Contains(strings.ToLower(body), "billing database") {
		t.Errorf("the deny leaked the underlying failure: %s", body)
	}
}

// TestEntitlement_NoTenantDenies: nothing to look up a plan for.
func TestEntitlement_NoTenantDenies(t *testing.T) {
	store := &entStore{byTenant: map[string]tenant.Entitlements{"paid": {SSOEnabled: true}}}
	var ran bool
	rec := callAsTenant(gatedRoute(store, CapabilitySSO, &ran), "", false) // no pin

	if rec.Code != http.StatusForbidden || ran {
		t.Errorf("status = %d ran = %v, want 403/false — an unresolvable tenant was allowed",
			rec.Code, ran)
	}
}

// TestEntitlement_UnknownTenantDenies: a tenant with no plan row has
// bought nothing, which is the zero Entitlements — and the zero value
// denies every boolean capability.
func TestEntitlement_UnknownTenantDenies(t *testing.T) {
	store := &entStore{byTenant: map[string]tenant.Entitlements{"paid": {SSOEnabled: true}}}
	var ran bool
	rec := callAsTenant(gatedRoute(store, CapabilitySSO, &ran), "never-heard-of", true)
	if rec.Code != http.StatusForbidden || ran {
		t.Errorf("status = %d ran = %v, want 403/false", rec.Code, ran)
	}
}

// TestEntitlement_UnknownCapabilityDenies: a typo in a gate must not
// open the route it was meant to close.
func TestEntitlement_UnknownCapabilityDenies(t *testing.T) {
	store := &entStore{byTenant: map[string]tenant.Entitlements{
		"paid": {SSOEnabled: true, SCIMEnabled: true},
	}}
	var ran bool
	rec := callAsTenant(gatedRoute(store, Capability("sso-typo"), &ran), "paid", true)
	if rec.Code != http.StatusForbidden || ran {
		t.Errorf("status = %d ran = %v, want 403/false — an unknown capability was allowed",
			rec.Code, ran)
	}
}

// --- construction fails loudly ----------------------------------------

func TestEntitlement_NilStorePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("RequireEntitlement(nil store) did not panic; it would permit everything")
		}
	}()
	_ = RequireEntitlement(nil, CapabilitySSO, TenantFromRoutedContext)
}

func TestEntitlement_NilResolverPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("RequireEntitlement(nil resolver) did not panic; every request would " +
				"resolve to the empty tenant")
		}
	}()
	_ = RequireEntitlement(&entStore{}, CapabilitySSO, nil)
}

// --- the SCIM-shaped deny ---------------------------------------------

// TestEntitlement_SCIMDenyWriterUsesTheRFCEnvelope: a SCIM client
// fail-closes on an app-branded body, so the deny must be §3.12 shaped —
// same status, same meaning, different envelope.
func TestEntitlement_SCIMDenyWriterUsesTheRFCEnvelope(t *testing.T) {
	store := &entStore{byTenant: map[string]tenant.Entitlements{"free": {}}}
	var ran bool
	h := gatedRoute(store, CapabilitySCIM, &ran, WithEntitlementDenyWriter(WriteSCIMEntitlementDenied))

	rec := callAsTenant(h, "free", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/scim+json" {
		t.Errorf("content-type = %q, want application/scim+json", ct)
	}
	if body := rec.Body.String(); !strings.Contains(body, SchemaError) {
		t.Errorf("body is not a SCIM error envelope: %s", body)
	}
}

// --- MaxIdPConnections ------------------------------------------------

// TestEntitlement_MaxIdPConnectionsEnforcedOnCreate covers the count
// cap. The zero-is-unlimited reading is the part worth pinning: it is
// exactly the question two call sites answer differently, and the wrong
// answer locks every tenant out of SSO entirely.
func TestEntitlement_MaxIdPConnectionsEnforcedOnCreate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cap     int
		current int
		want    bool
	}{
		{"unlimited (zero) allows the first", 0, 0, true},
		{"unlimited (zero) allows the hundredth", 0, 99, true},
		{"negative is also unlimited", -1, 5, true},
		{"cap 1, none configured", 1, 0, true},
		{"cap 1, one configured", 1, 1, false},
		{"cap 3, two configured", 3, 2, true},
		{"cap 3, three configured", 3, 3, false},
		{"cap 3, somehow over", 3, 4, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := tenant.Entitlements{MaxIdPConnections: tc.cap}
			if got := e.AllowsAnotherIdP(tc.current); got != tc.want {
				t.Errorf("AllowsAnotherIdP(%d) with cap %d = %v, want %v",
					tc.current, tc.cap, got, tc.want)
			}
		})
	}
}

// TestEntitlement_ZeroValueBuysNothing: the zero Entitlements is a tenant
// that has purchased nothing. Its booleans must deny — an unset plan must
// not be the thing that accidentally permits.
func TestEntitlement_ZeroValueBuysNothing(t *testing.T) {
	var zero tenant.Entitlements
	if CapabilitySSO.allowed(zero) || CapabilitySCIM.allowed(zero) {
		t.Errorf("the zero Entitlements grants a capability: %+v", zero)
	}
}
