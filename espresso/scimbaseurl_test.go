package espresso

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Slice 7g-2 — per-tenant SCIM base URL. meta.location and $ref are
// ABSOLUTE URLs a SCIM client will follow, so rendering one tenant's
// resources under another's host hands a working link to the wrong
// place.

func perTenantSCIM(t *testing.T) *SCIMRoutes {
	t.Helper()
	store := newTenantSCIMStore()
	rt, err := NewSCIMRoutes(SCIMConfig{
		Prefix:            "/scim/v2",
		BaseURL:           "https://shared.test",
		MaxResults:        100,
		BulkMaxOperations: 50,
		MaxPayloadBytes:   1 << 20,
		Tenancy:           true,
		BaseURLForTenant: func(tenantID string) string {
			switch tenantID {
			case tenantA:
				return "https://acme.test"
			case tenantB:
				return "https://globex.test"
			}
			return ""
		},
	}, store, groupSide{s: store})
	if err != nil {
		t.Fatalf("NewSCIMRoutes: %v", err)
	}
	return rt
}

func locationOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var doc struct {
		Meta struct {
			Location string `json:"location"`
		} `json:"meta"`
	}
	if err := json.Unmarshal([]byte(bodyOf(t, rec)), &doc); err != nil {
		t.Fatalf("decode: %v (body %s)", err, bodyOf(t, rec))
	}
	return doc.Meta.Location
}

// --- distinct locations per tenant ------------------------------------

// TestSCIMBaseURL_TwoTenantsGetDistinctLocations is the invariant. Each
// tenant's own resource must render under that tenant's host.
func TestSCIMBaseURL_TwoTenantsGetDistinctLocations(t *testing.T) {
	rt := perTenantSCIM(t)

	a := asTenant(rt.UsersGet, tenantA, http.MethodGet, "/scim/v2/Users/u-a", "")
	b := asTenant(rt.UsersGet, tenantB, http.MethodGet, "/scim/v2/Users/u-b", "")
	if a.Code != http.StatusOK || b.Code != http.StatusOK {
		t.Fatalf("setup: statuses %d / %d", a.Code, b.Code)
	}

	locA, locB := locationOf(t, a), locationOf(t, b)
	if !strings.HasPrefix(locA, "https://acme.test/") {
		t.Errorf("tenant A location = %q, want the acme host", locA)
	}
	if !strings.HasPrefix(locB, "https://globex.test/") {
		t.Errorf("tenant B location = %q, want the globex host", locB)
	}
	if locA == locB {
		t.Errorf("both tenants rendered the same location: %q", locA)
	}
	// And neither leaks the other's host — a client following A's link
	// must never be sent to B.
	if strings.Contains(locA, "globex") {
		t.Errorf("tenant A's location points at tenant B: %q", locA)
	}
	if strings.Contains(locB, "acme") {
		t.Errorf("tenant B's location points at tenant A: %q", locB)
	}
}

// TestSCIMBaseURL_ListRefsAreTenantScoped: $ref inside a list page is
// the same absolute-link problem, one level down. A page of a hundred
// users is a hundred links.
func TestSCIMBaseURL_ListRefsAreTenantScoped(t *testing.T) {
	rt := perTenantSCIM(t)
	rec := asTenant(rt.UsersList, tenantA, http.MethodGet, "/scim/v2/Users", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, bodyOf(t, rec))
	}
	body := bodyOf(t, rec)
	if !strings.Contains(body, "https://acme.test/") {
		t.Errorf("list did not render acme's host: %s", body)
	}
	if strings.Contains(body, "globex.test") {
		t.Errorf("list rendered another tenant's host: %s", body)
	}
	if strings.Contains(body, "shared.test") {
		t.Errorf("list fell back to the process-wide host for a tenant that has its own: %s", body)
	}
}

// TestSCIMBaseURL_UnknownTenantFallsBackNotLeaks: a tenant the mapping
// does not know returns "", which falls through to the process-wide
// BaseURL. It must NOT inherit some other tenant's host.
func TestSCIMBaseURL_UnknownTenantFallsBackNotLeaks(t *testing.T) {
	rt := perTenantSCIM(t)

	// tenantA's own record, but asked for by a principal whose tenant the
	// mapping has no entry for: the store denies (404) and no URL is
	// rendered at all — the safe outcome.
	rec := asTenant(rt.UsersGet, "stranger", http.MethodGet, "/scim/v2/Users/u-a", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if body := bodyOf(t, rec); strings.Contains(body, "acme.test") || strings.Contains(body, "globex.test") {
		t.Errorf("the refusal leaked a tenant host: %s", body)
	}
}

// --- "" mode is byte-identical ----------------------------------------

// TestSCIMBaseURL_SingleTenantIsByteIdentical is the compatibility
// proof: a build with no per-tenant mapping renders exactly what it
// rendered before this slice, byte for byte.
func TestSCIMBaseURL_SingleTenantIsByteIdentical(t *testing.T) {
	cfg := SCIMConfig{
		Prefix: "/scim/v2", BaseURL: "https://panel.test", MaxResults: 100,
		BulkMaxOperations: 50, MaxPayloadBytes: 1 << 20,
	}
	before, err := NewSCIMRoutes(cfg, stubUserStore{}, stubGroupStore{})
	if err != nil {
		t.Fatalf("NewSCIMRoutes: %v", err)
	}
	// The same config PLUS a mapping that declines every tenant. The
	// fall-through must be exact, not merely similar.
	cfgWith := cfg
	cfgWith.BaseURLForTenant = func(string) string { return "" }
	after, err := NewSCIMRoutes(cfgWith, stubUserStore{}, stubGroupStore{})
	if err != nil {
		t.Fatalf("NewSCIMRoutes: %v", err)
	}

	for _, tc := range []struct {
		name, path string
		h1, h2     http.HandlerFunc
	}{
		{"ServiceProviderConfig", "/scim/v2/ServiceProviderConfig", before.ServiceProviderConfig, after.ServiceProviderConfig},
		{"UsersGet", "/scim/v2/Users/u-1", before.UsersGet, after.UsersGet},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r1 := httptest.NewRecorder()
			tc.h1(r1, httptest.NewRequest(http.MethodGet, tc.path, nil))
			r2 := httptest.NewRecorder()
			tc.h2(r2, httptest.NewRequest(http.MethodGet, tc.path, nil))

			if r1.Code != r2.Code {
				t.Fatalf("status differs: %d vs %d", r1.Code, r2.Code)
			}
			if got, want := bodyOf(t, r2), bodyOf(t, r1); got != want {
				t.Errorf("body drifted:\n before: %s\n  after: %s", want, got)
			}
		})
	}
}

// --- advertised == enforced, per tenant --------------------------------

// TestSCIMBaseURL_AdvertisedEqualsEnforcedPerTenant is the 4e-4 no-drift
// rule extended to tenancy. An advertised limit nothing enforces is
// worse than no limit: an IdP connector reads maxResults, sizes its
// paging to it, and silently truncates every sync if the server enforces
// something smaller.
//
// It asserts the two ends against each other rather than against a
// literal, so changing the config moves both or fails.
func TestSCIMBaseURL_AdvertisedEqualsEnforcedPerTenant(t *testing.T) {
	rt := perTenantSCIM(t)

	for _, tenant := range []string{tenantA, tenantB} {
		t.Run(tenant, func(t *testing.T) {
			// What this tenant is TOLD.
			spc := asTenant(rt.ServiceProviderConfig, tenant, http.MethodGet, "/scim/v2/ServiceProviderConfig", "")
			var adv struct {
				Filter struct {
					MaxResults int `json:"maxResults"`
				} `json:"filter"`
				Bulk struct {
					MaxPayloadSize int `json:"maxPayloadSize"`
				} `json:"bulk"`
				Meta struct {
					Location string `json:"location"`
				} `json:"meta"`
			}
			if err := json.Unmarshal([]byte(bodyOf(t, spc)), &adv); err != nil {
				t.Fatalf("decode SPC: %v", err)
			}

			// What this tenant actually GETS. Ask for far more than the
			// cap and check the page honours the advertised ceiling.
			list := asTenant(rt.UsersList, tenant, http.MethodGet,
				"/scim/v2/Users?count=99999", "")
			var page struct {
				ItemsPerPage int `json:"itemsPerPage"`
				Resources    []struct {
					ID string `json:"id"`
				} `json:"Resources"`
			}
			if err := json.Unmarshal([]byte(bodyOf(t, list)), &page); err != nil {
				t.Fatalf("decode list: %v (body %s)", err, bodyOf(t, list))
			}
			if len(page.Resources) > adv.Filter.MaxResults {
				t.Errorf("returned %d resources, advertised cap %d — the advertised limit is "+
					"not the enforced one", len(page.Resources), adv.Filter.MaxResults)
			}
			if adv.Filter.MaxResults != rt.cfg.MaxResults {
				t.Errorf("advertised maxResults %d != enforced %d", adv.Filter.MaxResults, rt.cfg.MaxResults)
			}
			if int64(adv.Bulk.MaxPayloadSize) != rt.cfg.MaxPayloadBytes {
				t.Errorf("advertised maxPayloadSize %d != enforced %d",
					adv.Bulk.MaxPayloadSize, rt.cfg.MaxPayloadBytes)
			}

			// And the discovery document itself points at this tenant's
			// host — a connector that reads SPC from acme must not be
			// handed globex's URL to follow.
			want := map[string]string{tenantA: "https://acme.test", tenantB: "https://globex.test"}[tenant]
			if !strings.HasPrefix(adv.Meta.Location, want+"/") {
				t.Errorf("SPC location = %q, want the %s host", adv.Meta.Location, want)
			}
		})
	}
}

// TestSCIMBaseURL_DiscoveryWorksUnauthenticated: the discovery endpoints
// are commonly mounted without the service-account gate so a connector
// can read capabilities before it holds a credential. The per-tenant
// resolver must not panic there — no principal means no tenant, which
// falls through to the process-wide host.
func TestSCIMBaseURL_DiscoveryWorksUnauthenticated(t *testing.T) {
	rt := perTenantSCIM(t)
	rec := httptest.NewRecorder()
	rt.ServiceProviderConfig(rec, httptest.NewRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if loc := locationOf(t, rec); !strings.HasPrefix(loc, "https://shared.test/") {
		t.Errorf("unauthenticated discovery location = %q, want the process-wide host", loc)
	}
}
