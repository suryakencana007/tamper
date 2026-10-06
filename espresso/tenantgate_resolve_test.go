package espresso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/suryakencana007/tamper/tenant"
)

// TD-28: a gate's resolver says whether it found a tenant. An empty
// answer is never the single tenant; the single tenant is said.

// unresolved are the ways a resolver can fail to name a tenant.
var unresolved = map[string]func(*http.Request) (tenant.ID, bool){
	"not resolved":            func(*http.Request) (tenant.ID, bool) { return tenant.ID{}, false },
	"resolved to the zero ID": func(*http.Request) (tenant.ID, bool) { return tenant.ID{}, true },
	"tenant.New of a lost path segment": func(*http.Request) (tenant.ID, bool) {
		return tenant.New(""), true
	},
}

// RequireTenant refuses a request whose tenant did not resolve with the
// refusal a wrong-tenant token gets, and the handler is not reached.
// The token that would have fitted a guessed single tenant is the one
// that is sent.
func TestRequireTenant_UnresolvedTenantIsRefused(t *testing.T) {
	j := tenantJWT(t)
	ref := serveGate(j, RequireTenant(routeTo(tenantA)), tokenFor(t, j, tenant.New(tenantB)), noContent)
	for how, resolve := range unresolved {
		for name, gate := range map[string]func(http.Handler) http.Handler{
			"RequireTenant":             RequireTenant(resolve),
			"RequireTenantAllowEntered": RequireTenantAllowEntered(resolve),
		} {
			t.Run(name+"/"+how, func(t *testing.T) {
				reached := false
				got := serveGate(j, gate, tokenFor(t, j, tenant.Single), func(w http.ResponseWriter, _ *http.Request) {
					reached = true
					w.WriteHeader(http.StatusNoContent)
				})
				if reached {
					t.Fatal("the handler ran although the tenant did not resolve")
				}
				if got.Code != ref.Code || got.Body.String() != ref.Body.String() {
					t.Errorf("%d %s; want the wrong-tenant refusal %d %s", got.Code, got.Body.String(), ref.Code, ref.Body.String())
				}
			})
		}
	}
}

// PinTenant, which runs before any token exists, answers a tenant that
// did not resolve with a 404 and does not reach the handler. A public
// route of a tenant that does not exist is a wrong path.
func TestPinTenant_UnresolvedTenantIs404(t *testing.T) {
	for how, resolve := range unresolved {
		t.Run(how, func(t *testing.T) {
			reached := false
			h := PinTenant(resolve)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusNoContent)
			}))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
			if reached {
				t.Fatal("the handler ran although the tenant did not resolve")
			}
			if rec.Code != http.StatusNotFound {
				t.Errorf("status %d, want 404", rec.Code)
			}
		})
	}

	// The single tenant, said, pins the single tenant.
	var seen tenant.ID
	var ok bool
	h := PinTenant(FixedRequestTenant(tenant.Single))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, ok = TenantFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != http.StatusNoContent || !ok || !seen.IsSingle() {
		t.Errorf("status %d pinned=%v tenant=%q; want 204 and the single tenant", rec.Code, ok, seen)
	}
}

// A gate fixed to no tenant is refused where it is built.
func TestFixedRequestTenant_PanicsOnAnUnsetID(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("FixedRequestTenant accepted the zero tenant.ID")
		}
	}()
	FixedRequestTenant(tenant.ID{})
}

// The service-account resolver reports the principal's tenant as a
// stored fact, "" being the single tenant, and nothing without a
// principal.
func TestTenantFromServiceAccount(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	if id, ok := TenantFromServiceAccount(req); ok || id.Valid() {
		t.Errorf("without a principal: %q, %v; want nothing", id, ok)
	}
	for stored, want := range map[string]tenant.ID{"": tenant.Single, "acme": tenant.New("acme")} {
		r := req.WithContext(context.WithValue(req.Context(), principalKey{}, Principal{ID: "sa-1", TenantID: stored}))
		if id, ok := TenantFromServiceAccount(r); !ok || id != want {
			t.Errorf("principal tenant %q: %q, %v; want %q", stored, id, ok, want)
		}
	}
}
