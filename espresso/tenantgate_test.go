package espresso

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
)

// Slice 7c-2 — the tenant gate. RequireAuth verifies the token;
// RequireTenant pins it to the tenant the route names.

func tenantJWT(t *testing.T) *crypto.JWTService {
	t.Helper()
	return crypto.NewJWTService(crypto.JWTConfig{
		Secret: "tamper-espresso-test-secret",
		TTL:    time.Hour,
		Issuer: "tamper-test",
	})
}

func tokenFor(t *testing.T, j *crypto.JWTService, tenantID tenant.ID) string {
	t.Helper()
	tok, err := j.IssueAccess("u-1", tenantID, time.Now().Unix(), crypto.ACRLocalPassword)
	if err != nil {
		t.Fatalf("issue for tenant %q: %v", tenantID, err)
	}
	return tok
}

// gated builds RequireAuth -> RequireTenant over a handler that records
// whether it ran and what tenant it saw.
func gated(j *crypto.JWTService, routeTenant string, ran *bool, seen *tenant.ID, seenOK *bool) http.Handler {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*ran = true
		*seen, *seenOK = TenantFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	return RequireAuth(j)(RequireTenant(func(*http.Request) string { return routeTenant })(inner))
}

func callWith(t *testing.T, h http.Handler, bearer string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, string(body)
}

// TestRequireTenant_Matrix walks every combination of routed tenant and
// token tenant. Only exact equality passes; absent, empty and mismatched
// all deny.
func TestRequireTenant_Matrix(t *testing.T) {
	j := tenantJWT(t)
	for _, tc := range []struct {
		name        string
		routeTenant string
		tokenTenant string
		wantStatus  int
	}{
		// The compatibility path: no tenant anywhere. This is the shape a
		// single-tenant deployment has today, and it must still pass.
		{"untenanted route, untenanted token", "", "", http.StatusOK},
		// Tenancy ON with a token that has no tid. This is where 7c-1's
		// legacy tolerance ends: absence is not a match.
		{"tenanted route, untenanted token", "acme", "", http.StatusUnauthorized},
		// A tenant token on a route that names no tenant.
		{"untenanted route, tenanted token", "", "acme", http.StatusUnauthorized},
		{"matching tenant", "acme", "acme", http.StatusOK},
		{"cross tenant", "globex", "acme", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ran, seenOK bool
			var seen tenant.ID
			h := gated(j, tc.routeTenant, &ran, &seen, &seenOK)
			code, _ := callWith(t, h, tokenFor(t, j, tenant.FromStored(tc.tokenTenant)))

			if code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusOK {
				if !ran {
					t.Error("handler did not run")
				}
				if !seenOK || seen != tenant.FromStored(tc.routeTenant) {
					t.Errorf("TenantFromContext = (%q, %v), want (%q, true)", seen, seenOK, tc.routeTenant)
				}
			} else if ran {
				t.Error("handler ran behind a denied gate")
			}
		})
	}
}

// TestRequireTenant_DenyBodyIsByteIdenticalToInvalidToken is the
// invariant this slice turns on. A cross-tenant deny must be
// indistinguishable from an ordinary invalid-token deny — same status,
// same bytes. Any difference tells a caller that its token is genuine
// and merely aimed at the wrong tenant, which is a tenant-existence
// oracle (§6.3).
func TestRequireTenant_DenyBodyIsByteIdenticalToInvalidToken(t *testing.T) {
	j := tenantJWT(t)
	var ran, seenOK bool
	var seen tenant.ID
	h := gated(j, "globex", &ran, &seen, &seenOK)

	// A real token for the wrong tenant.
	crossCode, crossBody := callWith(t, h, tokenFor(t, j, tenant.New("acme")))
	// A structurally invalid token — the reference rejection.
	badCode, badBody := callWith(t, h, "not-a-jwt")
	// An EXPIRED token, which the manifest names explicitly.
	expired := tenantJWT(t)
	expired.Testing().SetNow(func() time.Time { return time.Now().Add(-2 * time.Hour) })
	expCode, expBody := callWith(t, h, tokenFor(t, expired, tenant.New("globex")))

	if crossCode != badCode || crossCode != expCode {
		t.Errorf("statuses differ: cross-tenant %d, invalid %d, expired %d", crossCode, badCode, expCode)
	}
	if crossBody != badBody {
		t.Errorf("cross-tenant body differs from invalid-token body:\n cross: %s\n  bad:  %s", crossBody, badBody)
	}
	if crossBody != expBody {
		t.Errorf("cross-tenant body differs from expired-token body:\n cross: %s\n  exp:  %s", crossBody, expBody)
	}
}

// TestRequireTenant_DeniesWithoutRequireAuth is the programmer-error
// path, and the one shape that would otherwise let everything through:
// with no claims in context there is nothing to pin against, so the gate
// must deny rather than pass.
func TestRequireTenant_DeniesWithoutRequireAuth(t *testing.T) {
	ran := false
	h := RequireTenant(func(*http.Request) string { return "acme" })(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			ran = true
			w.WriteHeader(http.StatusOK)
		}))
	code, _ := callWith(t, h, "")
	if code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 — RequireTenant without RequireAuth must fail closed", code)
	}
	if ran {
		t.Error("handler ran with no claims in context")
	}
}

// TestRequireTenant_NilResolverPanics: a nil resolver is a gate that
// pins nothing. It fails at construction, not as traffic that looks
// ordinary (§6.4).
func TestRequireTenant_NilResolverPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("RequireTenant(nil) did not panic; a nil resolver would silently pin nothing")
		}
	}()
	_ = RequireTenant(nil)
}

// TestTenantFromContext_BareContext: absent is reported as absent, never
// as the single-tenant deployment. A handler that conflates the two
// turns a forgotten middleware into an unscoped query.
func TestTenantFromContext_BareContext(t *testing.T) {
	id, ok := TenantFromContext(t.Context())
	if ok || id.Valid() {
		t.Errorf("TenantFromContext(bare) = (%q, %v), want (unset, false)", id, ok)
	}
}
