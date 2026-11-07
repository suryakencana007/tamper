package espresso

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/tenant"
)

// TD-12: a service account had exactly one tenant, so platform-level automation — provisioning
// a tenant, syncing across tenants — had no principal it could use. The fix is a scope on the
// credential and a second gate, with the two gates mutually exclusive.
//
// Every refusal in these tests asserts the SAME 401 and the same body as a bad token, because
// that is the property that makes a scope check worth having: a caller probing with a real
// tenant credential must not be able to tell "wrong scope" from "wrong secret".

type gateResult struct {
	status    int
	body      string
	principal Principal
	hasP      bool
	actor     audit.Actor
	routed    tenant.ID
	hasTenant bool
}

func runGate(t *testing.T, mw func(http.Handler) http.Handler) gateResult {
	t.Helper()
	var res gateResult
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res.principal, res.hasP = GetPrincipal(r.Context())
		res.actor = audit.ActorFromContext(r.Context())
		res.routed, res.hasTenant = tenantOfPrincipal(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer machine-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res.status = rec.Code
	res.body = rec.Body.String()
	return res
}

func staticValidator(p Principal) ServiceAccountValidator {
	return ValidatorFunc(func(context.Context, string) (Principal, error) { return p, nil })
}

// The shape the item asked for: a principal that is valid on platform routes.
func TestPlatformGate_AcceptsAPlatformCredential(t *testing.T) {
	platform := Principal{ID: "sa-platform", Name: "provisioner", Scope: PrincipalScopePlatform}
	res := runGate(t, RequirePlatformServiceAccount(staticValidator(platform)))

	if res.status != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s; a platform credential must reach the handler", res.status, res.body)
	}
	if !res.hasP || res.principal.Scope != PrincipalScopePlatform {
		t.Fatalf("principal = %+v (stashed=%v); the platform principal must be on the context", res.principal, res.hasP)
	}
	// The actor is a service account with NO home tenant. tenant.Single would be a claim about
	// the deployment, which a platform credential is not entitled to make.
	if want := audit.ActorService("sa-platform", "provisioner", tenant.ID{}); res.actor != want {
		t.Errorf("actor = %+v, want %+v — a platform credential has no home tenant", res.actor, want)
	}
	// And it can never be handed to a store as a routed tenant.
	if res.hasTenant {
		t.Errorf("tenantOfPrincipal = %q (ok) for a platform credential; it has no tenant", res.routed)
	}
}

// The exclusion, both directions. This is the whole point: one process, two authorities.
func TestGates_AreMutuallyExclusive(t *testing.T) {
	tenantCred := Principal{ID: "sa-tenant", TenantID: "acme", Name: "sync"}
	platformCred := Principal{ID: "sa-platform", Name: "provisioner", Scope: PrincipalScopePlatform}

	t.Run("a tenant credential cannot reach the platform surface", func(t *testing.T) {
		res := runGate(t, RequirePlatformServiceAccount(staticValidator(tenantCred)))
		if res.status != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", res.status)
		}
		if res.hasP {
			t.Error("the tenant principal was stashed on a platform route")
		}
	})

	// The case the first version of this file missed. A tenant credential does NOT have to name
	// a tenant — a single-tenant deployment's service account has TenantID "" — so a platform
	// gate that only checks "has no tenant" would admit it. Found by a mutant that survived:
	// the original fixture always had a TenantID, which made the guard look sufficient.
	t.Run("a SINGLE-TENANT tenant credential cannot reach the platform surface", func(t *testing.T) {
		res := runGate(t, RequirePlatformServiceAccount(staticValidator(Principal{ID: "sa-single"})))
		if res.status != http.StatusUnauthorized {
			t.Fatalf("status = %d, body = %s; an unscoped credential is a TENANT credential, "+
				"however empty its tenant, and must not reach a platform route", res.status, res.body)
		}
		if res.hasP {
			t.Error("the single-tenant principal was stashed on a platform route")
		}
	})

	t.Run("a platform credential cannot read a tenant's directory", func(t *testing.T) {
		res := runGate(t, RequireServiceAccount(staticValidator(platformCred)))
		if res.status != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 — a platform credential must not satisfy the tenant gate", res.status)
		}
		if res.hasP {
			t.Error("the platform principal was stashed on a tenant route")
		}
	})

	t.Run("both refusals are indistinguishable from a bad token", func(t *testing.T) {
		bad := runGate(t, RequireServiceAccount(ValidatorFunc(
			func(context.Context, string) (Principal, error) { return Principal{}, ErrInvalidCredential })))
		wrongScope := runGate(t, RequireServiceAccount(staticValidator(platformCred)))
		platformWithTenant := runGate(t, RequirePlatformServiceAccount(staticValidator(
			Principal{ID: "sa-platform", TenantID: "acme", Scope: PrincipalScopePlatform})))

		if wrongScope.status != bad.status || wrongScope.body != bad.body {
			t.Errorf("wrong scope answers %d %s; a bad token answers %d %s — a probe can tell them apart",
				wrongScope.status, wrongScope.body, bad.status, bad.body)
		}
		if platformWithTenant.status != bad.status || platformWithTenant.body != bad.body {
			t.Errorf("ambiguous credential answers %d %s, want the bad-token answer %d %s",
				platformWithTenant.status, platformWithTenant.body, bad.status, bad.body)
		}
	})
}

// A platform credential that also names a tenant is ambiguous, and ambiguity on a credential is
// how a scope check becomes decoration.
func TestPlatformGate_RefusesATenantOnAPlatformCredential(t *testing.T) {
	res := runGate(t, RequirePlatformServiceAccount(staticValidator(
		Principal{ID: "sa", TenantID: "acme", Scope: PrincipalScopePlatform})))

	if res.status != http.StatusUnauthorized || res.hasP {
		t.Fatalf("status = %d (stashed=%v); a platform credential with a home tenant must be refused", res.status, res.hasP)
	}
}

// Deny by default extends to scopes this package has never heard of: neither gate accepts them,
// so an app cannot invent one and accidentally get authority.
func TestGates_RefuseAnUnknownScope(t *testing.T) {
	unknown := Principal{ID: "sa", Scope: PrincipalScope("superuser"), TenantID: "acme"}
	for name, mw := range map[string]func(http.Handler) http.Handler{
		"tenant gate":   RequireServiceAccount(staticValidator(unknown)),
		"platform gate": RequirePlatformServiceAccount(staticValidator(unknown)),
	} {
		if res := runGate(t, mw); res.status != http.StatusUnauthorized || res.hasP {
			t.Errorf("%s accepted scope %q (status %d)", name, unknown.Scope, res.status)
		}
	}
}

// The old behaviour, exactly: no scope set means a tenant credential, and both the single-tenant
// and multi-tenant shapes still work. This is the additive half of the change.
func TestTenantGate_UnchangedForACredentialWithNoScope(t *testing.T) {
	t.Run("multi-tenant", func(t *testing.T) {
		res := runGate(t, RequireServiceAccount(staticValidator(Principal{ID: "sa", TenantID: "acme"})))
		if res.status != http.StatusNoContent {
			t.Fatalf("status = %d, body = %s — an unscoped credential is a tenant credential", res.status, res.body)
		}
		if !res.hasTenant || res.routed.String() != "acme" {
			t.Errorf("routed tenant = %q (ok=%v), want acme", res.routed, res.hasTenant)
		}
	})
	t.Run("single-tenant", func(t *testing.T) {
		res := runGate(t, RequireServiceAccount(staticValidator(Principal{ID: "sa"})))
		if res.status != http.StatusNoContent || !res.hasTenant || !res.routed.IsSingle() {
			t.Errorf("single-tenant credential: status %d, tenant %q (ok=%v)", res.status, res.routed, res.hasTenant)
		}
	})
}

// The credential-failure split is the same on both gates — a backend outage is a 500, a wrong
// token a 401 — because the platform gate reuses the authentication half rather than restating
// it. If it ever restates it, this test is what notices.
func TestPlatformGate_CredentialFailureSemantics(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"wrong token", ErrInvalidCredential, http.StatusUnauthorized},
		{"backend failure", errors.New("validator down"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := ValidatorFunc(func(context.Context, string) (Principal, error) { return Principal{}, tc.err })
			if res := runGate(t, RequirePlatformServiceAccount(v)); res.status != tc.want {
				t.Errorf("status = %d, want %d", res.status, tc.want)
			}
		})
	}

	t.Run("no header", func(t *testing.T) {
		h := RequirePlatformServiceAccount(staticValidator(Principal{ID: "sa", Scope: PrincipalScopePlatform}))(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("handler ran without a credential") }))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}
