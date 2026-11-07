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
	//
	// Asserted field by field rather than against audit.ActorService(...): comparing to the
	// same constructor is circular — a change inside it would satisfy both sides of the
	// comparison and the test would agree while the stored payload moved.
	if res.actor.Type != audit.ActorTypeServiceAccount {
		t.Errorf("actor.Type = %q, want %q", res.actor.Type, audit.ActorTypeServiceAccount)
	}
	if res.actor.UserID != "sa-platform" || res.actor.Name != "provisioner" {
		t.Errorf("actor identity = %q/%q, want sa-platform/provisioner", res.actor.UserID, res.actor.Name)
	}
	if res.actor.TenantID != "" {
		t.Errorf("actor.TenantID = %q, want empty — a platform credential has no home tenant", res.actor.TenantID)
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

// A validator that vouches for nobody is not a credential. Refused by BOTH gates, because the
// refusal lives in the authentication half they share — and refused BEFORE the handler, so no
// mutation is attributed to an anonymous service account.
func TestGates_RefuseACredentialWithNoIdentity(t *testing.T) {
	// The boundary is deliberately EXACTLY the empty string, and this comment is here so the next
	// reader does not "fix" it into a trim. A Principal.ID is opaque and app-defined — tamper does
	// not parse identifiers anywhere else and should not start here — so an ID of "   " is a value
	// the app's validator vouched for, however unhelpful the log line looks. What is refused is
	// the ZERO value: the id a validator produces when it forgot to set one, which is the shape
	// that leaves GetPrincipal reporting false and the audit row nameless.
	cases := map[string]Principal{
		"empty":            {},
		"scope but no id":  {Scope: PrincipalScopePlatform},
		"tenant but no id": {TenantID: "acme"},
	}
	for name, cred := range cases {
		t.Run(name, func(t *testing.T) {
			for gateName, mw := range map[string]func(http.Handler) http.Handler{
				"tenant gate":   RequireServiceAccount(staticValidator(cred)),
				"platform gate": RequirePlatformServiceAccount(staticValidator(cred)),
			} {
				res := runGate(t, mw)
				if res.status != http.StatusUnauthorized {
					t.Errorf("%s accepted %+v (status %d) — a credential that identifies nobody "+
						"must not reach a handler", gateName, cred, res.status)
				}
				if res.hasP {
					t.Errorf("%s stashed an identity-less principal on %s", gateName, name)
				}
			}
		})
	}
}

// The footgun, pinned deliberately: the tenant scope's VALUE is the empty string, so an app that
// spells it out gets a 401 it cannot distinguish from a bad token. Pinned so that nobody later
// turns "tenant" into an accepted alias — a second spelling is how deny-by-default grows a hole.
func TestTenantGate_RefusesTheExplicitTenantSpelling(t *testing.T) {
	res := runGate(t, RequireServiceAccount(staticValidator(
		Principal{ID: "sa", TenantID: "acme", Scope: PrincipalScope("tenant")})))

	if res.status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — leave Scope unset for a tenant credential", res.status)
	}
}

// SCIM mounted under the platform gate: a platform credential has no tenant, so there is no
// tenant to hand a store. Before the platform gate existed this was unreachable — tenantOfPrincipal
// resolved through FromStored, which always answers a VALID id. The fix is that the misconfiguration
// says so instead of quietly passing an unset tenant down to fourteen store call sites.
func TestScimTenant_DeniesUnderThePlatformGate(t *testing.T) {
	var (
		reached   bool
		recovered any
		got       tenant.ID
	)
	h := RequirePlatformServiceAccount(staticValidator(
		Principal{ID: "sa-platform", Scope: PrincipalScopePlatform}))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() { recovered = recover() }()
			got = scimTenant(r.Context())
			reached = true
			w.WriteHeader(http.StatusOK)
		}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer tok")
	h.ServeHTTP(rec, req)

	if recovered == nil {
		t.Fatalf("scimTenant returned %q (Valid=%v) and the handler continued (status %d, reached=%v); "+
			"an unset tenant must not be handed to a store", got, got.Valid(), rec.Code, reached)
	}
}

// The other side: SCIM under its OWN gate, single-tenant included, still resolves.
func TestScimTenant_ResolvesUnderTheTenantGate(t *testing.T) {
	for name, cred := range map[string]Principal{
		"multi-tenant":  {ID: "sa", TenantID: "acme"},
		"single-tenant": {ID: "sa"},
	} {
		t.Run(name, func(t *testing.T) {
			var got tenant.ID
			h := RequireServiceAccount(staticValidator(cred))(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = scimTenant(r.Context()) }))
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
			req.Header.Set("Authorization", "Bearer tok")
			h.ServeHTTP(rec, req)

			if !got.Valid() {
				t.Errorf("scimTenant = %q (Valid=false) for a tenant credential", got)
			}
		})
	}
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
