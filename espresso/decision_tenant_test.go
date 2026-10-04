package espresso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/tenant"
)

// Phase 8b: RequireDecision asks its question with two tenants. The
// scope is the routed tenant; the subject's tenant is where the token
// says its subject is from.

// recordingAuthorizer captures what the gate asked.
type recordingAuthorizer struct {
	authz.Authorizer
	scopes   []tenant.ID
	subjects []authz.Subject
	allow    bool
}

func (a *recordingAuthorizer) Check(_ context.Context, scope tenant.ID, sub authz.Subject, _ authz.Action, _ authz.Resource) (authz.Decision, error) {
	a.scopes = append(a.scopes, scope)
	a.subjects = append(a.subjects, sub)
	return authz.Decision{Allowed: a.allow}, nil
}

func denied(w http.ResponseWriter) { w.WriteHeader(http.StatusForbidden) }

func decisionGate(a authz.Authorizer) func(http.Handler) http.Handler {
	return RequireDecision(DecisionGate{
		Authorizer:   a,
		Label:        "thing role",
		SubjectType:  "user",
		ResourceType: "thing",
		Action:       "thing.update",
		WriteDenied:  denied,
	})
}

func serveDecision(h http.Handler, bearer string) int {
	req := httptest.NewRequest(http.MethodPost, "/things", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestRequireDecision_AsksInTheRoutedScopeWithTheTokensHomeTenant(t *testing.T) {
	j := tenantJWT(t)
	acme, platform := tenant.New(tenantA), tenant.New(tenantPlatform)
	pass := func(next http.Handler) http.Handler { return next }

	for _, tc := range []struct {
		name      string
		gate      func(http.Handler) http.Handler
		bearer    string
		wantScope tenant.ID
		wantHome  tenant.ID
	}{
		{"single-tenant deployment, no tenant gate", pass, tokenFor(t, j, tenant.Single), tenant.Single, tenant.Single},
		{"the tenant's own user", RequireTenant(routeTo(tenantA)), tokenFor(t, j, acme), acme, acme},
		{"a platform admin who entered", RequireTenantAllowEntered(routeTo(tenantA)), enteredToken(t, j, tenantA), acme, platform},
		// A pooled route that forgot its tenant gate. The scope is the
		// single tenant, where nothing is granted to an acme subject.
		{"a tenant token on a route with no tenant gate", pass, tokenFor(t, j, acme), tenant.Single, acme},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &recordingAuthorizer{allow: true}
			h := RequireAuth(j)(tc.gate(decisionGate(a)(http.HandlerFunc(noContent))))
			if code := serveDecision(h, tc.bearer); code != http.StatusNoContent {
				t.Fatalf("status %d, want 204", code)
			}
			if len(a.scopes) != 1 {
				t.Fatalf("the Authorizer was asked %d time(s), want 1", len(a.scopes))
			}
			if a.scopes[0] != tc.wantScope {
				t.Errorf("scope = %q, want %q", a.scopes[0], tc.wantScope)
			}
			want := authz.Subject{Tenant: tc.wantHome, Type: "user", ID: "u-1"}
			if a.subjects[0] != want {
				t.Errorf("subject = %+v, want %+v", a.subjects[0], want)
			}
		})
	}
}

// The whole point, with the real engine: a platform admin who is an
// admin at home is nobody in the tenant they entered, until that tenant
// grants them something.
func TestRequireDecision_GuestNeedsABindingInTheTenantEntered(t *testing.T) {
	j := tenantJWT(t)
	acme, platform := tenant.New(tenantA), tenant.New(tenantPlatform)
	admin := authz.Subject{Tenant: platform, Type: "user", ID: "u-1"}
	thing := authz.Resource{Type: "thing"}

	store := authz.NewMemStore(
		// Admin at home. This must open nothing in acme.
		authz.Binding{Tenant: platform, Subject: admin, Resource: thing, Role: "admin"},
		// acme has a user with the SAME id, who is an admin in acme.
		// The guest must not be taken for them.
		authz.Binding{Tenant: acme, Subject: authz.Subject{Tenant: acme, Type: "user", ID: "u-1"}, Resource: thing, Role: "admin"},
	)
	rbac, err := authz.NewRBAC(store,
		authz.Hierarchy{"thing": {"viewer", "admin"}},
		authz.Policy{"thing.update": {{Type: "thing", Min: "admin"}}})
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}
	h := RequireAuth(j)(RequireTenantAllowEntered(routeTo(tenantA))(decisionGate(rbac)(http.HandlerFunc(noContent))))
	entered := enteredToken(t, j, tenantA)

	if code := serveDecision(h, entered); code != http.StatusForbidden {
		t.Fatalf("a guest with no binding in acme: status %d, want 403", code)
	}
	// acme's own u-1 is allowed: the fixture is not simply denying all.
	if code := serveDecision(h, tokenFor(t, j, acme)); code != http.StatusNoContent {
		t.Fatalf("acme's own admin: status %d, want 204", code)
	}

	store.Grant(authz.Binding{Tenant: acme, Subject: admin, Resource: thing, Role: "admin"})
	if code := serveDecision(h, entered); code != http.StatusNoContent {
		t.Errorf("a guest granted admin in acme: status %d, want 204", code)
	}
}

// An acme token on a route with no tenant gate is denied by the real
// engine, although the same subject is an admin in acme.
func TestRequireDecision_NoTenantGateDeniesATenantToken(t *testing.T) {
	j := tenantJWT(t)
	acme := tenant.New(tenantA)
	store := authz.NewMemStore(authz.Binding{
		Tenant: acme, Subject: authz.Subject{Tenant: acme, Type: "user", ID: "u-1"},
		Resource: authz.Resource{Type: "thing"}, Role: "admin",
	})
	rbac, err := authz.NewRBAC(store,
		authz.Hierarchy{"thing": {"viewer", "admin"}},
		authz.Policy{"thing.update": {{Type: "thing", Min: "admin"}}})
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}
	h := RequireAuth(j)(decisionGate(rbac)(http.HandlerFunc(noContent)))
	if code := serveDecision(h, tokenFor(t, j, acme)); code != http.StatusForbidden {
		t.Errorf("status %d, want 403", code)
	}
}
