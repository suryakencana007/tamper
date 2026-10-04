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

// Where a tenant is missing the gate refuses. It never fills one in.
func TestRequireDecision_RefusesWhenATenantIsMissing(t *testing.T) {
	j := tenantJWT(t)
	acme := tenant.New(tenantA)
	pass := func(next http.Handler) http.Handler { return next }

	for _, tc := range []struct {
		name   string
		gate   func(http.Handler) http.Handler
		bearer string
		want   int
	}{
		// A pooled route that forgot its tenant gate: a wiring bug, said
		// loudly, not a decision taken in the single scope.
		{"a tenant token and no tenant gate", pass, tokenFor(t, j, acme), http.StatusInternalServerError},
		// PinTenant checks no token, so these reach the gate.
		{"another tenant's token behind PinTenant", PinTenant(routeTo(tenantA)), tokenFor(t, j, tenant.New(tenantB)), http.StatusUnauthorized},
		{"a single-tenant token behind PinTenant", PinTenant(routeTo(tenantA)), tokenFor(t, j, tenant.Single), http.StatusUnauthorized},
		{"a token entered elsewhere behind PinTenant", PinTenant(routeTo(tenantA)), enteredToken(t, j, tenantB), http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &recordingAuthorizer{allow: true}
			h := RequireAuth(j)(tc.gate(decisionGate(a)(http.HandlerFunc(noContent))))
			if code := serveDecision(h, tc.bearer); code != tc.want {
				t.Errorf("status %d, want %d", code, tc.want)
			}
			if len(a.scopes) != 0 {
				t.Errorf("the Authorizer was asked (scope %q, subject %+v); the gate should have refused first", a.scopes[0], a.subjects[0])
			}
		})
	}

	// A user id with no claims: nothing says where the subject is from.
	t.Run("a user id in the context without claims", func(t *testing.T) {
		a := &recordingAuthorizer{allow: true}
		h := decisionGate(a)(http.HandlerFunc(noContent))
		req := httptest.NewRequest(http.MethodPost, "/things", nil)
		req = req.WithContext(ContextWithUserID(req.Context(), "u-1"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status %d, want 500", rec.Code)
		}
		if len(a.scopes) != 0 {
			t.Error("the Authorizer was asked about a subject with no claims")
		}
	})
}

// The ghost probe is told where the subject is stored. A denied guest
// is looked up at home, so they are denied (403) and not mistaken for a
// deleted user, and a local user who shares the id is not consulted.
func TestRequireDecision_GhostProbeLooksInTheHomeTenant(t *testing.T) {
	j := tenantJWT(t)
	acme, platform := tenant.New(tenantA), tenant.New(tenantPlatform)

	type probe struct {
		home tenant.ID
		id   string
	}
	var probes []probe
	gate := RequireDecision(DecisionGate{
		Authorizer:   &recordingAuthorizer{allow: false},
		Label:        "thing role",
		SubjectType:  "user",
		ResourceType: "thing",
		Action:       "thing.update",
		WriteDenied:  denied,
		WriteGhost:   func(w http.ResponseWriter) { w.WriteHeader(http.StatusGone) },
		// The admin exists in platform and nowhere else.
		UserExists: func(_ context.Context, home tenant.ID, id string) (bool, error) {
			probes = append(probes, probe{home, id})
			return home == platform && id == "u-1", nil
		},
	})
	h := RequireAuth(j)(RequireTenantAllowEntered(routeTo(tenantA))(gate(http.HandlerFunc(noContent))))

	if code := serveDecision(h, enteredToken(t, j, tenantA)); code != http.StatusForbidden {
		t.Errorf("a denied guest: status %d, want 403 (denied), not the ghost response", code)
	}
	if len(probes) != 1 || probes[0] != (probe{platform, "u-1"}) {
		t.Errorf("probe calls = %+v, want one, for u-1 in platform", probes)
	}

	// acme's own user, who (in this fixture) has no row: a real ghost.
	probes = nil
	if code := serveDecision(h, tokenFor(t, j, acme)); code != http.StatusGone {
		t.Errorf("a denied local user with no row: status %d, want the ghost response", code)
	}
	if len(probes) != 1 || probes[0] != (probe{acme, "u-1"}) {
		t.Errorf("probe calls = %+v, want one, for u-1 in acme", probes)
	}
}
