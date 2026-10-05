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
// scope is the tenant the gate itself resolves; the subject's tenant is
// where the token says its subject is from. The gate needs RequireAuth
// in front of it and nothing else.

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

// thingGate is the gate under test for the routed tenant.
func thingGate(a authz.Authorizer, routed string, allowEntered bool) DecisionGate {
	return DecisionGate{
		Authorizer:   a,
		Label:        "thing role",
		Tenant:       routeTo(routed),
		AllowEntered: allowEntered,
		SubjectType:  "user",
		ResourceType: "thing",
		Action:       "thing.update",
		WriteDenied:  denied,
	}
}

func serveDecision(h http.Handler, bearer string) int {
	req := httptest.NewRequest(http.MethodPost, "/things", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestRequireDecision_AsksInItsOwnScopeWithTheTokensHomeTenant(t *testing.T) {
	j := tenantJWT(t)
	acme, platform := tenant.New(tenantA), tenant.New(tenantPlatform)

	for _, tc := range []struct {
		name         string
		routed       string
		allowEntered bool
		bearer       string
		wantScope    tenant.ID
		wantHome     tenant.ID
	}{
		{"a single-tenant application", "", false, tokenFor(t, j, tenant.Single), tenant.Single, tenant.Single},
		{"the tenant's own user", tenantA, false, tokenFor(t, j, acme), acme, acme},
		{"the tenant's own user on a route that also takes guests", tenantA, true, tokenFor(t, j, acme), acme, acme},
		{"a platform admin who entered", tenantA, true, enteredToken(t, j, tenantA), acme, platform},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &recordingAuthorizer{allow: true}
			var seen tenant.ID
			var seenOK bool
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen, seenOK = TenantFromContext(r.Context())
				w.WriteHeader(http.StatusNoContent)
			})
			h := RequireAuth(j)(RequireDecision(thingGate(a, tc.routed, tc.allowEntered))(inner))
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
			// What runs behind the gate sees the scope it decided in.
			if !seenOK || seen != tc.wantScope {
				t.Errorf("TenantFromContext behind the gate = %q, %v; want %q", seen, seenOK, tc.wantScope)
			}
		})
	}
}

// The token must fit the gate's tenant. Everything else is the 401
// RequireTenant writes, and the Authorizer is never asked. There is no
// path that guesses a tenant.
func TestRequireDecision_RefusesATokenThatDoesNotFitItsTenant(t *testing.T) {
	j := tenantJWT(t)
	acme := tenant.New(tenantA)

	// The reference refusal: what RequireTenant writes for a wrong tenant.
	ref := serveGate(j, RequireTenant(routeTo(tenantA)), tokenFor(t, j, tenant.New(tenantB)), noContent)

	for _, tc := range []struct {
		name         string
		routed       string
		allowEntered bool
		bearer       string
	}{
		{"another tenant's token", tenantA, false, tokenFor(t, j, tenant.New(tenantB))},
		{"a single-tenant token on a tenant's route", tenantA, false, tokenFor(t, j, tenant.Single)},
		{"a tenant token on a single-tenant route", "", false, tokenFor(t, j, acme)},
		{"a token entered here, where guests are not invited", tenantA, false, enteredToken(t, j, tenantA)},
		{"a token entered elsewhere, where guests are invited", tenantA, true, enteredToken(t, j, tenantB)},
		{"an entered token on a single-tenant route", "", true, enteredToken(t, j, tenantA)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &recordingAuthorizer{allow: true}
			h := RequireAuth(j)(RequireDecision(thingGate(a, tc.routed, tc.allowEntered))(http.HandlerFunc(noContent)))
			req := httptest.NewRequest(http.MethodPost, "/things", nil)
			req.Header.Set("Authorization", "Bearer "+tc.bearer)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != ref.Code || rec.Body.String() != ref.Body.String() {
				t.Errorf("%d %s; want the wrong-tenant refusal %d %s", rec.Code, rec.Body.String(), ref.Code, ref.Body.String())
			}
			if len(a.scopes) != 0 {
				t.Errorf("the Authorizer was asked (scope %q, subject %+v); the gate should have refused first", a.scopes[0], a.subjects[0])
			}
		})
	}

	// A user id that reached the context without a token. Nothing says
	// where that subject is from, on any route.
	for name, routed := range map[string]string{"on a tenant's route": tenantA, "on a single-tenant route": ""} {
		t.Run("a user id without a token "+name, func(t *testing.T) {
			a := &recordingAuthorizer{allow: true}
			h := RequireDecision(thingGate(a, routed, true))(http.HandlerFunc(noContent))
			req := httptest.NewRequest(http.MethodPost, "/things", nil)
			req = req.WithContext(ContextWithUserID(req.Context(), "u-1"))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status %d, want 401", rec.Code)
			}
			if len(a.scopes) != 0 {
				t.Error("the Authorizer was asked about a subject with no token")
			}
		})
	}
}

// A gate that names no tenant is refused when it is built, not on a
// request (standing rule 4).
func TestRequireDecision_PanicsWithoutATenant(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("RequireDecision accepted a DecisionGate with no Tenant")
		}
	}()
	g := thingGate(&recordingAuthorizer{}, tenantA, false)
	g.Tenant = nil
	RequireDecision(g)
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
	h := RequireAuth(j)(RequireDecision(thingGate(rbac, tenantA, true))(http.HandlerFunc(noContent)))
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
	g := thingGate(&recordingAuthorizer{allow: false}, tenantA, true)
	g.WriteGhost = func(w http.ResponseWriter) { w.WriteHeader(http.StatusGone) }
	// The admin exists in platform and nowhere else.
	g.UserExists = func(_ context.Context, home tenant.ID, id string) (bool, error) {
		probes = append(probes, probe{home, id})
		return home == platform && id == "u-1", nil
	}
	h := RequireAuth(j)(RequireDecision(g)(http.HandlerFunc(noContent)))

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
