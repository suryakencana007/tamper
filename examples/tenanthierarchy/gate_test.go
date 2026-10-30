package tenanthierarchy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/crypto"
	tamperespresso "github.com/suryakencana007/tamper/espresso"
	"github.com/suryakencana007/tamper/tenant"
)

// ---------------------------------------------------------------------
// HTTP integration: the whole point of ADR-0001 is that the hierarchy
// lives in the BindingStore and the espresso call-site does not change.
// These tests wire the REAL stack —
//
//	RequireAuth → RequireTenant(TenantGroupResolve) → RequireDecision
//
// — with real JWTs, so the claim is proven on the wire rather than only
// at the authz.RBAC layer. They also pin the two-layer deny discipline:
// a cross-group / unknown org is a 401 at the tenant gate (byte-identical
// to an invalid token), while a visible-but-unauthorized org is a 404 and
// a visible-but-under-ranked role is a 403.
// ---------------------------------------------------------------------

func gateHierarchy() authz.Hierarchy {
	return authz.Hierarchy{
		"organization": {"org_viewer", "org_admin"},
		"system":       {"platform_admin"},
	}
}

func gatePolicy() authz.Policy {
	return authz.Policy{
		"org:view":        {{Type: "organization", Min: "org_viewer"}},
		"org:manage":      {{Type: "organization", Min: "org_admin"}},
		"platform:manage": {{Type: "system", Min: "platform_admin"}},
	}
}

func statusWriter(code int) tamperespresso.DenyWriter {
	return func(w http.ResponseWriter) { w.WriteHeader(code) }
}

func gateTestJWT(t *testing.T) *crypto.JWTService {
	t.Helper()
	return crypto.NewJWTService(crypto.JWTConfig{
		Secret: "adr-0001-gate-test-secret",
		TTL:    time.Hour,
		Issuer: "tenanthierarchy-gate-test",
	})
}

// gateToken mints an access token. tid == "" mints a Single token (the
// platform-admin / untenanted case); any other tid is a named tenant —
// here, the TENANT-GROUP id, per TenantGroupResolve's pin level.
func gateToken(t *testing.T, jwt *crypto.JWTService, userID, tid string) string {
	t.Helper()
	id := tenant.Single
	if tid != "" {
		id = tenant.New(tid)
	}
	tok, err := jwt.IssueAccess(userID, id, time.Now().Unix(), crypto.ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess(%q, %q): %v", userID, tid, err)
	}
	return tok
}

// gateStore builds the store with the viewer mapping too, so dave
// (tenant_group_viewer) exercises the view-yes/manage-no 403 path.
func gateStore(t *testing.T) (*Store, *fakeHierarchy) {
	t.Helper()
	hier := newFakeHierarchy()
	s, err := New(baseBindings(), hier, roleMapWithViewer())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, hier
}

// okHandler reports 200 and writes the pinned tenant id as its body, so
// a test can assert not just "allowed" but "pinned to the group".
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tid, ok := tamperespresso.TenantFromContext(r.Context()); ok {
			_, _ = w.Write([]byte(tid.String()))
		}
		w.WriteHeader(http.StatusOK)
	})
}

func orgChain(t *testing.T, jwt *crypto.JWTService, store *Store, hier OrgHierarchy) http.Handler {
	t.Helper()
	engine, err := authz.NewRBAC(store, gateHierarchy(), gatePolicy())
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}
	gate := tamperespresso.RequireDecision(tamperespresso.DecisionGate{
		Authorizer:       engine,
		Label:            "organization role",
		SubjectType:      "user",
		ResourceType:     "organization",
		ResourceIDFrom:   "org_id",
		Action:           "org:manage",
		VisibilityAction: "org:view",
		WriteNotVisible:  statusWriter(http.StatusNotFound),
		WriteDenied:      statusWriter(http.StatusForbidden),
	})
	return tamperespresso.RequireAuth(jwt)(
		tamperespresso.RequireTenant(TenantGroupResolve(hier, "org_id"))(
			gate(okHandler())))
}

func doOrg(t *testing.T, h http.Handler, token, orgID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/orgs/"+orgID, nil)
	req.SetPathValue("org_id", orgID)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestIntegration_TenantGroupAdminSpansChildOrgsOnTheWire(t *testing.T) {
	jwt := gateTestJWT(t)
	store, hier := gateStore(t)
	h := orgChain(t, jwt, store, hier)

	// bob's token is pinned to the group; one token, all three child orgs.
	tok := gateToken(t, jwt, "bob", "tg-acme")
	for _, org := range []string{"org-1", "org-2", "org-3"} {
		rec := doOrg(t, h, tok, org)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200 (body %q)", org, rec.Code, rec.Body.String())
		}
		if got := rec.Body.String(); got != "tg-acme" {
			t.Fatalf("%s: pinned tenant = %q, want %q", org, got, "tg-acme")
		}
	}
}

func TestIntegration_DenyDisciplineOnTheWire(t *testing.T) {
	jwt := gateTestJWT(t)
	store, hier := gateStore(t)
	h := orgChain(t, jwt, store, hier)

	cases := []struct {
		name string
		user string
		tid  string
		org  string
		want int
	}{
		// 401 at the tenant gate: cross-group, unknown, and root orgs are
		// indistinguishable from each other and from an invalid token.
		{"tg admin, another group's existing org", "bob", "tg-acme", "org-4", http.StatusUnauthorized},
		{"tg admin, unknown org", "bob", "tg-acme", "org-nope", http.StatusUnauthorized},
		{"tg admin, parentless root org", "bob", "tg-acme", "org-root", http.StatusUnauthorized},
		{"other group admin, org-1", "erin", "tg-other", "org-1", http.StatusUnauthorized},
		{"platform Single token on an org route", "carol", "", "org-1", http.StatusUnauthorized},

		// 200: same group, role satisfies both checks.
		{"org admin on own org", "alice", "tg-acme", "org-1", http.StatusOK},
		{"other group admin on own org-4", "erin", "tg-other", "org-4", http.StatusOK},

		// 404: in-group org the subject cannot even see (no org binding).
		{"org admin, sibling org not visible", "alice", "tg-acme", "org-2", http.StatusNotFound},

		// 403: visible (org:view passes) but under-ranked for org:manage.
		{"unmapped-into-viewer role, manage denied", "dave", "tg-acme", "org-1", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doOrg(t, h, gateToken(t, jwt, tc.user, tc.tid), tc.org)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestIntegration_MissingOrInvalidTokenIs401(t *testing.T) {
	jwt := gateTestJWT(t)
	store, hier := gateStore(t)
	h := orgChain(t, jwt, store, hier)

	if rec := doOrg(t, h, "", "org-1"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: status = %d, want 401", rec.Code)
	}
	if rec := doOrg(t, h, "not-a-jwt", "org-1"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token: status = %d, want 401", rec.Code)
	}
}

func TestIntegration_HierarchyErrorFailsClosedAtTenantGate(t *testing.T) {
	jwt := gateTestJWT(t)
	store, hier := gateStore(t)
	hier.err = errors.New("hierarchy store down")

	h := orgChain(t, jwt, store, hier)
	rec := doOrg(t, h, gateToken(t, jwt, "bob", "tg-acme"), "org-1")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — a resolver error must not let a request through", rec.Code)
	}
}

func TestIntegration_PlatformAdminUsesUntenantedSurface(t *testing.T) {
	jwt := gateTestJWT(t)
	store, _ := gateStore(t)
	engine, err := authz.NewRBAC(store, gateHierarchy(), gatePolicy())
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}
	gate := tamperespresso.RequireDecision(tamperespresso.DecisionGate{
		Authorizer:     engine,
		Label:          "platform role",
		SubjectType:    "user",
		ResourceType:   "system",
		ResourceIDFrom: "", // singleton / system-scope gate
		Action:         "platform:manage",
		WriteDenied:    statusWriter(http.StatusForbidden),
	})
	// No RequireTenant: /platform/** is the untenanted surface.
	h := tamperespresso.RequireAuth(jwt)(gate(okHandler()))

	cases := []struct {
		name string
		user string
		tid  string
		want int
	}{
		{"platform admin allowed", "carol", "", http.StatusOK},
		{"tenant-group admin denied", "bob", "tg-acme", http.StatusForbidden},
		{"org admin denied", "alice", "tg-acme", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/platform/tenants", nil)
			req.Header.Set("Authorization", "Bearer "+gateToken(t, jwt, tc.user, tc.tid))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestTenantGroupResolveRequiresArgs(t *testing.T) {
	mustPanic := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Fatalf("%s: want panic, got none", name)
			}
		}()
		fn()
	}

	mustPanic("nil OrgHierarchy", func() { TenantGroupResolve(nil, "org_id") })
	mustPanic("empty path param", func() { TenantGroupResolve(newFakeHierarchy(), "") })
}
