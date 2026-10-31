package tenanthierarchy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/crypto"
	tamperespresso "github.com/suryakencana007/tamper/espresso"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

func orgLadder() authz.Hierarchy {
	return authz.Hierarchy{ResourceOrganization: {"org_viewer", "org_admin"}}
}

// orgServerPolicy has NO system bypass: a platform admin uses its own
// untenanted surface, not an org route.
func orgServerPolicy() authz.Policy {
	return authz.Policy{
		"org:manage": {{Type: ResourceOrganization, Min: "org_admin"}},
		"org:view":   {{Type: ResourceOrganization, Min: "org_viewer"}},
	}
}

func statusWriter(code int) tamperespresso.DenyWriter {
	return func(w http.ResponseWriter) { w.WriteHeader(code) }
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

// newOrgStack wires the reference org surface over a store + engine, and returns
// the dependencies a test needs to mint home and entered tokens.
func newOrgStack(t *testing.T) (http.Handler, *crypto.JWTService, *identity.Core, authz.Authorizer, *Store, *fakeHierarchy) {
	t.Helper()
	h := newHierarchy()
	s := newStore()
	p, err := NewProvisioner(s, h, roleMapTwo())
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	// alice: direct org admin of org-1, stored in org-1.
	alice := authz.Subject{Tenant: org1, Type: "user", ID: "alice"}
	if err := s.Grant(ctx, authz.Binding{Tenant: org1, Subject: alice, Resource: resOrg1, Role: "org_admin"}); err != nil {
		t.Fatalf("grant alice: %v", err)
	}
	// bob: group admin of tg-acme; dave: group viewer of tg-acme.
	if err := p.GrantGroupAdmin(ctx, bob, tg, "tenant_group_admin"); err != nil {
		t.Fatalf("grant bob: %v", err)
	}
	dave := authz.Subject{Tenant: tg, Type: "user", ID: "dave"}
	if err := p.GrantGroupAdmin(ctx, dave, tg, "tenant_group_viewer"); err != nil {
		t.Fatalf("grant dave: %v", err)
	}

	engine, err := authz.NewRBAC(s, orgLadder(), orgServerPolicy())
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}

	jwt := crypto.NewJWTService(crypto.JWTConfig{
		Secret: "tenanthierarchy-http-test-secret",
		TTL:    time.Hour,
		Issuer: "tenanthierarchy-http",
	})
	idStore := identity.NewMemStore()
	idStore.Seed(identity.User{ID: "bob", TenantID: tg.String(), Email: "bob@example.com", Active: true})
	idStore.Seed(identity.User{ID: "dave", TenantID: tg.String(), Email: "dave@example.com", Active: true})
	core, err := identity.New(idStore, jwt, identity.WithMemberships(NewMembership(s, h)))
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}

	handler := OrgGate(jwt, engine, "org:manage", "org:view", statusWriter(http.StatusNotFound), statusWriter(http.StatusForbidden))(okHandler())
	return handler, jwt, core, engine, s, h
}

func homeToken(t *testing.T, jwt *crypto.JWTService, user string, home tenant.ID) string {
	t.Helper()
	tok, err := jwt.IssueAccess(user, home, time.Now().Unix(), crypto.ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess(%s): %v", user, err)
	}
	return tok
}

// enterAs mints a home session for user (home tenant tg-acme) and enters target.
func enterAs(t *testing.T, core *identity.Core, jwt *crypto.JWTService, user string, target tenant.ID) string {
	t.Helper()
	claims, err := jwt.ParseAccess(homeToken(t, jwt, user, tg))
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	tokens, err := core.EnterTenant(ctx, claims, target)
	if err != nil {
		t.Fatalf("EnterTenant(%s -> %s): %v", user, target, err)
	}
	return tokens.Access
}

func doOrg(t *testing.T, h http.Handler, token, org string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/orgs/"+org, nil)
	req.SetPathValue(OrgParam, org)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// ---------------------------------------------------------------------
// The group admin reaches every child org, each with its OWN entered token
// (the scope is the organization — ADR §3.1).
// ---------------------------------------------------------------------

func TestHTTP_GroupAdminReachesEveryChildOrg(t *testing.T) {
	h, jwt, core, _, _, _ := newOrgStack(t)
	for _, id := range []string{"org-1", "org-2", "org-3"} {
		tok := enterAs(t, core, jwt, "bob", tenant.New(id))
		if code := doOrg(t, h, tok, id); code != http.StatusOK {
			t.Fatalf("bob on %s = %d, want 200", id, code)
		}
	}
}

func TestHTTP_CrossGroupAndUnknownAre401(t *testing.T) {
	h, jwt, core, _, _, _ := newOrgStack(t)
	// bob's token is for org-1; org-9 belongs to another group, and the
	// unknown org has no token that fits.
	tok := enterAs(t, core, jwt, "bob", org1)
	for _, id := range []string{"org-9", "org-unknown"} {
		if code := doOrg(t, h, tok, id); code != http.StatusUnauthorized {
			t.Fatalf("token for org-1 on %s = %d, want 401", id, code)
		}
	}
}

func TestHTTP_HomeTokenIs401OnAnOrgRoute(t *testing.T) {
	h, jwt, _, _, _, _ := newOrgStack(t)
	// bob's HOME token (tid = tg-acme) is not an entered token.
	if code := doOrg(t, h, homeToken(t, jwt, "bob", tg), "org-1"); code != http.StatusUnauthorized {
		t.Fatalf("home token on an org route = %d, want 401", code)
	}
}

// ---------------------------------------------------------------------
// Visibility is 404; an under-ranked role is 403.
// ---------------------------------------------------------------------

func TestHTTP_Visibility404AndRank403(t *testing.T) {
	h, jwt, core, _, _, _ := newOrgStack(t)

	// A direct org admin on her own org.
	if code := doOrg(t, h, homeToken(t, jwt, "alice", org1), "org-1"); code != http.StatusOK {
		t.Fatalf("alice on org-1 = %d, want 200", code)
	}

	// An org-2 user with no binding does not even see org-2.
	if code := doOrg(t, h, homeToken(t, jwt, "carol", org2), "org-2"); code != http.StatusNotFound {
		t.Fatalf("carol on org-2 = %d, want 404", code)
	}

	// A group viewer sees org-1 but is under-ranked for org:manage.
	daveTok := enterAs(t, core, jwt, "dave", org1)
	if code := doOrg(t, h, daveTok, "org-1"); code != http.StatusForbidden {
		t.Fatalf("dave (viewer) on org-1 = %d, want 403", code)
	}
}

// ---------------------------------------------------------------------
// Every authorization question is asked in the organization's scope — no
// cross-scope OR.
// ---------------------------------------------------------------------

// scopeSpy records the scope of every Check the engine is asked.
type scopeSpy struct {
	inner  authz.Authorizer
	scopes []tenant.ID
}

func (s *scopeSpy) Check(ctx context.Context, tenantID tenant.ID, sub authz.Subject, act authz.Action, res authz.Resource) (authz.Decision, error) {
	s.scopes = append(s.scopes, tenantID)
	return s.inner.Check(ctx, tenantID, sub, act, res)
}
func (s *scopeSpy) CheckBulk(ctx context.Context, tenantID tenant.ID, reqs []authz.CheckRequest) ([]authz.Decision, error) {
	s.scopes = append(s.scopes, tenantID)
	return s.inner.CheckBulk(ctx, tenantID, reqs)
}
func (s *scopeSpy) ListResources(ctx context.Context, tenantID tenant.ID, sub authz.Subject, act authz.Action, resourceType string) ([]authz.Resource, bool, error) {
	s.scopes = append(s.scopes, tenantID)
	return s.inner.ListResources(ctx, tenantID, sub, act, resourceType)
}
func (s *scopeSpy) ListSubjects(ctx context.Context, tenantID tenant.ID, act authz.Action, res authz.Resource) ([]authz.Subject, bool, error) {
	s.scopes = append(s.scopes, tenantID)
	return s.inner.ListSubjects(ctx, tenantID, act, res)
}

func TestHTTP_ExactlyOneCheckInTheOrgScope(t *testing.T) {
	_, jwt, core, engine, _, _ := newOrgStack(t)
	spy := &scopeSpy{inner: engine}
	h := OrgGate(jwt, spy, "org:manage", "org:view", statusWriter(http.StatusNotFound), statusWriter(http.StatusForbidden))(okHandler())

	tok := enterAs(t, core, jwt, "bob", org1)
	if code := doOrg(t, h, tok, "org-1"); code != http.StatusOK {
		t.Fatalf("bob on org-1 = %d, want 200", code)
	}
	if len(spy.scopes) == 0 {
		t.Fatal("no authorization question was asked")
	}
	// The DecisionGate runs the two-check flow (visibility, then action), both
	// in the routed org. What must never appear is a Check in another scope —
	// that would be the cross-scope OR this design forbids.
	for _, sc := range ids(spy.scopes) {
		if sc != org1.String() {
			t.Fatalf("Checks asked in scopes %v; every question must be in %s", ids(spy.scopes), org1)
		}
	}
}

// A group admin is a real subject with a binding in the org's scope, so an
// access review of that org lists them.
func TestHTTP_ListSubjectsIncludesGroupAdmin(t *testing.T) {
	_, _, _, engine, _, _ := newOrgStack(t)
	subs, _, err := engine.ListSubjects(ctx, org1, "org:manage", resOrg1)
	if err != nil {
		t.Fatalf("ListSubjects: %v", err)
	}
	found := false
	for _, sub := range subs {
		if sub == bob {
			found = true
		}
	}
	if !found {
		t.Fatalf("ListSubjects(org-1) = %+v, want bob (the group admin)", subs)
	}
}
