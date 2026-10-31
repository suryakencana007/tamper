package tenanthierarchy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/suryakencana007/espresso/v2/extractor"

	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/crypto"
	tamperespresso "github.com/suryakencana007/tamper/espresso"
	"github.com/suryakencana007/tamper/tenant"
)

// captureLogger is an audit.Logger that keeps the events it is given. The
// example has no audit DB, so the proof is the event's scope, actor tenant and
// type — not a hash chain.
type captureLogger struct {
	mu     sync.Mutex
	events []audit.Event
}

var _ audit.Logger = (*captureLogger)(nil)

func (c *captureLogger) Log(_ context.Context, e audit.Event) (audit.Event, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	return e, nil
}

func (c *captureLogger) List(context.Context, audit.Filter) (audit.Page, error) {
	return audit.Page{}, nil
}

func (c *captureLogger) ListScoped(context.Context, []string, audit.Filter) (audit.Page, error) {
	return audit.Page{}, nil
}

func (c *captureLogger) Verify(context.Context) (audit.VerifyResult, error) {
	return audit.VerifyResult{}, nil
}

func (c *captureLogger) PruneOlderThan(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (c *captureLogger) CountByActionSince(context.Context, time.Time) ([]audit.ActionCount, error) {
	return nil, nil
}

func (c *captureLogger) DeleteEventByID(context.Context, string) error { return nil }

func (c *captureLogger) Close() error { return nil }

func (c *captureLogger) snapshot() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]audit.Event, len(c.events))
	copy(out, c.events)
	return out
}

// operatorCtx is the request-shaped context provisioning runs in: RequireAuth
// has put the operator's actor in it.
func operatorCtx(user, home string) context.Context {
	return audit.WithActor(context.Background(), audit.Actor{
		Type:     audit.ActorTypeUser,
		UserID:   user,
		TenantID: home,
	})
}

// ---------------------------------------------------------------------
// Provisioning events: one event per operation, scope = the group,
// actor = the operator, level never stamped into Actor.Type.
// ---------------------------------------------------------------------

func TestProvisioningAudit_GrantAndRevoke(t *testing.T) {
	capture := &captureLogger{}
	p, _ := newP(t, newHierarchy(), roleMap())
	p.audit = capture

	op := operatorCtx("ops", "platform")
	if err := p.GrantGroupAdmin(op, bob, tg, groupRole()); err != nil {
		t.Fatalf("GrantGroupAdmin: %v", err)
	}
	if err := p.RevokeGroupAdmin(op, bob, tg); err != nil {
		t.Fatalf("RevokeGroupAdmin: %v", err)
	}

	evs := capture.snapshot()
	if len(evs) != 2 {
		t.Fatalf("events = %d, want 2 (grant, revoke)", len(evs))
	}
	grant, revoke := evs[0], evs[1]
	if grant.Action != ActionGrantGroupAdmin || revoke.Action != ActionRevokeGroupAdmin {
		t.Fatalf("actions = %q, %q", grant.Action, revoke.Action)
	}
	for _, ev := range evs {
		if ev.TenantID != tg.String() {
			t.Fatalf("event scope = %q, want the group %q", ev.TenantID, tg)
		}
		if ev.ResourceType != auditResourceType || ev.ResourceID != bob.ID {
			t.Fatalf("event resource = %s:%s, want %s:%s", ev.ResourceType, ev.ResourceID, auditResourceType, bob.ID)
		}
		if ev.Actor.UserID != "ops" || ev.Actor.TenantID != "platform" {
			t.Fatalf("actor = %+v, want the operator ops@platform", ev.Actor)
		}
		// The level is read from scope + role, never from the subject type.
		if ev.Actor.Type != audit.ActorTypeUser {
			t.Fatalf("actor type = %q, want %q", ev.Actor.Type, audit.ActorTypeUser)
		}
		if ev.ID == "" || ev.At.IsZero() {
			t.Fatalf("event id/at not stamped: %+v", ev)
		}
	}
}

func TestProvisioningAudit_MembershipChanges(t *testing.T) {
	capture := &captureLogger{}
	p, _ := newP(t, newHierarchy(), roleMap())
	p.audit = capture
	op := operatorCtx("ops", "platform")

	if err := p.GrantGroupAdmin(op, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	newOrg := tenant.New("org-4")
	p.hier.(*fakeHierarchy).setParent("org-4", "tg-acme")
	if err := p.AddOrg(op, tg, newOrg); err != nil {
		t.Fatalf("AddOrg: %v", err)
	}
	p.hier.(*fakeHierarchy).setParent("org-9", "tg-acme")
	if err := p.MoveOrg(op, org9, tgOther, tg); err != nil {
		t.Fatalf("MoveOrg: %v", err)
	}
	if err := p.RemoveOrg(op, org1, tg); err != nil {
		t.Fatalf("RemoveOrg: %v", err)
	}

	got := map[audit.Action]string{}
	for _, ev := range capture.snapshot() {
		got[ev.Action] = ev.TenantID + "|" + ev.ResourceID
	}
	want := map[audit.Action]string{
		ActionGrantGroupAdmin: tg.String() + "|" + bob.ID,
		ActionAddOrg:          tg.String() + "|org-4",
		ActionMoveOrg:         tg.String() + "|org-9",
		ActionRemoveOrg:       tg.String() + "|org-1",
	}
	for action, w := range want {
		if got[action] != w {
			t.Fatalf("%s = %q, want %q (all %v)", action, got[action], w, got)
		}
	}
}

// ---------------------------------------------------------------------
// An org mutation audits with the ORGANIZATION as scope and the
// tenant-group as the actor's home tenant.
// ---------------------------------------------------------------------

func TestOrgMutationAudit_ScopeIsOrgActorTenantIsGroup(t *testing.T) {
	capture := &captureLogger{}
	auditor := tamperespresso.NewAuditor(capture, nil)
	mutation := auditor.For(tamperespresso.MutationContext{
		Action:         "org.rename",
		ResourceType:   "organization",
		ResourceIDFrom: OrgParam,
	})(okHandler())

	h, jwt, core, _, _, _ := newOrgStackWith(t, mutation)
	tok := enterAs(t, core, jwt, "bob", org1)

	req := httptest.NewRequest(http.MethodPost, "/orgs/org-1", nil)
	// Two path-param stores: espresso's extractor feeds Auditor.For, Go's
	// PathValue feeds DecisionGate.
	req = extractor.SetPathParams(req, extractor.PathParams{OrgParam: "org-1"})
	req.SetPathValue(OrgParam, "org-1")
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mutation = %d, want 200", rec.Code)
	}

	evs := capture.snapshot()
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	ev := evs[0]
	if ev.TenantID != org1.String() {
		t.Fatalf("event scope = %q, want the org %q", ev.TenantID, org1)
	}
	if ev.Actor.TenantID != tg.String() {
		t.Fatalf("actor tenant = %q, want the home tenant %q", ev.Actor.TenantID, tg)
	}
	if ev.Actor.Type != audit.ActorTypeUser {
		t.Fatalf("actor type = %q, want %q — the level is not a subject type", ev.Actor.Type, audit.ActorTypeUser)
	}
	if ev.ResourceType != "organization" || ev.ResourceID != "org-1" {
		t.Fatalf("resource = %s:%s, want organization:org-1", ev.ResourceType, ev.ResourceID)
	}
}

// Provisioning and org mutations share ONE sink and one chain.
func TestAudit_OneSink(t *testing.T) {
	capture := &captureLogger{}
	auditor := tamperespresso.NewAuditor(capture, nil)
	mutation := auditor.For(tamperespresso.MutationContext{
		Action:         "org.rename",
		ResourceType:   "organization",
		ResourceIDFrom: OrgParam,
	})(okHandler())

	h, jwt, core, _, store, hier := newOrgStackWith(t, mutation)

	// Provisioning writes into the SAME capture.
	p, err := NewProvisioner(store, hier, roleMapTwo(), WithAudit(capture))
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	if err := p.GrantGroupAdmin(operatorCtx("ops", "platform"), carol, tg, groupRole()); err != nil {
		t.Fatalf("grant: %v", err)
	}

	tok := enterAs(t, core, jwt, "bob", org1)
	req := httptest.NewRequest(http.MethodPost, "/orgs/org-1", nil)
	// Two path-param stores: espresso's extractor feeds Auditor.For, Go's
	// PathValue feeds DecisionGate.
	req = extractor.SetPathParams(req, extractor.PathParams{OrgParam: "org-1"})
	req.SetPathValue(OrgParam, "org-1")
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(httptest.NewRecorder(), req)

	evs := capture.snapshot()
	if len(evs) != 2 {
		t.Fatalf("events = %d, want 2 in one sink (provisioning + org mutation)", len(evs))
	}
	scopes := map[string]bool{}
	for _, ev := range evs {
		scopes[ev.TenantID] = true
	}
	if !scopes[tg.String()] || !scopes[org1.String()] {
		t.Fatalf("scopes = %v, want both the group and the org", scopes)
	}
}

// ---------------------------------------------------------------------
// Decision 6: only a platform admin reaches the provisioning surface.
// ---------------------------------------------------------------------

func TestPlatformGate_OnlyPlatformAdmin(t *testing.T) {
	platform := tenant.New("platform")
	ops := authz.Subject{Tenant: platform, Type: "user", ID: "ops"}

	store := newStore()
	if err := store.Grant(ctx, authz.Binding{
		Tenant:   platform,
		Subject:  ops,
		Resource: authz.Resource{Type: ResourceSystem},
		Role:     "platform_admin",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	engine, err := authz.NewRBAC(store,
		authz.Hierarchy{ResourceSystem: {"platform_admin"}},
		authz.Policy{"platform:manage": {{Type: ResourceSystem, Min: "platform_admin"}}})
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}

	jwt := crypto.NewJWTService(crypto.JWTConfig{
		Secret: "tenanthierarchy-platform-test-secret", TTL: time.Hour, Issuer: "tenanthierarchy-platform",
	})
	h := PlatformGate(jwt, engine, platform, "platform:manage", statusWriter(http.StatusForbidden))(okHandler())

	call := func(tok string) int {
		req := httptest.NewRequest(http.MethodPost, "/platform/groups/grant", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	admin, err := jwt.IssueAccess("ops", platform, time.Now().Unix(), crypto.ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	if code := call(admin); code != http.StatusOK {
		t.Fatalf("platform admin = %d, want 200", code)
	}

	// A tenant-group admin's token is for its group, not the platform tenant.
	groupToken, err := jwt.IssueAccess("bob", tg, time.Now().Unix(), crypto.ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	if code := call(groupToken); code != http.StatusUnauthorized {
		t.Fatalf("group admin on the platform surface = %d, want 401", code)
	}
}
