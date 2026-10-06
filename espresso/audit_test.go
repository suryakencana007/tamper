package espresso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/tenant"
)

// TD-08 — the Auditor middleware and the tenant.
//
// Two different facts ride on an audit row and these tests keep them
// apart on purpose: audit.Event.TenantID is the row's SCOPE (the routed
// tenant, what ExportForTenant filters on) and audit.Actor.TenantID is
// the actor's HOME tenant (the token's `tid`). Before this fix the
// Auditor filled in neither, so in a pooled deployment its rows appeared
// in no tenant's export.

const (
	auditTestAction   = audit.Action("td08.thing.update")
	auditTestResource = audit.ResourceType("thing")
)

// recordingLogger captures the audit.Event exactly as the Auditor hands
// it to Log — before any logger fills in hashes or a canonical version —
// which is the only place the emitted shape can be compared field for
// field. Everything else falls through to the embedded no-op logger.
type recordingLogger struct {
	audit.Logger
	events []audit.Event
}

func newRecordingLogger() *recordingLogger {
	return &recordingLogger{Logger: audit.NewNoopLogger()}
}

func (l *recordingLogger) Log(_ context.Context, e audit.Event) (audit.Event, error) {
	l.events = append(l.events, e)
	return e, nil
}

// one returns the single event the request under test emitted.
func (l *recordingLogger) one(t *testing.T) audit.Event {
	t.Helper()
	if len(l.events) != 1 {
		t.Fatalf("emitted %d audit event(s), want exactly 1", len(l.events))
	}
	return l.events[0]
}

// noContent is the mutation handler: any 2xx makes the Auditor emit.
func noContent(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }

// routeTo returns a resolver that reports a fixed routed tenant. "" is
// the single tenant, said by the test.
func routeTo(tenantID string) func(*http.Request) (tenant.ID, bool) {
	return FixedRequestTenant(tenant.FromStored(tenantID))
}

// serveMutation sends one POST through h and requires the 204 that makes
// the Auditor emit. An empty bearer sends no Authorization header.
func serveMutation(t *testing.T, h http.Handler, bearer string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/things", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("request status = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestAuditor_PooledRowIsScopedAndExported is the regression test for
// TD-08, adapted from its reproduction proof: a mutation made in tenant
// "acme" through RequireAuth -> RequireTenant -> Auditor.Mutation lands
// in the chain with both tenant facts recorded, and it is in acme's
// export and in nobody else's.
func TestAuditor_PooledRowIsScopedAndExported(t *testing.T) {
	ctx := context.Background()
	logger, err := audit.NewSQLiteLogger(filepath.Join(t.TempDir(), "audit.db"),
		audit.SQLiteLoggerOptions{})
	if err != nil {
		t.Fatalf("NewSQLiteLogger: %v", err)
	}
	defer func() { _ = logger.Close() }()
	sl := logger.(*audit.SQLiteLogger)

	j := tenantJWT(t)
	acme := tenant.New(tenantA)
	h := RequireAuth(j)(
		RequireTenant(routeTo(tenantA))(
			NewAuditor(logger, nil).Mutation(auditTestAction, auditTestResource, "")(
				http.HandlerFunc(noContent))))
	serveMutation(t, h, tokenFor(t, j, acme))

	// Found by walking the page, not by Filter.Action: List does not
	// honour that filter (TD-17), and a test that leaned on it would
	// pass or fail for the wrong reason.
	page, err := logger.List(ctx, audit.Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var rows []audit.Event
	for _, e := range page.Events {
		if e.Action == auditTestAction {
			rows = append(rows, e)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("rows for the action = %d, want exactly 1", len(rows))
	}
	ev := rows[0]

	if ev.CanonicalVersion != audit.CanonicalVersion4 {
		t.Errorf("canonical_version = %d, want %d", ev.CanonicalVersion, audit.CanonicalVersion4)
	}
	if ev.TenantID != tenantA {
		t.Errorf("Event.TenantID = %q, want %q — the row has no scope", ev.TenantID, tenantA)
	}
	if ev.Actor.TenantID != tenantA {
		t.Errorf("Actor.TenantID = %q, want %q — the actor's home tenant was dropped", ev.Actor.TenantID, tenantA)
	}
	if ev.Actor.Type != audit.ActorTypeUser || ev.Actor.UserID != "u-1" {
		t.Errorf("actor = %+v, want user actor u-1", ev.Actor)
	}

	exp, err := sl.ExportForTenant(ctx, acme)
	if err != nil {
		t.Fatalf("ExportForTenant(%s): %v", tenantA, err)
	}
	if len(exp.Events) != 1 || exp.Events[0].ID != ev.ID {
		t.Errorf("ExportForTenant(%s) = %d row(s) %v, want exactly the mutation %s",
			tenantA, len(exp.Events), eventIDs(exp.Events), ev.ID)
	}

	// The other tenant, and the single-tenant scope. tenant.Single is
	// the one that matters most: it is where the row used to land, so a
	// scope that was stamped AND left in the unscoped bucket would still
	// pass the assertions above.
	for name, other := range map[string]tenant.ID{tenantB: tenant.New(tenantB), "tenant.Single": tenant.Single} {
		got, err := sl.ExportForTenant(ctx, other)
		if err != nil {
			t.Fatalf("ExportForTenant(%s): %v", name, err)
		}
		for _, e := range got.Events {
			if e.ID == ev.ID {
				t.Errorf("ExportForTenant(%s) returned %s's mutation %s", name, tenantA, ev.ID)
			}
		}
	}

	// The tenant is inside the v4 payload, so a wrongly-stamped row
	// would still verify; this only pins that stamping one does not
	// break the chain it is appended to.
	res, err := logger.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Tamper {
		t.Errorf("chain reports tamper at index %d after a tenant-scoped row", res.FirstBadIndex)
	}
}

func eventIDs(events []audit.Event) []string {
	ids := make([]string, 0, len(events))
	for _, e := range events {
		ids = append(ids, e.ID)
	}
	return ids
}

// TestAuditor_SingleTenantEventIsUnchanged pins the single-tenant event
// field by field: a token with no `tid` on a route of the single tenant
// hands the logger an event whose scope and actor tenant are both the
// single tenant, and nothing else about it depends on tenancy. Both
// single-tenant wirings are covered: no tenant gate at all, and
// RequireTenant resolving to the single tenant.
func TestAuditor_SingleTenantEventIsUnchanged(t *testing.T) {
	j := tenantJWT(t)
	tok := tokenFor(t, j, tenant.Single)
	email := func(_ context.Context, userID string) (string, bool) {
		return userID + "@example.test", true
	}

	wirings := map[string]func(http.Handler) http.Handler{
		"no tenant gate": func(next http.Handler) http.Handler { return next },
		"RequireTenant resolving to the single tenant": RequireTenant(routeTo("")),
	}
	for name, tenantGate := range wirings {
		t.Run(name, func(t *testing.T) {
			rec := newRecordingLogger()
			h := RequireAuth(j)(tenantGate(
				NewAuditor(rec, email).Mutation(auditTestAction, auditTestResource, "")(
					http.HandlerFunc(noContent))))
			serveMutation(t, h, tok)

			got := rec.one(t)
			if got.ID == "" || got.At.IsZero() {
				t.Fatalf("event id/at not set: id=%q at=%v", got.ID, got.At)
			}
			// ID and At are per-request; everything else is pinned.
			got.ID, got.At = "", time.Time{}
			want := audit.Event{
				Actor: audit.Actor{
					Type:   audit.ActorTypeUser,
					UserID: "u-1",
					Email:  "u-1@example.test",
					IP:     "192.0.2.1", // httptest.NewRequest's RemoteAddr, port stripped
				},
				Action:       auditTestAction,
				ResourceType: auditTestResource,
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("single-tenant event changed shape:\n got  %+v\n want %+v", got, want)
			}
		})
	}
}

// TestAuditor_PublicRoutePinnedTenant: a public route (login, TOTP
// verify) has no token, so there is no actor tenant to record — but the
// request was still routed to a tenant, and the row belongs in that
// tenant's log. The user id backfilled through SetUserID is captured as
// it always was.
func TestAuditor_PublicRoutePinnedTenant(t *testing.T) {
	rec := newRecordingLogger()
	h := PinTenant(routeTo(tenantA))(
		NewAuditor(rec, nil).Mutation(auditTestAction, auditTestResource, "")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				SetUserID(r.Context(), "u-9")
				w.WriteHeader(http.StatusNoContent)
			})))
	serveMutation(t, h, "")

	ev := rec.one(t)
	if ev.TenantID != tenantA {
		t.Errorf("Event.TenantID = %q, want the pinned tenant %q", ev.TenantID, tenantA)
	}
	if ev.Actor.TenantID != "" {
		t.Errorf("Actor.TenantID = %q, want empty — no token named a tenant for this actor", ev.Actor.TenantID)
	}
	if ev.Actor.Type != audit.ActorTypeUser || ev.Actor.UserID != "u-9" {
		t.Errorf("actor = %+v, want the user id captured via SetUserID (u-9)", ev.Actor)
	}
}

// TestAuditor_OutsideTenantGateRecordsNoScope pins what a mis-ordered
// stack does. The Auditor reads the context it was entered with, so a
// RequireTenant mounted INSIDE it is invisible: the row carries no
// scope, as before the fix. It must not borrow one from the actor — the
// token's `tid` is the actor's home tenant, and a scope read out of the
// credential is the token choosing whose log it writes to.
func TestAuditor_OutsideTenantGateRecordsNoScope(t *testing.T) {
	j := tenantJWT(t)
	rec := newRecordingLogger()
	h := RequireAuth(j)(
		NewAuditor(rec, nil).Mutation(auditTestAction, auditTestResource, "")(
			RequireTenant(routeTo(tenantA))(
				http.HandlerFunc(noContent))))
	serveMutation(t, h, tokenFor(t, j, tenant.New(tenantA)))

	ev := rec.one(t)
	if ev.TenantID != "" {
		t.Errorf("Event.TenantID = %q, want empty — no tenant was pinned where the Auditor could see it", ev.TenantID)
	}
	if ev.Actor.TenantID != tenantA {
		t.Errorf("Actor.TenantID = %q, want %q — the actor's home tenant does not depend on the gate order",
			ev.Actor.TenantID, tenantA)
	}
}

// TestAuditor_ServiceAccountActorPassesThrough: a non-user actor stashed
// by an upstream gate still wins untouched — name, id and its own tenant
// — with only the IP stamped. The actor's tenant is not promoted into
// the row's scope either: nothing pinned a routed tenant here.
func TestAuditor_ServiceAccountActorPassesThrough(t *testing.T) {
	rec := newRecordingLogger()
	validator := ValidatorFunc(func(context.Context, string) (Principal, error) {
		return Principal{ID: "sa-1", TenantID: tenantB, Name: "provisioner"}, nil
	})
	h := RequireServiceAccount(validator)(
		NewAuditor(rec, nil).Mutation(auditTestAction, auditTestResource, "")(
			http.HandlerFunc(noContent)))
	serveMutation(t, h, "machine-token")

	ev := rec.one(t)
	want := audit.ActorService("sa-1", "provisioner", tenant.New(tenantB))
	want.IP = "192.0.2.1"
	if ev.Actor != want {
		t.Errorf("service-account actor was not passed through:\n got  %+v\n want %+v", ev.Actor, want)
	}
	// A service account's tenant IS its scope: it comes from the
	// validated credential, and its routes pin no tenant.
	if ev.TenantID != tenantB {
		t.Errorf("Event.TenantID = %q, want %q — a service-account row with no scope is "+
			"missing from its own tenant's export", ev.TenantID, tenantB)
	}
}

// A pinned tenant still wins over the service account's own.
func TestAuditor_ServiceAccountPinnedTenantWins(t *testing.T) {
	rec := newRecordingLogger()
	validator := ValidatorFunc(func(context.Context, string) (Principal, error) {
		return Principal{ID: "sa-1", TenantID: tenantB, Name: "provisioner"}, nil
	})
	h := PinTenant(routeTo(tenantA))(
		RequireServiceAccount(validator)(
			NewAuditor(rec, nil).Mutation(auditTestAction, auditTestResource, "")(
				http.HandlerFunc(noContent))))
	serveMutation(t, h, "machine-token")

	if ev := rec.one(t); ev.TenantID != tenantA || ev.Actor.TenantID != tenantB {
		t.Errorf("scope = %q, actor tenant = %q; want the pinned %q and the principal's %q",
			ev.TenantID, ev.Actor.TenantID, tenantA, tenantB)
	}
}

// A service account with no tenant (single-tenant) writes no scope.
func TestAuditor_SingleTenantServiceAccountHasNoScope(t *testing.T) {
	rec := newRecordingLogger()
	validator := ValidatorFunc(func(context.Context, string) (Principal, error) {
		return Principal{ID: "sa-1", Name: "provisioner"}, nil
	})
	h := RequireServiceAccount(validator)(
		NewAuditor(rec, nil).Mutation(auditTestAction, auditTestResource, "")(
			http.HandlerFunc(noContent)))
	serveMutation(t, h, "machine-token")

	if ev := rec.one(t); ev.TenantID != "" || ev.Actor.TenantID != "" {
		t.Errorf("single-tenant service account grew a tenant: scope %q, actor %q", ev.TenantID, ev.Actor.TenantID)
	}
}

// TestRequireAuth_ActorCarriesTheTokensTenant pins the context actor
// itself, for both entry points that share decorateAuthed. Service-layer
// emissions read audit.ActorFromContext directly and never pass through
// the Auditor, so the tenant has to be on the stashed actor — the
// Auditor copying it is not enough.
func TestRequireAuth_ActorCarriesTheTokensTenant(t *testing.T) {
	j := tenantJWT(t)
	const prefix = "base64url.bearer.authorization.test.io."
	gates := map[string]func(http.Handler) http.Handler{
		"RequireAuth":   RequireAuth(j),
		"RequireAuthWS": RequireAuthWS(j, prefix),
	}
	tenants := map[string]tenant.ID{tenantA: tenant.New(tenantA), "": tenant.Single}

	for name, gate := range gates {
		for want, tenantID := range tenants {
			var got audit.Actor
			h := gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = audit.ActorFromContext(r.Context())
				w.WriteHeader(http.StatusNoContent)
			}))
			serveMutation(t, h, tokenFor(t, j, tenantID))

			if got.TenantID != want {
				t.Errorf("%s, token tid %q: actor TenantID = %q", name, want, got.TenantID)
			}
			if got.Type != audit.ActorTypeUser || got.UserID != "u-1" {
				t.Errorf("%s, token tid %q: actor = %+v, want user actor u-1", name, want, got)
			}
		}
	}
}
