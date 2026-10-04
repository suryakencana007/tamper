package espresso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
)

// Phase 8: an ENTERED token is one a platform admin holds while acting
// inside a customer's tenant (identity.Core.EnterTenant). Its tid is the
// tenant entered; its htid is the tenant the admin is stored in.

const tenantPlatform = "platform"

// enteredToken mints a token for u-1, stored in platform, acting in
// target.
func enteredToken(t *testing.T, j *crypto.JWTService, target string) string {
	t.Helper()
	tok, err := j.IssueAccessEntered("u-1", tenant.New(target), tenant.New(tenantPlatform),
		time.Now().Unix(), crypto.ACRLocalPassword, 0)
	if err != nil {
		t.Fatalf("IssueAccessEntered: %v", err)
	}
	return tok
}

// A mutation made while entered is the customer's row: scoped to the
// tenant entered and in that tenant's export. The actor on it is from
// the platform tenant, so the customer can see that it was not one of
// their own users. It is in nobody else's export — not the platform
// tenant's either.
func TestEnteredToken_AuditRowIsTheTenantsAndNamesTheHomeTenant(t *testing.T) {
	ctx := context.Background()
	logger, err := audit.NewSQLiteLogger(filepath.Join(t.TempDir(), "audit.db"),
		audit.SQLiteLoggerOptions{})
	if err != nil {
		t.Fatalf("NewSQLiteLogger: %v", err)
	}
	defer func() { _ = logger.Close() }()
	sl := logger.(*audit.SQLiteLogger)

	j := tenantJWT(t)
	h := RequireAuth(j)(
		RequireTenantAllowEntered(routeTo(tenantA))(
			NewAuditor(logger, nil).Mutation(auditTestAction, auditTestResource, "")(
				http.HandlerFunc(noContent))))
	serveMutation(t, h, enteredToken(t, j, tenantA))

	exp, err := sl.ExportForTenant(ctx, tenant.New(tenantA))
	if err != nil {
		t.Fatalf("ExportForTenant(%s): %v", tenantA, err)
	}
	if len(exp.Events) != 1 {
		t.Fatalf("ExportForTenant(%s) = %d row(s), want the one mutation", tenantA, len(exp.Events))
	}
	ev := exp.Events[0]
	if ev.TenantID != tenantA {
		t.Errorf("Event.TenantID = %q, want the tenant entered, %q", ev.TenantID, tenantA)
	}
	if ev.Actor.TenantID != tenantPlatform {
		t.Errorf("Actor.TenantID = %q, want the actor's home tenant, %q", ev.Actor.TenantID, tenantPlatform)
	}
	if ev.Actor.UserID != "u-1" {
		t.Errorf("Actor.UserID = %q, want u-1", ev.Actor.UserID)
	}

	for _, other := range []string{tenantPlatform, tenantB} {
		got, err := sl.ExportForTenant(ctx, tenant.New(other))
		if err != nil {
			t.Fatalf("ExportForTenant(%s): %v", other, err)
		}
		if len(got.Events) != 0 {
			t.Errorf("ExportForTenant(%s) returned %d row(s) of a mutation made in %s", other, len(got.Events), tenantA)
		}
	}
}

// serveGate sends one request through RequireAuth and the given tenant
// gate.
func serveGate(j *crypto.JWTService, gate func(http.Handler) http.Handler, bearer string, inner http.HandlerFunc) *httptest.ResponseRecorder {
	h := RequireAuth(j)(gate(inner))
	req := httptest.NewRequest(http.MethodPost, "/things", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// RequireTenant keeps the promise it made before entered tokens
// existed: the subject is a user of the routed tenant. An entered token
// is refused even on the tenant it was entered into, with the refusal a
// wrong-tenant token gets. Every existing route — "my account" handlers,
// authorization gates keyed by the user id — is therefore closed to
// guests until it opts in.
func TestRequireTenant_RefusesAnEnteredToken(t *testing.T) {
	j := tenantJWT(t)
	entered := enteredToken(t, j, tenantA)

	want := serveGate(j, RequireTenant(routeTo(tenantA)), tokenFor(t, j, tenant.New(tenantB)), noContent)
	if want.Code == http.StatusNoContent {
		t.Fatal("fixture: a wrong-tenant token was accepted")
	}

	reached := false
	got := serveGate(j, RequireTenant(routeTo(tenantA)), entered, func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	})
	if reached {
		t.Fatal("RequireTenant let an entered token through to the handler")
	}
	if got.Code != want.Code || got.Body.String() != want.Body.String() {
		t.Errorf("entered token on RequireTenant: %d %s; want the ordinary wrong-tenant refusal %d %s",
			got.Code, got.Body.String(), want.Code, want.Body.String())
	}

	// The tenant's own token is unaffected.
	if rec := serveGate(j, RequireTenant(routeTo(tenantA)), tokenFor(t, j, tenant.New(tenantA)), noContent); rec.Code != http.StatusNoContent {
		t.Errorf("the tenant's own token on RequireTenant: status %d, want 204", rec.Code)
	}
}

// RequireTenantAllowEntered accepts the tenant's own tokens and tokens
// entered into it, and refuses everything else exactly as RequireTenant
// does. In particular htid opens nothing: the token does not work on
// the admin's own home tenant.
func TestRequireTenantAllowEntered_OpensOnlyTheTenantEntered(t *testing.T) {
	j := tenantJWT(t)
	entered := enteredToken(t, j, tenantA)

	var home tenant.ID
	var isEntered, called bool
	var routed tenant.ID
	inner := func(w http.ResponseWriter, r *http.Request) {
		called = true
		home, isEntered = EnteredFromContext(r.Context())
		routed, _ = TenantFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}

	if rec := serveGate(j, RequireTenantAllowEntered(routeTo(tenantA)), entered, inner); rec.Code != http.StatusNoContent {
		t.Fatalf("entered token on the tenant entered: status %d, want 204", rec.Code)
	}
	if !called || !isEntered || home != tenant.New(tenantPlatform) || routed != tenant.New(tenantA) {
		t.Errorf("handler saw entered=%v home=%q routed=%q; want true / platform / %s", isEntered, home, routed, tenantA)
	}

	// The tenant's own token passes too, and is not a guest.
	isEntered = true
	if rec := serveGate(j, RequireTenantAllowEntered(routeTo(tenantA)), tokenFor(t, j, tenant.New(tenantA)), inner); rec.Code != http.StatusNoContent {
		t.Fatalf("the tenant's own token: status %d, want 204", rec.Code)
	}
	if isEntered {
		t.Error("EnteredFromContext reported an ordinary token as entered")
	}

	// The reference refusal: an ordinary globex token on an acme route.
	want := serveGate(j, RequireTenantAllowEntered(routeTo(tenantA)), tokenFor(t, j, tenant.New(tenantB)), noContent)
	if want.Code == http.StatusNoContent {
		t.Fatal("fixture: a wrong-tenant token was accepted")
	}
	for name, other := range map[string]string{"its home tenant": tenantPlatform, "a third tenant": tenantB, "an untenanted route": ""} {
		got := serveGate(j, RequireTenantAllowEntered(routeTo(other)), entered, noContent)
		if got.Code != want.Code || got.Body.String() != want.Body.String() {
			t.Errorf("entered token on %s: %d %s; want the ordinary wrong-tenant refusal %d %s",
				name, got.Code, got.Body.String(), want.Code, want.Body.String())
		}
	}
}

// The gate that existing "my account" and authorization routes sit
// behind. An entered token never reaches RequireDecision's Authorizer,
// so the roles the admin holds at home are never asked about this
// tenant's resources.
func TestEnteredToken_NeverReachesAGateBehindRequireTenant(t *testing.T) {
	j := tenantJWT(t)
	reached := false
	inner := func(w http.ResponseWriter, _ *http.Request) { reached = true; w.WriteHeader(http.StatusNoContent) }
	rec := serveGate(j, RequireTenant(routeTo(tenantA)), enteredToken(t, j, tenantA), inner)
	if reached || rec.Code == http.StatusNoContent {
		t.Fatalf("an entered token reached what is mounted behind RequireTenant (status %d)", rec.Code)
	}
}

// The context actor itself, which service-layer emissions read without
// going through the Auditor.
func TestRequireAuth_EnteredActorIsFromTheHomeTenant(t *testing.T) {
	j := tenantJWT(t)
	const prefix = "base64url.bearer.authorization.test.io."
	for name, gate := range map[string]func(http.Handler) http.Handler{
		"RequireAuth":   RequireAuth(j),
		"RequireAuthWS": RequireAuthWS(j, prefix),
	} {
		var got audit.Actor
		h := gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = audit.ActorFromContext(r.Context())
			w.WriteHeader(http.StatusNoContent)
		}))
		serveMutation(t, h, enteredToken(t, j, tenantA))
		if got.TenantID != tenantPlatform || got.UserID != "u-1" {
			t.Errorf("%s: actor = %+v, want u-1 from %s", name, got, tenantPlatform)
		}
	}
}
