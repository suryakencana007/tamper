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
		RequireTenant(routeTo(tenantA))(
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

// An entered token is accepted on the tenant it was entered into, and
// refused everywhere else exactly as any wrong-tenant token is. In
// particular htid opens nothing: the token does not work on the
// admin's own home tenant.
func TestEnteredToken_OpensOnlyTheTenantEntered(t *testing.T) {
	j := tenantJWT(t)
	entered := enteredToken(t, j, tenantA)
	ordinaryOther := tokenFor(t, j, tenant.New(tenantB))

	serve := func(routed, bearer string) *httptest.ResponseRecorder {
		h := RequireAuth(j)(RequireTenant(routeTo(routed))(http.HandlerFunc(noContent)))
		req := httptest.NewRequest(http.MethodPost, "/things", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := serve(tenantA, entered); rec.Code != http.StatusNoContent {
		t.Fatalf("entered token on the tenant entered: status %d, want 204", rec.Code)
	}

	// The reference refusal: an ordinary globex token on an acme route.
	want := serve(tenantA, ordinaryOther)
	if want.Code == http.StatusNoContent {
		t.Fatal("fixture: a wrong-tenant token was accepted")
	}
	for name, routed := range map[string]string{"its home tenant": tenantPlatform, "a third tenant": tenantB, "an untenanted route": ""} {
		got := serve(routed, entered)
		if got.Code != want.Code || got.Body.String() != want.Body.String() {
			t.Errorf("entered token on %s: %d %s; want the ordinary wrong-tenant refusal %d %s",
				name, got.Code, got.Body.String(), want.Code, want.Body.String())
		}
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
