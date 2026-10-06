package espresso

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
)

// The STEP_UP_REQUIRED envelope is a security boundary between the
// gate and the consuming SPA — its JSON shape is byte-pinned here (in
// the engine's own suite) AND in the consuming app's tripwire.

type wireLogger struct {
	audit.Logger
	events []audit.Event
}

func (l *wireLogger) Log(_ context.Context, e audit.Event) (audit.Event, error) {
	l.events = append(l.events, e)
	return e, nil
}

func TestStepUpWire_StaleAuth_PinnedEnvelopeAndDeniedAction(t *testing.T) {
	jwt := crypto.NewJWTService(crypto.JWTConfig{
		Secret: "stepup-wire-test-secret",
		TTL:    time.Hour,
		Issuer: "tamper-test",
	})
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	stale := now.Add(-time.Hour).Unix()
	token, err := jwt.IssueAccess("u-wire", tenant.Single, stale, "urn:mace:incommon:iap:silver")
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	logger := &wireLogger{Logger: audit.NewNoopLogger()}

	chain := RequireAuth(jwt)(
		RequireFreshAuthWithAudit(
			5*time.Minute,
			[]string{"urn:mace:incommon:iap:silver", "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"},
			logger,
			"app.stepup.denied",
			"provider.delete",
			WithStepUpClock(func() time.Time { return now }),
		)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			t.Fatal("handler must not run behind a tripped gate")
		})),
	)
	req := httptest.NewRequest(http.MethodPost, "/api/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	// Byte-level pin: field names + nesting are the SPA contract.
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	e, _ := got["error"].(map[string]any)
	if e["code"] != "STEP_UP_REQUIRED" || e["message"] != "this operation requires fresh authentication" {
		t.Fatalf("envelope head drifted: %v", e)
	}
	d, _ := e["details"].(map[string]any)
	if d["max_age_seconds"] != float64(300) || d["current_auth_time"] != float64(stale) || d["now"] != float64(now.Unix()) {
		t.Fatalf("details drifted: %v", d)
	}
	if acrs, _ := d["acr_values"].([]any); len(acrs) != 2 || acrs[0] != "urn:mace:incommon:iap:silver" {
		t.Fatalf("acr_values drifted: %v", d["acr_values"])
	}

	// The denied event carries the APP's action string verbatim.
	if len(logger.events) != 1 || string(logger.events[0].Action) != "app.stepup.denied" {
		t.Fatalf("denied event = %+v, want one app.stepup.denied", logger.events)
	}
	var after map[string]any
	_ = json.Unmarshal(logger.events[0].After, &after)
	if after["denial_reason"] != "stale_auth_time" || after["endpoint"] != "provider.delete" {
		t.Fatalf("after payload drifted: %v", after)
	}
}

// stepUpDenied runs a request with a stale token through RequireAuth and
// the given gates, and returns the one denied event.
func stepUpDenied(t *testing.T, tid tenant.ID, wrap func(http.Handler) http.Handler) audit.Event {
	t.Helper()
	jwt := crypto.NewJWTService(crypto.JWTConfig{
		Secret: "stepup-wire-test-secret", TTL: time.Hour, Issuer: "tamper-test",
	})
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	token, err := jwt.IssueAccess("u-wire", tid, now.Add(-time.Hour).Unix(), "urn:mace:incommon:iap:silver")
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	logger := &wireLogger{Logger: audit.NewNoopLogger()}
	gate := RequireFreshAuthWithAudit(5*time.Minute, []string{"urn:mace:incommon:iap:silver"},
		logger, "app.stepup.denied", "provider.delete",
		WithStepUpClock(func() time.Time { return now }),
	)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run behind a tripped gate")
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	RequireAuth(jwt)(wrap(gate)).ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if len(logger.events) != 1 {
		t.Fatalf("denied events = %d, want 1", len(logger.events))
	}
	return logger.events[0]
}

// TD-20: a step-up denial on a tenant route is scoped to that tenant and
// records the actor's home tenant, like every other audit row.
func TestStepUpDenied_CarriesTheTenant(t *testing.T) {
	inAcme := RequireTenant(routeTo("acme"))
	ev := stepUpDenied(t, tenant.New("acme"), inAcme)
	if ev.TenantID != "acme" {
		t.Errorf("Event.TenantID = %q, want %q — the denial is missing from the tenant's export", ev.TenantID, "acme")
	}
	if ev.Actor.TenantID != "acme" || ev.Actor.UserID != "u-wire" {
		t.Errorf("actor = %+v, want user u-wire homed in acme", ev.Actor)
	}
}

// With no tenant gate outside it the denial has no scope, but the
// actor's home tenant is still recorded. The scope is never taken from
// the token.
func TestStepUpDenied_NoGateNoScope(t *testing.T) {
	ev := stepUpDenied(t, tenant.New("acme"), func(h http.Handler) http.Handler { return h })
	if ev.TenantID != "" {
		t.Errorf("Event.TenantID = %q, want empty — nothing pinned a tenant", ev.TenantID)
	}
	if ev.Actor.TenantID != "acme" {
		t.Errorf("Actor.TenantID = %q, want %q", ev.Actor.TenantID, "acme")
	}
}

// Single-tenant: no tid, the route resolves to "", and the event carries
// no tenant anywhere.
func TestStepUpDenied_SingleTenantIsUnchanged(t *testing.T) {
	single := RequireTenant(routeTo(""))
	ev := stepUpDenied(t, tenant.Single, single)
	if ev.TenantID != "" || ev.Actor.TenantID != "" {
		t.Errorf("single-tenant denial grew a tenant: scope %q, actor %q", ev.TenantID, ev.Actor.TenantID)
	}
}
