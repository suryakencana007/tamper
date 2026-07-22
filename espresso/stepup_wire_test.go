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
	token, err := jwt.IssueAccess("u-wire", stale, "urn:mace:incommon:iap:silver")
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
