package espresso

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/crypto"
)

// Phase 16 slice 16c (D3'): a gate can ask about METHODS, not just the policy class — the
// question a locally-enrolled TOTP session can actually answer.

// stepUpClaims builds claims carrying an acr and the methods in question, and a handler
// that runs RequireAuth's job (putting the claims in context) so the gate can read them.
func stepUpWithClaims(t *testing.T, gate func(http.Handler) http.Handler, claims *crypto.AccessClaims) int {
	t.Helper()
	ran := false
	h := gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ran = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req = req.WithContext(decorateAuthed(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK && !ran {
		t.Fatal("gate allowed but the handler did not run")
	}
	return rec.Code
}

func claimsWith(acr string, age time.Duration, amr ...string) *crypto.AccessClaims {
	c := &crypto.AccessClaims{TenantID: "acme", AMR: amr}
	c.Subject = "u-1"
	c.AuthTime = time.Now().Add(-age).Unix()
	c.ACR = acr
	return c
}

// The point of the feature: a local TOTP session satisfies a method gate even though its
// ACR is the password class.
func TestStepUp_MethodGateIsSatisfiedByALocalTOTPSession(t *testing.T) {
	gate := RequireFreshAuth(time.Hour, []string{crypto.ACRLocalPassword}, StepUpRequireMethods(crypto.AMROTP))
	if got := stepUpWithClaims(t, gate, claimsWith(crypto.ACRLocalPassword, time.Minute, crypto.AMRPassword, crypto.AMROTP)); got != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a session carrying otp satisfies the method gate", got)
	}
}

// And the converse: password-only is refused, with the method reason rather than a
// misleading ACK/ACR one.
func TestStepUp_MethodGateRefusesAPasswordOnlySession(t *testing.T) {
	gate := RequireFreshAuth(time.Hour, []string{crypto.ACRLocalPassword}, StepUpRequireMethods(crypto.AMROTP))
	if got := stepUpWithClaims(t, gate, claimsWith(crypto.ACRLocalPassword, time.Minute, crypto.AMRPassword)); got != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", got)
	}
}

// No option = today's behaviour, byte for byte.
func TestStepUp_NoMethodOptionChangesNothing(t *testing.T) {
	gate := RequireFreshAuth(time.Hour, []string{crypto.ACRLocalPassword})
	if got := stepUpWithClaims(t, gate, claimsWith(crypto.ACRLocalPassword, time.Minute)); got != http.StatusOK {
		t.Fatalf("status = %d, want 200 without a method requirement", got)
	}
}

// A token minted before the amr claim existed has no methods at all, so a method gate
// refuses it — the safe direction.
func TestStepUp_MethodGateRefusesATokenWithoutAMR(t *testing.T) {
	gate := RequireFreshAuth(time.Hour, []string{crypto.ACRLocalPassword}, StepUpRequireMethods(crypto.AMROTP))
	if got := stepUpWithClaims(t, gate, claimsWith(crypto.ACRLocalPassword, time.Minute)); got != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a token with no amr", got)
	}
}

// Any one of the listed methods satisfies the gate.
func TestStepUp_MethodGateAcceptsAnyListedMethod(t *testing.T) {
	gate := RequireFreshAuth(time.Hour, []string{crypto.ACRLocalPassword}, StepUpRequireMethods(crypto.AMRSAML, crypto.AMROTP))
	if got := stepUpWithClaims(t, gate, claimsWith(crypto.ACRLocalPassword, time.Minute, crypto.AMROTP)); got != http.StatusOK {
		t.Fatalf("status = %d, want 200 (otp is one of the accepted methods)", got)
	}
}

// The two axes are independent: a strong class does not carry a method, and a method does
// not lift the class requirement.
func TestStepUp_ClassAndMethodAreSeparateAxes(t *testing.T) {
	byClass := RequireFreshAuth(time.Hour, []string{crypto.ACRIncommonSilver}, StepUpRequireMethods(crypto.AMROTP))
	if got := stepUpWithClaims(t, byClass, claimsWith(crypto.ACRLocalPassword, time.Minute, crypto.AMRPassword, crypto.AMROTP)); got != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — otp does not satisfy a silver-only class gate", got)
	}
}
