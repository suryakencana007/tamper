package saml

import (
	"strings"
	"testing"
	"time"
)

// TestStateCookieRoundTrip sign → verify happy path: every field
// (including v1.15 walk-fix Mode + UserID) round-trips.
func TestStateCookieRoundTrip(t *testing.T) {
	secret := []byte("saml-state-secret-32-bytes-long!!")
	issuer := "barista-saml-state-test"
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)

	in := StateCookieClaims{
		ProviderID:             "keycloak-saml",
		RedirectAfterLogin:     "/projects",
		RequestedMaxAgeSeconds: 300,
		RequestedACRValues:     []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor"},
		CallingUserID:          "user-abc",
		Mode:                   ModeLink,
		UserID:                 "user-abc",
	}
	signed, err := SignStateCookieWithSecret(secret, in, issuer, now, 10*time.Minute)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := VerifyStateCookieWithSecret(secret, signed, issuer, func() time.Time { return now.Add(time.Minute) })
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.ProviderID != "keycloak-saml" {
		t.Errorf("ProviderID = %q, want %q", got.ProviderID, "keycloak-saml")
	}
	if got.RedirectAfterLogin != "/projects" {
		t.Errorf("RedirectAfterLogin = %q, want %q", got.RedirectAfterLogin, "/projects")
	}
	if got.RequestedMaxAgeSeconds != 300 {
		t.Errorf("RequestedMaxAgeSeconds = %d, want 300", got.RequestedMaxAgeSeconds)
	}
	if got.CallingUserID != "user-abc" {
		t.Errorf("CallingUserID = %q, want user-abc", got.CallingUserID)
	}
	if got.Mode != ModeLink {
		t.Errorf("Mode = %q, want %q", got.Mode, ModeLink)
	}
	if got.UserID != "user-abc" {
		t.Errorf("UserID = %q, want user-abc", got.UserID)
	}
	if got.Purpose != "saml_state" {
		t.Errorf("Purpose = %q, want saml_state", got.Purpose)
	}
}

// TestStateCookieEmptyModeDefaultsLogin verifies that cookies signed
// without an explicit Mode (i.e. v1.12 / v1.14-era /login cookies)
// still verify cleanly + the caller reads Mode == "" which the ACS
// handler maps to ModeLogin. This protects the rolling-deploy window
// where in-flight cookies from a previous version land on a new
// binary. v1.15 walk-fix (TD-FUNC-18).
func TestStateCookieEmptyModeDefaultsLogin(t *testing.T) {
	secret := []byte("saml-state-secret-32-bytes-long!!")
	issuer := "barista-saml-state-test"
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)

	signed, err := SignStateCookieWithSecret(secret, StateCookieClaims{
		ProviderID: "kc",
		// Mode + UserID intentionally omitted.
	}, issuer, now, 10*time.Minute)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := VerifyStateCookieWithSecret(secret, signed, issuer, func() time.Time { return now.Add(time.Minute) })
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Mode != "" {
		t.Errorf("Mode = %q, want empty (caller treats as ModeLogin)", got.Mode)
	}
	if got.UserID != "" {
		t.Errorf("UserID = %q, want empty on non-link cookie", got.UserID)
	}
}

// TestStateCookieExpired ensures expiry collapses to ErrStateExpired.
func TestStateCookieExpired(t *testing.T) {
	secret := []byte("saml-state-secret-32-bytes-long!!")
	issuer := "barista-saml-state-test"
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)

	signed, err := SignStateCookieWithSecret(secret, StateCookieClaims{
		ProviderID: "kc",
	}, issuer, now, 1*time.Minute)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	_, err = VerifyStateCookieWithSecret(secret, signed, issuer, func() time.Time {
		return now.Add(10 * time.Minute)
	})
	if err == nil {
		t.Fatalf("expected expired token to fail verification")
	}
	if !strings.Contains(err.Error(), "expir") {
		t.Errorf("expected expiry-related error, got %v", err)
	}
}

// TestStateCookieBadSignature ensures a tampered token fails verify
// without panic.
func TestStateCookieBadSignature(t *testing.T) {
	secret := []byte("saml-state-secret-32-bytes-long!!")
	issuer := "barista-saml-state-test"
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)

	signed, err := SignStateCookieWithSecret(secret, StateCookieClaims{
		ProviderID: "kc",
	}, issuer, now, 10*time.Minute)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Flip a character in the signature segment (last segment).
	parts := strings.Split(signed, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWT to have 3 parts, got %d", len(parts))
	}
	// Use a different secret for verification.
	_, err = VerifyStateCookieWithSecret([]byte("different-secret-32-bytes-long!!"), signed, issuer, func() time.Time { return now.Add(time.Minute) })
	if err == nil {
		t.Fatalf("expected wrong-secret verify to fail")
	}
}

// TestStateCookieModeConstants ensures the exported mode values match
// the OIDC sibling literals — the ACS handler reads both surfaces with
// identical case-sensitive comparisons.
func TestStateCookieModeConstants(t *testing.T) {
	if ModeLogin != "login" {
		t.Errorf("ModeLogin = %q, want login", ModeLogin)
	}
	if ModeLink != "link" {
		t.Errorf("ModeLink = %q, want link", ModeLink)
	}
}
