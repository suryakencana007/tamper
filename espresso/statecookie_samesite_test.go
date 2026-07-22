package espresso

// The SameSite zero-value trap — closed at wiring.
//
// TD-FUNC-28 was: the SAML state cookie shipped SameSite=Lax while the
// ACS is a cross-site POST, so the cookie never arrived on any real IdP.
// Link mode and step-up were dead in the field; login kept working
// (RelayState duplicates the redirect), which is why nobody noticed.
//
// The fix added StateCookieConfig.SameSite. That field then RE-ARMED the
// same bug for the next caller: its zero value resolves to Lax, and the
// natural way to write a new protocol's config is to copy the OIDC one —
// which omits SameSite, because Lax is right there. Copy it for SAML and
// you silently get Lax again, in production only (dev runs HTTP, where
// Lax works fine).
//
// So the field is now required. One line per call site, and the trap
// becomes unrepresentable — the same fence Secure/__Host- already has.
//
// These tests exist because the failure mode is invisible everywhere
// else: httptest has no cookie jar and no site boundary, so no
// behavioural test in this repo can observe a browser's SameSite rule.
// Wiring-time rejection is the only place it CAN be caught.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/oidc"
)

// minimalFederationConfig is a valid config except for whatever the
// caller overrides.
func minimalFederationConfig() (FederationConfig, FederationHooks) {
	cfg := FederationConfig{
		LandingPath: "/auth/oidc/landing",
		StateCookie: StateCookieConfig{
			BaseName: "app_oidc_state",
			Secure:   false,
			Path:     "/",
			TTL:      5 * time.Minute,
			SameSite: http.SameSiteLaxMode,
		},
		StateSecret: []byte("secret"),
		StateIssuer: "app-oidc-state",
		Cookies:     CookieConfig{Name: "app_refresh"},
		MountPrefix: "/api/auth",
	}
	hooks := FederationHooks{
		Registry: func(context.Context) (*oidc.ProviderRegistry, error) { return nil, nil },
		OnFederatedExchange: func(context.Context, *oidc.Provider, OIDCVerified) (FederationOutcome, error) {
			return FederationOutcome{}, nil
		},
	}
	return cfg, hooks
}

// TestStateCookie_SameSiteMustBeExplicit is the guard. A config that
// omits SameSite — i.e. one written by copying another protocol's — must
// fail at wiring, not ship Lax to production.
func TestStateCookie_SameSiteMustBeExplicit(t *testing.T) {
	cfg, hooks := minimalFederationConfig()
	cfg.StateCookie.SameSite = 0 // the copy-paste omission

	_, err := NewFederationRoutes(cfg, hooks)
	if err == nil {
		t.Fatal("a zero SameSite must be REJECTED at wiring: it silently resolves to Lax, " +
			"which is correct for a GET callback and fatal for a cross-site POST ACS (TD-FUNC-28). " +
			"Failing here is the only place this is catchable — no behavioural test can see a browser's SameSite rule.")
	}
	if !strings.Contains(err.Error(), "SameSite") {
		t.Errorf("error should name the field so the fix is obvious; got: %v", err)
	}
}

// TestStateCookie_SameSiteNoneRequiresSecure keeps the other half:
// browsers reject None without Secure outright, so the cookie would
// simply never be set — a runtime-only, silent failure.
func TestStateCookie_SameSiteNoneRequiresSecure(t *testing.T) {
	cfg, hooks := minimalFederationConfig()
	cfg.StateCookie.SameSite = http.SameSiteNoneMode
	cfg.StateCookie.Secure = false

	if _, err := NewFederationRoutes(cfg, hooks); err == nil {
		t.Fatal("SameSite=None without Secure must be rejected — browsers drop the pair and the cookie never lands")
	}
}

// TestStateCookie_ValidCombinationsAccepted pins that the fence rejects
// only the genuinely broken shapes. A guard that rejects valid configs
// would just get deleted by the next person.
func TestStateCookie_ValidCombinationsAccepted(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sameSite http.SameSite
		secure   bool
	}{
		{"lax insecure (dev, GET callback)", http.SameSiteLaxMode, false},
		{"lax secure (prod, GET callback)", http.SameSiteLaxMode, true},
		{"none secure (prod, cross-site POST ACS)", http.SameSiteNoneMode, true},
		{"strict secure", http.SameSiteStrictMode, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, hooks := minimalFederationConfig()
			cfg.StateCookie.SameSite = tc.sameSite
			cfg.StateCookie.Secure = tc.secure
			if _, err := NewFederationRoutes(cfg, hooks); err != nil {
				t.Errorf("valid config rejected: %v", err)
			}
		})
	}
}

// TestStateCookie_SetAndClearAgreeOnSameSite pins attribute parity. A
// clear cookie whose attributes differ from the set cookie is refused as
// an overwrite by browsers, so the single-use fence silently stops
// working.
func TestStateCookie_SetAndClearAgreeOnSameSite(t *testing.T) {
	for _, ss := range []http.SameSite{http.SameSiteLaxMode, http.SameSiteNoneMode, http.SameSiteStrictMode} {
		c := StateCookieConfig{BaseName: "s", Path: "/", TTL: time.Minute, SameSite: ss, Secure: ss == http.SameSiteNoneMode}
		set, clear := c.Set("v"), c.Clear()
		if set.SameSite != ss || clear.SameSite != ss {
			t.Errorf("SameSite=%v: set=%v clear=%v — both must carry the configured value", ss, set.SameSite, clear.SameSite)
		}
		if set.SameSite != clear.SameSite {
			t.Errorf("set/clear SameSite drift (%v vs %v) — the browser refuses the overwrite and the cookie outlives its single use",
				set.SameSite, clear.SameSite)
		}
	}
}
