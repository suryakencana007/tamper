package espresso

// readState — the SAML state cookie's verify path and its cross-provider
// replay defense.
//
// WHY THIS FILE EXISTS (4d-5). These properties were covered in Barista
// (saml_stepup_test.go) against an app-side readSAMLStateCookie. The
// 4d-4c lift moved production onto the readState below and left that
// function behind; because its tests still called it, `unused` stayed
// quiet and the coverage silently stopped tracking production.
//
// Proven by mutation rather than by inspection: DELETING the
// ProviderID check below — a security control — compiled and passed
// every test in BOTH modules. The replay defense was implemented here
// and guarded nowhere.
//
// The rule this encodes: when a mechanic moves into tamper, its tests
// move with it. A test left pointing at the vacated app-side copy is
// worse than no test, because it reports the coverage it no longer
// provides.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/suryakencana007/barista/packages/tamper/saml"
)

// stateRoutesFixture builds SAMLRoutes with a known signing secret and
// returns it alongside a signer for minting cookie values the way Login
// would.
func stateRoutesFixture(t *testing.T) (*SAMLRoutes, []byte, string) {
	t.Helper()
	secret := []byte("saml-state-secret-32-bytes-long!!")
	const issuer = "test-saml-state"

	routes, err := NewSAMLRoutes(
		SAMLConfig{
			StateCookie: StateCookieConfig{
				BaseName: "app_saml_state",
				Secure:   false,
				Path:     "/",
				TTL:      5 * time.Minute,
				SameSite: http.SameSiteLaxMode,
			},
			StateSecret: secret,
			StateIssuer: issuer,
			StateTTL:    5 * time.Minute,
			Cookies:     CookieConfig{Name: "app_refresh"},
			MountPrefix: "/api/auth",
		},
		SAMLHooks{
			Registry: func(context.Context) (*saml.ProviderRegistry, error) { return nil, nil },
			OnFederatedAssertion: func(context.Context, *saml.Provider, SAMLVerified) (SAMLOutcome, error) {
				return SAMLOutcome{}, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("NewSAMLRoutes: %v", err)
	}
	return routes, secret, issuer
}

// withStateCookie runs fn with a context carrying value in the SAML
// state slot, populated through the real middleware so the slot name is
// exercised rather than assumed.
func withStateCookie(t *testing.T, r *SAMLRoutes, value string, fn func(ctx context.Context)) {
	t.Helper()
	r.ReadStateCookie()(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		fn(req.Context())
	})).ServeHTTP(httptest.NewRecorder(), func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/saml/acs/prov-a", nil)
		if value != "" {
			req.AddCookie(&http.Cookie{Name: r.cfg.StateCookie.Name(), Value: value})
		}
		return req
	}())
}

// TestReadState_HappyPath round-trips a signed cookie and pins that the
// step-up claims survive verbatim.
func TestReadState_HappyPath(t *testing.T) {
	routes, secret, issuer := stateRoutesFixture(t)

	value, err := saml.SignStateCookieWithSecret(secret, saml.StateCookieClaims{
		ProviderID:             "prov-a",
		RedirectAfterLogin:     "/projects/foo",
		RequestedMaxAgeSeconds: 600,
		RequestedACRValues:     []string{"urn:silver"},
		CallingUserID:          "user-xyz",
	}, issuer, time.Now(), 5*time.Minute)
	if err != nil {
		t.Fatalf("SignStateCookieWithSecret: %v", err)
	}

	withStateCookie(t, routes, value, func(ctx context.Context) {
		got, ok := routes.readState(ctx, "prov-a")
		if !ok {
			t.Fatal("readState ok=false on the happy path")
		}
		if got.RequestedMaxAgeSeconds != 600 {
			t.Errorf("RequestedMaxAgeSeconds = %d, want 600", got.RequestedMaxAgeSeconds)
		}
		if got.CallingUserID != "user-xyz" {
			t.Errorf("CallingUserID = %q, want user-xyz", got.CallingUserID)
		}
	})
}

// TestReadState_CrossProviderReplayRejected is the security control.
//
// A cookie minted at provider A's /login must not be honored at
// provider B's ACS. Without this, an attacker who can get a victim to
// start a flow at a provider they control can replay that state — with
// its Mode=link and UserID — against a different provider's ACS.
//
// This is the mutation that passed every test in both modules before
// this file existed. If you delete the ProviderID check in readState,
// THIS is what must go red.
func TestReadState_CrossProviderReplayRejected(t *testing.T) {
	routes, secret, issuer := stateRoutesFixture(t)

	// Minted under prov-a...
	value, err := saml.SignStateCookieWithSecret(secret, saml.StateCookieClaims{
		ProviderID:    "prov-a",
		Mode:          saml.ModeLink,
		UserID:        "victim-user",
		CallingUserID: "victim-user",
	}, issuer, time.Now(), 5*time.Minute)
	if err != nil {
		t.Fatalf("SignStateCookieWithSecret: %v", err)
	}

	// ...replayed against prov-b's ACS.
	withStateCookie(t, routes, value, func(ctx context.Context) {
		if _, ok := routes.readState(ctx, "prov-b"); ok {
			t.Error("readState honored a prov-a cookie at prov-b's ACS — cross-provider replay defense is gone. " +
				"The cookie is signed, so the signature check passes; only the ProviderID comparison stops this.")
		}
	})
}

// TestReadState_RejectsBadSignature pins that a tampered value collapses
// to ok=false rather than panicking or, worse, parsing.
func TestReadState_RejectsBadSignature(t *testing.T) {
	routes, _, _ := stateRoutesFixture(t)

	withStateCookie(t, routes, "not.a.valid.jwt", func(ctx context.Context) {
		if _, ok := routes.readState(ctx, "prov-a"); ok {
			t.Error("readState accepted an unsigned/garbage cookie value")
		}
	})
}

// TestReadState_RejectsForeignIssuer pins the issuer check. Barista mints
// several HS256 tokens with the same secret (access JWT, OIDC state, SAML
// state); only the issuer keeps a misrouted one from satisfying this
// verifier.
func TestReadState_RejectsForeignIssuer(t *testing.T) {
	routes, secret, _ := stateRoutesFixture(t)

	value, err := saml.SignStateCookieWithSecret(secret, saml.StateCookieClaims{
		ProviderID: "prov-a",
	}, "some-other-issuer", time.Now(), 5*time.Minute)
	if err != nil {
		t.Fatalf("SignStateCookieWithSecret: %v", err)
	}

	withStateCookie(t, routes, value, func(ctx context.Context) {
		if _, ok := routes.readState(ctx, "prov-a"); ok {
			t.Error("readState accepted a cookie signed by the right secret but a FOREIGN issuer — " +
				"the iss check is what separates the SAML state cookie from the access JWT and the OIDC state cookie")
		}
	})
}

// TestReadState_MissingCookieIsNotAnError pins the fallthrough the ACS
// depends on: no cookie means "not SP-initiated / not step-up", not a
// failure. Login must still work for an IdP-initiated assertion.
func TestReadState_MissingCookieIsNotAnError(t *testing.T) {
	routes, _, _ := stateRoutesFixture(t)

	withStateCookie(t, routes, "", func(ctx context.Context) {
		if _, ok := routes.readState(ctx, "prov-a"); ok {
			t.Error("readState reported ok=true with no cookie present")
		}
	})
}
