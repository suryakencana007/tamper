package espresso

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/oauth2social"
	"golang.org/x/oauth2"
)

const oa2Secret = "oauth2-social-state-secret-32-bytes!"
const oa2Issuer = "tamper-test"

// fakeSocialIdP stands in for Discord: a token endpoint that hands back
// an access token, and a userinfo endpoint that returns an identity.
// Both are plain HTTP handlers, so the flow is exercised end to end
// without a network.
type fakeSocialIdP struct {
	srv       *httptest.Server
	userinfo  map[string]any
	lastForm  url.Values
	tokenCode int
}

func newFakeSocialIdP(t *testing.T, userinfo map[string]any) *fakeSocialIdP {
	t.Helper()
	f := &fakeSocialIdP{userinfo: userinfo, tokenCode: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.lastForm = r.Form
		if f.tokenCode != http.StatusOK {
			w.WriteHeader(f.tokenCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at-12345",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/users/@me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-12345" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.userinfo)
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// provider builds a social provider pointed at the fake IdP. The fake
// serves TLS so the https-only construction guard is satisfied honestly
// rather than being worked around.
func (f *fakeSocialIdP) provider(t *testing.T) *oauth2social.Provider {
	t.Helper()
	cfg := oauth2social.Discord("cid", "csecret", "https://app.example/cb")
	cfg.AuthURL = f.srv.URL + "/authorize"
	cfg.TokenURL = f.srv.URL + "/token"
	cfg.UserinfoURL = f.srv.URL + "/users/@me"
	p, err := oauth2social.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// ctx returns a context carrying the fake IdP's OWN http client, which
// trusts its self-signed certificate.
//
// Deliberately not InsecureSkipVerify: the package refuses plain http
// on purpose, and a test that disabled verification would be quietly
// exercising a transport the product does not permit. Handing over the
// server's client keeps the TLS requirement real and satisfies it
// honestly.
func (f *fakeSocialIdP) ctx() context.Context {
	return context.WithValue(context.Background(), oauth2.HTTPClient, f.srv.Client())
}

func oa2Cookie() StateCookieConfig {
	return StateCookieConfig{BaseName: "oa2_state", Path: "/", TTL: 10 * time.Minute}
}

func startFlow(t *testing.T, p *oauth2social.Provider) (authURL string, cookieVal string, state string) {
	t.Helper()
	u, c, err := StartOAuth2Flow(p, []byte(oa2Secret), oa2Issuer, time.Now(), oa2Cookie(), StartOptions{})
	if err != nil {
		t.Fatalf("StartOAuth2Flow: %v", err)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	return u, c.Value, parsed.Query().Get("state")
}

// TestStartOAuth2Flow_AlwaysSendsPKCEAndNeverANonce pins the two
// protocol differences from the OIDC sibling.
//
// PKCE is unconditional because there is no id_token to bind the
// exchange; the code verifier is what stops a stolen authorization code
// being redeemed by anyone else. The nonce is absent because nothing
// downstream could check it — shipping one would look like replay
// protection to a future reader while protecting nothing.
func TestStartOAuth2Flow_AlwaysSendsPKCEAndNeverANonce(t *testing.T) {
	f := newFakeSocialIdP(t, nil)
	p := f.provider(t)

	authURL, _, _ := startFlow(t, p)
	q, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	params := q.Query()

	if got := params.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	if params.Get("code_challenge") == "" {
		t.Error("no code_challenge on the authorize url; a stolen code would be redeemable by anyone")
	}
	if params.Get("nonce") != "" {
		t.Error("a nonce was sent; nothing in this protocol can verify one, so it is false assurance")
	}
	// Step-up parameters must not be forwarded either -- a social
	// provider cannot satisfy them, and sending them would tell the app
	// a re-auth had been demanded when none was.
	if params.Get("max_age") != "" || params.Get("acr_values") != "" {
		t.Error("step-up parameters forwarded to a provider that cannot honour them")
	}
}

// TestVerifyOAuth2Callback_HappyPath walks the whole flow and asserts
// the output is protocol-blind: the claims are the same *oidc.Claims an
// OIDC callback yields.
func TestVerifyOAuth2Callback_HappyPath(t *testing.T) {
	f := newFakeSocialIdP(t, map[string]any{
		"id": "80351110224678912", "email": "nelly@example.com",
		"verified": true, "username": "nelly", "global_name": "Nelly",
	})
	p := f.provider(t)
	_, cookieVal, state := startFlow(t, p)

	out, err := VerifyOAuth2Callback(f.ctx(), p, "the-code", state, cookieVal,
		[]byte(oa2Secret), oa2Issuer, time.Now)
	if err != nil {
		t.Fatalf("VerifyOAuth2Callback: %v", err)
	}
	if out.ProviderID != "discord" {
		t.Errorf("ProviderID = %q", out.ProviderID)
	}
	if out.Claims.Sub != "80351110224678912" || out.Claims.Email != "nelly@example.com" {
		t.Errorf("claims = %+v", out.Claims)
	}
	if !out.Claims.EmailVerified {
		t.Error("EmailVerified lost in transit")
	}
	// The exchange must have presented the PKCE verifier.
	if f.lastForm.Get("code_verifier") == "" {
		t.Error("token exchange sent no code_verifier")
	}
}

// TestVerifyOAuth2Callback_StateIsTheWholeCSRFDefence is the security
// test of this file.
//
// With no id_token and no nonce, the cookie-vs-parameter state check and
// the cookie-vs-provider check ARE the binding between the browser that
// started the flow and the response arriving back. Both would pass every
// manual test if removed, and both would then accept a callback injected
// by any other site.
func TestVerifyOAuth2Callback_StateIsTheWholeCSRFDefence(t *testing.T) {
	f := newFakeSocialIdP(t, map[string]any{
		"id": "1", "email": "a@example.com", "verified": true,
	})
	p := f.provider(t)

	t.Run("state parameter must match the cookie", func(t *testing.T) {
		_, cookieVal, _ := startFlow(t, p)
		// f.ctx() so that if the state check were ever REMOVED, this
		// fails by reporting the callback was accepted -- not by
		// tripping over TLS on the way to the exchange. A pin should
		// fail for the reason it names.
		_, err := VerifyOAuth2Callback(f.ctx(), p, "code", "attacker-supplied-state", cookieVal,
			[]byte(oa2Secret), oa2Issuer, time.Now)
		if !errors.Is(err, ErrOAuth2State) {
			t.Fatalf("err = %v, want ErrOAuth2State", err)
		}
	})

	t.Run("a cookie from ANOTHER provider is refused", func(t *testing.T) {
		// Provider-binding: without it, a state cookie minted for a
		// weakly-protected provider could be replayed at a stronger one.
		other := f.provider(t)
		cfg := other.Config
		cfg.ID = "some-other-provider"
		otherP, err := oauth2social.New(cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		_, cookieVal, state := startFlow(t, otherP)

		_, err = VerifyOAuth2Callback(f.ctx(), p, "code", state, cookieVal,
			[]byte(oa2Secret), oa2Issuer, time.Now)
		if !errors.Is(err, ErrOAuth2State) {
			t.Fatalf("cookie from another provider accepted: err = %v", err)
		}
	})

	t.Run("a cookie signed with another secret is refused", func(t *testing.T) {
		u, _, _ := startFlow(t, p)
		_ = u
		_, forged, err := StartOAuth2Flow(p, []byte("a-different-secret-32-bytes-long!!"), oa2Issuer,
			time.Now(), oa2Cookie(), StartOptions{})
		if err != nil {
			t.Fatalf("StartOAuth2Flow: %v", err)
		}
		parsed, _ := url.Parse(u)
		_, err = VerifyOAuth2Callback(f.ctx(), p, "code", parsed.Query().Get("state"), forged.Value,
			[]byte(oa2Secret), oa2Issuer, time.Now)
		if !errors.Is(err, ErrOAuth2State) {
			t.Fatalf("forged cookie accepted: err = %v", err)
		}
	})
}

// TestVerifyOAuth2Callback_SurfacesIdentityFences pins that the
// oauth2social sentinels reach the caller unwrapped, so an app can tell
// a user-actionable refusal (verify your address) from upstream trouble.
func TestVerifyOAuth2Callback_SurfacesIdentityFences(t *testing.T) {
	t.Run("unverified email", func(t *testing.T) {
		f := newFakeSocialIdP(t, map[string]any{
			"id": "1", "email": "a@example.com", "verified": false,
		})
		p := f.provider(t)
		_, cookieVal, state := startFlow(t, p)
		_, err := VerifyOAuth2Callback(f.ctx(), p, "code", state, cookieVal,
			[]byte(oa2Secret), oa2Issuer, time.Now)
		if !errors.Is(err, oauth2social.ErrEmailUnverified) {
			t.Fatalf("err = %v, want ErrEmailUnverified", err)
		}
	})

	t.Run("no email at all", func(t *testing.T) {
		f := newFakeSocialIdP(t, map[string]any{"id": "1", "verified": true})
		p := f.provider(t)
		_, cookieVal, state := startFlow(t, p)
		_, err := VerifyOAuth2Callback(f.ctx(), p, "code", state, cookieVal,
			[]byte(oa2Secret), oa2Issuer, time.Now)
		if !errors.Is(err, oauth2social.ErrEmailRequired) {
			t.Fatalf("err = %v, want ErrEmailRequired", err)
		}
	})

	t.Run("token exchange failure is distinguishable", func(t *testing.T) {
		f := newFakeSocialIdP(t, map[string]any{"id": "1", "email": "a@b.co", "verified": true})
		f.tokenCode = http.StatusInternalServerError
		p := f.provider(t)
		_, cookieVal, state := startFlow(t, p)
		_, err := VerifyOAuth2Callback(f.ctx(), p, "code", state, cookieVal,
			[]byte(oa2Secret), oa2Issuer, time.Now)
		if !errors.Is(err, ErrOAuth2Exchange) {
			t.Fatalf("err = %v, want ErrOAuth2Exchange", err)
		}
		// Upstream trouble must NOT read as a user-actionable refusal.
		if errors.Is(err, oauth2social.ErrEmailRequired) || errors.Is(err, oauth2social.ErrEmailUnverified) {
			t.Error("an upstream 500 was reported as a user-fixable identity problem")
		}
	})
}

// TestStartOAuth2Flow_CookieIsHardened pins the cookie attributes. The
// state cookie is the only thing binding this flow to this browser, so
// a script-readable or cross-site-sent cookie would undo the defence
// the rest of this file tests.
func TestStartOAuth2Flow_CookieIsHardened(t *testing.T) {
	f := newFakeSocialIdP(t, nil)
	p := f.provider(t)
	_, c, err := StartOAuth2Flow(p, []byte(oa2Secret), oa2Issuer, time.Now(),
		StateCookieConfig{BaseName: "oa2_state", Path: "/", TTL: time.Minute, Secure: true}, StartOptions{})
	if err != nil {
		t.Fatalf("StartOAuth2Flow: %v", err)
	}
	if !c.HttpOnly {
		t.Error("state cookie is script-readable")
	}
	if !c.Secure {
		t.Error("Secure not honoured")
	}
	if c.SameSite == http.SameSiteNoneMode {
		t.Error("SameSite=None on the state cookie defeats its CSRF purpose")
	}
	if !strings.Contains(c.Name, "oa2_state") {
		t.Errorf("cookie name %q ignores the configured BaseName", c.Name)
	}
}
