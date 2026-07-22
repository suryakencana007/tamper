package espresso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/suryakencana007/tamper/oidc"
)

// --- compact fake OIDC IdP (discovery + JWKS + token) --------------
// A lean twin of tamper/oidc's package-private harness, sufficient to
// build a real *oidc.Provider and drive the Exchange + ID-token-verify
// leg of VerifyOIDCCallback. Full auth-code parity also rides on
// Barista's OIDC handler suite.

type fakeIdP struct {
	url      string
	key      *rsa.PrivateKey
	kid      string
	clientID string
	codes    map[string]jwt.MapClaims
}

func newFakeIdP(t *testing.T, clientID string) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	f := &fakeIdP{key: key, kid: "k1", clientID: clientID, codes: map[string]jwt.MapClaims{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.url, "authorization_endpoint": f.url + "/auth",
			"token_endpoint": f.url + "/token", "jwks_uri": f.url + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := f.key.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": f.kid,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		claims, ok := f.codes[r.PostForm.Get("code")]
		if !ok {
			http.Error(w, "unknown code", http.StatusBadRequest)
			return
		}
		now := time.Now()
		claims["iss"] = f.url
		claims["aud"] = f.clientID
		claims["exp"] = now.Add(5 * time.Minute).Unix()
		claims["iat"] = now.Unix()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = f.kid
		signed, _ := tok.SignedString(f.key)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "stub", "id_token": signed, "token_type": "Bearer", "expires_in": 300,
		})
	})
	srv := httptest.NewServer(mux)
	f.url = srv.URL
	t.Cleanup(srv.Close)
	return f
}

func (f *fakeIdP) mintCode(claims jwt.MapClaims) string {
	code := "code-" + base64.RawURLEncoding.EncodeToString([]byte(time.Now().String()))
	f.codes[code] = claims
	return code
}

func fakeProvider(t *testing.T, f *fakeIdP) *oidc.Provider {
	t.Helper()
	reg, err := oidc.BuildRegistryFromConfigs(context.Background(), []oidc.ProviderConfig{{
		ID: "kc", IssuerURL: f.url, ClientID: f.clientID, ClientSecret: "secret",
		RedirectURL: "https://rp.example/cb/kc",
	}}, false)
	if err != nil {
		t.Fatalf("BuildRegistry: %v", err)
	}
	p, _ := reg.Get("kc")
	return p
}

const (
	testSecret = "oidc-spine-test-secret-key-32bytes!!"
	testIssuer = "test-oidc-state"
)

func testStateCookie() StateCookieConfig {
	return StateCookieConfig{BaseName: "app_oidc_state", Secure: false, Path: "/", TTL: oidc.StateTTL}
}

// --- StartOIDCFlow -------------------------------------------------

func TestStartOIDCFlow_AuthURLAndCookie(t *testing.T) {
	f := newFakeIdP(t, "kc")
	p := fakeProvider(t, f)
	now := time.Unix(1_700_000_000, 0)

	authURL, cookie, err := StartOIDCFlow(p, []byte(testSecret), testIssuer, now, testStateCookie(),
		StartOptions{Redirect: "/projects", MaxAge: 300, ACRValues: []string{"urn:x:silver"}, Mode: oidc.ModeLogin, CallingUserID: "u1"})
	if err != nil {
		t.Fatalf("StartOIDCFlow: %v", err)
	}
	u, _ := url.Parse(authURL)
	q := u.Query()
	for k, want := range map[string]string{
		"response_type": "code", "client_id": "kc",
		"code_challenge_method": "S256", "max_age": "300",
		"acr_values": "urn:x:silver", "prompt": "login",
	} {
		if q.Get(k) != want {
			t.Errorf("authURL[%s] = %q, want %q", k, q.Get(k), want)
		}
	}
	if q.Get("nonce") == "" || q.Get("code_challenge") == "" || q.Get("state") == "" {
		t.Fatalf("authURL missing pkce/nonce/state: %s", authURL)
	}
	// Cookie: name (insecure → bare brand), attrs, and it must verify.
	if cookie.Name != "app_oidc_state" || cookie.Path != "/" || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie attrs drifted: %+v", cookie)
	}
	claims, err := oidc.VerifyOIDCStateWithSecret([]byte(testSecret), cookie.Value, testIssuer, func() time.Time { return now.Add(time.Minute) })
	if err != nil {
		t.Fatalf("cookie must verify: %v", err)
	}
	if claims.State != q.Get("state") || claims.RedirectAfterLogin != "/projects" ||
		claims.RequestedMaxAgeSeconds != 300 || claims.CallingUserID != "u1" || claims.Mode != oidc.ModeLogin {
		t.Fatalf("state claims drifted: %+v", claims)
	}
}

func TestStartOIDCFlow_NonStepUpNoPromptOrParams(t *testing.T) {
	f := newFakeIdP(t, "kc")
	p := fakeProvider(t, f)
	authURL, _, err := StartOIDCFlow(p, []byte(testSecret), testIssuer, time.Now(), testStateCookie(),
		StartOptions{Mode: oidc.ModeLink, UserID: "u9"})
	if err != nil {
		t.Fatalf("StartOIDCFlow: %v", err)
	}
	q, _ := url.ParseQuery(strings.SplitN(authURL, "?", 2)[1])
	if q.Has("max_age") || q.Has("acr_values") || q.Has("prompt") {
		t.Fatalf("link start must forward no step-up params: %s", authURL)
	}
}

func TestStartOIDCFlow_SecureCookieHostPrefix(t *testing.T) {
	f := newFakeIdP(t, "kc")
	p := fakeProvider(t, f)
	_, cookie, err := StartOIDCFlow(p, []byte(testSecret), testIssuer, time.Now(),
		StateCookieConfig{BaseName: "app_oidc_state", Secure: true, Path: "/", TTL: oidc.StateTTL},
		StartOptions{})
	if err != nil {
		t.Fatalf("StartOIDCFlow: %v", err)
	}
	if cookie.Name != "__Host-app_oidc_state" || !cookie.Secure {
		t.Fatalf("secure cookie must be __Host--prefixed: %+v", cookie)
	}
}

// --- VerifyOIDCCallback --------------------------------------------

func startAndMint(t *testing.T, f *fakeIdP, p *oidc.Provider, nonceClaims func(jwt.MapClaims)) (code, state, cookieVal string) {
	t.Helper()
	now := time.Now()
	authURL, cookie, err := StartOIDCFlow(p, []byte(testSecret), testIssuer, now, testStateCookie(), StartOptions{})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	q, _ := url.ParseQuery(strings.SplitN(authURL, "?", 2)[1])
	stateClaims, _ := oidc.VerifyOIDCStateWithSecret([]byte(testSecret), cookie.Value, testIssuer, time.Now)
	mc := jwt.MapClaims{"sub": "u-001", "email": "a@example.com", "nonce": stateClaims.Nonce}
	if nonceClaims != nil {
		nonceClaims(mc)
	}
	return f.mintCode(mc), q.Get("state"), cookie.Value
}

func TestVerifyOIDCCallback_HappyPath(t *testing.T) {
	f := newFakeIdP(t, "kc")
	p := fakeProvider(t, f)
	code, state, cookieVal := startAndMint(t, f, p, nil)

	v, err := VerifyOIDCCallback(context.Background(), p, code, state, cookieVal, []byte(testSecret), testIssuer, time.Now)
	if err != nil {
		t.Fatalf("VerifyOIDCCallback: %v", err)
	}
	if v.ProviderID != "kc" || v.Claims.Sub != "u-001" || v.Claims.Email != "a@example.com" {
		t.Fatalf("verified claims drifted: %+v", v.Claims)
	}
	if v.State.Nonce == "" {
		t.Fatal("state claims must round-trip")
	}
}

func TestVerifyOIDCCallback_NonceMismatch(t *testing.T) {
	f := newFakeIdP(t, "kc")
	p := fakeProvider(t, f)
	code, state, cookieVal := startAndMint(t, f, p, func(mc jwt.MapClaims) { mc["nonce"] = "WRONG" })
	_, err := VerifyOIDCCallback(context.Background(), p, code, state, cookieVal, []byte(testSecret), testIssuer, time.Now)
	if !errors.Is(err, oidc.ErrNonceMismatch) {
		t.Fatalf("err = %v, want ErrNonceMismatch", err)
	}
}

func TestVerifyOIDCCallback_StateFailures(t *testing.T) {
	f := newFakeIdP(t, "kc")
	p := fakeProvider(t, f)
	code, state, cookieVal := startAndMint(t, f, p, nil)

	// Wrong cookie value → ErrOIDCState (before any Exchange).
	if _, err := VerifyOIDCCallback(context.Background(), p, code, state, "garbage", []byte(testSecret), testIssuer, time.Now); !errors.Is(err, ErrOIDCState) {
		t.Errorf("bad cookie: err = %v, want ErrOIDCState", err)
	}
	// State param mismatch → ErrOIDCState.
	if _, err := VerifyOIDCCallback(context.Background(), p, code, "not-the-state", cookieVal, []byte(testSecret), testIssuer, time.Now); !errors.Is(err, ErrOIDCState) {
		t.Errorf("state mismatch: err = %v, want ErrOIDCState", err)
	}
	// Wrong secret → ErrOIDCState.
	if _, err := VerifyOIDCCallback(context.Background(), p, code, state, cookieVal, []byte("different-secret-of-some-length!!"), testIssuer, time.Now); !errors.Is(err, ErrOIDCState) {
		t.Errorf("bad secret: err = %v, want ErrOIDCState", err)
	}
}

func TestVerifyOIDCCallback_ExchangeFailure(t *testing.T) {
	f := newFakeIdP(t, "kc")
	p := fakeProvider(t, f)
	_, state, cookieVal := startAndMint(t, f, p, nil)
	// An unknown code makes the IdP token endpoint 400 → ErrOIDCExchange.
	if _, err := VerifyOIDCCallback(context.Background(), p, "no-such-code", state, cookieVal, []byte(testSecret), testIssuer, time.Now); !errors.Is(err, ErrOIDCExchange) {
		t.Fatalf("err = %v, want ErrOIDCExchange", err)
	}
}
