package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeIDP is an httptest-backed minimal OIDC IdP that stands in for a real
// one (Keycloak, Auth0, Okta, ...). It serves discovery + JWKS + a
// browser-driven authorization endpoint + a token endpoint, signing ID
// tokens with a per-process RSA key — just enough for the coreos/go-oidc
// library that tamper/oidc wraps to run the auth-code flow end to end with
// no external dependency.
//
// The tamper wiring against this fake IdP is IDENTICAL to a real one — only
// the issuer URL and client credentials change. See the README's
// "Integrating with Keycloak" section for the real-IdP config.
type fakeIDP struct {
	URL          string
	server       *httptest.Server
	signingKey   *rsa.PrivateKey
	kid          string
	clientID     string
	clientSecret string

	mu    sync.Mutex
	codes map[string]jwt.MapClaims
}

func newFakeIDP() (*fakeIDP, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("fakeidp: generate key: %w", err)
	}
	idp := &fakeIDP{
		signingKey:   key,
		kid:          "example-key-1",
		clientID:     "example-client",
		clientSecret: "example-secret",
		codes:        map[string]jwt.MapClaims{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", idp.handleDiscovery)
	mux.HandleFunc("/jwks", idp.handleJWKS)
	mux.HandleFunc("/auth", idp.handleAuth)
	mux.HandleFunc("/token", idp.handleToken)
	mux.HandleFunc("/userinfo", idp.handleUserinfo)
	srv := httptest.NewServer(mux)
	idp.URL = srv.URL
	idp.server = srv
	return idp, nil
}

// Close shuts the IdP's HTTP server down. Safe on a nil server.
func (i *fakeIDP) Close() {
	if i != nil && i.server != nil {
		i.server.Close()
	}
}

func (i *fakeIDP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	// coreos/go-oidc pins the discovery doc's issuer to equal the
	// configured IssuerURL, so this MUST echo i.URL exactly.
	doc := map[string]any{
		"issuer":                                i.URL,
		"authorization_endpoint":                i.URL + "/auth",
		"token_endpoint":                        i.URL + "/token",
		"jwks_uri":                              i.URL + "/jwks",
		"userinfo_endpoint":                     i.URL + "/userinfo",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (i *fakeIDP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	pub := i.signingKey.PublicKey
	doc := map[string]any{
		"keys": []map[string]string{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": i.kid,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big2bytes(int64(pub.E))),
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

// handleAuth is the authorization endpoint the browser lands on after the
// app's /oidc/start 302. A real IdP would render a login page; here we
// auto-approve a fixed demo user: mint a single-use code, remember the
// request's nonce (it must ride into the eventual ID token so tamper's
// callback nonce check passes), and 302 back to the app's redirect_uri
// with code + state.
func (i *fakeIDP) handleAuth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	nonce := q.Get("nonce")
	if redirectURI == "" {
		http.Error(w, "fakeidp: missing redirect_uri", http.StatusBadRequest)
		return
	}

	i.mu.Lock()
	code := fmt.Sprintf("code-%d", time.Now().UnixNano())
	i.codes[code] = jwt.MapClaims{
		"sub":            "keycloak-user-001",
		"email":          "alice@example.com",
		"email_verified": true,
		"name":           "Alice Example",
		"nonce":          nonce,
	}
	i.mu.Unlock()

	loc := redirectURI + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
	http.Redirect(w, r, loc, http.StatusFound)
}

// handleToken exchanges a code for tokens. NOTE (fidelity gap): it checks
// client_id but deliberately does NOT verify the client_secret or the PKCE
// code_verifier — a real IdP does both. So a green end-to-end test proves the
// happy-path wiring, not full IdP-contract coverage; a regression that broke
// secret or PKCE propagation would still pass here but fail against Keycloak.
func (i *fakeIDP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil { //nolint:gosec // fake test IdP; local trusted traffic, no body-size hardening needed
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	clientID := r.PostForm.Get("client_id")
	if clientID == "" {
		// Some clients send credentials via Basic auth instead of the body.
		if u, _, ok := r.BasicAuth(); ok {
			clientID = u
		}
	}
	if clientID != i.clientID {
		http.Error(w, "client_id mismatch", http.StatusUnauthorized)
		return
	}

	code := r.PostForm.Get("code")
	i.mu.Lock()
	stored, ok := i.codes[code]
	delete(i.codes, code) // single-use
	i.mu.Unlock()
	if !ok {
		http.Error(w, "unknown code", http.StatusBadRequest)
		return
	}

	claims := jwt.MapClaims{}
	for k, v := range stored {
		claims[k] = v
	}
	now := time.Now()
	claims["iss"] = i.URL
	claims["aud"] = i.clientID
	claims["exp"] = now.Add(5 * time.Minute).Unix()
	claims["iat"] = now.Unix()

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = i.kid
	signed, err := tok.SignedString(i.signingKey)
	if err != nil {
		http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "stub-access",
		"id_token":     signed,
		"token_type":   "Bearer",
		"expires_in":   300,
	})
}

func (i *fakeIDP) handleUserinfo(w http.ResponseWriter, _ *http.Request) {
	// Not reached in this flow — tamper verifies the ID token, not userinfo —
	// but advertised in discovery, so answer coherently.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"sub": "keycloak-user-001", "email": "alice@example.com"})
}

// big2bytes serialises a small RSA public exponent (almost always 65537)
// into the big-endian byte shape the JWKS "e" member expects.
func big2bytes(e int64) []byte {
	b := []byte{byte(e >> 16), byte(e >> 8), byte(e)} //nolint:gosec // intentional byte extraction of a small (<=2^24) exponent
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}
