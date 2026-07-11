package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testIdP is an httptest-backed minimal OIDC IdP used by the package
// tests. It serves the well-known discovery doc, a JWKS, a token
// endpoint, and a userinfo endpoint — just enough surface for the
// coreos/go-oidc library to run end-to-end without a real IdP.
//
// The IdP signs ID tokens with an RSA key generated per-test; the
// JWKS endpoint exposes the public half. Tokens are minted on demand
// via the MintIDToken helper so callers can drive nonce / sub /
// email scenarios independently.
type testIdP struct {
	URL          string
	server       *httptest.Server
	signingKey   *rsa.PrivateKey
	kid          string
	clientID     string
	clientSecret string

	mu                  sync.Mutex
	codes               map[string]storedCode
	idTokenMintOverride func(claims jwt.MapClaims) jwt.MapClaims
}

type storedCode struct {
	claims jwt.MapClaims
}

func newTestIdP(t *testing.T, clientID, clientSecret string) *testIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	idp := &testIdP{
		signingKey:   key,
		kid:          "test-key-1",
		clientID:     clientID,
		clientSecret: clientSecret,
		codes:        map[string]storedCode{},
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
	t.Cleanup(func() { srv.Close() })
	return idp
}

func (i *testIdP) handleDiscovery(w http.ResponseWriter, r *http.Request) {
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

func (i *testIdP) handleJWKS(w http.ResponseWriter, r *http.Request) {
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

// handleAuth is the authorization endpoint stub. It accepts the
// browser-driven GET and, in a real IdP, would render the login
// page. For tests we never hit it through a browser; the integration
// path drives the IdP via the token endpoint with a pre-issued
// code from MintCode.
func (i *testIdP) handleAuth(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "test idp: this endpoint exists for discovery, not for browser auth", http.StatusNotImplemented)
}

// MintCode pre-issues a code with a fixed claim bag. Tests pass the
// returned code to provider.OAuth2.Exchange.
func (i *testIdP) MintCode(claims jwt.MapClaims) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	code := fmt.Sprintf("code-%d", time.Now().UnixNano())
	i.codes[code] = storedCode{claims: claims}
	return code
}

// SetIDTokenMintOverride lets a test mutate the claim bag at mint
// time — used to drive the nonce-mismatch + audience-mismatch
// scenarios.
func (i *testIdP) SetIDTokenMintOverride(fn func(jwt.MapClaims) jwt.MapClaims) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.idTokenMintOverride = fn
}

func (i *testIdP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	clientID := r.PostForm.Get("client_id")
	if clientID == "" {
		// Some libraries put the credentials in Basic auth instead
		// of the form body.
		if u, _, ok := r.BasicAuth(); ok {
			clientID = u
		}
	}
	if clientID != i.clientID {
		http.Error(w, "client_id mismatch", http.StatusUnauthorized)
		return
	}
	code := r.PostForm.Get("code")
	stored, ok := i.codes[code]
	if !ok {
		http.Error(w, "unknown code", http.StatusBadRequest)
		return
	}
	delete(i.codes, code)

	claims := jwt.MapClaims{}
	for k, v := range stored.claims {
		claims[k] = v
	}
	now := time.Now()
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = i.URL
	}
	if _, ok := claims["aud"]; !ok {
		claims["aud"] = i.clientID
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = now.Add(5 * time.Minute).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = now.Unix()
	}
	i.mu.Lock()
	override := i.idTokenMintOverride
	i.mu.Unlock()
	if override != nil {
		claims = override(claims)
	}

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

func (i *testIdP) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"sub":   "test-sub",
		"email": "userinfo@example.com",
	})
}

// big2bytes is a copy of the helper coreos/go-oidc uses internally
// for serialising RSA public exponents into the JWKS shape. We
// implement it here so the test fixture stays standalone.
func big2bytes(e int64) []byte {
	// e is small (almost always 65537); 3 bytes is enough.
	b := []byte{byte(e >> 16), byte(e >> 8), byte(e)}
	// Trim leading zeros.
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

// hashTOTPSecret keeps gosec quiet about the unused crypto/sha256
// import the package retains for kid hashing in expansion.
var _ = sha256.Sum256
