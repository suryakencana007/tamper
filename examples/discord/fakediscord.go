package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
)

// fakeDiscord is an embedded stand-in for discord.com so the example runs
// with no external dependencies and no real application registration.
//
// It implements the three endpoints the flow touches, and NOTHING else — no
// signing keys, no discovery document — because that absence is the point of
// the package this example exercises. A real Discord integration changes only
// the endpoint URLs and the client credentials; the tamper wiring is identical.
type fakeDiscord struct {
	srv *httptest.Server

	mu sync.Mutex
	// user is what /users/@me returns. Mutable so a test can flip the
	// verification flag and watch the fence fire.
	user map[string]any
	// codes maps an issued authorization code to the PKCE challenge that was
	// presented at /authorize, so the token endpoint can refuse a mismatch the
	// way the real one does.
	codes map[string]string
}

func newFakeDiscord() *fakeDiscord {
	f := &fakeDiscord{
		codes: map[string]string{},
		user: map[string]any{
			// A real snowflake shape: 64-bit, delivered as a STRING.
			"id":          "80351110224678912",
			"username":    "nelly",
			"global_name": "Nelly",
			"email":       "nelly@example.com",
			"verified":    true,
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/authorize", f.authorize)
	mux.HandleFunc("/api/oauth2/token", f.token)
	mux.HandleFunc("/api/users/@me", f.userinfo)

	// TLS, because oauth2social refuses plain-http endpoints. The example
	// hands its own client to the flow rather than disabling verification —
	// see clientContext in main.go.
	f.srv = httptest.NewTLSServer(mux)
	return f
}

func (f *fakeDiscord) Close()      { f.srv.Close() }
func (f *fakeDiscord) URL() string { return f.srv.URL }

// setVerified flips the email verification flag, so the example's test can
// prove the RejectUnverifiedEmail fence actually refuses a sign-in.
func (f *fakeDiscord) setVerified(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.user["verified"] = v
}

// authorize stands in for the consent screen: it immediately redirects back
// to the app with a code, echoing state. It records the PKCE challenge so the
// token endpoint can enforce it.
func (f *fakeDiscord) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	if redirect == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	code := "code-" + q.Get("state")

	f.mu.Lock()
	f.codes[code] = q.Get("code_challenge")
	f.mu.Unlock()

	u, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := u.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// token exchanges the code. It verifies a code_verifier was presented,
// because a token endpoint that ignores PKCE would let this example pass
// while the real one rejected it.
func (f *fakeDiscord) token(w http.ResponseWriter, r *http.Request) {
	// Bound the read before parsing. Even a fixture should not model an
	// endpoint that will happily buffer an unbounded body -- this file is
	// what a reader copies when wiring a real provider.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	code := r.Form.Get("code")

	f.mu.Lock()
	challenge, known := f.codes[code]
	delete(f.codes, code) // single-use, like the real thing
	f.mu.Unlock()

	if !known {
		http.Error(w, "unknown or reused code", http.StatusBadRequest)
		return
	}
	if challenge != "" && r.Form.Get("code_verifier") == "" {
		http.Error(w, "code_challenge was sent but no code_verifier presented", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "demo-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        "identify email",
	})
}

// userinfo is Discord's GET /users/@me. It requires the bearer token, so the
// example proves the access token is actually spent rather than assumed.
func (f *fakeDiscord) userinfo(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer demo-access-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	body := make(map[string]any, len(f.user))
	for k, v := range f.user {
		body[k] = v
	}
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}
