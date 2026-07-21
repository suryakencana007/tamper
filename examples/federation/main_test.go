package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/suryakencana007/barista/packages/tamper/identity"
)

type exchangeResp struct {
	Token    string          `json:"token"`
	User     json.RawMessage `json:"user"`
	Redirect string          `json:"redirect"`
}

// TestFederation_EndToEnd is the proof: it drives the full OIDC authorization-
// code flow — start -> IdP -> callback -> exchange — through the wired server
// against the embedded fake IdP, and asserts a session is minted. Running it
// twice proves BOTH halves of the identity core: the first flow JIT-provisions
// the user, the second resolves the same (provider, subject) identity.
func TestFederation_EndToEnd(t *testing.T) {
	idp, err := newFakeIDP()
	if err != nil {
		t.Fatalf("newFakeIDP: %v", err)
	}
	defer idp.Close()

	// appBaseURL is lazy: the app's own URL is only known after httptest starts.
	var srv *httptest.Server
	router, provider, err := buildHandler(identity.NewMemStore(), "federation-test-secret", idp.URL, func() string { return srv.URL })
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	defer func() { _ = provider.Close() }()
	srv = httptest.NewServer(router)
	defer srv.Close()

	first := driveSSO(t, srv, idp)
	assertEmail(t, first.User, "alice@example.com")
	if first.Token == "" {
		t.Error("first SSO (provision): expected an access token")
	}

	second := driveSSO(t, srv, idp)
	assertEmail(t, second.User, "alice@example.com")
	if second.Token == "" {
		t.Error("second SSO (resolve): expected an access token")
	}

	// The resolve path must reuse the SAME user, not provision a duplicate —
	// assert the user id is identical across the two flows (directly, not just
	// via the store's uniqueness constraint).
	if id1, id2 := userID(t, first.User), userID(t, second.User); id1 != id2 {
		t.Errorf("resolve created a new user: first id %q != second id %q", id1, id2)
	}
}

// driveSSO walks the browser dance by hand. The client MUST NOT follow
// redirects: the callback carries code+state in the URL FRAGMENT, which Go's
// http.Client silently drops when it auto-follows a 302. A fresh cookie jar
// per call models an independent browser session.
func driveSSO(t *testing.T, srv *httptest.Server, idp *fakeIDP) exchangeResp {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// 1. Start -> 302 to the IdP authorize endpoint; the state cookie is set.
	authURL := location(t, client, srv.URL+"/api/auth/oidc/start/keycloak")
	if !strings.HasPrefix(authURL, idp.URL+"/auth") {
		t.Fatalf("start: Location = %q, want prefix %q", authURL, idp.URL+"/auth")
	}
	for _, k := range []string{"state", "nonce", "redirect_uri", "code_challenge"} {
		if mustQuery(t, authURL).Get(k) == "" {
			t.Errorf("authorize URL missing %q: %s", k, authURL)
		}
	}

	// 2. IdP authorize -> 302 back to the app callback with code + state.
	cbURL := location(t, client, authURL)
	if !strings.HasPrefix(cbURL, srv.URL+"/api/auth/oidc/callback/keycloak") {
		t.Fatalf("idp: Location = %q, want app callback prefix", cbURL)
	}

	// 3. Callback -> 302 to the landing path with code/state/provider in the FRAGMENT.
	landing := location(t, client, cbURL)
	frag := fragment(t, landing)
	if frag.Get("provider") != "keycloak" {
		t.Errorf("landing fragment provider = %q, want keycloak", frag.Get("provider"))
	}
	code, state := frag.Get("code"), frag.Get("state")
	if code == "" || state == "" {
		t.Fatalf("landing fragment missing code/state: %s", landing)
	}

	// 4. Exchange the code/state (the state cookie rides via the jar).
	body := `{"provider_id":"keycloak","code":"` + code + `","state":"` + state + `"}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/oidc/exchange", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange: status %d: %s", resp.StatusCode, raw)
	}
	haveRefresh := false
	for _, ck := range resp.Cookies() {
		if ck.Name == "federation_refresh" && ck.Value != "" {
			haveRefresh = true
		}
	}
	if !haveRefresh {
		t.Error("exchange: expected a federation_refresh cookie on the login leg")
	}
	var out exchangeResp
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("exchange decode %q: %v", raw, err)
	}
	return out
}

// location does a GET that is expected to 302, returning the Location header.
func location(t *testing.T, client *http.Client, rawURL string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("GET %s: status %d, want a 302/303", rawURL, resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatalf("GET %s: no Location header", rawURL)
	}
	return loc
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Query()
}

func fragment(t *testing.T, raw string) url.Values {
	t.Helper()
	_, frag, ok := strings.Cut(raw, "#")
	if !ok {
		t.Fatalf("no fragment in %q", raw)
	}
	vals, err := url.ParseQuery(frag)
	if err != nil {
		t.Fatalf("parse fragment %q: %v", frag, err)
	}
	return vals
}

func assertEmail(t *testing.T, raw json.RawMessage, want string) {
	t.Helper()
	var u struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(raw, &u); err != nil {
		t.Fatalf("decode user %q: %v", raw, err)
	}
	if u.Email != want {
		t.Errorf("user email = %q, want %q", u.Email, want)
	}
}

func userID(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var u struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &u); err != nil {
		t.Fatalf("decode user %q: %v", raw, err)
	}
	if u.ID == "" {
		t.Fatalf("user payload has no id: %s", raw)
	}
	return u.ID
}
