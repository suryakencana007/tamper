package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/suryakencana007/tamper/identity"
)

// authResp mirrors the AuthRes envelope the auth routes return.
type authResp struct {
	Token string          `json:"token"`
	User  json.RawMessage `json:"user"`
}

// TestQuickstart_EndToEnd is the proof the facade compiles and works against
// the real API: it drives register -> login -> me -> refresh through the
// wired server over HTTP, with a cookie jar so the HttpOnly refresh cookie
// round-trips exactly as a browser's would.
func TestQuickstart_EndToEnd(t *testing.T) {
	handler, provider, err := buildHandler(identity.NewMemStore(), "quickstart-test-secret")
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	defer func() { _ = provider.Close() }()

	srv := httptest.NewServer(handler)
	defer srv.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{Jar: jar}

	const email = "alice@example.com"
	const password = "correct-horse-battery"
	body := `{"email":"` + email + `","password":"` + password + `"}`

	// --- register: mints the first session + sets the refresh cookie ---
	reg := postAuth(t, client, srv.URL+"/api/auth/register", body)
	if reg.Token == "" {
		t.Error("register: expected an access token")
	}
	assertEmail(t, reg.User, email)

	// --- me without a token: RequireAuth must reject ---
	if code := getStatus(t, client, srv.URL+"/api/auth/me", ""); code != http.StatusUnauthorized {
		t.Errorf("me without bearer: status = %d, want 401", code)
	}

	// --- login: a fresh access token + rotated refresh cookie ---
	login := postAuth(t, client, srv.URL+"/api/auth/login", body)
	if login.Token == "" {
		t.Error("login: expected an access token")
	}

	// --- me with the bearer token: returns the projected user ---
	meBody := getMe(t, client, srv.URL+"/api/auth/me", login.Token)
	assertEmail(t, meBody, email)

	// --- refresh: the cookie jar carries the refresh cookie; a new token ---
	refreshed := postAuth(t, client, srv.URL+"/api/auth/refresh", "")
	if refreshed.Token == "" {
		t.Error("refresh: expected a rotated access token")
	}
}

func postAuth(t *testing.T, client *http.Client, url, body string) authResp {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(http.MethodPost, url, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("POST %s: status %d: %s", url, resp.StatusCode, raw)
	}
	var out authResp
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("POST %s: decode %q: %v", url, raw, err)
	}
	return out
}

func getMe(t *testing.T, client *http.Client, url, bearer string) json.RawMessage {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", url, resp.StatusCode, raw)
	}
	return raw
}

func getStatus(t *testing.T, client *http.Client, url, bearer string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
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
