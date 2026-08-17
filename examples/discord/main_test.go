package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	espresso "github.com/suryakencana007/espresso/v2"
)

// newTestApp wires the example against an embedded fake Discord and returns a
// live server plus a cookie-jar client — a browser, essentially.
func newTestApp(t *testing.T) (*httptest.Server, *http.Client, *fakeDiscord) {
	t.Helper()

	fake := newFakeDiscord()
	t.Cleanup(fake.Close)

	// Stand the server up FIRST behind a mux, so its URL exists before the
	// app is built. newApp resolves the callback URL eagerly -- as a real
	// deployment can, knowing its own hostname at boot -- so the test has to
	// supply a real one rather than a closure over a nil server.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	a := newApp("test-secret-32-bytes-long-enough!!", fake, func() string { return srv.URL })
	router := espresso.Portafilter()
	a.mount(router)
	mux.Handle("/", router)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{Jar: jar}
	// The fake serves TLS with a self-signed cert; give the browser the
	// same trust the app has. Not InsecureSkipVerify -- see clientContext.
	client.Transport = fake.srv.Client().Transport

	return srv, client, fake
}

// signInOnce drives the whole browser dance: start -> fake consent screen ->
// callback, following redirects with a cookie jar.
func signInOnce(t *testing.T, srv *httptest.Server, client *http.Client) (*http.Response, string) {
	t.Helper()
	res, err := client.Get(srv.URL + "/auth/discord/start")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	return res, string(body)
}

// TestDiscord_EndToEnd is the proof the package works against a provider with
// no OIDC layer: a full authorization-code flow, PKCE enforced by the fake's
// token endpoint, identity fetched from userinfo, and a real session minted.
//
// Running it TWICE is the second half of the proof: the first pass
// JIT-provisions the account, the second RESOLVES the same one by
// (provider, subject). If the subject were unstable — or if the app keyed on
// the email — the second pass would create a duplicate.
func TestDiscord_EndToEnd(t *testing.T) {
	srv, client, _ := newTestApp(t)

	res, body := signInOnce(t, srv, client)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first sign-in: status %d, body %s", res.StatusCode, body)
	}
	var first callbackResult
	if err := json.Unmarshal([]byte(body), &first); err != nil {
		t.Fatalf("decode: %v (body %s)", err, body)
	}
	if !first.FirstSignIn {
		t.Error("first pass should have JIT-provisioned")
	}
	if first.Subject != "80351110224678912" {
		t.Errorf("subject = %q, want the snowflake", first.Subject)
	}
	if first.Email != "nelly@example.com" {
		t.Errorf("email = %q", first.Email)
	}
	if first.Token == "" {
		t.Error("no session minted")
	}

	// Second sign-in: same person, same account.
	res2, body2 := signInOnce(t, srv, client)
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("second sign-in: status %d, body %s", res2.StatusCode, body2)
	}
	var second callbackResult
	if err := json.Unmarshal([]byte(body2), &second); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if second.FirstSignIn {
		t.Error("second pass provisioned AGAIN -- the identity did not resolve by (provider, subject)")
	}
	if second.UserID != first.UserID {
		t.Errorf("user id changed between sign-ins: %q -> %q", first.UserID, second.UserID)
	}
}

// TestDiscord_UnverifiedEmailIsRefused proves the fence is real end to end,
// not merely unit-tested. An app keys its email-collision veto on this
// address; an unverified one is an assertion, not a fact.
func TestDiscord_UnverifiedEmailIsRefused(t *testing.T) {
	srv, client, fake := newTestApp(t)
	fake.setVerified(false)

	res, body := signInOnce(t, srv, client)
	if res.StatusCode == http.StatusOK {
		t.Fatalf("an unverified email signed in: %s", body)
	}
	if !strings.Contains(body, "EMAIL_UNVERIFIED") {
		t.Errorf("expected the EMAIL_UNVERIFIED code, got: %s", body)
	}

	// And it is recoverable: verify upstream, sign in again, done. This is
	// the property that makes the refusal user-actionable rather than a
	// dead end.
	fake.setVerified(true)
	res2, body2 := signInOnce(t, srv, client)
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("sign-in after verifying still failed: %d %s", res2.StatusCode, body2)
	}
}

// TestDiscord_CallbackWithoutStateCookieIsRefused pins the CSRF fence at the
// example level. With no id_token and no nonce, the state cookie is the only
// thing binding the callback to the browser that started the flow — so a
// callback arriving without one must be refused outright.
func TestDiscord_CallbackWithoutStateCookieIsRefused(t *testing.T) {
	srv, _, _ := newTestApp(t)

	// A fresh client with NO cookie jar: exactly what an injected callback
	// from another site looks like.
	res, err := http.Get(srv.URL + "/auth/discord/callback?code=whatever&state=whatever")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)

	if res.StatusCode == http.StatusOK {
		t.Fatalf("a callback with no state cookie was accepted: %s", body)
	}
	if !strings.Contains(string(body), "INVALID_STATE") {
		t.Errorf("expected INVALID_STATE, got: %s", body)
	}
}
