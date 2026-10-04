package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/suryakencana007/tamper/tenant"
)

// call sends one request with a bearer token and returns the status,
// the body and the cookies the response set.
func call(t *testing.T, method, url, bearer string) (int, []byte, []*http.Cookie) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, resp.Cookies()
}

// enter asks for a token for target, presenting a token on home's route.
func enter(t *testing.T, srv *httptest.Server, home, target, bearer string) (int, string) {
	t.Helper()
	status, raw, cookies := call(t, http.MethodPost, srv.URL+"/t/"+home+"/auth/enter/"+target, bearer)
	if len(cookies) != 0 {
		t.Errorf("enter %s -> %s set %d cookie(s); entering gives an access token only", home, target, len(cookies))
	}
	var out enterResponse
	_ = json.Unmarshal(raw, &out)
	return status, out.Token
}

func getWhoami(t *testing.T, srv *httptest.Server, tenantID, bearer string) (int, whoamiResponse) {
	t.Helper()
	status, raw, _ := call(t, http.MethodGet, srv.URL+"/t/"+tenantID+"/whoami", bearer)
	var out whoamiResponse
	_ = json.Unmarshal(raw, &out)
	return status, out
}

// The Phase 8 flow, end to end over HTTP: a platform admin with a
// membership in acme enters acme, works there, and can go nowhere else.
func TestPlatformAdminEntersATenant(t *testing.T) {
	srv, store := newServer(t)

	admin := register(t, srv, tenantPlatform, "ops@platform.example")
	adminID := dto(t, admin.User).ID
	store.grantMembership(adminID, tenant.New(tenantAcme))

	status, entered := enter(t, srv, tenantPlatform, tenantAcme, admin.Token)
	if status != http.StatusOK || entered == "" {
		t.Fatalf("enter acme as a member: status %d, token %q", status, entered)
	}

	// Inside acme the token is accepted, and it says where its holder is from.
	status, who := getWhoami(t, srv, tenantAcme, entered)
	if status != http.StatusOK {
		t.Fatalf("whoami in acme with the entered token: status %d", status)
	}
	want := whoamiResponse{UserID: adminID, Tenant: tenantAcme, HomeTenant: tenantPlatform, Entered: true}
	if who != want {
		t.Errorf("whoami = %+v, want %+v", who, want)
	}

	// It is a token for acme and for nothing else — not globex, and not
	// the admin's own tenant either.
	for _, other := range []string{tenantGlobex, tenantPlatform} {
		if status, _ := getWhoami(t, srv, other, entered); status == http.StatusOK {
			t.Errorf("the token entered into acme was accepted on a %s route", other)
		}
	}

	// The admin has no account in acme. /me is "my account here".
	if status, _ := getMe(t, srv, tenantAcme, entered); status == http.StatusOK {
		t.Error("/me in acme answered for a platform admin, who is not an acme user")
	}

	// The home session is untouched: it still works at home, and still
	// does not work in acme.
	if status, who := getWhoami(t, srv, tenantPlatform, admin.Token); status != http.StatusOK || who.Entered {
		t.Errorf("home token at home: status %d, entered=%v", status, who.Entered)
	}
	if status, _ := getWhoami(t, srv, tenantAcme, admin.Token); status == http.StatusOK {
		t.Error("the admin's HOME token was accepted on an acme route without entering")
	}
}

// No membership, no entry — and the answer is the plain not-found.
func TestEnterIsRefusedWithoutAMembership(t *testing.T) {
	srv, store := newServer(t)

	admin := register(t, srv, tenantPlatform, "ops@platform.example")
	adminID := dto(t, admin.User).ID
	store.grantMembership(adminID, tenant.New(tenantAcme))

	// A member of acme is not a member of globex.
	if status, tok := enter(t, srv, tenantPlatform, tenantGlobex, admin.Token); status != http.StatusNotFound || tok != "" {
		t.Errorf("enter globex without a membership: status %d, token %q; want 404 and no token", status, tok)
	}

	// A customer's user has no membership anywhere.
	bob := register(t, srv, tenantAcme, "bob@acme.com")
	if status, tok := enter(t, srv, tenantAcme, tenantGlobex, bob.Token); status != http.StatusNotFound || tok != "" {
		t.Errorf("an acme user entering globex: status %d, token %q; want 404 and no token", status, tok)
	}
	// And cannot use the platform tenant's enter route: the gate on it
	// refuses a token that is not a platform token.
	if status, tok := enter(t, srv, tenantPlatform, tenantGlobex, bob.Token); status == http.StatusOK || tok != "" {
		t.Errorf("an acme token on the platform enter route: status %d, token %q", status, tok)
	}

	// Taking the membership away stops the next entry.
	if status, _ := enter(t, srv, tenantPlatform, tenantAcme, admin.Token); status != http.StatusOK {
		t.Fatalf("enter acme while a member: status %d", status)
	}
	store.revokeMembership(adminID, tenant.New(tenantAcme))
	if status, tok := enter(t, srv, tenantPlatform, tenantAcme, admin.Token); status != http.StatusNotFound || tok != "" {
		t.Errorf("enter acme after the membership was revoked: status %d, token %q; want 404 and no token", status, tok)
	}
}

// An entered token is not a way to enter further. The admin here is a
// member of both tenants, so only the route's own rule can refuse.
func TestEnteredTokenCannotEnterFurther(t *testing.T) {
	srv, store := newServer(t)

	admin := register(t, srv, tenantPlatform, "ops@platform.example")
	adminID := dto(t, admin.User).ID
	store.grantMembership(adminID, tenant.New(tenantAcme))
	store.grantMembership(adminID, tenant.New(tenantGlobex))

	status, entered := enter(t, srv, tenantPlatform, tenantAcme, admin.Token)
	if status != http.StatusOK {
		t.Fatalf("enter acme: status %d", status)
	}
	if status, tok := enter(t, srv, tenantAcme, tenantGlobex, entered); status != http.StatusNotFound || tok != "" {
		t.Errorf("entering globex with a token entered into acme: status %d, token %q; want 404 and no token", status, tok)
	}
	// From home it works: the right is real, the path was wrong.
	if status, _ := enter(t, srv, tenantPlatform, tenantGlobex, admin.Token); status != http.StatusOK {
		t.Errorf("enter globex from the home session: status %d, want 200", status)
	}
}
