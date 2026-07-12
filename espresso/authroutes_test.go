package espresso

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	espressofw "github.com/suryakencana007/espresso/v2"

	"github.com/suryakencana007/barista/packages/tamper/identity"
)

// fakeIdentity scripts the port surface per test.
type fakeIdentity struct {
	IdentityService
	login   func(email, password string) (AuthResult, error)
	refresh func(tok string) (AuthResult, error)
	logout  []string
	pending string
}

func (f *fakeIdentity) Login(_ context.Context, email, password string) (AuthResult, error) {
	return f.login(email, password)
}
func (f *fakeIdentity) IssueTOTPPending(userID string) (string, error) {
	f.pending = userID
	return "session-tok-" + userID, nil
}
func (f *fakeIdentity) Refresh(_ context.Context, tok string) (AuthResult, error) {
	return f.refresh(tok)
}
func (f *fakeIdentity) Logout(_ context.Context, tok string) error {
	f.logout = append(f.logout, tok)
	return nil
}

func testRoutes(t *testing.T, svc IdentityService) *AuthRoutes {
	t.Helper()
	a, err := NewAuthRoutes(svc, AuthRoutesConfig{
		MountPrefix: "/api/auth",
		Cookies:     CookieConfig{Name: "app_refresh", Secure: true, MaxAgeSeconds: 3600},
		ProjectUser: func(_ context.Context, u *identity.User) json.RawMessage {
			if u == nil {
				return json.RawMessage(`{"id":"","email":""}`)
			}
			b, _ := json.Marshal(map[string]string{"id": u.ID, "email": u.Email})
			return b
		},
	})
	if err != nil {
		t.Fatalf("NewAuthRoutes: %v", err)
	}
	return a
}

func TestAuthRoutes_ConfigValidation(t *testing.T) {
	svc := &fakeIdentity{}
	for name, cfg := range map[string]AuthRoutesConfig{
		"bad prefix":   {MountPrefix: "api/auth", Cookies: CookieConfig{Name: "c"}, ProjectUser: func(context.Context, *identity.User) json.RawMessage { return nil }},
		"slash suffix": {MountPrefix: "/api/auth/", Cookies: CookieConfig{Name: "c"}, ProjectUser: func(context.Context, *identity.User) json.RawMessage { return nil }},
		"no cookie":    {MountPrefix: "/api/auth", ProjectUser: func(context.Context, *identity.User) json.RawMessage { return nil }},
		"no projector": {MountPrefix: "/api/auth", Cookies: CookieConfig{Name: "c"}},
	} {
		if _, err := NewAuthRoutes(svc, cfg); err == nil {
			t.Errorf("%s: want wiring-time error", name)
		}
	}
}

func TestAuthRoutes_LoginMintsCookieWithDerivedPath(t *testing.T) {
	user := &identity.User{ID: "u1", Email: "a@example.com"}
	svc := &fakeIdentity{login: func(string, string) (AuthResult, error) {
		return AuthResult{User: user, Tokens: identity.Tokens{Access: "acc", Refresh: "ref"}}, nil
	}}
	a := testRoutes(t, svc)

	res, err := a.Login(context.Background(), &espressofw.JSON[LoginReq]{Data: LoginReq{Email: "a@example.com", Password: "pw"}})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if res.Data.Token != "acc" || res.Data.TOTPRequired || len(res.Cookies) != 1 {
		t.Fatalf("login shape: %+v", res.Data)
	}
	c := res.Cookies[0]
	if c.Name != "app_refresh" || c.Value != "ref" || c.Path != "/api/auth" ||
		!c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 3600 {
		t.Fatalf("cookie attributes drifted: %+v", c)
	}
}

func TestAuthRoutes_TOTPBranchSetsNoCookie(t *testing.T) {
	user := &identity.User{ID: "u2", Email: "b@example.com"}
	svc := &fakeIdentity{login: func(string, string) (AuthResult, error) {
		return AuthResult{User: user}, identity.ErrTOTPRequired
	}}
	a := testRoutes(t, svc)

	res, err := a.Login(context.Background(), &espressofw.JSON[LoginReq]{Data: LoginReq{}})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !res.Data.TOTPRequired || res.Data.SessionToken != "session-tok-u2" || res.Data.Token != "" {
		t.Fatalf("totp branch shape: %+v", res.Data)
	}
	if len(res.Cookies) != 0 {
		t.Fatal("refresh cookie must only mint after the second factor")
	}
}

func TestAuthRoutes_RefreshUserInactive401WithClearCookie(t *testing.T) {
	svc := &fakeIdentity{refresh: func(string) (AuthResult, error) {
		return AuthResult{}, identity.ErrUserInactive
	}}
	a := testRoutes(t, svc)
	ctx := context.WithValue(context.Background(), namedCookieKey(refreshCookieSlotName), "stale")

	res, err := a.Refresh(ctx)
	if err != nil {
		t.Fatalf("inactive branch must ride the JSON envelope, not the error path: %v", err)
	}
	if res.StatusCode != http.StatusUnauthorized || len(res.Cookies) != 1 || res.Cookies[0].MaxAge != -1 {
		t.Fatalf("USER_INACTIVE shape: status=%d cookies=%+v", res.StatusCode, res.Cookies)
	}
	if string(res.Data.User) != `{"id":"","email":""}` {
		t.Fatalf("zero-user projection drifted: %s", res.Data.User)
	}
	// Attribute parity on the clear cookie.
	c := res.Cookies[0]
	if c.Path != "/api/auth" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Value != "" {
		t.Fatalf("clear cookie attributes drifted: %+v", c)
	}
}

func TestAuthRoutes_RefreshErrorMapping(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		code string
	}{
		"invalid session": {identity.ErrInvalidSession, "UNAUTHENTICATED"},
		"not found":       {identity.ErrNotFound, "UNAUTHENTICATED"},
	} {
		svc := &fakeIdentity{refresh: func(string) (AuthResult, error) { return AuthResult{}, tc.err }}
		a := testRoutes(t, svc)
		ctx := context.WithValue(context.Background(), namedCookieKey(refreshCookieSlotName), "x")
		_, err := a.Refresh(ctx)
		var e *espressofw.Error
		if !errors.As(err, &e) || e.Code != tc.code {
			t.Errorf("%s: err=%v, want code %s", name, err, tc.code)
		}
	}
	// Missing cookie entirely.
	svc := &fakeIdentity{}
	a := testRoutes(t, svc)
	_, err := a.Refresh(context.Background())
	var e *espressofw.Error
	if !errors.As(err, &e) || e.Code != "UNAUTHENTICATED" {
		t.Errorf("missing cookie: err=%v, want UNAUTHENTICATED", err)
	}
}

func TestAuthRoutes_LogoutIdempotentClear(t *testing.T) {
	svc := &fakeIdentity{}
	a := testRoutes(t, svc)

	// No cookie: still 204 + clear.
	res, err := a.Logout(context.Background())
	if err != nil || res.StatusCode != http.StatusNoContent || len(res.Cookies) != 1 || res.Cookies[0].MaxAge != -1 {
		t.Fatalf("logout no-cookie: %+v err=%v", res, err)
	}
	if len(svc.logout) != 0 {
		t.Fatal("no revocation without a cookie")
	}
	// With cookie: revokes best-effort.
	ctx := context.WithValue(context.Background(), namedCookieKey(refreshCookieSlotName), "tok-1")
	if _, err := a.Logout(ctx); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if len(svc.logout) != 1 || svc.logout[0] != "tok-1" {
		t.Fatalf("revocation calls: %v", svc.logout)
	}
}
