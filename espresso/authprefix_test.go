package espresso

import (
	"context"
	"testing"

	"encoding/json"

	espressofw "github.com/suryakencana007/espresso/v2"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

// Phase 14 slice 14b (TD-14): a dynamic tenant surface. The cookie's Path is the CSRF
// fence, so these tests are about the path, not about cookie formatting.

func TestAuthPrefixFor_ThreeOutcomes(t *testing.T) {
	cases := []struct {
		name   string
		mount  string
		tid    tenant.ID
		want   string
		wantOK bool
	}{
		{"static prefix is unchanged", "/api/auth", tenant.Single, "/api/auth", true},
		{"static prefix ignores the tenant", "/api/auth", tenant.New("acme"), "/api/auth", true},
		{"template resolves", "/t/{tenant}/auth", tenant.New("acme"), "/t/acme/auth", true},
		{"template with tenant.Single cannot fill a segment", "/t/{tenant}/auth", tenant.Single, "", false},
		{"template with an unset id cannot fill a segment", "/t/{tenant}/auth", tenant.ID{}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := authPrefixFor(tc.mount, tc.tid)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("authPrefixFor(%q, %v) = (%q, %v), want (%q, %v)",
					tc.mount, tc.tid, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// routesOnTemplate builds an AuthRoutes whose mount is a template and whose ONE resolver
// pins the tenant from the request — the shape invariant 1a requires.
func routesOnTemplate(t *testing.T, svc IdentityService, tenantID tenant.ID) *AuthRoutes {
	t.Helper()
	a, err := NewAuthRoutes(svc, AuthRoutesConfig{
		MountPrefix: "/t/" + TenantPathSegment + "/auth",
		Tenant:      func(context.Context) (tenant.ID, bool) { return tenantID, tenantID.Valid() },
		Cookies:     CookieConfig{Name: "app_refresh"},
		ProjectUser: func(context.Context, *identity.User) json.RawMessage { return nil },
	})
	if err != nil {
		t.Fatalf("NewAuthRoutes: %v", err)
	}
	return a
}

func TestAuthRoutes_TemplateMountScopesTheCookieToTheTenant(t *testing.T) {
	svc := &tenantRecorder{}
	a := routesOnTemplate(t, svc, tenant.New("acme"))

	// The set path, asserted on the builder the success envelope uses: the fixture does
	// not mint refresh tokens, and the property under test is the Path, not the envelope.
	cookies := a.refreshCookies(identity.Tokens{Refresh: "r-token"}, tenant.New("acme"))
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	if got, want := cookies[0].Path, "/t/acme/auth"; got != want {
		t.Fatalf("cookie Path = %q, want %q — the fence is Path == the request's mount prefix", got, want)
	}
	if cookies[0].Name != "app_refresh" {
		t.Fatalf("cookie Name = %q; one name is correct now that the PATH separates tenants",
			cookies[0].Name)
	}

	// Invariant 1a is structural rather than asserted: the value that fills {tenant} is
	// the value that reached `refreshCookies`, which in the handler IS the tenant passed
	// to the port — there is one resolver, and no second opinion to compare against.
	_ = svc
}

// Fail closed: a template that cannot be filled writes no cookie at all, rather than one
// at the literal placeholder path.
func TestAuthRoutes_TemplateWithoutATenantSetsNoCookie(t *testing.T) {
	svc := &tenantRecorder{}
	a := routesOnTemplate(t, svc, tenant.Single)

	res, err := a.VerifyTOTP(context.Background(), &espressofw.JSON[TOTPVerifyReq]{
		Data: TOTPVerifyReq{SessionToken: "pending", Code: "123456"},
	})
	if err != nil {
		t.Fatalf("VerifyTOTP: %v", err)
	}
	if len(res.Cookies) != 0 {
		t.Fatalf("cookies = %+v, want none: a template with no tenant has no path to scope to",
			res.Cookies)
	}
}

// The clear must use the same derived path: a clear at another path deletes nothing and
// leaves the user logged in on a route that just signed them out.
func TestAuthRoutes_TemplateLogoutClearsTheSamePath(t *testing.T) {
	svc := &tenantRecorder{}
	a := routesOnTemplate(t, svc, tenant.New("globex"))

	res, err := a.Logout(context.Background())
	if err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if len(res.Cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(res.Cookies))
	}
	c := res.Cookies[0]
	if c.Path != "/t/globex/auth" {
		t.Fatalf("clear Path = %q, want /t/globex/auth", c.Path)
	}
	if c.MaxAge != -1 || c.Value != "" {
		t.Fatalf("clear cookie = %+v, want MaxAge=-1 and an empty value", c)
	}
}

// Static prefixes keep working exactly as before, including the clear on a request whose
// tenant did not resolve: the path is fixed, so there is still something to clear.
func TestAuthRoutes_StaticMountClearsEvenWithoutATenant(t *testing.T) {
	svc := &tenantRecorder{}
	a, err := NewAuthRoutes(svc, AuthRoutesConfig{
		MountPrefix: "/api/auth",
		Tenant:      func(context.Context) (tenant.ID, bool) { return tenant.ID{}, false },
		Cookies:     CookieConfig{Name: "app_refresh"},
		ProjectUser: func(context.Context, *identity.User) json.RawMessage { return nil },
	})
	if err != nil {
		t.Fatalf("NewAuthRoutes: %v", err)
	}
	res, err := a.Logout(context.Background())
	if err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if len(res.Cookies) != 1 || res.Cookies[0].Path != "/api/auth" {
		t.Fatalf("cookies = %+v, want one clear at /api/auth", res.Cookies)
	}
}
