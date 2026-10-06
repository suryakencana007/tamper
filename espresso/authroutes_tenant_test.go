package espresso

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	espressofw "github.com/suryakencana007/espresso/v2"

	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

// TD-28: every IdentityService call is made with the tenant the routes
// resolved for the request. The adapter never has to know it from
// somewhere else, and a route that resolves no tenant answers 404.

// tenantRecorder records the tenant each port method was handed.
type tenantRecorder struct {
	IdentityService
	seen []tenant.ID
}

func (r *tenantRecorder) note(id tenant.ID) { r.seen = append(r.seen, id) }

func (r *tenantRecorder) Register(_ context.Context, id tenant.ID, _, _ string) (AuthResult, error) {
	r.note(id)
	return AuthResult{User: &identity.User{ID: "u-1"}}, nil
}
func (r *tenantRecorder) Login(_ context.Context, id tenant.ID, _, _ string) (AuthResult, error) {
	r.note(id)
	return AuthResult{User: &identity.User{ID: "u-1"}}, identity.ErrTOTPRequired
}
func (r *tenantRecorder) IssueTOTPPending(_ context.Context, id tenant.ID, _ string) (string, error) {
	r.note(id)
	return "pending", nil
}
func (r *tenantRecorder) Me(_ context.Context, id tenant.ID, _ string) (*identity.User, error) {
	r.note(id)
	return &identity.User{ID: "u-1"}, nil
}
func (r *tenantRecorder) Refresh(_ context.Context, id tenant.ID, _ string) (AuthResult, error) {
	r.note(id)
	return AuthResult{User: &identity.User{ID: "u-1"}}, nil
}
func (r *tenantRecorder) Logout(_ context.Context, id tenant.ID, _ string) error {
	r.note(id)
	return nil
}
func (r *tenantRecorder) VerifyTOTPPending(_ context.Context, id tenant.ID, _ string) (string, error) {
	r.note(id)
	return "u-1", nil
}
func (r *tenantRecorder) VerifyTOTP(_ context.Context, id tenant.ID, _, _ string) error {
	r.note(id)
	return nil
}
func (r *tenantRecorder) IssueTokensForUser(_ context.Context, id tenant.ID, _ string) (AuthResult, error) {
	r.note(id)
	return AuthResult{User: &identity.User{ID: "u-1"}}, nil
}
func (r *tenantRecorder) EnrollTOTP(_ context.Context, id tenant.ID, _ string) (TOTPEnrollment, error) {
	r.note(id)
	return TOTPEnrollment{}, nil
}
func (r *tenantRecorder) DisableTOTP(_ context.Context, id tenant.ID, _, _ string) error {
	r.note(id)
	return nil
}
func (r *tenantRecorder) EnrollTOTPViaSession(_ context.Context, id tenant.ID, _, _ string) (*TOTPEnrollment, *AuthResult, error) {
	r.note(id)
	return &TOTPEnrollment{}, nil, nil
}

func routesFor(t *testing.T, svc IdentityService, resolve func(context.Context) (tenant.ID, bool)) *AuthRoutes {
	t.Helper()
	a, err := NewAuthRoutes(svc, AuthRoutesConfig{
		MountPrefix: "/api/auth",
		Tenant:      resolve,
		Cookies:     CookieConfig{Name: "app_refresh"},
		ProjectUser: func(context.Context, *identity.User) json.RawMessage { return nil },
	})
	if err != nil {
		t.Fatalf("NewAuthRoutes: %v", err)
	}
	return a
}

// every handler, as a call that reaches the port.
func everyHandler(a *AuthRoutes) map[string]func(ctx context.Context) error {
	withCookie := func(ctx context.Context) context.Context {
		return context.WithValue(ctx, namedCookieKey(refreshCookieSlotName), "tok")
	}
	withUser := func(ctx context.Context) context.Context { return ContextWithUserID(ctx, "u-1") }
	return map[string]func(ctx context.Context) error{
		"Register": func(ctx context.Context) error {
			_, err := a.Register(ctx, &espressofw.JSON[RegisterReq]{Data: RegisterReq{Email: "a@x", Password: "pw"}})
			return err
		},
		"Login (TOTP branch, pending token minted)": func(ctx context.Context) error {
			_, err := a.Login(ctx, &espressofw.JSON[LoginReq]{Data: LoginReq{Email: "a@x", Password: "pw"}})
			return err
		},
		"Me": func(ctx context.Context) error { _, err := a.Me(withUser(ctx)); return err },
		"VerifyTOTP": func(ctx context.Context) error {
			_, err := a.VerifyTOTP(ctx, &espressofw.JSON[TOTPVerifyReq]{Data: TOTPVerifyReq{SessionToken: "pending", Code: "123456"}})
			return err
		},
		"EnrollTOTP": func(ctx context.Context) error { _, err := a.EnrollTOTP(withUser(ctx)); return err },
		"DisableTOTP": func(ctx context.Context) error {
			_, err := a.DisableTOTP(withUser(ctx), &espressofw.JSON[TOTPDisableReq]{Data: TOTPDisableReq{Code: "123456"}})
			return err
		},
		"EnrollSession": func(ctx context.Context) error {
			_, err := a.EnrollSession(ctx, &espressofw.JSON[TOTPEnrollSessionReq]{Data: TOTPEnrollSessionReq{SessionToken: "pending"}})
			return err
		},
		"Refresh": func(ctx context.Context) error { _, err := a.Refresh(withCookie(ctx)); return err },
		"Logout":  func(ctx context.Context) error { _, err := a.Logout(withCookie(ctx)); return err },
	}
}

// The tenant the routes resolve is the tenant every port call gets.
func TestAuthRoutes_EveryPortCallCarriesTheRoutedTenant(t *testing.T) {
	acme := tenant.New("acme")
	for name := range everyHandler(nil) {
		t.Run(name, func(t *testing.T) {
			rec := &tenantRecorder{}
			a := routesFor(t, rec, FixedTenant(acme))
			if err := everyHandler(a)[name](context.Background()); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if len(rec.seen) == 0 {
				t.Fatalf("%s reached no port method", name)
			}
			for i, id := range rec.seen {
				if id != acme {
					t.Errorf("%s: port call %d was made with tenant %q, want acme", name, i, id)
				}
			}
		})
	}
}

// A route whose tenant does not resolve has no users. Every handler
// answers 404 and the port is never reached — no login, no mint, no
// revoke in a scope that does not exist.
func TestAuthRoutes_UnresolvedTenantIs404(t *testing.T) {
	for how, resolve := range map[string]func(context.Context) (tenant.ID, bool){
		"not resolved":               func(context.Context) (tenant.ID, bool) { return tenant.ID{}, false },
		"resolved to the zero ID":    func(context.Context) (tenant.ID, bool) { return tenant.ID{}, true },
		"FixedTenant of the zero ID": FixedTenant(tenant.ID{}),
	} {
		for name := range everyHandler(nil) {
			t.Run(how+"/"+name, func(t *testing.T) {
				rec := &tenantRecorder{}
				a := routesFor(t, rec, resolve)
				err := everyHandler(a)[name](context.Background())
				var e *espressofw.Error
				if !errors.As(err, &e) || e.StatusCode != http.StatusNotFound {
					t.Fatalf("%s: err = %v, want a 404", name, err)
				}
				if len(rec.seen) != 0 {
					t.Errorf("%s reached the port with tenants %v although no tenant resolved", name, rec.seen)
				}
			})
		}
	}
}

// Behind a tenant gate, TenantFromContext is the resolver.
func TestAuthRoutes_TenantFromContextResolvesThePinnedTenant(t *testing.T) {
	rec := &tenantRecorder{}
	a := routesFor(t, rec, TenantFromContext)
	ctx := context.WithValue(context.Background(), tenantCtxKey{}, tenant.New("globex"))
	if _, err := a.Register(ctx, &espressofw.JSON[RegisterReq]{Data: RegisterReq{Email: "a@x", Password: "pw"}}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(rec.seen) != 1 || rec.seen[0] != tenant.New("globex") {
		t.Errorf("port was called with %v, want [globex]", rec.seen)
	}
	// With no gate in front, nothing resolves.
	if _, err := a.Register(context.Background(), &espressofw.JSON[RegisterReq]{Data: RegisterReq{Email: "a@x", Password: "pw"}}); err == nil {
		t.Fatal("Register with no pinned tenant did not fail")
	}
}

// Auth routes that know no tenant are refused when they are built.
func TestNewAuthRoutes_RequiresTenant(t *testing.T) {
	_, err := NewAuthRoutes(&tenantRecorder{}, AuthRoutesConfig{
		MountPrefix: "/api/auth",
		Cookies:     CookieConfig{Name: "c"},
		ProjectUser: func(context.Context, *identity.User) json.RawMessage { return nil },
	})
	if err == nil {
		t.Fatal("NewAuthRoutes accepted a config with no Tenant resolver")
	}
}
