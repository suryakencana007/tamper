package espresso_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	tamper "github.com/suryakencana007/barista/packages/tamper"
	"github.com/suryakencana007/barista/packages/tamper/crypto"
	espresso "github.com/suryakencana007/barista/packages/tamper/espresso"
	"github.com/suryakencana007/barista/packages/tamper/identity"
	"github.com/suryakencana007/barista/packages/tamper/oidc"
	"github.com/suryakencana007/barista/packages/tamper/saml"
	"github.com/suryakencana007/barista/packages/tamper/scim"
)

// The route surfaces only HOLD these ports — Routes never calls a method — so
// embedding the interface (a nil value) satisfies the type compactly.
type stubIdentity struct{ espresso.IdentityService }
type stubUserStore struct{ scim.UserStore }
type stubGroupStore struct{ scim.GroupStore }

func newProvider(t *testing.T, withOIDC, withSAML bool) *tamper.Provider {
	t.Helper()
	cfg := tamper.Config{JWT: crypto.JWTConfig{Secret: "test-secret", TTL: time.Minute, Issuer: "test"}}
	if withOIDC {
		cfg.OIDC = &tamper.OIDCConfig{
			Store:       oidc.NewMemProviderStore(),
			RedirectURL: func(id string) string { return "https://app.example/cb/" + id },
		}
	}
	if withSAML {
		cfg.SAML = &tamper.SAMLConfig{
			Store:         saml.NewMemProviderStore(),
			SPMetadataURL: func(id, acsURL string) string { return acsURL + "/meta/" + id },
		}
	}
	tp, err := tamper.New(cfg)
	if err != nil {
		t.Fatalf("tamper.New: %v", err)
	}
	return tp
}

func authCfg() espresso.AuthRoutesConfig {
	return espresso.AuthRoutesConfig{
		MountPrefix: "/api/auth",
		Cookies:     espresso.CookieConfig{Name: "x_refresh"},
		ProjectUser: func(context.Context, *identity.User) json.RawMessage { return nil },
	}
}

func fedBundle() *espresso.FederationBundle {
	return &espresso.FederationBundle{
		Config: espresso.FederationConfig{
			LandingPath: "/landing",
			MountPrefix: "/api/auth",
			StateSecret: []byte("state-secret"),
			StateIssuer: "iss",
			Cookies:     espresso.CookieConfig{Name: "x_refresh"},
			StateCookie: espresso.StateCookieConfig{
				BaseName: "x_oidc_state", Path: "/", SameSite: http.SameSiteLaxMode, TTL: time.Minute,
			},
		},
		// Registry is intentionally left nil — Routes must fill it from the
		// Provider's OIDC manager.
		Hooks: espresso.FederationHooks{
			OnFederatedExchange: func(context.Context, *oidc.Provider, espresso.OIDCVerified) (espresso.FederationOutcome, error) {
				return espresso.FederationOutcome{}, nil
			},
		},
	}
}

func samlBundle() *espresso.SAMLBundle {
	return &espresso.SAMLBundle{
		Config: espresso.SAMLConfig{
			MountPrefix: "/api/auth",
			StateSecret: []byte("state-secret"),
			StateIssuer: "iss",
			StateTTL:    time.Minute,
			Cookies:     espresso.CookieConfig{Name: "x_refresh"},
			// SAML's ACS is a cross-site POST → SameSite=None under Secure.
			StateCookie: espresso.StateCookieConfig{
				BaseName: "x_saml_state", Secure: true, Path: "/", SameSite: http.SameSiteNoneMode, TTL: time.Minute,
			},
		},
		Hooks: espresso.SAMLHooks{
			OnFederatedAssertion: func(context.Context, *saml.Provider, espresso.SAMLVerified) (espresso.SAMLOutcome, error) {
				return espresso.SAMLOutcome{}, nil
			},
			LinkRedirect: func(string) string { return "/linked" },
		},
	}
}

func scimBundle() *espresso.SCIMBundle {
	return &espresso.SCIMBundle{
		Config:    espresso.SCIMConfig{Prefix: "/scim/v2", MaxResults: 100},
		Users:     stubUserStore{},
		Groups:    stubGroupStore{},
		Validator: espresso.ValidatorFunc(func(context.Context, string) (espresso.Principal, error) { return espresso.Principal{}, nil }),
	}
}

func TestRoutes_Minimal(t *testing.T) {
	t.Parallel()
	s, err := espresso.Routes(newProvider(t, false, false), espresso.RouteConfig{
		Auth:     authCfg(),
		Identity: stubIdentity{},
	})
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	if s.Auth == nil {
		t.Error("Auth surface should always be built")
	}
	if s.Auditor == nil {
		t.Error("Auditor should always be built")
	}
	if s.RequireAuth == nil || s.RequireAuthWS == nil {
		t.Error("RequireAuth + RequireAuthWS should be bound")
	}
	if s.RequireAuthWS("v1.") == nil {
		t.Error("RequireAuthWS should return a middleware for a subprotocol prefix")
	}
	if s.Federation != nil || s.SAML != nil || s.SCIM != nil {
		t.Error("optional surfaces should be nil when unconfigured")
	}
	if s.RequireServiceAccount != nil {
		t.Error("RequireServiceAccount should be nil without SCIM")
	}
}

func TestRoutes_Federation(t *testing.T) {
	t.Parallel()
	s, err := espresso.Routes(newProvider(t, true, false), espresso.RouteConfig{
		Auth:       authCfg(),
		Identity:   stubIdentity{},
		Federation: fedBundle(),
	})
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	if s.Federation == nil {
		t.Error("Federation surface should be built when configured with an OIDC Provider")
	}
}

func TestRoutes_SAML(t *testing.T) {
	t.Parallel()
	s, err := espresso.Routes(newProvider(t, false, true), espresso.RouteConfig{
		Auth:     authCfg(),
		Identity: stubIdentity{},
		SAML:     samlBundle(),
	})
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	if s.SAML == nil {
		t.Error("SAML surface should be built when configured with a SAML Provider")
	}
}

func TestRoutes_SCIM(t *testing.T) {
	t.Parallel()
	s, err := espresso.Routes(newProvider(t, false, false), espresso.RouteConfig{
		Auth:     authCfg(),
		Identity: stubIdentity{},
		SCIM:     scimBundle(),
	})
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	if s.SCIM == nil {
		t.Error("SCIM surface should be built when configured")
	}
	if s.RequireServiceAccount == nil {
		t.Error("RequireServiceAccount should be bound when SCIM is configured")
	}
}

func TestRoutes_Errors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		tp   *tamper.Provider
		cfg  espresso.RouteConfig
	}{
		{
			name: "nil provider",
			tp:   nil,
			cfg:  espresso.RouteConfig{Auth: authCfg(), Identity: stubIdentity{}},
		},
		{
			name: "federation without OIDC engine",
			tp:   newProvider(t, false, false),
			cfg:  espresso.RouteConfig{Auth: authCfg(), Identity: stubIdentity{}, Federation: fedBundle()},
		},
		{
			name: "saml without SAML engine",
			tp:   newProvider(t, false, false),
			cfg:  espresso.RouteConfig{Auth: authCfg(), Identity: stubIdentity{}, SAML: samlBundle()},
		},
		{
			name: "scim without validator",
			tp:   newProvider(t, false, false),
			cfg: espresso.RouteConfig{Auth: authCfg(), Identity: stubIdentity{}, SCIM: &espresso.SCIMBundle{
				Config: espresso.SCIMConfig{Prefix: "/scim/v2", MaxResults: 100},
				Users:  stubUserStore{}, Groups: stubGroupStore{},
			}},
		},
		{
			name: "missing IdentityService",
			tp:   newProvider(t, false, false),
			cfg:  espresso.RouteConfig{Auth: authCfg()},
		},
		{
			name: "invalid auth config (no ProjectUser)",
			tp:   newProvider(t, false, false),
			cfg: espresso.RouteConfig{Identity: stubIdentity{}, Auth: espresso.AuthRoutesConfig{
				MountPrefix: "/api/auth", Cookies: espresso.CookieConfig{Name: "x_refresh"},
			}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := espresso.Routes(tc.tp, tc.cfg)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if s != nil {
				t.Errorf("Surfaces should be nil on error, got %+v", s)
			}
		})
	}
}
