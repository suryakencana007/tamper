package tamper_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/suryakencana007/tamper"
	"github.com/suryakencana007/tamper/oidc"
	"github.com/suryakencana007/tamper/saml"
	"github.com/suryakencana007/tamper/tenant"
)

// Slice 12c — the boot guards for IdP inheritance.
//
// Standing rule 6: an optional upgrade ships a guard AND a test that the guard
// fires. A half-wired InheritanceConfig would be a feature that silently never
// inherits, because the Manager's own option ignores a nil either way — so this is
// the only place the mistake is loud, and each guard's message must name the field
// for the test to be worth anything.

func TestNew_IdPInheritanceGuards(t *testing.T) {
	t.Parallel()

	hierarchy := tenant.NewMemStore()
	allow := func(context.Context, tenant.ID) (bool, error) { return true, nil }
	oidcBase := func() tamper.OIDCConfig {
		return tamper.OIDCConfig{
			Store:       oidc.NewMemProviderStore(),
			RedirectURL: func(id string) string { return "https://app.example/cb/" + id },
			TTL:         time.Minute,
		}
	}
	samlBase := func() tamper.SAMLConfig {
		return tamper.SAMLConfig{
			Store:         saml.NewMemProviderStore(),
			SPMetadataURL: func(id, acsURL string) string { return acsURL + "/meta/" + id },
		}
	}

	cases := []struct {
		name string
		cfg  tamper.Config
		want string
	}{
		{
			name: "oidc inheritance without a parentage store",
			cfg: func() tamper.Config {
				c := oidcBase()
				c.Inheritance = &tamper.InheritanceConfig{Allow: allow}
				return tamper.Config{JWT: validJWT(), OIDC: &c}
			}(),
			want: "Config.OIDC.Inheritance.Store",
		},
		{
			name: "oidc inheritance without a policy",
			cfg: func() tamper.Config {
				c := oidcBase()
				c.Inheritance = &tamper.InheritanceConfig{Store: hierarchy}
				return tamper.Config{JWT: validJWT(), OIDC: &c}
			}(),
			want: "Config.OIDC.Inheritance.Allow",
		},
		{
			name: "saml inheritance without a parentage store",
			cfg: func() tamper.Config {
				c := samlBase()
				c.Inheritance = &tamper.InheritanceConfig{Allow: allow}
				return tamper.Config{JWT: validJWT(), SAML: &c}
			}(),
			want: "Config.SAML.Inheritance.Store",
		},
		{
			name: "saml inheritance without a policy",
			cfg: func() tamper.Config {
				c := samlBase()
				c.Inheritance = &tamper.InheritanceConfig{Store: hierarchy}
				return tamper.Config{JWT: validJWT(), SAML: &c}
			}(),
			want: "Config.SAML.Inheritance.Allow",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tp, err := tamper.New(tc.cfg)
			if err == nil {
				t.Fatal("expected a boot error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %q, want it to name %q", err.Error(), tc.want)
			}
			if tp != nil {
				t.Errorf("Provider should be nil on error, got %+v", tp)
			}
		})
	}
}

// The fully-wired form boots, and both engines come up. What the wiring DOES is
// proven by the inheritance suites in oidc and saml, where a tenant-scoped
// provider store can be injected; tamper.New's job is validate-and-pass-through,
// and the pass-through is compile-checked by the option signatures.
func TestNew_IdPInheritanceWired(t *testing.T) {
	t.Parallel()

	hierarchy := tenant.NewMemStore()
	allow := func(context.Context, tenant.ID) (bool, error) { return true, nil }

	tp, err := tamper.New(tamper.Config{
		JWT: validJWT(),
		OIDC: &tamper.OIDCConfig{
			Store:       oidc.NewMemProviderStore(),
			RedirectURL: func(id string) string { return "https://app.example/cb/" + id },
			Inheritance: &tamper.InheritanceConfig{Store: hierarchy, Allow: allow},
		},
		SAML: &tamper.SAMLConfig{
			Store:         saml.NewMemProviderStore(),
			SPMetadataURL: func(id, acsURL string) string { return acsURL + "/meta/" + id },
			Inheritance:   &tamper.InheritanceConfig{Store: hierarchy, Allow: allow},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if tp.OIDC == nil || tp.SAML == nil {
		t.Fatal("both engines should be constructed")
	}
	if err := tp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
