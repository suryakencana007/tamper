package tamper_test

import (
	"context"
	"strings"
	"testing"
	"time"

	tamper "github.com/suryakencana007/tamper"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/oidc"
	"github.com/suryakencana007/tamper/saml"
)

// Slice 7b-2 — the tenancy boot guard. Every tenancy misconfiguration
// fails at New, never as a per-request denial (sketch §6.4).

// singleTenantStore implements identity.Store but NOT
// identity.TenantScopedStore — the shape of an app adapter written
// before Phase 7, and the one the boot guard exists to reject.
type singleTenantStore struct{ *identity.MemStore }

// Shadow one scoped method with the wrong signature so the embedded
// MemStore's implementation cannot satisfy the interface through
// promotion. This is what an un-upgraded adapter looks like to the
// type system.
func (singleTenantStore) CountUsersInTenant() {}

func TestNew_TenancyRequiresTenantScopedStore(t *testing.T) {
	_, err := tamper.New(tamper.Config{
		JWT:      validJWT(),
		Identity: &tamper.IdentityConfig{Store: singleTenantStore{identity.NewMemStore()}},
		Tenancy:  &tamper.TenancyConfig{Enabled: true},
	})
	if err == nil {
		t.Fatal("New accepted a Store that does not implement identity.TenantScopedStore")
	}
	// Naming the CONCRETE type is the whole point. Phase 0c shipped a
	// type assertion that silently did not hold; without %T here, the
	// symptom is "tenancy doesn't work" with nothing to grep for.
	if !strings.Contains(err.Error(), "singleTenantStore") {
		t.Errorf("boot error does not name the concrete type: %v", err)
	}
	if !strings.Contains(err.Error(), "TenantScopedStore") {
		t.Errorf("boot error does not name the required interface: %v", err)
	}
}

// TestNew_TenancyRequiresTenantScopedProviderStore is the OIDC half of
// the boot guard (slice 7e-1). Without it a pooled deployment boots
// happily and fails on the first tenant-scoped registry build — a
// per-request failure for a misconfiguration.
func TestNew_TenancyRequiresTenantScopedProviderStore(t *testing.T) {
	_, err := tamper.New(tamper.Config{
		JWT:      validJWT(),
		Identity: &tamper.IdentityConfig{Store: identity.NewMemStore()},
		OIDC: &tamper.OIDCConfig{
			Store:       oidc.NewMemProviderStore(), // implements ProviderStore only
			RedirectURL: func(id string) string { return "https://x.test/" + id },
		},
		Tenancy: &tamper.TenancyConfig{Enabled: true},
	})
	if err == nil {
		t.Fatal("New accepted an oidc.ProviderStore that cannot scope by tenant")
	}
	if !strings.Contains(err.Error(), "TenantScopedProviderStore") {
		t.Errorf("boot error does not name the required interface: %v", err)
	}
	if !strings.Contains(err.Error(), "MemProviderStore") {
		t.Errorf("boot error does not name the concrete type: %v", err)
	}
}

// TestNew_TenancyRequiresTenantScopedSAMLStore is the SAML half of the
// boot guard (slice 7e-2), mirroring the OIDC one above.
func TestNew_TenancyRequiresTenantScopedSAMLStore(t *testing.T) {
	_, err := tamper.New(tamper.Config{
		JWT:      validJWT(),
		Identity: &tamper.IdentityConfig{Store: identity.NewMemStore()},
		SAML: &tamper.SAMLConfig{
			Store:         saml.NewMemProviderStore(), // implements ProviderStore only
			SPMetadataURL: func(id, _ string) string { return "https://x.test/" + id },
		},
		Tenancy: &tamper.TenancyConfig{Enabled: true},
	})
	if err == nil {
		t.Fatal("New accepted a saml.ProviderStore that cannot scope by tenant")
	}
	if !strings.Contains(err.Error(), "saml.TenantScopedProviderStore") {
		t.Errorf("boot error does not name the required interface: %v", err)
	}
	if !strings.Contains(err.Error(), "MemProviderStore") {
		t.Errorf("boot error does not name the concrete type: %v", err)
	}
}

// TestNew_TenancyDisabledAcceptsPlainProviderStore: the compatibility
// path is untouched — a pre-Phase-7 provider store still boots.
func TestNew_TenancyDisabledAcceptsPlainProviderStore(t *testing.T) {
	p, err := tamper.New(tamper.Config{
		JWT:      validJWT(),
		Identity: &tamper.IdentityConfig{Store: identity.NewMemStore()},
		OIDC: &tamper.OIDCConfig{
			Store:       oidc.NewMemProviderStore(),
			RedirectURL: func(id string) string { return "https://x.test/" + id },
		},
	})
	if err != nil {
		t.Fatalf("New rejected a plain provider store with tenancy off: %v", err)
	}
	defer func() { _ = p.Close() }()
	if p.OIDC == nil {
		t.Fatal("OIDC manager not constructed")
	}
}

func TestNew_TenancyRequiresIdentity(t *testing.T) {
	_, err := tamper.New(tamper.Config{
		JWT:     validJWT(),
		Tenancy: &tamper.TenancyConfig{Enabled: true},
	})
	if err == nil {
		t.Fatal("New accepted Tenancy.Enabled with no Identity config")
	}
}

func TestNew_TenancyDisabledAcceptsPlainStore(t *testing.T) {
	// The compatibility path, and the local stand-in for Barista's
	// adapter: a pre-Phase-7 Store still boots, untouched.
	for _, tc := range []struct {
		name    string
		tenancy *tamper.TenancyConfig
	}{
		{"nil Tenancy", nil},
		{"Tenancy present but disabled", &tamper.TenancyConfig{Enabled: false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := tamper.New(tamper.Config{
				JWT:      validJWT(),
				Identity: &tamper.IdentityConfig{Store: singleTenantStore{identity.NewMemStore()}},
				Tenancy:  tc.tenancy,
			})
			if err != nil {
				t.Fatalf("New rejected a plain Store with tenancy off: %v", err)
			}
			defer func() { _ = p.Close() }()
			if p.Identity == nil {
				t.Fatal("Identity core not constructed")
			}
		})
	}
}

// TestNew_TenancyEnabledWiresTheCore proves the boot guard is not merely
// a validation gate that then forgets to turn tenancy on. A Provider
// built with Tenancy.Enabled must produce a Core that actually denies an
// empty tenant — otherwise the config would pass validation and behave
// exactly like single-tenant, which is the silent-success failure mode.
func TestNew_TenancyEnabledWiresTheCore(t *testing.T) {
	p, err := tamper.New(tamper.Config{
		JWT: validJWT(),
		Identity: &tamper.IdentityConfig{
			Store:   identity.NewMemStore(),
			Options: []identity.Option{identity.WithRefreshTTL(time.Hour)},
		},
		Tenancy: &tamper.TenancyConfig{Enabled: true},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = p.Close() }()

	if _, _, err := p.Identity.Register(context.Background(), "a@example.com", "correct-horse"); err == nil {
		t.Fatal("tenancy-enabled Core accepted an empty tenant; the option did not reach identity.New")
	}
}
