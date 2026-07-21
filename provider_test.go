package tamper_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tamper "github.com/suryakencana007/barista/packages/tamper"
	"github.com/suryakencana007/barista/packages/tamper/audit"
	"github.com/suryakencana007/barista/packages/tamper/authz"
	"github.com/suryakencana007/barista/packages/tamper/crypto"
	"github.com/suryakencana007/barista/packages/tamper/identity"
	"github.com/suryakencana007/barista/packages/tamper/oidc"
	"github.com/suryakencana007/barista/packages/tamper/saml"
)

// validJWT returns a JWT config that passes New's secret check.
func validJWT() crypto.JWTConfig {
	return crypto.JWTConfig{Secret: "test-secret", TTL: 15 * time.Minute, Issuer: "tamper-test"}
}

// validKEK is a well-formed 64-hex-char (32-byte) KEK entry.
func validKEK() crypto.KEKEntry {
	return crypto.KEKEntry{ID: 1, Key: strings.Repeat("a", 64)}
}

func TestNew_Minimal(t *testing.T) {
	t.Parallel()
	tp, err := tamper.New(tamper.Config{JWT: validJWT()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if tp.JWT == nil {
		t.Error("JWT should always be non-nil")
	}
	if tp.KeySet != nil {
		t.Error("KeySet should be nil with no KEKs")
	}
	if _, isNoop := tp.Audit.(audit.NoopLogger); !isNoop {
		t.Errorf("Audit should be NoopLogger with no DBPath, got %T", tp.Audit)
	}
	if tp.Authz != nil {
		t.Error("Authz should be nil when not configured")
	}
	if tp.Identity != nil || tp.OIDC != nil || tp.SAML != nil {
		t.Error("Identity/OIDC/SAML should be nil when not configured")
	}
	if err := tp.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestNew_WithKeySet(t *testing.T) {
	t.Parallel()
	tp, err := tamper.New(tamper.Config{JWT: validJWT(), KEKs: []crypto.KEKEntry{validKEK()}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if tp.KeySet == nil {
		t.Error("KeySet should be non-nil when KEKs are supplied")
	}
}

func TestNew_SQLiteAudit(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	tp, err := tamper.New(tamper.Config{
		JWT:   validJWT(),
		Audit: tamper.AuditConfig{DBPath: dbPath},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = tp.Close() })
	if _, isNoop := tp.Audit.(audit.NoopLogger); isNoop {
		t.Error("Audit should be SQLite-backed when DBPath is set, got NoopLogger")
	}
	if err := tp.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestNew_Identity(t *testing.T) {
	t.Parallel()
	tp, err := tamper.New(tamper.Config{
		JWT:      validJWT(),
		KEKs:     []crypto.KEKEntry{validKEK()},
		Identity: &tamper.IdentityConfig{Store: identity.NewMemStore()},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if tp.Identity == nil {
		t.Error("Identity core should be non-nil when configured")
	}
}

func TestNew_Federation(t *testing.T) {
	t.Parallel()
	tp, err := tamper.New(tamper.Config{
		JWT:  validJWT(),
		KEKs: []crypto.KEKEntry{validKEK()},
		OIDC: &tamper.OIDCConfig{
			Store:       oidc.NewMemProviderStore(),
			RedirectURL: func(id string) string { return "https://app.example/cb/" + id },
			TTL:         time.Minute,
		},
		SAML: &tamper.SAMLConfig{
			Store:             saml.NewMemProviderStore(),
			SPMetadataURL:     func(id, acsURL string) string { return acsURL + "/meta/" + id },
			AllowIDPInitiated: true,
			SkewTolerance:     30 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if tp.OIDC == nil {
		t.Error("OIDC manager should be non-nil when configured")
	}
	if tp.SAML == nil {
		t.Error("SAML manager should be non-nil when configured")
	}
}

func TestNew_ValidationErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  tamper.Config
	}{
		{"empty JWT secret", tamper.Config{}},
		{"identity without store", tamper.Config{JWT: validJWT(), Identity: &tamper.IdentityConfig{}}},
		{"oidc without store", tamper.Config{JWT: validJWT(), OIDC: &tamper.OIDCConfig{}}},
		{"oidc without redirect mapping", tamper.Config{JWT: validJWT(), OIDC: &tamper.OIDCConfig{Store: oidc.NewMemProviderStore()}}},
		{"saml without store", tamper.Config{JWT: validJWT(), SAML: &tamper.SAMLConfig{}}},
		{"saml without metadata mapping", tamper.Config{JWT: validJWT(), SAML: &tamper.SAMLConfig{Store: saml.NewMemProviderStore()}}},
		{"malformed KEK", tamper.Config{JWT: validJWT(), KEKs: []crypto.KEKEntry{{ID: 1, Key: "too-short"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tp, err := tamper.New(tc.cfg)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if tp != nil {
				t.Errorf("Provider should be nil on error, got %+v", tp)
			}
		})
	}
}

func TestRBAC_Helper(t *testing.T) {
	t.Parallel()
	a, err := tamper.RBAC(authz.NewMemStore(), authz.Hierarchy{}, authz.Policy{})
	if err != nil {
		t.Fatalf("RBAC: %v", err)
	}
	if a == nil {
		t.Error("RBAC should return a non-nil Authorizer")
	}
}

func TestPermissionSet_Helper(t *testing.T) {
	t.Parallel()
	a, err := tamper.PermissionSet(authz.NewMemPermissionStore())
	if err != nil {
		t.Fatalf("PermissionSet: %v", err)
	}
	if a == nil {
		t.Error("PermissionSet should return a non-nil Authorizer")
	}
}

// On the error path the helpers must return a TRUE nil interface, not the
// typed-nil-in-interface landmine (a non-nil Authorizer wrapping a nil *RBAC /
// *PermissionSet) that would panic at Check time.
func TestRBAC_Helper_NilStoreReturnsNilInterface(t *testing.T) {
	t.Parallel()
	a, err := tamper.RBAC(nil, authz.Hierarchy{}, authz.Policy{})
	if err == nil {
		t.Fatal("expected an error for a nil store")
	}
	if a != nil {
		t.Errorf("Authorizer must be a true nil interface on error, got %#v", a)
	}
}

func TestPermissionSet_Helper_NilStoreReturnsNilInterface(t *testing.T) {
	t.Parallel()
	a, err := tamper.PermissionSet(nil)
	if err == nil {
		t.Fatal("expected an error for a nil store")
	}
	if a != nil {
		t.Errorf("Authorizer must be a true nil interface on error, got %#v", a)
	}
}

// A failure AFTER the SQLite audit DB is opened must close that DB. Empty
// defaultACR makes identity.New fail at exactly that point; the assertion here
// is that New surfaces the error cleanly (the close line runs without panic).
func TestNew_IdentityFailureClosesAudit(t *testing.T) {
	t.Parallel()
	tp, err := tamper.New(tamper.Config{
		JWT:   validJWT(),
		Audit: tamper.AuditConfig{DBPath: filepath.Join(t.TempDir(), "audit.db")},
		Identity: &tamper.IdentityConfig{
			Store:   identity.NewMemStore(),
			Options: []identity.Option{identity.WithDefaultACR("")},
		},
	})
	if err == nil {
		t.Fatal("expected identity failure")
	}
	if tp != nil {
		t.Errorf("Provider should be nil on error, got %+v", tp)
	}
}

// The KeySet must auto-thread into the identity Core so envelope-sealing TOTP
// flows work. StartTOTPEnrollment checks keys==nil FIRST, so its error tells us
// whether the keyset threaded: ErrNoKeySet means it did not.
func TestNew_KeySetThreadsIntoIdentity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	withKEK, err := tamper.New(tamper.Config{
		JWT:      validJWT(),
		KEKs:     []crypto.KEKEntry{validKEK()},
		Identity: &tamper.IdentityConfig{Store: identity.NewMemStore()},
	})
	if err != nil {
		t.Fatalf("New (with KEK): %v", err)
	}
	if _, err := withKEK.Identity.StartTOTPEnrollment(ctx, "no-such-user"); errors.Is(err, identity.ErrNoKeySet) {
		t.Error("KeySet did not thread into the identity Core (got ErrNoKeySet with KEKs configured)")
	}

	noKEK, err := tamper.New(tamper.Config{
		JWT:      validJWT(),
		Identity: &tamper.IdentityConfig{Store: identity.NewMemStore()},
	})
	if err != nil {
		t.Fatalf("New (no KEK): %v", err)
	}
	if _, err := noKEK.Identity.StartTOTPEnrollment(ctx, "no-such-user"); !errors.Is(err, identity.ErrNoKeySet) {
		t.Errorf("expected ErrNoKeySet without KEKs, got %v", err)
	}
}
