package tamper_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tamper "github.com/suryakencana007/tamper"
	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/oidc"
	"github.com/suryakencana007/tamper/saml"
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

// --- Audit.Tenancy (TD-09) ---

// chainAnchors counts the chain-restart anchor rows at the given
// canonical_version. It matches on the ACTION as well as the version, so it
// counts anchors and nothing else — HasChainRestartV4 alone cannot tell an
// anchor from an ordinary v4 row once one has been logged. The match is done
// here rather than through Filter.Action because SQLiteLogger.List does not
// dispatch on that field; every test below stays far under the page limit.
func chainAnchors(t *testing.T, l audit.Logger, version int) int {
	t.Helper()
	page, err := l.List(context.Background(), audit.Filter{Limit: 100})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	n := 0
	for _, e := range page.Events {
		if e.Action == audit.ActionAuditChainRestart && e.CanonicalVersion == version {
			n++
		}
	}
	return n
}

// tenantEvent is an ordinary application event carrying a tenant and PII.
func tenantEvent(id string) audit.Event {
	return audit.Event{
		ID: id, At: time.Now().UTC(), Action: "td09.proof", TenantID: "acme",
		Actor: audit.Actor{Type: audit.ActorTypeUser, UserID: "user-1", Email: "bob@acme.test", TenantID: "acme"},
	}
}

// requireCleanChain fails the test unless Verify walks the chain clean.
func requireCleanChain(t *testing.T, l audit.Logger) {
	t.Helper()
	vr, err := l.Verify(context.Background())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if vr.Tamper {
		t.Fatalf("Verify reports tamper at index %d of %d on a chain nobody touched", vr.FirstBadIndex, vr.Total)
	}
}

// The TD-09 proof, inverted: with Audit.Tenancy a logger built by New writes
// canonical_version=4, the v4 anchor is already there when New returns, the
// chain verifies, and the row's PII can be redacted.
func TestNew_AuditTenancy_WritesV4(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tp, err := tamper.New(tamper.Config{
		JWT:   validJWT(),
		Audit: tamper.AuditConfig{DBPath: filepath.Join(t.TempDir(), "audit.db"), Tenancy: true},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = tp.Close() })
	sl, ok := tp.Audit.(*audit.SQLiteLogger)
	if !ok {
		t.Fatalf("Audit should be *audit.SQLiteLogger, got %T", tp.Audit)
	}

	// Asked BEFORE any application event: the anchor is New's doing, and it
	// precedes the first v4 row.
	has, err := sl.HasChainRestartV4(ctx)
	if err != nil {
		t.Fatalf("HasChainRestartV4: %v", err)
	}
	if !has {
		t.Fatal("no v4 anchor when New returned; the first application event would land before it")
	}
	if n := chainAnchors(t, tp.Audit, audit.CanonicalVersion4); n != 1 {
		t.Fatalf("v4 anchors after New = %d, want 1", n)
	}

	ev, err := tp.Audit.Log(ctx, tenantEvent("e1"))
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if ev.CanonicalVersion != audit.CanonicalVersion4 {
		t.Fatalf("canonical_version = %d, want %d", ev.CanonicalVersion, audit.CanonicalVersion4)
	}
	requireCleanChain(t, tp.Audit)

	redacted, err := sl.RedactEvent(ctx, "e1")
	if err != nil {
		t.Fatalf("RedactEvent: %v", err)
	}
	if !redacted {
		t.Fatal("RedactEvent(e1) = false; a row written through New is not erasable")
	}
	// Redaction must not cost the chain its integrity.
	requireCleanChain(t, tp.Audit)
}

// The case where the anchor's ORDER is what matters: an existing deployment
// whose chain already has an older anchor. Verify takes its encoder from the
// newest anchor, so without New's v4 anchor the first v4 row is re-hashed as
// v3 and an untouched chain reports itself forged.
func TestNew_AuditTenancy_OnAnchoredV3Chain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "audit.db")

	before, err := tamper.New(tamper.Config{JWT: validJWT(), Audit: tamper.AuditConfig{DBPath: dbPath}})
	if err != nil {
		t.Fatalf("New (v3): %v", err)
	}
	if _, err := before.Audit.Log(ctx, audit.Event{
		ID: "anchor-v3", At: time.Now().UTC(), Actor: audit.ActorSystem("audit"),
		Action: audit.ActionAuditChainRestart, ResourceType: "audit_chain", ResourceID: "v3",
		CanonicalVersion: audit.CanonicalVersion3,
	}); err != nil {
		t.Fatalf("emit v3 anchor: %v", err)
	}
	if _, err := before.Audit.Log(ctx, tenantEvent("v3-row")); err != nil {
		t.Fatalf("Log (v3): %v", err)
	}
	requireCleanChain(t, before.Audit)
	if err := before.Close(); err != nil {
		t.Fatalf("Close (v3): %v", err)
	}

	after, err := tamper.New(tamper.Config{JWT: validJWT(), Audit: tamper.AuditConfig{DBPath: dbPath, Tenancy: true}})
	if err != nil {
		t.Fatalf("New (tenancy): %v", err)
	}
	t.Cleanup(func() { _ = after.Close() })
	ev, err := after.Audit.Log(ctx, tenantEvent("v4-row"))
	if err != nil {
		t.Fatalf("Log (v4): %v", err)
	}
	if ev.CanonicalVersion != audit.CanonicalVersion4 {
		t.Fatalf("canonical_version = %d, want %d", ev.CanonicalVersion, audit.CanonicalVersion4)
	}
	requireCleanChain(t, after.Audit)
	if n := chainAnchors(t, after.Audit, audit.CanonicalVersion4); n != 1 {
		t.Fatalf("v4 anchors = %d, want 1", n)
	}
}

// New bootstraps on every boot; only the first may write a row.
func TestNew_AuditTenancy_BootstrapIsIdempotent(t *testing.T) {
	t.Parallel()
	cfg := tamper.Config{
		JWT:   validJWT(),
		Audit: tamper.AuditConfig{DBPath: filepath.Join(t.TempDir(), "audit.db"), Tenancy: true},
	}

	first, err := tamper.New(cfg)
	if err != nil {
		t.Fatalf("New (first boot): %v", err)
	}
	if n := chainAnchors(t, first.Audit, audit.CanonicalVersion4); n != 1 {
		t.Fatalf("v4 anchors after the first boot = %d, want 1", n)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close (first boot): %v", err)
	}

	second, err := tamper.New(cfg)
	if err != nil {
		t.Fatalf("New (second boot): %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if n := chainAnchors(t, second.Audit, audit.CanonicalVersion4); n != 1 {
		t.Fatalf("v4 anchors after the second boot = %d, want exactly 1", n)
	}
	requireCleanChain(t, second.Audit)
}

// Standing rule 1: without Tenancy nothing changes — v3 rows, no anchor, and
// no row in the DB that the application did not log itself.
func TestNew_AuditDefault_StaysV3(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tp, err := tamper.New(tamper.Config{
		JWT:   validJWT(),
		Audit: tamper.AuditConfig{DBPath: filepath.Join(t.TempDir(), "audit.db")},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = tp.Close() })

	ev, err := tp.Audit.Log(ctx, tenantEvent("e1"))
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if ev.CanonicalVersion != audit.CanonicalVersion3 {
		t.Errorf("canonical_version = %d, want %d", ev.CanonicalVersion, audit.CanonicalVersion3)
	}
	has, err := tp.Audit.(*audit.SQLiteLogger).HasChainRestartV4(ctx)
	if err != nil {
		t.Fatalf("HasChainRestartV4: %v", err)
	}
	if has {
		t.Error("HasChainRestartV4 = true on a default-config logger")
	}
	page, err := tp.Audit.List(ctx, audit.Filter{Limit: 100})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Events) != 1 || page.Events[0].ID != "e1" {
		t.Errorf("default config wrote %d row(s), want only the one logged event: %+v", len(page.Events), page.Events)
	}
	requireCleanChain(t, tp.Audit)
}

// Tenancy with no DBPath would silently select the NoopLogger. It is a
// misconfiguration and fails at New (standing rule 4).
func TestNew_AuditTenancyRequiresDBPath(t *testing.T) {
	t.Parallel()
	tp, err := tamper.New(tamper.Config{JWT: validJWT(), Audit: tamper.AuditConfig{Tenancy: true}})
	if err == nil {
		t.Fatal("expected an error for Audit.Tenancy with an empty DBPath, got nil")
	}
	if tp != nil {
		t.Errorf("Provider should be nil on error, got %+v", tp)
	}
	if !strings.Contains(err.Error(), "Audit.DBPath") {
		t.Errorf("error should name the missing field, got %q", err)
	}
}

// Standing rule 6: the guard must FIRE. A logger that cannot write the v4
// anchor is an error, not a skipped step.
func TestBootstrapAuditV4_RejectsLoggerThatCannotBootstrap(t *testing.T) {
	t.Parallel()
	if err := tamper.BootstrapAuditV4(audit.NewNoopLogger()); err == nil {
		t.Fatal("expected an error for a logger without BootstrapChainV4, got nil")
	}
}
