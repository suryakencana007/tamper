package tamper

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/oidc"
	"github.com/suryakencana007/tamper/saml"
)

// Config is the single boot input for New. It bundles the engine
// configuration; the application still supplies the leaves — the Store
// implementations, the built Authz PDP, and (at the transport layer) the
// route policy and the Espresso router.
//
// The zero value is NOT valid: JWT.Secret is required. Everything else is
// optional and nil-encodes "not configured" exactly as the subpackage
// constructors already do (no KEKs => no KeySet; no DBPath => Noop audit;
// nil Identity/OIDC/SAML => that engine is absent from the Provider).
type Config struct {
	// JWT is required — New returns an error on an empty Secret (the
	// underlying crypto.NewJWTService panics on empty, so New guards first).
	JWT crypto.JWTConfig

	// KEKs + WriteKeyID build the envelope keyset that seals at-rest
	// secrets (identity TOTP envelopes, OIDC/SAML provider secrets). Empty
	// KEKs leaves Provider.KeySet nil, mirroring crypto.NewKeySet's
	// (nil, nil) contract — callers gate "sealing configured" on
	// Provider.KeySet != nil exactly as before.
	KEKs       []crypto.KEKEntry
	WriteKeyID uint8

	// Audit configures the tamper-evident log. A non-empty DBPath opens the
	// SQLite hash-chain logger; an empty DBPath yields a NoopLogger.
	// Provider.Audit is always non-nil.
	Audit AuditConfig

	// Authz is the application's built policy-decision point. Optional —
	// nil leaves Provider.Authz nil (the transport's RequireDecision gate is
	// then unusable). Greenfield consumers can build one with the RBAC or
	// PermissionSet helpers in this package.
	Authz authz.Authorizer

	// Identity, when non-nil, builds the credentials + session Core over the
	// supplied Store, with JWT and (when configured) the KeySet auto-threaded
	// in. Applications with a richer identity service of their own leave this
	// nil and pass that service to the transport layer instead.
	Identity *IdentityConfig

	// OIDC / SAML, when non-nil, build the respective federation provider
	// Manager over the supplied Store, sealing provider secrets with the
	// KeySet. Nil leaves the corresponding Provider field nil.
	OIDC *OIDCConfig
	SAML *SAMLConfig
}

// AuditConfig configures the audit logger. An empty DBPath selects the
// NoopLogger; otherwise the SQLite hash-chain logger is opened at DBPath.
type AuditConfig struct {
	DBPath string
	// EmailLookup optionally enriches service-direct emissions (an event
	// carrying a user id but no email) at Log time. Its signature matches
	// audit.SQLiteLoggerOptions.EmailLookup exactly. Optional.
	EmailLookup func(ctx context.Context, userID string) (email string, ok bool)
	// Tenancy switches the logger to the canonical_version=4 encoder: the
	// tenant enters the hashed payload, and PII moves to per-row salted
	// commitments — the only encoding audit.SQLiteLogger.RedactEvent can
	// erase. It is passed to audit.SQLiteLoggerOptions.Tenancy, and it is
	// the single switch for both capabilities.
	//
	// The flag alone is not enough, so New also writes the v4 chain anchor
	// (audit.SQLiteLogger.BootstrapChainV4) before it returns. The anchor
	// has to precede the first v4 row — Verify takes its encoder from the
	// newest anchor, and a v4 row behind an older one reads as tamper — and
	// the method is not on the audit.Logger interface Provider.Audit
	// exposes, so "the application calls it at boot" is an instruction New
	// can keep and a caller can miss. The bootstrap is idempotent: every
	// boot asks, only the first writes a row.
	//
	// False is the default and is byte-identical to today: v3 rows, v3
	// hashes, no anchor. Despite the name, true is legal for a single-tenant
	// deployment that wants erasure — leave TenantID empty on every event.
	//
	// It is a one-way switch, for the same newest-anchor reason. Turning it
	// back off writes v3 rows behind the v4 anchor, and an application boot
	// step that emits an older (v2/v3) chain-restart anchor after New puts
	// that anchor in front of every later v4 row; either way Verify reports
	// tamper on a chain nobody touched.
	//
	// Requires DBPath. New rejects Tenancy with an empty DBPath instead of
	// handing a NoopLogger to a caller that asked for a tenant-hashed log.
	Tenancy bool
}

// IdentityConfig configures the identity Core. Store is required (New
// returns an error when it is nil). Options are passed through to
// identity.New; the KeySet is auto-threaded ahead of them when configured,
// so an explicit identity.WithKeySet in Options still wins.
type IdentityConfig struct {
	Store   identity.Store
	Options []identity.Option
}

// OIDCConfig configures the OIDC provider Manager. Store is required. TTL
// sets the live-registry cache lifetime (0 = the Manager default).
// RedirectURL maps a provider id to its callback URL — the route shape is
// the application's, so this is a function, not a base string. Optional.
type OIDCConfig struct {
	Store       oidc.ProviderStore
	RedirectURL func(id string) string
	TTL         time.Duration
}

// SAMLConfig configures the SAML provider Manager. Store is required.
// SPMetadataURL maps (provider id, ACS URL) to the SP-metadata URL — again
// an application route shape, so a function. The remaining fields are flow
// knobs passed straight through to the Manager.
type SAMLConfig struct {
	Store             saml.ProviderStore
	SPMetadataURL     func(id, acsURL string) string
	TTL               time.Duration
	AllowIDPInitiated bool
	SkewTolerance     time.Duration
}

// Provider is the constructed engine bag. Every field mirrors a subpackage
// constructor's output; a nil field means "not configured", encoded the same
// way the subpackages themselves do. The application reads these to wire its
// services and (via tamper/espresso.Routes) its HTTP surface.
//
// The Provider owns the audit DB handle when audit is SQLite-backed — call
// Close on shutdown to release it.
type Provider struct {
	JWT      *crypto.JWTService // always non-nil
	KeySet   *crypto.KeySet     // nil when KEKs is empty
	Audit    audit.Logger       // always non-nil (NoopLogger fallback)
	Authz    authz.Authorizer   // nil unless Config.Authz is set
	Identity *identity.Core     // nil unless Config.Identity is set
	OIDC     *oidc.Manager      // nil unless Config.OIDC is set
	SAML     *saml.Manager      // nil unless Config.SAML is set
}

// New builds a Provider from cfg. It validates inputs and constructs each
// configured engine as a DAG rooted at the JWT service + KeySet, so a
// misconfiguration fails here at boot rather than as a per-request denial.
//
// Cheap validation runs before any resource is allocated; the audit DB is
// opened only after every input has passed, and is closed again if a later
// step fails.
func New(cfg Config) (*Provider, error) {
	// --- validation (no allocation) ---
	if cfg.JWT.Secret == "" {
		return nil, errors.New("tamper: Config.JWT.Secret is required")
	}
	if cfg.Identity != nil && cfg.Identity.Store == nil {
		return nil, errors.New("tamper: Config.Identity.Store is required when Identity is set")
	}
	if cfg.OIDC != nil && cfg.OIDC.Store == nil {
		return nil, errors.New("tamper: Config.OIDC.Store is required when OIDC is set")
	}
	// RedirectURL / SPMetadataURL are manager-required: the live registry
	// refuses to rebuild without them once a provider row exists, which would
	// surface as a per-request federated-login failure rather than a boot
	// failure. Fail here at wiring instead (matches the design's promise).
	if cfg.OIDC != nil && cfg.OIDC.RedirectURL == nil {
		return nil, errors.New("tamper: Config.OIDC.RedirectURL is required when OIDC is set")
	}
	if cfg.SAML != nil && cfg.SAML.Store == nil {
		return nil, errors.New("tamper: Config.SAML.Store is required when SAML is set")
	}
	if cfg.SAML != nil && cfg.SAML.SPMetadataURL == nil {
		return nil, errors.New("tamper: Config.SAML.SPMetadataURL is required when SAML is set")
	}
	// Tenancy without a DBPath would select the NoopLogger: the caller asked
	// for a tenant-hashed, redactable log and would get one that records
	// nothing, with no error anywhere. A tenancy misconfiguration fails here
	// at wiring, not as rows that are silently never written.
	if cfg.Audit.Tenancy && cfg.Audit.DBPath == "" {
		return nil, errors.New("tamper: Config.Audit.DBPath is required when Audit.Tenancy is set")
	}
	// Tenancy boot guard. The optional-interface upgrade is checked once,
	// here, and the message names the concrete type that failed it —

	// --- keyset (validates the KEK entries) ---
	keySet, err := crypto.NewKeySet(cfg.KEKs, cfg.WriteKeyID)
	if err != nil {
		return nil, fmt.Errorf("tamper: keyset: %w", err)
	}

	// --- jwt (safe: secret is non-empty) ---
	jwtSvc := crypto.NewJWTService(cfg.JWT)

	// --- audit (opens the DB when SQLite-backed) ---
	var auditLogger audit.Logger
	if cfg.Audit.DBPath != "" {
		auditLogger, err = audit.NewSQLiteLogger(cfg.Audit.DBPath, audit.SQLiteLoggerOptions{
			EmailLookup: cfg.Audit.EmailLookup,
			Tenancy:     cfg.Audit.Tenancy,
		})
		if err != nil {
			return nil, fmt.Errorf("tamper: audit: %w", err)
		}
		// The v4 anchor goes in HERE, before the logger is reachable by
		// anything that could log through it. Once New returns, the first
		// application event may already be a v4 row, and an anchor written
		// after it is too late (see AuditConfig.Tenancy).
		if cfg.Audit.Tenancy {
			if berr := bootstrapAuditV4(auditLogger); berr != nil {
				_ = auditLogger.Close()
				return nil, fmt.Errorf("tamper: audit: %w", berr)
			}
		}
	} else {
		auditLogger = audit.NewNoopLogger()
	}

	p := &Provider{
		JWT:    jwtSvc,
		KeySet: keySet,
		Audit:  auditLogger,
		Authz:  cfg.Authz,
	}

	// --- identity core (fallible; close audit on failure) ---
	if cfg.Identity != nil {
		opts := cfg.Identity.Options
		if keySet != nil {
			// Thread the KeySet ahead of the app's options so an explicit
			// identity.WithKeySet in Options still wins (last setter wins).
			opts = append([]identity.Option{identity.WithKeySet(keySet)}, opts...)
		}
		core, cerr := identity.New(cfg.Identity.Store, jwtSvc, opts...)
		if cerr != nil {
			_ = auditLogger.Close()
			return nil, fmt.Errorf("tamper: identity: %w", cerr)
		}
		p.Identity = core
	}

	// --- oidc manager (infallible) ---
	if cfg.OIDC != nil {
		mopts := []oidc.ManagerOption{oidc.WithRedirectURL(cfg.OIDC.RedirectURL)}
		if cfg.OIDC.TTL > 0 {
			mopts = append(mopts, oidc.WithTTL(cfg.OIDC.TTL))
		}
		p.OIDC = oidc.NewManager(cfg.OIDC.Store, keySet, mopts...)
	}

	// --- saml manager (infallible) ---
	if cfg.SAML != nil {
		mopts := []saml.ManagerOption{saml.WithSPMetadataURL(cfg.SAML.SPMetadataURL)}
		if cfg.SAML.TTL > 0 {
			mopts = append(mopts, saml.WithTTL(cfg.SAML.TTL))
		}
		if cfg.SAML.AllowIDPInitiated {
			mopts = append(mopts, saml.WithAllowIDPInitiated(true))
		}
		if cfg.SAML.SkewTolerance > 0 {
			mopts = append(mopts, saml.WithSkewTolerance(cfg.SAML.SkewTolerance))
		}
		p.SAML = saml.NewManager(cfg.SAML.Store, keySet, mopts...)
	}

	return p, nil
}

// chainV4Bootstrapper is the one method New needs that audit.Logger does not
// carry. *audit.SQLiteLogger implements it; the NoopLogger does not.
type chainV4Bootstrapper interface {
	BootstrapChainV4(ctx context.Context, at time.Time, id string) (emitted bool, err error)
}

// bootstrapAuditV4 writes the v4 chain anchor through l, once. It runs on
// every boot of a tenancy-configured Provider and is a no-op when the anchor
// already exists (BootstrapChainV4 is idempotent), so the fresh id below is
// only ever stored on the boot that actually emits the row.
//
// A logger that cannot bootstrap is an ERROR, never a skip. An `if ok`
// around the call would let a tenancy-configured Provider boot with no
// anchor and say nothing — the same quiet optional-interface miss that
// disabled the exit-3 chain guard in Phase 0c.
func bootstrapAuditV4(l audit.Logger) error {
	b, ok := l.(chainV4Bootstrapper)
	if !ok {
		return fmt.Errorf("logger %T cannot write the v4 chain anchor that Audit.Tenancy requires", l)
	}
	if _, err := b.BootstrapChainV4(context.Background(), time.Now().UTC(), uuid.NewString()); err != nil {
		return fmt.Errorf("bootstrap v4 chain: %w", err)
	}
	return nil
}

// Close releases resources the Provider owns — today the audit DB handle
// (a no-op for the NoopLogger). Safe on a nil Provider. Call it on
// application shutdown.
func (p *Provider) Close() error {
	if p == nil || p.Audit == nil {
		return nil
	}
	return p.Audit.Close()
}
