package tamper

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/oidc"
	"github.com/suryakencana007/tamper/saml"
	"github.com/suryakencana007/tamper/tenant"
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

	// Tenancy, when non-nil and Enabled, puts the Provider into pooled
	// multi-tenant mode. Nil (the default) is single-tenant and every
	// call path stays byte-identical to a pre-tenancy build.
	Tenancy *TenancyConfig
}

// TenancyConfig turns on pooled multi-tenancy — one process, N tenants.
//
// Enabling it requires Identity.Store to implement
// identity.TenantScopedStore; New returns an error naming the concrete
// type when it does not. That check is here, at boot, and never as a
// per-request denial: a store that cannot scope by tenant is a
// misconfiguration, and discovering it on the first cross-tenant read
// would mean discovering it in production (sketch §4.2, §6.4).
type TenancyConfig struct {
	// Enabled turns tenancy on. False is identical to leaving Tenancy nil.
	Enabled bool

	// Store resolves tenant descriptors. OPTIONAL — nil means the
	// application resolves tenants itself and only needs the identity
	// core to scope its reads. tamper does not require a tenant table.
	Store tenant.Store
}

// AuditConfig configures the audit logger. An empty DBPath selects the
// NoopLogger; otherwise the SQLite hash-chain logger is opened at DBPath.
type AuditConfig struct {
	DBPath string
	// EmailLookup optionally enriches service-direct emissions (an event
	// carrying a user id but no email) at Log time. Its signature matches
	// audit.SQLiteLoggerOptions.EmailLookup exactly. Optional.
	EmailLookup func(ctx context.Context, userID string) (email string, ok bool)
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
	// Tenancy boot guard. The optional-interface upgrade is checked once,
	// here, and the message names the concrete type that failed it —
	// Phase 0c is why: a type assertion that quietly does not hold
	// compiles fine and disables the guard it was supposed to be. Without
	// naming %T, "tenancy doesn't work" is a debugging session; with it,
	// it is one line.
	if cfg.Tenancy != nil && cfg.Tenancy.Enabled {
		if cfg.Identity == nil {
			return nil, errors.New("tamper: Config.Tenancy.Enabled requires Config.Identity")
		}
		if _, ok := cfg.Identity.Store.(identity.TenantScopedStore); !ok {
			return nil, fmt.Errorf(
				"tamper: Tenancy.Enabled requires an identity.Store that implements "+
					"identity.TenantScopedStore; %T does not", cfg.Identity.Store)
		}
	}

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
		})
		if err != nil {
			return nil, fmt.Errorf("tamper: audit: %w", err)
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
		if cfg.Tenancy != nil && cfg.Tenancy.Enabled {
			// Prepended, like the KeySet below, so an explicit
			// identity.WithTenancy in Options still wins (last setter wins).
			opts = append([]identity.Option{identity.WithTenancy(true)}, opts...)
		}
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

// Close releases resources the Provider owns — today the audit DB handle
// (a no-op for the NoopLogger). Safe on a nil Provider. Call it on
// application shutdown.
func (p *Provider) Close() error {
	if p == nil || p.Audit == nil {
		return nil
	}
	return p.Audit.Close()
}
