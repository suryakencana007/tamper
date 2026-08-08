package espresso

import (
	"errors"
	"net/http"

	espressofw "github.com/suryakencana007/espresso/v2"

	tamper "github.com/suryakencana007/tamper"
	"github.com/suryakencana007/tamper/scim"
	"github.com/suryakencana007/tamper/tenant"
)

// RouteConfig carries the transport-layer policy the engines cannot own —
// route branding, cookie names, the app's hooks and ports. Routes fills in
// only the pieces it can derive from the Provider: the federation registry
// hooks (from the OIDC/SAML managers), the auth/WS middleware (from the JWT
// service), and the Auditor (from the audit logger).
type RouteConfig struct {
	// Auth is the always-built core-auth surface config (register / login /
	// me / refresh / logout / the TOTP ceremony). See AuthRoutesConfig.
	Auth AuthRoutesConfig

	// Identity is the port the auth routes drive. REQUIRED — and it must be
	// app-supplied. identity.Core does NOT satisfy IdentityService: the port
	// adds Me (a user-by-id lookup Core does not expose) and the two-phase
	// session-token TOTP methods (IssueTOTPPending / VerifyTOTPPending /
	// EnrollTOTPViaSession), whose ceremony token is app policy. Greenfield
	// consumers wrap identity.Core with a small adapter that fills those
	// (the quickstart example shows the shape).
	Identity IdentityService

	// AuditEmailLookup enriches the Auditor's actor rows (user id -> email).
	// Optional; nil records actor.user_id only.
	AuditEmailLookup EmailLookup

	// Federation, when non-nil, builds the OIDC federation surface. It
	// requires the Provider to carry an OIDC manager (Routes wires
	// Hooks.Registry from it); the app supplies the remaining hooks + config.
	Federation *FederationBundle

	// SAML, when non-nil, builds the SAML federation surface. Requires the
	// Provider to carry a SAML manager (Routes wires Hooks.Registry from it).
	SAML *SAMLBundle

	// SCIM, when non-nil, builds the SCIM surface and the bound
	// RequireServiceAccount middleware.
	SCIM *SCIMBundle
}

// FederationBundle is the OIDC federation surface's config + hooks. Routes
// overwrites Hooks.Registry with the Provider's OIDC manager — leave it nil.
type FederationBundle struct {
	Config FederationConfig
	Hooks  FederationHooks
}

// SAMLBundle is the SAML federation surface's config + hooks. Routes
// overwrites Hooks.Registry with the Provider's SAML manager — leave it nil.
type SAMLBundle struct {
	Config SAMLConfig
	Hooks  SAMLHooks
}

// SCIMBundle is the SCIM surface's config + ports. Users, Groups, and
// Validator are all app-supplied leaves; the port impls emit their own audit
// (A3), so Routes threads no logger into them — the app constructs them with
// the Provider's audit logger itself.
type SCIMBundle struct {
	Config    SCIMConfig
	Users     scim.UserStore
	Groups    scim.GroupStore
	Validator ServiceAccountValidator
}

// Surfaces bundles what Routes hands back for the app to register. Each route
// surface is a value struct the app mounts on its own Espresso router (there
// is deliberately no Mount — the surfaces span both public and authed blocks
// and Espresso's Use is positional; see PHASE4D-BOUNDARY-DECISION.md §A10).
// The middleware closures are pre-bound to the Provider's engines.
type Surfaces struct {
	Auth       *AuthRoutes       // always
	Federation *FederationRoutes // nil unless RouteConfig.Federation is set
	SAML       *SAMLRoutes       // nil unless RouteConfig.SAML is set
	SCIM       *SCIMRoutes       // nil unless RouteConfig.SCIM is set
	Auditor    *Auditor          // always — for the app's OWN mutation routes

	// RequireAuth gates a route on a valid access JWT.
	RequireAuth func(http.Handler) http.Handler
	// RequireAuthWS gates a WebSocket upgrade, smuggling the token through
	// the given subprotocol prefix.
	RequireAuthWS func(subprotocolPrefix string) func(http.Handler) http.Handler
	// RequireServiceAccount gates a route on a service-account token. Nil
	// unless RouteConfig.SCIM is set (its Validator binds this).
	RequireServiceAccount func(http.Handler) http.Handler
}

// Routes constructs the auth/federation/SCIM route surfaces + middleware from
// a built Provider and the app's RouteConfig. It validates at wiring time
// (never per-request), auto-wires the federation registry hooks from the
// Provider's managers, and gates each optional surface on both its config
// being set AND the Provider carrying the matching engine.
//
// The app registers the returned surfaces on its own router and constructs
// its SCIM port impls (which emit their own audit) with the Provider's audit
// logger — Routes does not wrap them (A3).
func Routes(tp *tamper.Provider, cfg RouteConfig) (*Surfaces, error) {
	if tp == nil {
		return nil, errors.New("tamper/espresso: Routes requires a non-nil Provider")
	}
	if tp.JWT == nil {
		return nil, errors.New("tamper/espresso: Routes requires a Provider with a JWT service")
	}

	s := &Surfaces{}

	// --- Auth surface (always) ---
	auth, err := NewAuthRoutes(cfg.Identity, cfg.Auth)
	if err != nil {
		return nil, err
	}
	s.Auth = auth

	// --- Middleware bound to the Provider's JWT service ---
	jwt := tp.JWT
	s.RequireAuth = RequireAuth(jwt)
	s.RequireAuthWS = func(subprotocolPrefix string) func(http.Handler) http.Handler {
		return RequireAuthWS(jwt, subprotocolPrefix)
	}

	// --- Auditor (tp.Audit is always non-nil) ---
	s.Auditor = NewAuditor(tp.Audit, cfg.AuditEmailLookup)

	// --- OIDC federation (optional) ---
	if cfg.Federation != nil {
		if tp.OIDC == nil {
			return nil, errors.New("tamper/espresso: RouteConfig.Federation is set but the Provider has no OIDC manager")
		}
		hooks := cfg.Federation.Hooks
		hooks.Registry = tp.OIDC.GetRegistry // Routes owns the registry wiring
		fed, ferr := NewFederationRoutes(cfg.Federation.Config, hooks)
		if ferr != nil {
			return nil, ferr
		}
		s.Federation = fed
	}

	// --- SAML federation (optional) ---
	if cfg.SAML != nil {
		if tp.SAML == nil {
			return nil, errors.New("tamper/espresso: RouteConfig.SAML is set but the Provider has no SAML manager")
		}
		hooks := cfg.SAML.Hooks
		hooks.Registry = tp.SAML.GetRegistry
		sm, serr := NewSAMLRoutes(cfg.SAML.Config, hooks)
		if serr != nil {
			return nil, serr
		}
		s.SAML = sm
	}

	// --- SCIM (optional) ---
	if cfg.SCIM != nil {
		if cfg.SCIM.Validator == nil {
			return nil, errors.New("tamper/espresso: RouteConfig.SCIM requires a ServiceAccountValidator")
		}
		sc, cerr := NewSCIMRoutes(cfg.SCIM.Config, cfg.SCIM.Users, cfg.SCIM.Groups)
		if cerr != nil {
			return nil, cerr
		}
		s.SCIM = sc
		s.RequireServiceAccount = RequireServiceAccount(cfg.SCIM.Validator)
	}

	return s, nil
}

// --- entitlement gating (slice 7h-1) ---------------------------------
//
// Entitlements are gated HERE, at the route surface, and never at boot.
// Boot-time nil-encoding — "no OIDC config, no OIDC routes" — is
// per-process, and a pooled process serves every tier at once. It
// structurally cannot express "acme bought SSO, globex did not".

// EntitlementDeniedCode is the wire-stable code a client receives when a
// capability is not purchased. Stable because an SPA branches on it to
// render an upgrade prompt rather than an error toast.
const EntitlementDeniedCode = "FEATURE_NOT_ENABLED"

// Capability names the entitlement a route requires.
type Capability string

const (
	// CapabilitySSO gates federated login (the OIDC/SAML start routes).
	CapabilitySSO Capability = "sso"
	// CapabilitySCIM gates the directory-provisioning surface.
	CapabilitySCIM Capability = "scim"
)

// allowed reports whether e includes c.
func (c Capability) allowed(e tenant.Entitlements) bool {
	switch c {
	case CapabilitySSO:
		return e.SSOEnabled
	case CapabilitySCIM:
		return e.SCIMEnabled
	default:
		// An unknown capability denies. A typo in a gate must not open
		// the route it was meant to close.
		return false
	}
}

// TenantFromRoutedContext resolves the tenant RequireTenant pinned.
// The resolver to use on authenticated routes behind that gate.
func TenantFromRoutedContext(r *http.Request) (string, bool) {
	return TenantFromContext(r.Context())
}

// TenantFromServiceAccount resolves the tenant on the validated SCIM
// principal — the resolver to use behind RequireServiceAccount.
func TenantFromServiceAccount(r *http.Request) (string, bool) {
	p, ok := GetPrincipal(r.Context())
	return p.TenantID, ok
}

type entitlementConfig struct {
	deny func(w http.ResponseWriter, r *http.Request, c Capability)
}

// EntitlementOption configures RequireEntitlement.
type EntitlementOption func(*entitlementConfig)

// WithEntitlementDenyWriter replaces the deny renderer. The SCIM surface
// supplies one that emits the RFC 7644 §3.12 envelope, because a SCIM
// client fail-closes on an app-branded body.
//
// Whatever it writes MUST be a 403 with a stable code. See
// RequireEntitlement for why this is the one place in the phase that
// does not answer 404.
func WithEntitlementDenyWriter(fn func(w http.ResponseWriter, r *http.Request, c Capability)) EntitlementOption {
	return func(cfg *entitlementConfig) {
		if fn != nil {
			cfg.deny = fn
		}
	}
}

// RequireEntitlement returns middleware that refuses a route when the
// request's tenant has not purchased the capability.
//
// THE DENY IS 403, NOT 404, AND THAT IS A DELIBERATE INVERSION of the
// rule this phase applies everywhere else. A cross-tenant miss is 404
// because a deny and a miss must be indistinguishable — telling a caller
// that another tenant's resource exists is the leak. Here the caller IS
// the tenant, the tenant exists, and the feature is simply not bought.
// That is not a secret; it is a fact the customer needs, and answering
// 404 would send an operator hunting a broken route when the real answer
// is "upgrade your plan". Nothing about another tenant is disclosed by
// telling you about your own.
//
// resolve extracts the tenant from the request. It is explicit rather
// than inferred because the two gated surfaces carry the tenant
// differently — federation start routes are pre-auth and sit behind
// RequireTenant (TenantFromRoutedContext), SCIM sits behind
// RequireServiceAccount (TenantFromServiceAccount). Guessing would mean
// silently falling back to "" on the surface that used the other one.
//
// EVERY failure denies, and each is a case someone could have made
// permissive: no resolvable tenant, a store error, an unknown
// capability. A store outage must not become a free upgrade (§6.2 — no
// error return may be read as allow).
//
// Panics if store or resolve is nil: a gate that cannot look anything up
// is a gate that permits everything, and that fails at construction
// rather than as traffic that looks ordinary.
func RequireEntitlement(store tenant.EntitlementStore, capability Capability,
	resolve func(*http.Request) (string, bool), opts ...EntitlementOption,
) func(http.Handler) http.Handler {
	if store == nil {
		panic("tamper/espresso: RequireEntitlement requires an EntitlementStore — " +
			"a nil store would be a gate that permits everything")
	}
	if resolve == nil {
		panic("tamper/espresso: RequireEntitlement requires a tenant resolver — " +
			"without one every request resolves to the empty tenant")
	}
	cfg := entitlementConfig{deny: writeEntitlementDenied}
	for _, o := range opts {
		o(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID, ok := resolve(r)
			if !ok {
				// No tenant means nothing to check the plan of. Deny.
				cfg.deny(w, r, capability)
				return
			}
			ent, err := store.ForTenant(r.Context(), tenantID)
			if err != nil {
				cfg.deny(w, r, capability)
				return
			}
			if !capability.allowed(ent) {
				cfg.deny(w, r, capability)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// writeEntitlementDenied is the default 403 renderer.
func writeEntitlementDenied(w http.ResponseWriter, _ *http.Request, c Capability) {
	err := espressofw.ErrForbidden(string(c) + " is not enabled for this tenant").
		WithCode(EntitlementDeniedCode)
	_ = err.WriteResponse(w)
}

// WriteSCIMEntitlementDenied is the SCIM-shaped deny writer, for use with
// WithEntitlementDenyWriter on the SCIM surface. Same status and the same
// stable meaning, in the envelope RFC 7644 §3.12 mandates.
func WriteSCIMEntitlementDenied(w http.ResponseWriter, _ *http.Request, c Capability) {
	WriteSCIMErrorTyped(w, http.StatusForbidden,
		string(c)+" is not enabled for this tenant", "")
}
