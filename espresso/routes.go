package espresso

import (
	"errors"
	"net/http"

	tamper "github.com/suryakencana007/barista/packages/tamper"
	"github.com/suryakencana007/barista/packages/tamper/scim"
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
