package espresso

import (
	"context"
	"net/http"

	espressofw "github.com/suryakencana007/espresso/v2"

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/tenant"
)

// DenyWriter writes the app's deny response — status, code, and copy
// are the app's SPA contract, never the framework's.
type DenyWriter func(w http.ResponseWriter)

// DecisionGate configures RequireDecision — the generalized skeleton
// of the PDP-consulting HTTP gates (per-resource role tiers, the
// two-check visibility flow, singleton admin gates with a ghost-user
// probe).
type DecisionGate struct {
	// Authorizer is the PDP. Required — nil is a 500 CONFIG_ERROR at
	// request time (fail closed, loudly).
	Authorizer authz.Authorizer
	// Label names the gate in internal-error messages
	// ("cluster role", "org role", "system role") so operator logs
	// keep their pre-lift grep-ability.
	Label string
	// Tenant resolves the tenant the request is routed to — a path
	// segment, a subdomain, a constant. Required: RequireDecision panics
	// without it. It is the SCOPE of the question, and the token must be
	// for exactly this tenant. The answer never comes from the token.
	//
	// A single-tenant application returns "" for every request. That is
	// the single tenant said out loud, not a tenant left out.
	Tenant func(*http.Request) string
	// AllowEntered lets a platform admin who ENTERED this tenant
	// (identity.Core.EnterTenant) through to the Authorizer. False, the
	// default, refuses an entered token like a wrong-tenant one. A guest
	// who is let through is asked about with their home tenant on the
	// subject, so they get only what this tenant granted them.
	AllowEntered bool
	// SubjectType is the app's subject taxonomy value (e.g. "user").
	SubjectType string
	// ResourceType is the app's resource taxonomy value. Also used in
	// the missing-path-param error message ("<type> id path param
	// missing").
	ResourceType string
	// ResourceIDFrom is the path-param key carrying the resource id.
	// Empty means the resource is a singleton (system-scope gates) and
	// no path param is read.
	ResourceIDFrom string
	// Action is the tier action the gate enforces. Required.
	Action authz.Action
	// VisibilityAction, when non-empty and different from Action, runs
	// FIRST; a deny invokes WriteNotVisible instead of WriteDenied —
	// the two-check flow that keeps cross-tenant probes from learning
	// whether the resource exists (a deny and a miss look identical).
	VisibilityAction authz.Action
	// WriteNotVisible writes the visibility-deny response (e.g. 404
	// ORG_NOT_FOUND). Required when VisibilityAction is set.
	WriteNotVisible DenyWriter
	// WriteDenied writes the tier-deny response (e.g. 403
	// INSUFFICIENT_ORG_ROLE). Required.
	WriteDenied DenyWriter
	// WriteProbeError writes the response when the UserExists probe
	// itself errors (fail closed, app copy). Optional — nil falls
	// back to WriteDenied.
	WriteProbeError DenyWriter
	// UserExists, when set, runs on the deny path ONLY and
	// distinguishes ghost subjects (a valid JWT whose user row is
	// gone) from real subjects lacking the role: a ghost gets
	// WriteGhost (the app's 401 so its session-refresh path logs the
	// caller out) instead of WriteDenied. Allowed requests never pay
	// the probe.
	//
	// home is the tenant the subject is STORED in — the token's home
	// tenant. Look the user up there. It is not always the routed
	// tenant: a platform admin who entered this tenant has no row in
	// it, and a probe that looked here would call every denied guest a
	// ghost (or answer for a local user who happens to share the id).
	UserExists func(ctx context.Context, home tenant.ID, userID string) (bool, error)
	// WriteGhost writes the ghost-subject response. Required when
	// UserExists is set.
	WriteGhost DenyWriter
}

// RequireDecision returns middleware enforcing the gate. Deny by
// default: missing authentication is 401; any misconfiguration
// (nil authorizer, empty action, missing path param, missing
// writers) is a 500 CONFIG_ERROR — never a silent pass.
//
// Panics if g.Tenant is nil. A decision gate that does not know whose
// resources it guards is a tenancy misconfiguration, and that fails
// when the gate is built, not on a request (the posture RequireTenant
// takes on a nil resolver).
//
// Stack ordering: must run AFTER RequireAuth. It needs nothing else
// around it. The gate carries its own tenant, so it does not depend on
// a tenant gate having been mounted first, and it cannot be mounted
// "without one" by mistake.
//
// The question is asked with two tenants, and they are different facts:
//
//   - The SCOPE is the tenant g.Tenant resolves — whose resources these
//     are.
//   - The SUBJECT's tenant is where the token says its subject is from:
//     the scope itself for the tenant's own user, the home tenant for a
//     platform admin who entered. The Authorizer therefore finds only
//     what was granted to that exact subject inside this scope; roles
//     held at home are bindings of another scope and are never
//     consulted.
//
// The token must fit the tenant by the one rule RequireTenant applies
// (tokenFitsTenant): its tid is exactly the resolved tenant, and an
// entered token only where AllowEntered is set. Anything else is the
// 401 RequireTenant writes — including a user id that reached the
// context without a token. There is no path that guesses a tenant.
//
// On success the tenant is also pinned for TenantFromContext, so what
// runs behind the gate (a handler, the Auditor) sees the same scope the
// decision was made in.
func RequireDecision(g DecisionGate) func(http.Handler) http.Handler {
	if g.Tenant == nil {
		panic("tamper/espresso: RequireDecision requires DecisionGate.Tenant — " +
			"a decision gate that names no tenant would authorize in no scope")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := GetUserID(r.Context())
			if !ok {
				writeUnauthenticated(w, "missing authentication")
				return
			}
			if g.Authorizer == nil || g.Action == "" || g.WriteDenied == nil ||
				(g.VisibilityAction != "" && g.WriteNotVisible == nil) ||
				(g.UserExists != nil && g.WriteGhost == nil) {
				_ = espressofw.ErrInternal("middleware: " + g.Label + " gate misconfigured (nil authorizer or unmapped min role)").
					WithCode("CONFIG_ERROR").
					WriteResponse(w)
				return
			}
			claims, _ := AccessClaimsFromContext(r.Context())
			routed := g.Tenant(r)
			if !tokenFitsTenant(claims, routed, g.AllowEntered) {
				writeUnauthenticated(w, "invalid token")
				return
			}
			// FromStored, as RequireTenant does: routed has just been
			// compared with a signed tid, so "" here is the single
			// tenant as a fact. The home tenant of a guest is a claim
			// of its own and goes through tenant.New.
			scope := tenant.FromStored(routed)
			home := scope
			if claims.Entered() {
				home = tenant.New(claims.HomeTenantID)
			}
			r = r.WithContext(context.WithValue(r.Context(), tenantCtxKey{}, scope))
			resourceID := ""
			if g.ResourceIDFrom != "" {
				resourceID = r.PathValue(g.ResourceIDFrom)
				if resourceID == "" {
					_ = espressofw.ErrInternal("middleware: " + g.ResourceType + " id path param missing").
						WithCode("CONFIG_ERROR").
						WriteResponse(w)
					return
				}
			}

			subject := authz.Subject{Tenant: home, Type: g.SubjectType, ID: userID}
			resource := authz.Resource{Type: g.ResourceType, ID: resourceID}

			// Check 1 — visibility (the leak rule), when configured.
			if g.VisibilityAction != "" {
				visible, err := g.Authorizer.Check(r.Context(), scope, subject, g.VisibilityAction, resource)
				if err != nil {
					_ = espressofw.ErrInternal("middleware: " + g.Label + " check failed").Wrap(err).
						WriteResponse(w)
					return
				}
				if !visible.Allowed {
					g.WriteNotVisible(w)
					return
				}
				// When the requested tier IS the visibility tier,
				// check 1 already answered it.
				if g.VisibilityAction == g.Action {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Check 2 — the requested tier.
			decision, err := g.Authorizer.Check(r.Context(), scope, subject, g.Action, resource)
			if err != nil {
				_ = espressofw.ErrInternal("middleware: " + g.Label + " check failed").Wrap(err).
					WriteResponse(w)
				return
			}
			if !decision.Allowed {
				// Ghost probe: deny path only.
				if g.UserExists != nil {
					exists, exErr := g.UserExists(r.Context(), home, userID)
					if exErr != nil {
						if g.WriteProbeError != nil {
							g.WriteProbeError(w)
						} else {
							g.WriteDenied(w)
						}
						return
					}
					if !exists {
						g.WriteGhost(w)
						return
					}
				}
				g.WriteDenied(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
