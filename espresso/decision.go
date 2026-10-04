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
// Stack ordering: must run AFTER RequireAuth so the subject id is in
// context, and AFTER the tenant gate on a pooled route.
//
// The question is asked with two tenants, and they are different facts:
//
//   - The SCOPE is the tenant a tenant gate put in the context
//     (RequireTenant, RequireTenantAllowEntered, PinTenant) — whose
//     resources these are.
//   - The SUBJECT's tenant is the token's home tenant. For a platform
//     admin who entered this tenant that is their own tenant, not the
//     routed one, so the Authorizer finds only what was granted to that
//     guest inside this scope; the roles they hold at home are bindings
//     of another scope and are never consulted.
//
// Neither is ever filled in with a guess. Where a tenant is missing the
// gate refuses:
//
//   - No access claims in the context (a user id stashed by something
//     other than RequireAuth) is a 500 CONFIG_ERROR: nothing says where
//     the subject is from.
//   - No tenant gate ran and the token HAS a tenant: a pooled route that
//     forgot its tenant gate. 500 CONFIG_ERROR, loudly, rather than a
//     decision taken in the wrong scope.
//   - No tenant gate ran and the token has no tenant: the single-tenant
//     deployment. Scope and subject are both tenant.Single.
//   - A tenant gate ran and the token is not for that tenant (possible
//     behind PinTenant, which checks no token): the 401 RequireTenant
//     writes. A subject may not be authorized in a scope its token was
//     not minted for.
func RequireDecision(g DecisionGate) func(http.Handler) http.Handler {
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

			claims, ok := AccessClaimsFromContext(r.Context())
			if !ok || claims == nil {
				_ = espressofw.ErrInternal("middleware: " + g.Label + " gate has a user id but no access claims (RequireAuth did not run)").
					WithCode("CONFIG_ERROR").
					WriteResponse(w)
				return
			}
			scope, gated := TenantFromContext(r.Context())
			switch {
			case !gated && claims.TenantID != "":
				_ = espressofw.ErrInternal("middleware: " + g.Label + " gate got a tenant token on a route with no tenant gate").
					WithCode("CONFIG_ERROR").
					WriteResponse(w)
				return
			case !gated:
				scope = tenant.Single
			case claims.TenantID != scope.String():
				writeUnauthenticated(w, "invalid token")
				return
			}
			// From here the token is for exactly this scope. Its subject
			// is from the scope itself, unless the token says it entered
			// from somewhere else. tenant.New, not FromStored: an htid is
			// a claim, and an empty one must not become a tenant.
			home := scope
			if claims.Entered() {
				home = tenant.New(claims.HomeTenantID)
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
