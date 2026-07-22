package espresso

import (
	"context"
	"net/http"

	espressofw "github.com/suryakencana007/espresso/v2"

	"github.com/suryakencana007/tamper/authz"
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
	UserExists func(ctx context.Context, userID string) (bool, error)
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
// context.
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

			subject := authz.Subject{Type: g.SubjectType, ID: userID}
			resource := authz.Resource{Type: g.ResourceType, ID: resourceID}

			// Check 1 — visibility (the leak rule), when configured.
			if g.VisibilityAction != "" {
				visible, err := g.Authorizer.Check(r.Context(), subject, g.VisibilityAction, resource)
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
			decision, err := g.Authorizer.Check(r.Context(), subject, g.Action, resource)
			if err != nil {
				_ = espressofw.ErrInternal("middleware: " + g.Label + " check failed").Wrap(err).
					WriteResponse(w)
				return
			}
			if !decision.Allowed {
				// Ghost probe: deny path only.
				if g.UserExists != nil {
					exists, exErr := g.UserExists(r.Context(), userID)
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
