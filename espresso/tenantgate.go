// Tenant gate for the Tamper Espresso adapter.
//
// Pins an authenticated request to the tenant its route names: reads the
// typed AccessClaims stashed by RequireAuth, compares the token's `tid`
// against the tenant the app resolved from the request, and fails closed
// on any mismatch — including a token with no tenant on a route that has
// one.
//
// Composes with RequireAuth, which MUST run first so the JWT is verified
// and the claims are in context. RequireTenant reads those claims; it
// does NOT re-verify the JWT, exactly as RequireFreshAuth does not.
//
// PLACEMENT (sketch §8, open item 4 — "does the cross-check belong in
// RequireAuth, or in a separate composable middleware?"). Separate, on
// the same reasoning 4b applied to the step-up gate:
//
//   - Resolving a tenant from a request is ROUTE SHAPE, and route shape
//     is the app's. A path segment, a subdomain, a header, a claim on a
//     service token — tamper cannot know, and RequireAuth taking a
//     resolver would force every single-tenant consumer to pass nil.
//     A nil resolver inside RequireAuth is a gate that is present and
//     does nothing, which is the failure mode this phase keeps finding.
//   - The step-up gate already established this shape for "a check that
//     reads RequireAuth's claims and fails closed". Two security gates
//     with two different composition models is a worse outcome than the
//     ergonomic cost of one more Use().
//
// The honest cost of separate: it is skippable, therefore forgettable,
// and a pooled deployment that forgets it on an authed route accepts
// cross-tenant tokens there. Three things blunt that, and none of them
// eliminates it: this gate is the ONLY thing that puts a tenant in the
// context, so any handler that reads TenantFromContext gets ("", false)
// rather than a wrong answer; a missing-claims request denies rather
// than passing; and crypto.VerifyAccessInTenant exists for callers who
// would rather do the check at verification time, where it cannot be
// composed wrong. A deployment enabling tenancy should wrap every authed
// route with this and treat an unwrapped one as a bug.
package espresso

import (
	"context"
	"net/http"

	"github.com/suryakencana007/tamper/tenant"
)

// tenantCtxKey carries the routed tenant. Unexported type, per the
// stdlib context guidance, so nothing outside this package can collide
// with or forge it.
type tenantCtxKey struct{}

// TenantFromContext returns the tenant RequireTenant pinned for this
// request, and whether one was pinned at all.
//
// (the zero ID, false) means RequireTenant did not run. It is NOT "the
// single-tenant deployment" — a handler that treats it as one turns a
// forgotten middleware into an unscoped query. Handlers in a pooled
// deployment should treat !ok as a programmer error and fail closed.
func TenantFromContext(ctx context.Context) (tenant.ID, bool) {
	id, ok := ctx.Value(tenantCtxKey{}).(tenant.ID)
	return id, ok
}

// RequireTenant returns middleware that pins the request to the tenant
// resolve reports, rejecting any token whose `tid` does not match it
// exactly. On success the tenant is stashed for TenantFromContext.
//
// resolve extracts the tenant from the request — a path segment, a
// subdomain, whatever the app's routing says. It runs BEFORE the
// comparison and its answer is never taken from the token: a tenant
// read out of the credential being checked would be checking the token
// against itself.
//
// The deny is a 401 with the byte-identical body RequireAuth writes for
// an expired or malformed token. A wrong-tenant request and an
// invalid-token request are indistinguishable on the wire, so the
// response cannot be used to discover which tenants exist or that a
// token is valid somewhere else (§6.3).
//
// Every one of these denies:
//
//   - no claims in context (RequireAuth did not run) — programmer error,
//     and the one shape that would otherwise pass anything;
//   - token `tid` empty, route tenant non-empty — tenancy is on and the
//     token predates it or was minted without one;
//   - token `tid` non-empty, route tenant empty — a tenant token on an
//     untenanted route;
//   - any mismatch between the two.
//
// Panics if resolve is nil. That is a boot-time programmer error and
// the same posture crypto.NewJWTService takes on an empty secret:
// tenancy misconfiguration fails at construction, never as a per-request
// denial that looks like ordinary traffic (§6.4).
func RequireTenant(resolve func(*http.Request) string) func(http.Handler) http.Handler {
	if resolve == nil {
		panic("tamper/espresso: RequireTenant requires a resolve function — " +
			"a nil resolver would be a tenant gate that pins nothing")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := AccessClaimsFromContext(r.Context())
			if !ok || claims == nil {
				// RequireAuth did not run, so there is nothing to pin
				// against. Fail closed and say nothing more than the
				// ordinary rejection says.
				writeUnauthenticated(w, "invalid token")
				return
			}
			routed := resolve(r)
			// The same single equality crypto.VerifyAccessInTenant
			// applies. Absent, empty and mismatched all land here.
			if claims.TenantID != routed {
				writeUnauthenticated(w, "invalid token")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tenantCtxKey{}, tenant.FromStored(routed))))
		})
	}
}
