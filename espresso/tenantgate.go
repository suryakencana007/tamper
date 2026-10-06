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
// eliminates it: only a gate puts a tenant in the context (RequireTenant,
// RequireTenantAllowEntered, PinTenant, and RequireDecision for what
// runs behind it), so any handler that reads TenantFromContext with
// none of them mounted gets ("", false) rather than a wrong answer; a missing-claims request denies rather
// than passing; and crypto.VerifyAccess exists for callers who
// would rather do the check at verification time, where it cannot be
// composed wrong. A deployment enabling tenancy should wrap every authed
// route with this and treat an unwrapped one as a bug.
package espresso

import (
	"context"
	"net/http"

	espressofw "github.com/suryakencana007/espresso/v2"

	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
)

// tenantCtxKey carries the routed tenant. Unexported type, per the
// stdlib context guidance, so nothing outside this package can collide
// with or forge it.
type tenantCtxKey struct{}

// TenantFromContext returns the tenant a gate pinned for this request,
// and whether one was pinned at all. RequireTenant,
// RequireTenantAllowEntered and RequireDecision pin it after checking
// the token against it; PinTenant pins it with no token check.
//
// (the zero ID, false) means none of them ran. It is NOT "the
// single-tenant deployment" — a handler that treats it as one turns a
// forgotten middleware into an unscoped query. Handlers in a pooled
// deployment should treat !ok as a programmer error and fail closed.
func TenantFromContext(ctx context.Context) (tenant.ID, bool) {
	id, ok := ctx.Value(tenantCtxKey{}).(tenant.ID)
	return id, ok
}

// tokenFitsTenant is the one rule for "may this token be used on a
// route of this tenant". RequireTenant and RequireDecision both apply
// it, each to the tenant it resolves itself.
//
//   - the token's tid is exactly the routed tenant; absent, empty and
//     mismatched all fail the one equality;
//   - an entered token only where guests were invited.
func tokenFitsTenant(claims *crypto.AccessClaims, routed string, guests bool) bool {
	return claims != nil && claims.TenantID == routed && (guests || !claims.Entered())
}

// RequireTenant returns middleware that pins the request to the tenant
// resolve reports, rejecting any token whose `tid` does not match it
// exactly. On success the tenant is stashed for TenantFromContext.
//
// resolve extracts the tenant from the request — a path segment, a
// subdomain, whatever the app's routing says — and whether it found
// one. It runs BEFORE the comparison and its answer is never taken from
// the token: a tenant read out of the credential being checked would be
// checking the token against itself. A tenant that does not resolve
// (false, or the zero ID) denies: an empty path segment is not the
// single tenant, it is no tenant. The single tenant is said, as
// tenant.Single; [FixedRequestTenant] says it for a whole surface.
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
//   - the route's tenant did not resolve;
//   - token `tid` empty, route tenant named — a single-tenant token on a
//     tenant's route;
//   - token `tid` non-empty, route tenant tenant.Single — a tenant token
//     on a single-tenant route;
//   - any mismatch between the two;
//   - an ENTERED token (identity.Core.EnterTenant), even when its `tid`
//     matches. See below.
//
// An entered token belongs to a platform admin acting inside this
// tenant. Its subject is NOT a user of this tenant, and most routes are
// written for the tenant's own users: "my account" routes act on the
// subject's row wherever it is stored. So this gate keeps the
// promise it made before entered tokens existed — the subject is a user
// of the routed tenant — and a route that is meant for platform admins
// says so with [RequireTenantAllowEntered].
//
// Panics if resolve is nil. That is a boot-time programmer error and
// the same posture crypto.NewJWTService takes on an empty secret:
// tenancy misconfiguration fails at construction, never as a per-request
// denial that looks like ordinary traffic (§6.4).
func RequireTenant(resolve func(*http.Request) (tenant.ID, bool)) func(http.Handler) http.Handler {
	return requireTenant(resolve, false)
}

// RequireTenantAllowEntered is [RequireTenant] for a route that platform
// admins may use too: it accepts the tenant's own tokens AND entered
// tokens whose `tid` is the routed tenant. Everything else about the
// gate is the same, including the refusal.
//
// Opting a route in is a statement about the handler behind it:
//
//   - It must not treat the subject as a user of this tenant. Do not
//     mount "my account" handlers (the AuthRoutes TOTP and profile
//     routes, identity linking) behind this gate; they would act on the
//     admin's home account.
//   - Its authorization must know the subject may be a guest.
//     [RequireDecision] does when DecisionGate.AllowEntered is set: it
//     asks with the guest's home tenant on the subject, so the guest
//     gets only what this tenant granted them. A handler that decides
//     by itself reads [EnteredFromContext].
func RequireTenantAllowEntered(resolve func(*http.Request) (tenant.ID, bool)) func(http.Handler) http.Handler {
	return requireTenant(resolve, true)
}

// EnteredFromContext reports whether the request was made with an
// entered token, and if so the subject's home tenant. False behind
// [RequireTenant], which refuses such tokens.
func EnteredFromContext(ctx context.Context) (home tenant.ID, entered bool) {
	claims, ok := AccessClaimsFromContext(ctx)
	if !ok || claims == nil || !claims.Entered() {
		return tenant.ID{}, false
	}
	return tenant.New(claims.HomeTenantID), true
}

// FixedRequestTenant returns a resolver that reports one tenant for
// every request: a surface mounted for exactly one tenant, or the
// single-tenant application's (tenant.Single). It is [FixedTenant] for
// the gates, which resolve from the request rather than the context.
//
// Panics on an unset id, for the reason FixedTenant does: a gate fixed
// to no tenant would refuse every request, and that fails where the
// gate is built.
func FixedRequestTenant(id tenant.ID) func(*http.Request) (tenant.ID, bool) {
	if !id.Valid() {
		panic("tamper/espresso: FixedRequestTenant requires a set tenant.ID — " +
			"a gate fixed to no tenant would refuse every request; the single tenant is tenant.Single")
	}
	return func(*http.Request) (tenant.ID, bool) { return id, true }
}

func requireTenant(resolve func(*http.Request) (tenant.ID, bool), allowEntered bool) func(http.Handler) http.Handler {
	if resolve == nil {
		panic("tamper/espresso: RequireTenant requires a resolve function — " +
			"a nil resolver would be a tenant gate that pins nothing")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No claims means RequireAuth did not run: there is nothing
			// to pin against. A tenant that did not resolve, a wrong
			// tenant, and a guest on a route that did not invite guests,
			// get the same refusal, so the response never says the token
			// is good somewhere else.
			claims, _ := AccessClaimsFromContext(r.Context())
			routed, ok := resolve(r)
			if !ok || !routed.Valid() || !tokenFitsTenant(claims, routed.String(), allowEntered) {
				writeUnauthenticated(w, "invalid token")
				return
			}
			ctx := context.WithValue(r.Context(), tenantCtxKey{}, routed)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// PinTenant pins the tenant a request is routed to, WITHOUT requiring a
// token. It is the pre-authentication sibling of [RequireTenant].
//
// Routes that run before RequireAuth still need a tenant — an OIDC or
// SAML start leg has to know whose IdP to look up, and the provider
// registry is keyed by tenant.
//
// The split matters: RequireTenant cross-checks the token's tid against
// the routed tenant and therefore CANNOT run before RequireAuth, while
// PinTenant makes no claim about a credential because there is none yet.
// Using PinTenant on an authenticated route would skip the cross-check, so
// the two are deliberately separate names rather than one flag.
//
// resolve returns the application's routed tenant and whether it found
// one. A tenant that does not resolve (false, or the zero ID) is
// answered 404 and the handler is not reached: a public route of a
// tenant that does not exist is a miss, like any other wrong path, and
// says nothing more. It is never read as the single tenant; a
// single-tenant application says so with FixedRequestTenant(tenant.Single).
func PinTenant(resolve func(*http.Request) (tenant.ID, bool)) func(http.Handler) http.Handler {
	if resolve == nil {
		panic("tamper/espresso: PinTenant requires a resolve function — " +
			"a nil resolver would be a tenant gate that pins nothing")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			routed, ok := resolve(r)
			if !ok || !routed.Valid() {
				_ = espressofw.ErrNotFound("not found").WithCode("NOT_FOUND").WriteResponse(w)
				return
			}
			ctx := context.WithValue(r.Context(), tenantCtxKey{}, routed)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
