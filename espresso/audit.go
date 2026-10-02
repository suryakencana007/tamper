package espresso

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/suryakencana007/espresso/v2/extractor"
	httpmiddleware "github.com/suryakencana007/espresso/v2/middleware/http"

	"github.com/suryakencana007/tamper/audit"
)

// MutationContext describes what an audit middleware should capture
// for a particular mutation route. Created at route-registration
// time and passed to Auditor.For.
//
// ResourceIDFrom is the path-param key to read resource_id from.
// Empty means "no path-scoped resource_id" (e.g. a create route whose
// new id comes from the response body and isn't visible to the
// middleware).
type MutationContext struct {
	Action         audit.Action
	ResourceType   audit.ResourceType
	ResourceIDFrom string
}

// EmailLookup resolves an email for a user id. The Auditor calls it
// best-effort for audit-row enrichment. Returning ("", false) is fine
// — the audit event still records user_id, just not email.
type EmailLookup func(ctx context.Context, userID string) (email string, ok bool)

// Auditor builds audit-mutation middlewares with a shared logger +
// email lookup. Constructed once at server init and reused to stamp
// each mutation route via Auditor.For(MutationContext{...}).
//
// IP may be nil (IPFromRequest). Inject an app policy to change how
// the actor's source IP is derived.
type Auditor struct {
	Logger audit.Logger
	Email  EmailLookup
	IP     IPExtractor
}

// NewAuditor returns an Auditor with the given logger and email
// lookup. logger may be audit.NewNoopLogger() to disable audit
// emission without removing the middleware; emailLookup may be nil —
// audit rows then record actor.user_id only.
func NewAuditor(logger audit.Logger, emailLookup EmailLookup) *Auditor {
	if logger == nil {
		logger = audit.NewNoopLogger()
	}
	return &Auditor{Logger: logger, Email: emailLookup}
}

// Mutation is a terser wrapper around For for the most common
// route-registration shape. Use idFrom = "" when the route doesn't
// have a path-scoped resource id.
func (a *Auditor) Mutation(action audit.Action, rt audit.ResourceType, idFrom string) func(http.Handler) http.Handler {
	return a.For(MutationContext{Action: action, ResourceType: rt, ResourceIDFrom: idFrom})
}

// For returns the per-route middleware that wraps the mutation
// handler, captures actor + request_id + IP + (optional) resource_id,
// and emits an audit.Event after a 2xx response.
//
// In a pooled deployment mount it INSIDE the tenant gate (RequireAuth
// -> RequireTenant -> For, or PinTenant -> For on a public route): the
// event is scoped to the tenant that gate pinned, and that scope is
// what audit's per-tenant export filters on. Mounted outside the gate
// it still emits, with no scope.
//
// Audit emission is best-effort: a Log error is reported via
// log.Printf but never causes the HTTP response to fail — the
// mutation has already been written to the wire by the time we log.
func (a *Auditor) For(mc MutationContext) func(http.Handler) http.Handler {
	if a == nil {
		// Defensive: wrap with a passthrough rather than panic. Wiring
		// should always supply a non-nil Auditor, but tests + dev runs
		// that don't shouldn't 500.
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Install the cluster-id capture slot BEFORE the handler
			// runs. The handler (or any service it calls) populates it
			// via audit.SetClusterID once the id is in scope; we read
			// it back when stamping the event after a 2xx response.
			ctx, clusterCap := audit.WithClusterIDCapture(r.Context())
			// Install the user-id slot so handlers on PUBLIC routes
			// that complete authentication mid-request (login, TOTP
			// verify) can backfill the actor BEFORE the audit row
			// emits. RequireAuth-gated routes already carry the
			// JWT-derived id at request entry.
			ctx, _ = WithUserIDCapture(ctx)
			r = r.WithContext(ctx)

			sw := &statusCapturingWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)

			if sw.status < 200 || sw.status >= 300 {
				return
			}

			actor := a.captureActor(ctx, r)
			requestID := httpmiddleware.GetRequestID(ctx)

			resourceID := ""
			if mc.ResourceIDFrom != "" {
				if v, ok := extractor.GetPathParams(r)[mc.ResourceIDFrom]; ok {
					resourceID = v
				}
			}

			// The row's SCOPE is the ROUTED tenant — the one RequireTenant
			// or PinTenant pinned — and never the token's `tid`. The two
			// are different facts (audit.Event.TenantID vs
			// audit.Actor.TenantID): an actor homed in tenant A acting on
			// a route in tenant B belongs in B's export, and a scope taken
			// from the actor would file it under A instead.
			//
			// ctx is the context this middleware was ENTERED with, so only
			// a gate mounted outside it is visible here. An Auditor
			// mounted outside RequireTenant (or with no tenant gate at
			// all) finds nothing pinned and records no scope, exactly as
			// before tenancy; there is deliberately no fallback to the
			// actor's tenant. tenant.Single stringifies to "", so the
			// single-tenant row is unchanged too.
			tenantID := ""
			if routed, ok := TenantFromContext(ctx); ok {
				tenantID = routed.String()
			}

			event := audit.Event{
				ID:           uuid.NewString(),
				At:           time.Now().UTC(),
				Actor:        actor,
				Action:       mc.Action,
				ResourceType: mc.ResourceType,
				ResourceID:   resourceID,
				ClusterID:    clusterCap.ID,
				RequestID:    requestID,
				TenantID:     tenantID,
			}

			if _, err := a.Logger.Log(ctx, event); err != nil {
				// mc.Action / ResourceType are route-registration-time
				// constants; resourceID + actor are %q-escaped —
				// server-controlled, not user-controlled.
				log.Printf("audit: log %q (resource=%s/%s actor=%s): %v", //nolint:gosec // server-controlled values, %q-escaped
					mc.Action, mc.ResourceType, resourceID, actor.UserID, err)
			}
		})
	}
}

// statusCapturingWriter wraps http.ResponseWriter and intercepts the
// status code so the middleware can branch on 2xx vs not.
type statusCapturingWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusCapturingWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusCapturingWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// captureActor builds an audit.Actor from the request context + HTTP
// request. Default path: UserID comes from the JWT claim stashed by
// RequireAuth (empty for public routes), falling back to the
// SetUserID capture slot; Email comes from the EmailLookup; IP from
// the Auditor's IPExtractor.
//
// When an upstream gate has stashed a non-user actor via
// audit.WithActor (service accounts, system emissions), that actor
// wins — the IP is stamped fresh and the row records the non-user
// attribution honestly.
//
// A user actor is still REBUILT rather than passed through, so the
// id, email and IP keep coming from the sources above. The one field
// carried over from the context actor is TenantID: it is the actor's
// home tenant as RequireAuth read it off the token's `tid`, and there
// is no other place to recover it from here. On a public route no
// actor was stashed, ActorFromContext returns the bare user default,
// and the field stays "" — a user id backfilled through SetUserID says
// who logged in, not which tenant a token of theirs would name.
func (a *Auditor) captureActor(ctx context.Context, r *http.Request) audit.Actor {
	extract := a.IP
	if extract == nil {
		extract = IPFromRequest
	}
	ip := extract(r)
	ctxActor := audit.ActorFromContext(ctx)
	if ctxActor.Type != "" && ctxActor.Type != audit.ActorTypeUser {
		ctxActor.IP = ip
		return ctxActor
	}
	userID, _ := GetUserID(ctx)
	// Public-route fallback: honour the SetUserID slot when GetUserID
	// came back empty so the row's actor.user_id is populated.
	if userID == "" {
		userID = UserIDFromContext(ctx)
	}
	email := ""
	if a.Email != nil && userID != "" {
		if e, ok := a.Email(ctx, userID); ok {
			email = e
		}
	}
	return audit.Actor{Type: audit.ActorTypeUser, UserID: userID, Email: email, IP: ip, TenantID: ctxActor.TenantID}
}
