// Package espresso is the Tamper transport adapter for the Espresso
// HTTP framework (Phase 4). It provides the identity middleware set —
// bearer-JWT authentication for plain and WebSocket routes, the
// request-context identity accessors, the post-handler user-id
// capture slot, cookie-to-context bridging, source-IP stashing, and
// the audit-mutation middleware — as reusable building blocks the
// host app mounts.
//
// Dependency rule: everything rides in constructor closures. The
// adapter NEVER reads the host's espresso.WithState bag — that stays
// exclusively the app's.
//
// Context keys are unexported: the whole middleware set that shares
// them moves (and upgrades) atomically. Apps read values only through
// the exported accessors.
package espresso

import (
	"context"
	"net/http"
	"strings"
	"sync"

	espressofw "github.com/suryakencana007/espresso/v2"

	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/crypto"
)

type userIDKey struct{}

// accessClaimsKey carries the typed access-token claims (auth_time +
// acr + sub). RequireAuth stashes these so a downstream fresh-auth
// gate can read freshness state without re-parsing the JWT.
type accessClaimsKey struct{}

// MustGetUserID returns the user id stashed by RequireAuth. It panics
// when the context has no id — that can only happen when a handler is
// mounted outside a RequireAuth group, which is a programmer error.
func MustGetUserID(ctx context.Context) string {
	id, ok := GetUserID(ctx)
	if !ok {
		panic("tamper/espresso: user id not in context — handler mounted outside RequireAuth")
	}
	return id
}

// GetUserID returns (id, true) if RequireAuth stashed one, otherwise
// ("", false).
func GetUserID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(userIDKey{}).(string)
	return id, ok && id != ""
}

// AccessClaimsFromContext returns the typed access-token claims that
// RequireAuth stashed, or (nil, false) when the context wasn't
// decorated by RequireAuth. Fresh-auth gates use this to read
// auth_time + acr without a re-parse; (nil, false) is the
// programmer-error path they treat as fail-closed.
func AccessClaimsFromContext(ctx context.Context) (*crypto.AccessClaims, bool) {
	c, ok := ctx.Value(accessClaimsKey{}).(*crypto.AccessClaims)
	return c, ok && c != nil
}

// actorCaptureKey lets the audit middleware learn an authenticated actor AFTER the
// handler runs. Without this slot, public routes like /login carry no actor into the
// audit middleware, so the login row ships with an empty one even when the login
// succeeded.
type actorCaptureKey struct{}

// actorSlot is the mutable slot the audit middleware installs at request entry.
// Handlers that complete authentication mid-request write the just-authenticated
// actor via SetAuditActor; the audit middleware reads it back when building the
// event's actor.
//
// It carries an audit.Actor, not a bare user id (Phase 13, D3): a login row belongs
// to a TENANT, and until this change the public-route actor had none — the caller
// knew the tenant and the middleware had no way to be told. A user id alone cannot
// express that, which is the same defect as every other compatibility shim: the
// second way to say who this is, and the second way carries no tenant.
//
// Mutex-guarded because the slot lives across the full request lifetime and a
// handler may legitimately set it from a goroutine it spawns.
type actorSlot struct {
	mu    sync.Mutex
	actor audit.Actor
}

// WithAuditActorCapture returns a derived context carrying a fresh actor slot, plus
// a reader for the captured actor once the handler has returned. The audit-mutation
// middleware calls this exactly once per request.
func WithAuditActorCapture(ctx context.Context) (context.Context, *AuditActorCapture) {
	slot := &actorSlot{}
	return context.WithValue(ctx, actorCaptureKey{}, slot), &AuditActorCapture{slot: slot}
}

// AuditActorCapture is the middleware-side handle onto the capture slot.
type AuditActorCapture struct{ slot *actorSlot }

// Value returns the captured actor and whether anything was stashed.
func (c *AuditActorCapture) Value() (audit.Actor, bool) {
	if c == nil || c.slot == nil {
		return audit.Actor{}, false
	}
	c.slot.mu.Lock()
	defer c.slot.mu.Unlock()
	if c.slot.actor == (audit.Actor{}) {
		return audit.Actor{}, false
	}
	return c.slot.actor, true
}

// SetAuditActor stashes the actor that completed authentication mid-request, so the
// post-handler audit row names it — and the tenant it belongs to. No-op when the
// context was not wrapped by the audit middleware.
//
// The Type is forced to ActorTypeUser: this slot exists for the public routes where
// a HUMAN authenticated, and a caller that wants to claim another actor type has
// audit.WithActor for the authenticated path, where the type comes from verified
// claims rather than from the caller's word.
func SetAuditActor(ctx context.Context, actor audit.Actor) {
	slot, ok := ctx.Value(actorCaptureKey{}).(*actorSlot)
	if !ok || slot == nil {
		return
	}
	actor.Type = audit.ActorTypeUser
	slot.mu.Lock()
	slot.actor = actor
	slot.mu.Unlock()
}

// AuditActorFromContext returns the actor stashed by SetAuditActor, and whether one
// was stashed. Used by the audit middleware after the handler has returned (the
// public-route case where the request was anonymous at entry but identified by the
// time it handed back). Handlers behind RequireAuth should keep using GetUserID and
// the claims.
func AuditActorFromContext(ctx context.Context) (audit.Actor, bool) {
	slot, ok := ctx.Value(actorCaptureKey{}).(*actorSlot)
	if !ok || slot == nil {
		return audit.Actor{}, false
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	return slot.actor, slot.actor != (audit.Actor{})
}

// RequireAuth returns middleware that enforces an
// `Authorization: Bearer <token>` header, verifies the token, and
// stashes the subject (user id), the typed claims, and an audit Actor
// in the request context for downstream handlers and service-layer
// emissions. Any failure writes a 401 with code UNAUTHENTICATED.
//
// The middleware does NOT hit any database. It only validates the
// token; loading the user is the service layer's job.
func RequireAuth(jwt *crypto.JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, err := bearerToken(r.Header.Get("Authorization"))
			if err != nil {
				writeUnauthenticated(w, err.Error())
				return
			}
			// ParseAccess, not VerifyAccess: the tenant comparison belongs to
			// RequireTenant, which runs INSIDE this middleware and checks the
			// token's tid against the ROUTED tenant. RequireAuth cannot do it
			// — the route's tenant is not resolved yet at this point, and a
			// tenant taken from the token would be checking the token against
			// itself.
			claims, err := jwt.ParseAccess(tok)
			if err != nil {
				writeUnauthenticated(w, "invalid token")
				return
			}
			next.ServeHTTP(w, r.WithContext(decorateAuthed(r.Context(), claims)))
		})
	}
}

// decorateAuthed stashes the identity triple RequireAuth and
// RequireAuthWS share: user id, typed claims, and the audit Actor so
// service-layer emissions that go through audit.ActorFromContext
// inherit the authenticated user's id.
//
// The actor also carries the actor's HOME tenant as Actor.TenantID — a
// fact the signature vouches for and therefore safe to record before
// RequireTenant has run. For an ordinary token that is the token's
// `tid`. For an ENTERED token (identity.Core.EnterTenant: a platform
// admin acting inside a customer's tenant) it is `htid`, the tenant the
// admin is stored in, not the tenant they entered: a row written while
// entered must say who acted and where they came from.
//
// It is the home tenant and nothing more: it is NOT the row's scope
// (audit.Event.TenantID), which only the routed tenant may fill,
// because a scope read out of the credential would let the token
// decide whose log its own actions land in. A token with no `tid`
// leaves the field "", so the single-tenant actor is the one this
// function always stashed.
func decorateAuthed(ctx context.Context, claims *crypto.AccessClaims) context.Context {
	userID := claims.Subject
	ctx = context.WithValue(ctx, userIDKey{}, userID)
	ctx = context.WithValue(ctx, accessClaimsKey{}, claims)
	// ActorUserID, not Subject: on an impersonated token the subject is the
	// customer's user and the actor is the human behind them. Every audit row
	// this request produces must name the human, or the record blames the wrong
	// person while looking complete.
	return audit.WithActor(ctx, audit.Actor{
		Type:     audit.ActorTypeUser,
		UserID:   claims.ActorUserID(),
		TenantID: claims.ActorTenantID(),
	})
}

// bearerToken extracts the raw token from an Authorization header
// value. Returns a plain error whose message is safe for direct
// exposure.
func bearerToken(header string) (string, error) {
	if header == "" {
		return "", errMissingAuthHeader
	}
	const prefix = "Bearer "
	// Case-insensitive scheme match per RFC 6750, then trim the token.
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", errMalformedAuthHeader
	}
	tok := strings.TrimSpace(header[len(prefix):])
	if tok == "" {
		return "", errEmptyBearerToken
	}
	return tok, nil
}

// writeUnauthenticated writes the canonical 401 JSON envelope.
func writeUnauthenticated(w http.ResponseWriter, msg string) {
	err := espressofw.ErrUnauthorized(msg).WithCode("UNAUTHENTICATED")
	_ = err.WriteResponse(w)
}

// Package-local sentinels so the error messages stay deterministic.
var (
	errMissingAuthHeader   = &staticErr{"missing Authorization header"}
	errMalformedAuthHeader = &staticErr{"Authorization header must be 'Bearer <token>'"}
	errEmptyBearerToken    = &staticErr{"bearer token is empty"}
)

type staticErr struct{ msg string }

func (e *staticErr) Error() string { return e.msg }

// ContextWithAccessClaims returns a context carrying claims exactly
// as RequireAuth stashes them. Test support for exercising fresh-auth
// gates without minting real JWTs (a typed-nil pointer is stored
// as-is so fail-closed paths can be pinned). Production code must
// never call this.
func ContextWithAccessClaims(ctx context.Context, claims *crypto.AccessClaims) context.Context {
	return context.WithValue(ctx, accessClaimsKey{}, claims)
}
