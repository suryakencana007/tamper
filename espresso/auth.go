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

// userIDCaptureKey lets the audit middleware learn an authenticated
// user_id AFTER the handler runs. Without this slot, public routes
// like /login carry no user_id into the audit middleware, so the
// login row ships with an empty actor even when the login succeeded.
type userIDCaptureKey struct{}

// userIDSlot is the mutable slot the audit middleware installs at
// request entry. Handlers that complete authentication mid-request
// write the just-authenticated user id via SetUserID; the audit
// middleware reads it back when building the audit.Event actor.
//
// Mutex-guarded because the slot lives across the full request
// lifetime and a handler may legitimately call SetUserID from a
// goroutine it spawns.
type userIDSlot struct {
	mu     sync.Mutex
	userID string
}

// WithUserIDCapture returns a derived context carrying a fresh
// user-id slot, plus a reader for the captured value once the handler
// has returned. The audit-mutation middleware calls this exactly once
// per request.
func WithUserIDCapture(ctx context.Context) (context.Context, *UserIDCapture) {
	slot := &userIDSlot{}
	return context.WithValue(ctx, userIDCaptureKey{}, slot), &UserIDCapture{slot: slot}
}

// UserIDCapture is the middleware-side handle onto the capture slot.
type UserIDCapture struct{ slot *userIDSlot }

// Value returns the captured user id, or "" when nothing was stashed.
func (c *UserIDCapture) Value() string {
	if c == nil || c.slot == nil {
		return ""
	}
	c.slot.mu.Lock()
	defer c.slot.mu.Unlock()
	return c.slot.userID
}

// SetUserID stashes userID into the slot installed by
// WithUserIDCapture. Used by handlers that complete authentication
// mid-request (login, TOTP verify) so the post-handler audit row
// carries the right actor. No-op when the context wasn't wrapped.
func SetUserID(ctx context.Context, userID string) {
	if slot, ok := ctx.Value(userIDCaptureKey{}).(*userIDSlot); ok && slot != nil {
		slot.mu.Lock()
		slot.userID = userID
		slot.mu.Unlock()
	}
}

// UserIDFromContext returns the user_id stashed by SetUserID, or ""
// when nothing was stashed. Used by the audit middleware after the
// handler has returned (the public-route case where the user was
// anonymous at request entry but identified by the time the handler
// returns). Handlers behind RequireAuth should keep using GetUserID.
func UserIDFromContext(ctx context.Context) string {
	if slot, ok := ctx.Value(userIDCaptureKey{}).(*userIDSlot); ok && slot != nil {
		slot.mu.Lock()
		defer slot.mu.Unlock()
		return slot.userID
	}
	return ""
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
func decorateAuthed(ctx context.Context, claims *crypto.AccessClaims) context.Context {
	userID := claims.Subject
	ctx = context.WithValue(ctx, userIDKey{}, userID)
	ctx = context.WithValue(ctx, accessClaimsKey{}, claims)
	return audit.WithActor(ctx, audit.Actor{
		Type:   audit.ActorTypeUser,
		UserID: userID,
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

// ContextWithUserID returns a context carrying userID exactly as
// RequireAuth stashes it (id only — no claims, no audit actor). Test
// support for exercising handlers and middleware that read GetUserID
// without minting real JWTs; production code must never call this —
// authentication is RequireAuth's job.
func ContextWithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey{}, userID)
}

// ContextWithAccessClaims returns a context carrying claims exactly
// as RequireAuth stashes them. Test support for exercising fresh-auth
// gates without minting real JWTs (a typed-nil pointer is stored
// as-is so fail-closed paths can be pinned). Production code must
// never call this.
func ContextWithAccessClaims(ctx context.Context, claims *crypto.AccessClaims) context.Context {
	return context.WithValue(ctx, accessClaimsKey{}, claims)
}
