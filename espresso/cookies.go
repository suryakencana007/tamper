package espresso

import (
	"context"
	"net/http"
)

// namedCookieKey scopes stashed cookie values by a caller-chosen slot
// name so several ReadNamedCookie middlewares can coexist on one
// chain (refresh token + OIDC state + SAML state).
type namedCookieKey string

// ReadNamedCookie returns middleware that reads the named cookie from
// the request and stashes its value in the request context under
// slot. Handlers whose typed extractors don't surface *http.Request
// (Espresso's JSON[T] / Form[T]) pick the value up via
// NamedCookieValue.
//
// Non-blocking: a missing or empty cookie still passes the request
// through; the value resolves to ("", false) and the handler decides
// the failure shape (401 for a missing refresh token, invalid-state
// for a missing state cookie, non-step-up for a missing SAML state).
func ReadNamedCookie(slot, cookieName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			val := ""
			if c, err := r.Cookie(cookieName); err == nil {
				val = c.Value
			}
			ctx := context.WithValue(r.Context(), namedCookieKey(slot), val)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// NamedCookieValue returns the cookie value stashed by
// ReadNamedCookie under slot. Returns ("", false) when the middleware
// wasn't in the chain or the cookie was absent/empty — handlers treat
// both the same way.
func NamedCookieValue(ctx context.Context, slot string) (string, bool) {
	v, ok := ctx.Value(namedCookieKey(slot)).(string)
	return v, ok && v != ""
}
