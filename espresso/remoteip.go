package espresso

import (
	"context"
	"net/http"
	"strings"
)

// remoteIPKey is the context key for the source-IP value stashed by
// RemoteIP.
type remoteIPKey struct{}

// IPExtractor picks the source IP for a request. The default
// (IPFromRequest) trusts X-Forwarded-For's first entry when present
// and falls back to r.RemoteAddr with the port stripped. Apps with a
// trusted-proxy policy inject their own.
type IPExtractor func(*http.Request) string

// RemoteIP wraps a handler so the source IP is available via
// GetRemoteIP(ctx). Used by public-route handlers that need the
// source IP for audit and can't reach http.Request through a typed
// extractor. extract may be nil (IPFromRequest).
func RemoteIP(extract IPExtractor) func(http.Handler) http.Handler {
	if extract == nil {
		extract = IPFromRequest
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), remoteIPKey{}, extract(r))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetRemoteIP returns the source IP stashed by RemoteIP, or "" when
// the middleware wasn't applied.
func GetRemoteIP(ctx context.Context) string {
	if v, ok := ctx.Value(remoteIPKey{}).(string); ok {
		return v
	}
	return ""
}

// IPFromRequest is the default IPExtractor: X-Forwarded-For's first
// entry when the header is set (most installs sit behind a reverse
// proxy), else r.RemoteAddr with the port stripped.
//
// No trusted-proxy enforcement here — source IP is best-effort
// attribution for audit + triage, not an integrity claim (the audit
// chain is the integrity proof). Apps that need stricter policy
// inject their own IPExtractor.
func IPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	addr := r.RemoteAddr
	if i := strings.LastIndexByte(addr, ':'); i > 0 {
		return addr[:i]
	}
	return addr
}
