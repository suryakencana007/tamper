package espresso

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ETag emission + If-Match precondition helpers (RFC 7232 §2.3, RFC 7644
// §3.14). Lifted from Barista's SCIM handler in Phase 4e-3 — generic RFC
// 7232 mechanics with no SCIM-specific coupling, so they live in the
// transport layer for any resource with a version timestamp. The
// SCIM-writer-coupled helpers (a JSON-with-ETag writer, the 412 envelope)
// stay app-side; they compose these + the app's own response writers.
//
// Derivation — Option B (timestamp): ResourceETag computes
// W/"<unix-nanos>" from a resource's updated_at. Cheap under a
// single-writer control plane; a content-hash shape can replace it purely
// inside ResourceETag since CheckIfMatch compares opaques byte-for-byte
// after stripping W/.
//
// All emitted ETags are WEAK (W/ prefix). SCIM clients (Azure AD, Okta)
// send weak ETags on If-Match by default; the comparison strips W/ and
// compares the opaque per RFC 7232 §2.3.2 "weak comparison". Strong
// comparison would reject every IdP-issued conditional request.

// etagWeakPrefix is the RFC 7232 §2.3 weak-validator prefix.
const etagWeakPrefix = `W/`

// ResourceETag returns the weak ETag for a resource whose version
// timestamp is t: W/"<unix-nanos>". A zero t returns "" — the caller then
// emits no ETag header.
func ResourceETag(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return fmt.Sprintf(`%s"%d"`, etagWeakPrefix, t.UTC().UnixNano())
}

// WriteETagHeader stamps the ETag header on w. No-op when value is empty.
func WriteETagHeader(w http.ResponseWriter, value string) {
	if value == "" {
		return
	}
	w.Header().Set("ETag", value)
}

// CheckIfMatch reads If-Match from r and compares it against currentETag.
// Returns ok=true on a match OR when If-Match is absent (SCIM clients may
// skip the precondition, RFC 7644 §3.14). The "*" wildcard (RFC 7232
// §3.1) matches any current resource. Multi-value If-Match is honored:
// any opaque in the comma-separated list matching currentETag suffices.
// Comparison is WEAK (RFC 7232 §2.3.2). On mismatch returns ok=false plus
// (412, "PRECONDITION_FAILED") for the caller to render.
func CheckIfMatch(r *http.Request, currentETag string) (ok bool, status int, code string) {
	ifMatch := strings.TrimSpace(r.Header.Get("If-Match"))
	if ifMatch == "" {
		return true, 0, ""
	}
	if ifMatch == "*" {
		return true, 0, ""
	}
	want := NormalizeETag(currentETag)
	for _, part := range strings.Split(ifMatch, ",") {
		if NormalizeETag(part) == want {
			return true, 0, ""
		}
	}
	return false, http.StatusPreconditionFailed, "PRECONDITION_FAILED"
}

// NormalizeETag strips surrounding whitespace + the weak-validator W/
// prefix (tolerating a lowercase w/) so two weak ETags with the same
// opaque compare equal. The opaque's quotes are preserved.
func NormalizeETag(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, etagWeakPrefix)
	s = strings.TrimPrefix(s, "w/")
	return s
}
