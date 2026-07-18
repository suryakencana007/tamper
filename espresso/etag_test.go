package espresso

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestResourceETag(t *testing.T) {
	ts := time.Unix(0, 1_700_000_000_123_456_789).UTC()
	if got, want := ResourceETag(ts), `W/"1700000000123456789"`; got != want {
		t.Errorf("ResourceETag = %q, want %q", got, want)
	}
	if got := ResourceETag(time.Time{}); got != "" {
		t.Errorf("ResourceETag(zero) = %q, want \"\" (no header)", got)
	}
}

func TestNormalizeETag(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`W/"abc"`, `"abc"`},
		{`w/"abc"`, `"abc"`},
		{`"abc"`, `"abc"`},
		{` W/"abc" `, `"abc"`},
		{`W/"123"`, `"123"`},
	} {
		if got := NormalizeETag(c.in); got != c.want {
			t.Errorf("NormalizeETag(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestCheckIfMatch covers the full matrix — the app previously only
// pinned the wildcard case; the lift is the moment to make the mechanic's
// own test exhaustive.
func TestCheckIfMatch(t *testing.T) {
	const cur = `W/"v1"`
	ifMatch := func(v string) *http.Request {
		r := httptest.NewRequest(http.MethodPut, "/x", nil)
		if v != "" {
			r.Header.Set("If-Match", v)
		}
		return r
	}

	// Absent → passes (SCIM clients may skip the precondition).
	if ok, _, _ := CheckIfMatch(ifMatch(""), cur); !ok {
		t.Error("absent If-Match should pass")
	}
	// Wildcard → passes.
	if ok, _, _ := CheckIfMatch(ifMatch("*"), cur); !ok {
		t.Error("If-Match: * should pass")
	}
	// Weak-vs-weak exact opaque → passes.
	if ok, _, _ := CheckIfMatch(ifMatch(`W/"v1"`), cur); !ok {
		t.Error("matching weak validator should pass")
	}
	// Strong client tag vs weak current, same opaque → weak comparison passes.
	if ok, _, _ := CheckIfMatch(ifMatch(`"v1"`), cur); !ok {
		t.Error("weak comparison should ignore the W/ prefix")
	}
	// Multi-value list, one matches → passes.
	if ok, _, _ := CheckIfMatch(ifMatch(`"v0", W/"v1"`), cur); !ok {
		t.Error("any member of a multi-value If-Match should pass")
	}
	// Mismatch → 412 PRECONDITION_FAILED.
	ok, status, code := CheckIfMatch(ifMatch(`W/"stale"`), cur)
	if ok || status != http.StatusPreconditionFailed || code != "PRECONDITION_FAILED" {
		t.Errorf("stale If-Match = (ok=%v, status=%d, code=%q), want (false, 412, PRECONDITION_FAILED)", ok, status, code)
	}
}
