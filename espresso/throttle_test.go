package espresso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/crypto"
)

// Slice 7k-1 — the HTTP half.

// gateThrottle answers a fixed verdict and records the keys it saw.
type gateThrottle struct {
	mu     sync.Mutex
	keys   []string
	refuse bool
	after  time.Duration
}

var _ crypto.Throttle = (*gateThrottle)(nil)

func (s *gateThrottle) Allow(_ context.Context, key string) (bool, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, key)
	return !s.refuse, s.after
}

func (s *gateThrottle) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.keys...)
}

// throttledRoute wraps a handler that records whether it ran.
func throttledRoute(t crypto.Throttle, key func(*http.Request) string, ran *bool,
	opts ...ThrottleOption,
) http.Handler {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*ran = true
		w.WriteHeader(http.StatusOK)
	})
	return Throttled(t, key, opts...)(inner)
}

func callPath(h http.Handler, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// --- the refusal ------------------------------------------------------

func TestThrottled_RefusesWith429AndRetryAfter(t *testing.T) {
	st := &gateThrottle{refuse: true, after: 90 * time.Second}
	var ran bool
	rec := callPath(throttledRoute(st, ThrottleKeyByRemoteAddr, &ran), "/scim/v2/Users")

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if ran {
		t.Error("the handler ran behind a refused gate")
	}
	if got := rec.Header().Get("Retry-After"); got != "90" {
		t.Errorf("Retry-After = %q, want %q; a refusal that names no wait trains "+
			"clients to hot-loop on it", got, "90")
	}
	if body := rec.Body.String(); !strings.Contains(body, ThrottledCode) {
		t.Errorf("deny body does not carry the stable code %q: %s", ThrottledCode, body)
	}
}

func TestThrottled_AllowsWhenPermitted(t *testing.T) {
	st := &gateThrottle{}
	var ran bool
	rec := callPath(throttledRoute(st, ThrottleKeyByRemoteAddr, &ran), "/scim/v2/Users")
	if rec.Code != http.StatusOK || !ran {
		t.Errorf("status = %d ran = %v, want 200/true — the gate refuses everything",
			rec.Code, ran)
	}
	if got := rec.Header().Get("Retry-After"); got != "" {
		t.Errorf("Retry-After = %q on an ALLOWED request; the header leaks the "+
			"limiter's state to callers it did not refuse", got)
	}
}

// TestThrottled_RetryAfterRoundsUp: rounding down names an instant at
// which the caller is still refused, so a client that obeys it to the
// second gets a second 429 and learns to ignore the header. Sub-second
// becomes 1, never 0 — 0 reads as "retry now".
func TestThrottled_RetryAfterRoundsUp(t *testing.T) {
	for _, tc := range []struct {
		after time.Duration
		want  string
	}{
		{0, "1"},
		{time.Millisecond, "1"},
		{999 * time.Millisecond, "1"},
		{time.Second, "1"},
		{1500 * time.Millisecond, "2"},
		{2 * time.Second, "2"},
		{2100 * time.Millisecond, "3"},
	} {
		t.Run(tc.after.String(), func(t *testing.T) {
			st := &gateThrottle{refuse: true, after: tc.after}
			var ran bool
			rec := callPath(throttledRoute(st, ThrottleKeyByRemoteAddr, &ran), "/x")
			if got := rec.Header().Get("Retry-After"); got != tc.want {
				t.Errorf("Retry-After for %v = %q, want %q", tc.after, got, tc.want)
			}
		})
	}
}

// --- the disclosure invariant at the HTTP surface ----------------------

// TestThrottled_RefusalIsIdenticalForExistingAndMissingResources. The
// gate runs before the handler, so a 429 cannot vary by what the handler
// would have found. Asserted on the whole response — status, headers and
// body — because "identical" is the property, not "similar".
//
// The inner handler here deliberately answers differently per path. If
// the gate ever consulted it, or were moved below it, the two recorded
// responses would diverge and this goes red.
func TestThrottled_RefusalIsIdenticalForExistingAndMissingResources(t *testing.T) {
	st := &gateThrottle{refuse: true, after: 30 * time.Second}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/real-user") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"real-user"}`))
			return
		}
		WriteSCIMErrorTyped(w, http.StatusNotFound, "not found", "")
	})
	h := Throttled(st, ThrottleKeyByRemoteAddr)(inner)

	hit := callPath(h, "/scim/v2/Users/real-user")
	miss := callPath(h, "/scim/v2/Users/no-such-user")

	if hit.Code != miss.Code {
		t.Errorf("status differs: existing %d missing %d", hit.Code, miss.Code)
	}
	if hit.Body.String() != miss.Body.String() {
		t.Errorf("body differs between an existing and a missing resource:\n"+
			"existing: %s\n missing: %s\nthe throttled response discloses existence",
			hit.Body.String(), miss.Body.String())
	}
	for _, hdr := range []string{"Retry-After", "Content-Type"} {
		if hit.Header().Get(hdr) != miss.Header().Get(hdr) {
			t.Errorf("%s differs: existing %q missing %q",
				hdr, hit.Header().Get(hdr), miss.Header().Get(hdr))
		}
	}
	if hit.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 — the gate did not refuse and this test "+
			"compared two handler responses", hit.Code)
	}
}

// --- key composition ---------------------------------------------------

// TestThrottled_ServiceAccountKeySeparatesTenants: one customer's
// runaway connector must not exhaust another's budget. A key function
// that ignored the principal would put every tenant in one bucket, and
// the busiest customer would lock out the rest.
func TestThrottled_ServiceAccountKeySeparatesTenants(t *testing.T) {
	st := &gateThrottle{}
	h := Throttled(st, ThrottleKeyByServiceAccount)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	for _, tenantID := range []string{"acme", "globex"} {
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		req = req.WithContext(context.WithValue(req.Context(), principalKey{},
			Principal{ID: "svc-1", TenantID: tenantID}))
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	keys := st.seen()
	if len(keys) != 2 {
		t.Fatalf("throttle consulted %d time(s), want 2: %v", len(keys), keys)
	}
	if keys[0] == keys[1] {
		t.Errorf("both tenants shared the bucket %q; one customer's traffic limits "+
			"another's", keys[0])
	}
	for _, k := range keys {
		if !strings.Contains(k, "tenant:") {
			t.Errorf("key %q does not carry the tenant", k)
		}
	}
}

// TestThrottled_SingleTenantPrincipalKeysOnTheServiceAccount covers the
// "" path, which is the case a plausible-looking `!ok || p.TenantID ==
// ""` guard gets wrong: a single-tenant deployment has an authenticated
// principal with no tenant, and demoting it to the anonymous bucket puts
// every real connector in the same budget as an unauthenticated flood.
func TestThrottled_SingleTenantPrincipalKeysOnTheServiceAccount(t *testing.T) {
	st := &gateThrottle{}
	h := Throttled(st, ThrottleKeyByServiceAccount)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	for _, said := range []string{"okta-connector", "azure-connector"} {
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		req = req.WithContext(context.WithValue(req.Context(), principalKey{},
			Principal{ID: said})) // no tenant: the single-tenant shape
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	callPath(h, "/scim/v2/Users") // no principal at all

	keys := st.seen()
	if len(keys) != 3 {
		t.Fatalf("throttle consulted %d time(s), want 3: %v", len(keys), keys)
	}
	if keys[0] == keys[1] {
		t.Errorf("two distinct service accounts shared the bucket %q", keys[0])
	}
	for i, k := range keys[:2] {
		if k == keys[2] {
			t.Errorf("authenticated single-tenant principal %d keyed as unauthenticated "+
				"(%q); every real connector shares the anonymous budget", i, k)
		}
	}
}

// TestThrottled_UnauthenticatedShareOneBucket: requests with no
// principal get a single collective budget rather than a per-request
// free pass. Those requests are about to be rejected anyway; giving them
// one shared bucket is what stops an unauthenticated flood being free.
func TestThrottled_UnauthenticatedShareOneBucket(t *testing.T) {
	st := &gateThrottle{}
	h := Throttled(st, ThrottleKeyByServiceAccount)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	callPath(h, "/scim/v2/Users")
	callPath(h, "/scim/v2/Groups")

	keys := st.seen()
	if len(keys) != 2 {
		t.Fatalf("throttle consulted %d time(s), want 2: %v", len(keys), keys)
	}
	if keys[0] != keys[1] {
		t.Errorf("unauthenticated requests got different buckets (%q, %q); an "+
			"unauthenticated flood is unlimited", keys[0], keys[1])
	}
}

// TestThrottled_RoutedTenantKeyFallsBackToOneBucket: an unresolved
// tenant must not mean an unlimited one.
func TestThrottled_RoutedTenantKeyFallsBackToOneBucket(t *testing.T) {
	st := &gateThrottle{}
	h := Throttled(st, ThrottleKeyByRoutedTenant)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	callPath(h, "/api/auth/oidc/start/okta")

	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/start/okta", nil)
	req = req.WithContext(context.WithValue(req.Context(), tenantCtxKey{}, "acme"))
	h.ServeHTTP(httptest.NewRecorder(), req)

	keys := st.seen()
	if len(keys) != 2 {
		t.Fatalf("throttle consulted %d time(s), want 2: %v", len(keys), keys)
	}
	if keys[0] == keys[1] {
		t.Errorf("an unresolved tenant shared a bucket with a resolved one: %q", keys[0])
	}
	if !strings.Contains(keys[1], "acme") {
		t.Errorf("resolved key %q does not carry the tenant", keys[1])
	}
}

// --- the SCIM envelope -------------------------------------------------

// TestThrottled_SCIMDenyWriterUsesTheRFCEnvelope: a SCIM client
// fail-closes on an app-branded body, so the refusal must be §3.12
// shaped — same status, same meaning, different envelope. The same
// discipline WriteSCIMEntitlementDenied follows for 403.
func TestThrottled_SCIMDenyWriterUsesTheRFCEnvelope(t *testing.T) {
	st := &gateThrottle{refuse: true, after: 5 * time.Second}
	var ran bool
	h := throttledRoute(st, ThrottleKeyByServiceAccount, &ran,
		WithThrottleDenyWriter(WriteSCIMThrottled))

	rec := callPath(h, "/scim/v2/Users")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/scim+json" {
		t.Errorf("content-type = %q, want application/scim+json", ct)
	}
	if got := rec.Header().Get("Retry-After"); got != "5" {
		t.Errorf("Retry-After = %q, want %q — the SCIM writer dropped the header",
			got, "5")
	}
	if body := rec.Body.String(); !strings.Contains(body, SchemaError) {
		t.Errorf("body is not a SCIM error envelope: %s", body)
	}
}

// --- construction fails loudly -----------------------------------------

func TestThrottled_NilThrottlePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Throttled(nil throttle) did not panic; it would permit everything")
		}
	}()
	_ = Throttled(nil, ThrottleKeyByRemoteAddr)
}

func TestThrottled_NilKeyPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Throttled(nil key) did not panic; every request would share the " +
				"empty key and the first busy caller would lock out every other")
		}
	}()
	_ = Throttled(&gateThrottle{}, nil)
}
