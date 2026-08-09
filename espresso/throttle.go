package espresso

import (
	"math"
	"net/http"
	"strconv"
	"time"

	espressofw "github.com/suryakencana007/espresso/v2"

	"github.com/suryakencana007/tamper/crypto"
)

// Slice 7k-1 — the HTTP half of rate limiting.
//
// identity throttles the credential calls it owns; this gates whole
// routes, which is what the SCIM surface needs. A SCIM client is a
// machine on a loop: it does not get tired, it does not back off unless
// told to, and one misconfigured connector will replay a full directory
// sync every thirty seconds until someone notices the bill.

// ThrottledCode is the wire-stable code a client receives when a route
// refuses it for rate. Stable because a client branches on it to back
// off rather than to retry immediately.
const ThrottledCode = "TOO_MANY_REQUESTS"

type throttleConfig struct {
	deny func(w http.ResponseWriter, r *http.Request, retryAfter time.Duration)
}

// ThrottleOption configures Throttled.
type ThrottleOption func(*throttleConfig)

// WithThrottleDenyWriter replaces the deny renderer. The SCIM surface
// supplies WriteSCIMThrottled, because a SCIM client fail-closes on an
// app-branded body.
//
// Whatever it writes MUST be a 429 and MUST set Retry-After. A limiter
// that refuses without saying for how long trains clients to hot-loop
// on the refusal, which costs more than the traffic it was blocking.
func WithThrottleDenyWriter(fn func(w http.ResponseWriter, r *http.Request, retryAfter time.Duration)) ThrottleOption {
	return func(cfg *throttleConfig) {
		if fn != nil {
			cfg.deny = fn
		}
	}
}

// Throttled returns middleware that refuses a route when the limiter
// says the caller has had enough.
//
// key composes the bucket key from the request, and it is explicit for
// the same reason RequireEntitlement's resolver is: the surfaces carry
// their identity differently. SCIM sits behind RequireServiceAccount and
// should key on the principal's tenant (ThrottleKeyByServiceAccount);
// a pre-auth route has only the address (ThrottleKeyByRemoteAddr, with
// the caveat documented there). Guessing would mean silently keying on
// "" for every request on the surface that used the other one — one
// global bucket, and the first busy tenant locks out everyone else.
//
// THE GATE RUNS BEFORE THE HANDLER, which is what keeps it from
// disclosing anything: the key is composed from what the caller
// presented, never from what a store returned, so a 429 is identical
// whether the addressed user, group or tenant exists. Compose a key from
// a lookup result and the limiter becomes an enumeration oracle.
//
// Panics if throttle or key is nil. A gate that cannot decide is a gate
// that permits everything, and that fails at construction rather than as
// traffic that looks ordinary — the same posture as RequireEntitlement.
// A deployment that does not want limiting omits the middleware; it does
// not pass nil.
func Throttled(throttle crypto.Throttle, key func(*http.Request) string, opts ...ThrottleOption) func(http.Handler) http.Handler {
	if throttle == nil {
		panic("tamper/espresso: Throttled requires a crypto.Throttle — " +
			"a nil limiter would be a gate that permits everything")
	}
	if key == nil {
		panic("tamper/espresso: Throttled requires a key function — " +
			"without one every request shares the empty key, so the first " +
			"busy caller locks out every other")
	}
	cfg := throttleConfig{deny: writeThrottled}
	for _, o := range opts {
		o(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ok, retryAfter := throttle.Allow(r.Context(), key(r))
			if !ok {
				cfg.deny(w, r, retryAfter)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ThrottleKeyByServiceAccount keys on the validated SCIM principal's
// tenant, so one customer's runaway connector cannot exhaust another's
// budget. The resolver to use behind RequireServiceAccount — and INSIDE
// it, not outside: run the limiter before the auth gate and there is no
// principal yet, so every request keys as unauthenticated and the
// per-tenant separation this function exists for silently disappears.
//
// The tenant is the dimension when there is one, deliberately in
// preference to the service account: two connectors belonging to one
// customer should share that customer's budget, because the budget is a
// property of the customer and not of how many tokens they minted.
//
// A principal with NO tenant is the single-tenant deployment (§ the ""
// path), and it keys on the service account instead. Not on one global
// bucket — that would put every authenticated connector in the same
// budget as the unauthenticated flood, and one busy sync would refuse
// every other. This is the case that is easy to get wrong by writing
// `!ok || p.TenantID == ""`, which reads as careful and quietly demotes
// every authenticated single-tenant caller to the anonymous bucket.
//
// An unauthenticated request resolves to a single shared bucket, which
// is deliberate: those requests are about to be rejected anyway, and
// giving them one collective budget is what stops an unauthenticated
// flood from being free. Behind RequireServiceAccount they never arrive
// at all, which is cheaper still.
func ThrottleKeyByServiceAccount(r *http.Request) string {
	p, ok := GetPrincipal(r.Context())
	if !ok {
		return "scim:unauthenticated"
	}
	if p.TenantID == "" {
		return "scim:sa:" + p.ID
	}
	return "scim:tenant:" + p.TenantID
}

// ThrottleKeyByRoutedTenant keys on the tenant RequireTenant pinned —
// the resolver for gated pre-auth routes.
func ThrottleKeyByRoutedTenant(r *http.Request) string {
	tenantID, ok := TenantFromContext(r.Context())
	if !ok || !tenantID.Valid() {
		return "tenant:unresolved"
	}
	// Single is a real bucket, not an absent one: a single-tenant
	// deployment throttles under one key rather than "unresolved".
	return "tenant:" + tenantID.String()
}

// ThrottleKeyByRemoteAddr keys on r.RemoteAddr.
//
// PROVIDED, NOT RECOMMENDED, and the caveat is the point. RemoteAddr is
// the peer's address, which behind a load balancer or ingress is the
// PROXY — every request in the fleet shares one bucket and the limiter
// becomes a global kill switch. It is also trivially rotated on IPv6,
// where a single customer often holds a /64.
//
// A deployment that means "the client's address" reads its own trusted
// forwarding header, having decided which hops it trusts. tamper will
// not read X-Forwarded-For for you: honouring an untrusted one lets an
// attacker pick a fresh bucket per request by editing a header.
func ThrottleKeyByRemoteAddr(r *http.Request) string {
	return "addr:" + r.RemoteAddr
}

// writeThrottled is the default 429 renderer.
func writeThrottled(w http.ResponseWriter, _ *http.Request, retryAfter time.Duration) {
	setRetryAfter(w, retryAfter)
	err := espressofw.ErrTooManyRequests("too many requests").WithCode(ThrottledCode)
	_ = err.WriteResponse(w)
}

// WriteSCIMThrottled is the SCIM-shaped deny writer, for use with
// WithThrottleDenyWriter on the SCIM surface. Same status and the same
// meaning, in the envelope RFC 7644 §3.12 mandates.
func WriteSCIMThrottled(w http.ResponseWriter, _ *http.Request, retryAfter time.Duration) {
	setRetryAfter(w, retryAfter)
	WriteSCIMErrorTyped(w, http.StatusTooManyRequests, "too many requests", "")
}

// setRetryAfter writes the RFC 9110 §10.2.3 delay-seconds form.
//
// Rounded UP: rounding down would name an instant at which the caller is
// still refused, and a client that obeys it to the second gets a second
// 429 and learns to ignore the header. A sub-second wait becomes 1 for
// the same reason — the header has no finer unit, and 0 reads as "retry
// now", which is the hot loop this exists to prevent.
func setRetryAfter(w http.ResponseWriter, retryAfter time.Duration) {
	secs := int64(1)
	if retryAfter > time.Second {
		secs = int64(math.Ceil(retryAfter.Seconds()))
	}
	w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
}
