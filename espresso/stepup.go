// Step-up (fresh-auth) gate for the Tamper Espresso adapter.
//
// Step-up authentication gate. Reads the typed AccessClaims stashed
// by RequireAuth + fails-closed when the calling JWT's auth_time is
// older than maxAge OR the JWT's acr is not in the acrValues set.
// Returns STEP_UP_REQUIRED 401 with a structured envelope the SPA's
// fetcher.ts catches + drives the re-auth modal off of.
//
// Composes with RequireAuth — RequireAuth MUST run first so the JWT
// is verified + AccessClaims are in context. RequireFreshAuth reads
// the claims; it does NOT re-verify the JWT.
//
// Decision 1 from v1.14 AGENTS.md: this is the authoritative,
// server-side fail-closed gate. The SPA polish layer (Task 02) reads
// the STEP_UP_REQUIRED envelope's `details` payload to drive the
// re-auth modal + retry the gated request. The wire-shape contract
// is pinned by stepup_test.go's JSON assertions — Espresso updates
// that change the *espresso.Error envelope shape MUST NOT change
// this envelope.
//
// v1.14 Sprint 1 Task 03 — RequireFreshAuthWithAudit is the audited
// sibling that emits `auth.stepup.denied` on every gate trip. Sprint 0's
// signature is preserved exactly so its tests don't change; the new
// audited variant shares the gate-evaluation helper to keep the security
// surface single-source-of-truth.

package espresso

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/suryakencana007/barista/packages/tamper/audit"
	"github.com/suryakencana007/barista/packages/tamper/crypto"
)

// StepUpErrorCode is the wire-stable error code the SPA's fetcher.ts
// catches to open the re-auth modal. Exported so handler tests +
// Sprint 1 / 2 surfaces don't sprinkle string literals.
const StepUpErrorCode = "STEP_UP_REQUIRED"

// StepUpDenialReason discriminates the rejection axes for the
// auth.stepup.denied audit event Sprint 1 Task 03 wires. Exported so
// the audit middleware can read it off the request context without
// duplicating the logic the gate already evaluated.
type StepUpDenialReason string

const (
	// StepUpDenyStaleAuth — JWT's auth_time was older than the
	// configured maxAge (or zero, in the pre-v1.14 legacy-JWT case).
	StepUpDenyStaleAuth StepUpDenialReason = "stale_auth_time"
	// StepUpDenyWeakACR — JWT's acr was not in the configured
	// acrValues set (local-password trying to satisfy a silver gate
	// is the canonical case).
	StepUpDenyWeakACR StepUpDenialReason = "weak_acr"
	// StepUpDenyMissingClaims — programmer-error path: RequireFreshAuth
	// ran without RequireAuth upstream.
	StepUpDenyMissingClaims StepUpDenialReason = "missing_claims"
)

// RequireFreshAuth fails-closed if the calling JWT's auth_time is
// older than maxAge OR if its acr is not in acrValues. Returns
// STEP_UP_REQUIRED HTTP 401 with a structured envelope the SPA's
// fetcher.ts catches + drives the re-auth modal off of.
//
// Composes with RequireAuth — RequireAuth must run first so the JWT
// is verified + AccessClaims are in context. RequireFreshAuth reads
// the claims; it does NOT re-verify the JWT.
//
// Panics on maxAge<=0 or empty acrValues — these are config-
// validation contracts. v1.14's config.Validate is expected to catch
// the invalid shape upstream; reaching this constructor with a bad
// value is a programmer error worth a clear panic.
//
// The `clock` test seam matches the v0.8 task 04 convention applied
// to JWTService: middleware uses time.Now in production; tests inject
// a fixed clock via the Testing handle so freshness assertions are
// race-safe + deterministic.
//
// v1.14 Sprint 1 Task 03 — this signature is pinned by Sprint 0 + its
// test suite. Routes that want denied-event audit emission wrap with
// RequireFreshAuthWithAudit instead; the audit-emitting variant shares
// the same gate-evaluation helper (evaluateStepUpGate) so the security
// surface stays single-source-of-truth.
func RequireFreshAuth(maxAge time.Duration, acrValues []string, opts ...StepUpOption) func(http.Handler) http.Handler {
	frozenACR, acrSet := prepareStepUpConfig(maxAge, acrValues)
	clock := stepUpClock(opts)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			now := clock().Unix()
			claims, _ := AccessClaimsFromContext(r.Context())
			if _, _, authTime, ok := evaluateStepUpGate(claims, maxAge, acrSet, now); !ok {
				writeStepUpError(w, maxAge, frozenACR, authTime, now)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireFreshAuthWithAudit is the audit-emitting sibling of
// RequireFreshAuth. Same gate; on rejection, emits `auth.stepup.denied`
// via auditLog before writing the canonical 401 envelope. The endpoint
// label is captured in the audit row's After payload so operators can
// audit-grep by which sensitive endpoint a given user tripped against.
//
// v1.14 Sprint 1 Task 03 — wired by server.go on the locked sensitive-
// endpoint inventory. Sprint 0's RequireFreshAuth stays the minimal
// primitive (no audit dependency); this variant carries the audit-row
// emission so the wire shape of Sprint 0's middleware stays unchanged.
//
// deniedAction is the app's audit action string for the denial rows —
// audit vocabulary is the app's contract (Barista passes
// auth.stepup.denied); tamper owns the emit point + payload shape.
//
// auditLog may be nil — emission is best-effort. A nil logger downgrades
// to RequireFreshAuth-equivalent behaviour (the gate still fails-closed,
// just without the audit-row side-effect). audit.NewNoopLogger() also
// works; either is safe in tests + audit-disabled deployments.
//
// endpoint is a stable label (e.g. "identity_provider.delete") that
// rides through to the audit row's After payload via the "endpoint"
// key. Keep these aligned with the chart-config endpoint-name surface
// (see deploy/helm/barista/values.yaml `auth.stepup.endpoints[]`).
//
// Panics on maxAge<=0 or empty acrValues, mirroring RequireFreshAuth.
func RequireFreshAuthWithAudit(maxAge time.Duration, acrValues []string, auditLog audit.Logger, deniedAction audit.Action, endpoint string, opts ...StepUpOption) func(http.Handler) http.Handler {
	frozenACR, acrSet := prepareStepUpConfig(maxAge, acrValues)
	clock := stepUpClock(opts)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			now := clock().Unix()
			claims, _ := AccessClaimsFromContext(r.Context())
			_, reason, authTime, ok := evaluateStepUpGate(claims, maxAge, acrSet, now)
			if !ok {
				emitStepUpDenied(r.Context(), auditLog, claims, r, deniedAction, endpoint, reason, maxAge, frozenACR, authTime, now)
				writeStepUpError(w, maxAge, frozenACR, authTime, now)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// prepareStepUpConfig validates the constructor inputs + materialises
// the frozen acrValues copy + the membership set used by the gate.
// Shared between RequireFreshAuth + RequireFreshAuthWithAudit so the
// panic contracts + the frozen-copy semantics stay aligned across both
// constructors.
func prepareStepUpConfig(maxAge time.Duration, acrValues []string) ([]string, map[string]struct{}) {
	if maxAge <= 0 {
		panic("middleware: RequireFreshAuth: maxAge must be positive — config.Validate should have caught this")
	}
	if len(acrValues) == 0 {
		panic("middleware: RequireFreshAuth: acrValues must be non-empty")
	}
	acrSet := make(map[string]struct{}, len(acrValues))
	for _, v := range acrValues {
		acrSet[v] = struct{}{}
	}
	// snapshot acrValues so the response envelope can echo the
	// configured set back to the SPA without leaking mutation.
	frozenACR := make([]string, len(acrValues))
	copy(frozenACR, acrValues)
	return frozenACR, acrSet
}

// evaluateStepUpGate is the freshness-gate decision shared between
// RequireFreshAuth + RequireFreshAuthWithAudit. Returns:
//
//   - ok=true when the claim satisfies the gate (handler should run).
//   - ok=false + reason in {StepUpDenyMissingClaims, StepUpDenyStaleAuth,
//     StepUpDenyWeakACR} when the gate fails.
//
// authTime is the claim's auth_time (or 0 when claims is nil) — the
// caller threads it through to the response envelope + the audit row
// so the SPA can render "your session is N seconds old" UX + operators
// can audit-grep on it.
func evaluateStepUpGate(claims *crypto.AccessClaims, maxAge time.Duration, acrSet map[string]struct{}, now int64) (currentACR string, reason StepUpDenialReason, authTime int64, ok bool) {
	if claims == nil {
		// Programmer error: RequireFreshAuth without RequireAuth upstream.
		return "", StepUpDenyMissingClaims, 0, false
	}
	authTime = claims.AuthTime
	maxAgeSec := int64(maxAge.Seconds())
	if authTime <= 0 || now-authTime > maxAgeSec {
		return claims.ACR, StepUpDenyStaleAuth, authTime, false
	}
	if _, hit := acrSet[claims.ACR]; !hit {
		return claims.ACR, StepUpDenyWeakACR, authTime, false
	}
	return claims.ACR, "", authTime, true
}

// emitStepUpDenied logs the `auth.stepup.denied` audit event. Best-
// effort — a nil auditLog is a silent no-op (callers in tests may not
// wire one). When emission fails (audit.Logger.Log error), the wire-
// response still gets written; the audit miss is a downstream-only
// observability gap.
//
// Wire shape: ResourceType=audit.ResourceAuth (the auth subsystem is
// the resource, not a user/IdP row); ResourceID="" (no specific entity);
// Action=audit.ActionStepUpDenied; After carries the discriminator +
// the requested-vs-current contrast so operators can audit-grep
// "why was this denied" without rejoining against config tables.
//
// The current_acr / current_auth_time fields are echoed verbatim from
// the calling JWT. requested_acr_values + requested_max_age_seconds
// echo the gate's configured policy. denial_reason is the
// StepUpDenialReason discriminator (stable string).
func emitStepUpDenied(ctx context.Context, auditLog audit.Logger, claims *crypto.AccessClaims, r *http.Request, deniedAction audit.Action, endpoint string, reason StepUpDenialReason, maxAge time.Duration, acrValues []string, authTime, now int64) {
	if auditLog == nil {
		return
	}
	actorID := ""
	currentACR := ""
	if claims != nil {
		actorID = claims.Subject
		currentACR = claims.ACR
	}
	// Resolve the actor through the standard captureActor path so the
	// audit row carries the same shape as every other actor-emitting
	// audit event (UserID + IP). EmailLookup is omitted here — the
	// middleware doesn't have AuthService access, and downstream audit
	// pages already enrich via ActorPill's user-id fallback.
	actor := audit.Actor{
		Type:   audit.ActorTypeUser,
		UserID: actorID,
		IP:     IPFromRequest(r),
	}
	after := stepUpDeniedAfter{
		Endpoint:               endpoint,
		Method:                 r.Method,
		Path:                   r.URL.Path,
		DenialReason:           string(reason),
		RequestedMaxAgeSeconds: int64(maxAge.Seconds()),
		RequestedACRValues:     acrValues,
		CurrentACR:             currentACR,
		CurrentAuthTime:        authTime,
		Now:                    now,
	}
	afterJSON, err := json.Marshal(after)
	if err != nil {
		// Defensive — stepUpDeniedAfter is plain struct; marshalling
		// can only fail if a future field carries an un-encodable value.
		// Drop the After payload rather than panic; the row still
		// records the action + actor.
		afterJSON = nil
	}
	event := audit.Event{
		ID:           uuid.NewString(),
		At:           time.Now().UTC(),
		Actor:        actor,
		Action:       deniedAction,
		ResourceType: audit.ResourceAuth,
		After:        afterJSON,
	}
	// audit.Logger.Log is goroutine-safe (per the v0.6 task 01 contract).
	// Errors are swallowed — the security gate has already fired; the
	// audit miss is a logged-elsewhere observability concern.
	_, _ = auditLog.Log(ctx, event)
}

// stepUpDeniedAfter is the JSON shape of the After payload on an
// auth.stepup.denied audit row. Field names are wire-stable —
// operators audit-grep these via the /admin/audit SPA + via the
// audit-digest scheduler. Mirror the STEP_UP_REQUIRED envelope's
// `details` shape where the fields overlap (max_age_seconds,
// current_auth_time, now) so the audit row + the 401 the SPA saw
// reconcile cleanly.
type stepUpDeniedAfter struct {
	Endpoint               string   `json:"endpoint"`
	Method                 string   `json:"method"`
	Path                   string   `json:"path"`
	DenialReason           string   `json:"denial_reason"`
	RequestedMaxAgeSeconds int64    `json:"requested_max_age_seconds"`
	RequestedACRValues     []string `json:"requested_acr_values"`
	CurrentACR             string   `json:"current_acr"`
	CurrentAuthTime        int64    `json:"current_auth_time"`
	Now                    int64    `json:"now"`
}

// StepUpOption configures a fresh-auth gate at construction.
type StepUpOption func(*stepUpConfig)

type stepUpConfig struct{ now func() time.Time }

// WithStepUpClock injects the gate's clock — per-INSTANCE, replacing
// the pre-4b package-global seam (one of the two sanctioned lift-time
// fixes: a global clock seam leaks test overrides across parallel
// tests and across unrelated gate instances).
func WithStepUpClock(now func() time.Time) StepUpOption {
	return func(c *stepUpConfig) {
		if now != nil {
			c.now = now
		}
	}
}

func stepUpClock(opts []StepUpOption) func() time.Time {
	c := &stepUpConfig{now: time.Now}
	for _, o := range opts {
		o(c)
	}
	return c.now
}

// writeStepUpError emits the canonical STEP_UP_REQUIRED envelope.
// Hand-written rather than routed through *espresso.Error.WithCode
// because the SPA's fetcher.ts pins the exact `details` payload
// shape — the JSON contract is the security boundary between
// middleware + SPA. Any future Espresso envelope-shape change MUST
// NOT alter this wire shape; the integration tests pin it.
//
// Wire shape (Decision 1 in v1.14 AGENTS.md):
//
//	{
//	  "error": {
//	    "code": "STEP_UP_REQUIRED",
//	    "message": "this operation requires fresh authentication",
//	    "details": {
//	      "max_age_seconds": <int>,
//	      "acr_values": [<urn>...],
//	      "current_auth_time": <unix-seconds-or-zero>,
//	      "now": <unix-seconds>
//	    }
//	  }
//	}
func writeStepUpError(w http.ResponseWriter, maxAge time.Duration, acrValues []string, authTime, now int64) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    StepUpErrorCode,
			"message": "this operation requires fresh authentication",
			"details": map[string]any{
				"max_age_seconds":   int64(maxAge.Seconds()),
				"acr_values":        acrValues,
				"current_auth_time": authTime,
				"now":               now,
			},
		},
	})
}
