All cross-checks verified. Producing the synthesis now.

# Tamper Phase 4 — `tamper/espresso` Transport Adapter: Design + Execution Plan

## 0. Cross-check results (report claims vs code)

All three subsystem reports were spot-verified against the tree. Every load-bearing claim held; conflicts between reports were terminological, not substantive.

**Verified (file:line confirmed):**

| Claim | Evidence |
|---|---|
| Middleware package never reads AppState | zero `appstate` imports under `apps/barista/internal/api/middleware/` (grep: no files) |
| Unexported context keys force atomic move | `userIDKey{}`/`accessClaimsKey{}`/`serviceAccountKey{}` at `middleware/auth.go:22,28,219` |
| Post-handler user-id capture slot (TD-AUDIT-07) | `WithUserIDCapture/SetUserID/UserIDFromContext`, `middleware/auth.go:69-131`, mutex-guarded |
| `RequireAuthWS` uses `jwt.Verify`, not `VerifyAccess` → no claims stash, WS can never compose with step-up | `middleware/auth_ws.go:49`; branded prefix `base64url.bearer.authorization.barista.io.` at `:27` |
| Refresh-cookie path is a mount-coupled literal | `const refreshCookiePath = "/api/auth"` at `handler/auth.go:62`; name default at `:31` |
| USER_INACTIVE 401-through-JSON-envelope workaround (Espresso errors can't carry cookies) | `handler/auth.go:390-401`, comment states the framework limitation explicitly |
| STEP_UP_REQUIRED envelope is hand-written + SPA-pinned; clock seam is a package global | `middleware/stepup.go:287-323` (pinned shape), `:285` (`var stepUpNow = time.Now`) |
| Step-up policy constants app-side, local-password deliberately excluded | `server.go:33-45` |
| `RequireServiceAccount` maps `service.ErrInvalidToken`→401 SCIM envelope, stashes `*domain.ServiceAccount` + `audit.ActorService` | `middleware/auth.go:262-284` — note middleware imports `internal/domain` + `internal/service` (`auth.go:17-18`), the one concrete-type leak in the package |
| SCIM lift blocked on concrete service types | `scim/router.go:28-35` takes `*service.AuthService`, `*service.GroupService` |
| crewjam leaks into the ACS handler | `handler/saml.go:15` (import), `:428` (`provider.SP.ParseResponse(httpReq, []string{})` — non-nil empty slice, TD-INFRA-32), `:782,:810` (`*crewjamsaml.Assertion` helpers) |
| `effectiveRoleForUser` takes `appstate.AppState` directly | `handler/auth.go:45` — the one handler-side AppState coupling the projection hook must break |

**Conflicts resolved:**

1. *Step-up policy constants:* middleware report says "config-hook", federation says "app-policy." Same substance — the **values** are Barista's security promise (app-policy), the **mechanism of delivery** is constructor config. Classified: config/hook, values owned by app.
2. *DTO shapes:* auth-routes says "adapter defaults" (config-hook), federation says "pinned SPA contracts." Both true → resolved in Decision 2 below: tamper ships Barista's exact current bytes as its versioned v1 defaults, so the Barista delegation PR is a wire no-op.
3. *TOTP pending-token verification ownership* (Barista `AuthService` verifies what `tamper/crypto` mints): real split, resolved in Decision 1 (the port absorbs it).
4. *Registration-vs-404 semantics* (SAML/SCIM conditionally register; OIDC always registers and 404s in-handler): confirmed at `server.go` — resolved in the mount API (explicit feature flags; disabled feature = route not mounted, matching the SAML convention, with OIDC's list route always mounted returning `[]`).

---

## 1. The `tamper/espresso` mount API

Package: `packages/tamper/espresso` (import alias `tamperespresso`). Core principle from all three reports: **constructor args, never the host's state bag** — the adapter captures its dependencies in closures; `espresso.WithState` remains exclusively the app's.

```go
package tamperespresso

// ── Deps: the port struct that replaces AppState coupling ──────────────

type Deps struct {
    // JWT is the access-token verifier. Required.
    // In-module dependency on tamper/crypto — never on an app façade.
    JWT *crypto.JWTService

    // Identity is the auth flow port. Barista satisfies it with
    // *service.AuthService (method set already matches ~1:1).
    // The adapter mounts OVER this port, not over identity.Core
    // directly — see Decision 1.
    Identity IdentityService

    // Authz is tamper's own PDP (Phase 1). Optional; nil disables
    // RequireDecision construction (constructor returns error if a
    // gate is requested without it).
    Authz authz.Authorizer

    // OIDCProviders / SAMLProviders resolve the live registries
    // (already tamper Managers behind Barista wrappers). Nil = protocol
    // disabled (flow routes 404 PROTOCOL_NOT_CONFIGURED; list route
    // folds in what exists).
    OIDCProviders oidc.RegistrySource   // GetRegistry(ctx) (*oidc.ProviderRegistry, error)
    SAMLProviders saml.RegistrySource   // + AllowIdPInitiated() bool via flow options

    // ServiceAccounts authenticates SCIM bearer tokens.
    ServiceAccounts ServiceAccountValidator

    // SCIM stores (Phase 4e prerequisite ports — see sub-phases).
    SCIMUsers  scim.UserStore
    SCIMGroups scim.GroupStore

    // Audit is tamper's logger. Nil = NoopLogger.
    Audit audit.Logger
}

// IdentityService is the narrow port over Barista's AuthService.
// Everything returns identity.User + identity.Tokens (tamper types);
// sentinel errors are tamper identity.Err* — the app's port impl maps
// its domain errors before returning.
type IdentityService interface {
    Register(ctx context.Context, email, password string) (*identity.User, identity.Tokens, error)
    Login(ctx context.Context, email, password string) (*identity.User, identity.Tokens, error)
    Refresh(ctx context.Context, refreshToken string) (*identity.User, identity.Tokens, error)
    Logout(ctx context.Context, refreshToken string) error
    Me(ctx context.Context, userID string) (*identity.User, error)

    // TOTP two-phase (session_token owned HERE, closing the split
    // where mint/verify is tamper/crypto but verification lives in
    // Barista's AuthService today).
    IssueTOTPPending(userID string) (string, error)
    VerifyTOTP(ctx context.Context, sessionToken, code string) (*identity.User, identity.Tokens, error)
    VerifyRecoveryCode(ctx context.Context, sessionToken, code string) (*identity.User, identity.Tokens, error)
    EnrollTOTPViaSession(ctx context.Context, sessionToken, currentCode string) (identity.EnrollResult, error)

    // Federation mints + upserts (delegating to identity core Phase 2d).
    UpsertOIDCUser(ctx context.Context, in identity.FederatedUpsert) (*identity.User, error)
    UpsertSAMLUser(ctx context.Context, in identity.FederatedUpsert) (*identity.User, error)
    LinkIdentity(ctx context.Context, userID string, in identity.FederatedUpsert) error
    UnlinkIdentity(ctx context.Context, userID, identityID string) (identity.Identity, error)
    ListIdentities(ctx context.Context, userID string) ([]identity.Identity, error)
    IssueTokensForUserWithACR(ctx context.Context, userID string, authTime int64, acr string) (*identity.User, identity.Tokens, error)
}

type ServiceAccountValidator interface {
    // Validate returns tamper's ErrInvalidCredential sentinel on bad
    // tokens (the adapter maps it to the SCIM 401 envelope). The token
    // FORMAT (bsa_ prefix, bcrypt loop) is validator-internal —
    // invisible to the adapter.
    Validate(ctx context.Context, token string) (Principal, error)
}

// Principal replaces the *domain.ServiceAccount context stash.
type Principal struct{ ID, Name string }

// ── Config: injected literals (every Barista brand string lands here) ──

type Config struct {
    // MountPrefix is the route prefix ("/api/auth"). The refresh-cookie
    // Path is DERIVED from this — not independently settable. This is
    // the CSRF fence by construction.
    MountPrefix string

    Cookies CookieConfig // RefreshName ("barista_refresh"), OIDCStateName,
                         // SAMLStateName (base names; __Host- prefix derived
                         // from Secure), Secure bool (ONE toggle for all
                         // cookies), RefreshTTL time.Duration
    StateCookie StateCookieConfig // Secret []byte, OIDCIssuer, SAMLIssuer

    StepUp StepUpPolicy // MaxAge, ACRValues []string — app's promise, opaque here

    WS WSConfig // BearerSubprotocolPrefix — REQUIRED when RequireAuthWS is
                // used; no tamper default (anti-cross-service-replay branding)

    SCIM SCIMConfig // Prefix ("/scim/v2"), BaseURL, BulkMaxOperations,
                    // DocumentationURI, AuthSchemeDescription

    Features Features // Refresh, TOTP, OIDC, SAML, SCIM bool — replaces
                      // nil-sniffing route gates; disabled = not mounted

    // ErrorCodes overrides entries in the versioned default table
    // (defaults == Barista's current strings byte-for-byte). See Decision 2.
    ErrorCodes map[ErrorKey]string
}

// ── Hooks: app policy injected at flow instants ─────────────────────────

type Hooks struct {
    // ProjectUser builds the wire `user` payload on every token-issuing
    // response. Hook error != request failure — the hook owns its own
    // fallback (Barista: effective-role compose, fail-open to inline role).
    // Runs AFTER OnFederatedLogin (TD-FUNC-15 ordering, contractual).
    ProjectUser func(ctx context.Context, u *identity.User) (json.RawMessage, error)

    // OnFederatedLogin fires post-upsert, pre-token-mint on OIDC/SAML
    // LOGIN legs only (never link legs). Errors are logged + swallowed
    // (a group-sync hiccup must not lock the user out).
    OnFederatedLogin func(ctx context.Context, u *identity.User, provider string, groups []string)

    // SanitizeRedirect is the open-redirect policy. Nil = deny-all-to-"/".
    // Barista passes its /projects|/admin|/clusters|/account allowlist.
    SanitizeRedirect func(raw string) string

    // Events is the typed audit-emission seam — see Decision 3.
    Events EventSink

    // EmailLookup enriches audit actors (Barista: closure over AuthSvc.Me).
    EmailLookup func(ctx context.Context, userID string) string

    // ResolveClientIP overrides the default first-hop-XFF policy
    // (documented default matches Barista's Traefik-fronted assumption).
    ResolveClientIP func(r *http.Request) string
}

// ── Constructor + mount ─────────────────────────────────────────────────

func New(deps Deps, cfg Config, hooks Hooks) (*Adapter, error) // validates at boot, panics never

// Mount registers all enabled auth routes under cfg.MountPrefix,
// auto-wiring the cookie-reader + RemoteIP + capture-slot middleware
// internally. Also mounts SCIM under cfg.SCIM.Prefix when enabled.
// CoMount lets the app hang extra routes (e.g. Barista's TOTP email
// recovery) under the same prefix without route conflicts.
func (a *Adapter) Mount(r *espresso.Router)
func (a *Adapter) CoMount(r *espresso.Router, pattern string, h http.Handler, mw ...func(http.Handler) http.Handler)

// ── Middleware (all previously in barista internal/api/middleware) ──────

func (a *Adapter) RequireAuth() func(http.Handler) http.Handler
func (a *Adapter) RequireAuthWS() func(http.Handler) http.Handler        // unified on VerifyAccess (lift-time fix)
func (a *Adapter) RequireFreshAuth(endpoint string) func(http.Handler) http.Handler // per-instance clock, no globals
func (a *Adapter) RequireServiceAccount() func(http.Handler) http.Handler
func (a *Adapter) Auditor() *Auditor                                     // Mutation(action, resourceType) wrapper

// RequireDecision generalizes the PDP edge gates (cluster/org shape).
func (a *Adapter) RequireDecision(opts DecisionGateOpts) func(http.Handler) http.Handler

type DecisionGateOpts struct {
    PathParam        string
    ResourceType     string
    Action           string   // simple 403 flow
    VisibilityAction string   // optional: two-check 404-leak flow (org pattern)
    DenyCode         string   // e.g. "INSUFFICIENT_CLUSTER_ROLE"
    NotFoundCode     string   // e.g. "ORG_NOT_FOUND"
}

// ── Package-level context accessors (the atomic-move unit) ──────────────

func MustGetUserID(ctx context.Context) string
func GetUserID(ctx context.Context) (string, bool)
func AccessClaimsFromContext(ctx context.Context) (*crypto.AccessClaims, bool)
func GetPrincipal(ctx context.Context) (Principal, bool)          // replaces GetServiceAccount
func WithUserIDCapture(ctx context.Context) (context.Context, *UserIDSlot)
func SetUserID(ctx context.Context, userID string)                // exported cross-package contract (TD-AUDIT-07)
func UserIDFromContext(ctx context.Context) string

// Shared response types papering over Espresso gaps (see Decision 5):
type Redirect struct{ URL string; Cookies []*http.Cookie }        // IntoResponse
type XML struct{ Body []byte; ContentType string }                // IntoResponse

func (a *Adapter) Testing() *TestingHandles // SetClock etc. — per-instance, Barista Testing() convention
```

**Barista façade after delegation** (`internal/api/middleware` shrinks to re-exports):

```go
// functions can't be type-aliased → var re-exports; types alias per Phase-0 rule
var (
    MustGetUserID = tamperespresso.MustGetUserID
    GetUserID     = tamperespresso.GetUserID
    SetUserID     = tamperespresso.SetUserID
    // ...
)
type Principal = tamperespresso.Principal
```

---

## 2. Sub-phase split (core-then-delegate, ordered by risk)

Pre-work items are Barista-side refactors that must land **before** their phase; each sub-phase follows the proven playbook (copy → parity → façade → delete) and the validation bar (`-race` green, `barista:ci` green, container-mode walk boots).

### 4a — Identity middleware core (the atomic unit) — *lowest risk, unblocks everything*

- **Scope:** `RequireAuth`, `bearerToken`, `writeUnauthenticated`, `RequireAuthWS` (unified on `VerifyAccess` — the lift-time fix at `auth_ws.go:49`), all context accessors, the `WithUserIDCapture` slot, the generic cookie-reader (collapsing the refresh/OIDC-state/SAML-state trio), `RemoteIP` + injectable IP policy, `Auditor` (Mutation/For/captureActor/statusCapturingWriter, cluster-ID slot generalized to an opaque attribute-capture hook).
- **Barista deletes:** `middleware/auth.go` (minus SA gate), `auth_ws.go`, `refresh_cookie.go`, `oidc_cookie.go`, `saml_cookie.go`, `remote_ip.go`, `audit.go` → var-re-export façade.
- **Parity proof:** the existing middleware test suite runs unchanged against the façade; plus a new **runtime tripwire test** — an end-to-end request through Barista's real router asserting `MustGetUserID` returns the JWT sub and the audit row carries `actor.user_id` (the context-key mismatch failure mode compiles clean and only fails at runtime; this test is the guard the type-alias compile-check can't provide).
- **Security invariants:** no-DB-in-RequireAuth contract; audit-actor stash for service-layer emissions (TD-AUDIT-01); WS subprotocol prefix passed as required config (SPA wire contract + anti-replay branding); capture-slot exported contract (TD-AUDIT-07 regression risk).

### 4b — Gate middleware (step-up + service-account + PDP gate) — *contained, contract-pinned*

- **Pre-work (Barista-side, separate PR):** migrate `RequireClusterAdmin` off `AuthService.EffectiveSystemRole` onto a `system.admin` PDP action in `internal/authz`'s BindingStore (mirroring the Phase-1c org-gate migration, replacing the role-stash with a decision). Until this lands, `RequireClusterAdmin` stays Barista and Phase 4 ships without it.
- **Scope:** `RequireFreshAuth(+WithAudit)` with per-instance clock (kill the `stepUpNow` package global, `stepup.go:285`), `writeStepUpError` **with the byte-pinning JSON test moved into tamper**, `RequireServiceAccount` over the `ServiceAccountValidator` port + `Principal` stash + `writeSCIMError` (RFC 7644 §3.12), and `RequireDecision` generalizing the cluster/org gate skeleton.
- **Barista deletes:** `stepup.go`/`stepup_testing.go`, SA gate + `scim_errors.go`, `cluster_role.go`/`org_role.go` bodies (registration sites become `adapter.RequireDecision(opts)` calls with Barista's action maps/codes as args). Keeps: `preflight.go` (RequireAppAccess), step-up policy values, endpoint labels.
- **Parity proof:** STEP_UP_REQUIRED pinning test in tamper AND a Barista end-to-end wire test kept as tripwire (the #420/#422 lesson: tamper-only builds miss adapter breaks — every 4x PR builds `apps/barista` per the HARD rule). SCIM 401 envelope byte-diff. Two-check 404-leak flow covered by existing org-gate tests unchanged.
- **Security invariants:** fail-closed on missing claims; local-password ACR exclusion arrives only via config; `ErrInvalidCredential` 401-vs-500 mapping; deny-by-default in `RequireDecision`; SA principal must keep flowing into SCIM audit actors (adapt `handler/scim/` readers of `MustGetServiceAccount` in the same PR).

### 4c — Core auth routes (login/refresh/logout/me/TOTP) — *the cookie machinery; medium-high risk*

- **Scope:** Register/Login/Refresh/Logout/Me/VerifyTOTP/EnrollSession handler shells over the `IdentityService` port; `refreshCookies`/`clearRefreshCookieValue` with Path derived from `MountPrefix`; the USER_INACTIVE cookies-on-error workaround (`auth.go:390-401`) as adapter-standard behavior; the sentinel→code mapping keyed on `identity.Err*`; the versioned default DTO/code table; the `ProjectUser` hook; `Features` flags replacing nil-sniffing gates; `CoMount` for Barista's TOTP email-recovery routes (which stay app-side wholesale).
- **Barista deletes:** most of `handler/auth.go` (keeps `effectiveRoleForUser` as its `ProjectUser` hook impl + the recovery-flow handlers); `refreshCookieFromConfig` becomes the koanf→`CookieConfig` translation; the `/api/auth/*` registration block in `server.go` collapses to `adapter.Mount(r)`.
- **Parity proof:** full handler test suite green against the mounted adapter; **HTTP-level golden diff** of every auth response (status, body bytes, Set-Cookie attributes incl. Path/HttpOnly/SameSite/MaxAge) before/after — the Phase-0c parity-diff bar applied to the wire. Registration-matrix parity test (which routes exist under which feature flags vs today's nil-gates).
- **Security invariants:** cookie Path == mount prefix by construction; refresh-cookie-only-after-MFA (phase-1 returns no cookie); attribute-parity clear cookie (MaxAge=-1); anti-enumeration collapses (all credential failures → INVALID_CREDENTIALS); wrapped-sentinel-before-parent mapping order (USER_INACTIVE before generic unauthorized); audit-only-phase-2 on enroll-session.

### 4d — Federation routes (OIDC + SAML flows, link/unlink) — *highest risk*

- **Pre-work (tamper/saml, separate PR):** the `ParseAssertion` view flagged in 3a scope notes — a tamper-owned assertion type (email, attributes, groups, AuthnInstant, ACR, isIdPInitiated) so the adapter's ACS handler never imports crewjam. **Hard blocker; do not start 4d without it.**
- **Scope:** Start/Callback/Exchange OIDC, SAMLLogin/ACS/Metadata, link-start/link legs, unlink/list, provider union list; state-cookie orchestration (mint/verify/single-use-clear, mode dispatch with the rolling-deploy ModeLogin default); `buildPostFormRequest` shim; `extractAuthTime/ACR` + `stepUpSatisfied` as shared pure functions; step-up param forwarding (max_age/acr_values/ForceAuthn/RequestedAuthnContext); `Redirect`/`XML` response types.
- **Barista deletes:** ~all of `handler/oidc.go` + `handler/saml.go`; keeps `internal/auth/oidc/redirect.go` (the `SanitizeRedirect` hook impl), the group-reconcile hook impl, and its audit sink.
- **Parity proof:** the fake-IdP integration harness (already moved with 3a/3b) drives full auth-code + ACS flows through the mounted adapter; audit-row byte-diff for `auth.oidc.login`/`auth.saml.login`/`auth.identity.link`/step-up events (pinned payload shapes + the CanonicalVersion3-on-step-up-only quirk reproduced exactly); redirect-precedence and cookie-name (`__Host-` switch) golden tests.
- **Security invariants (each needs its own adapter test):** ModeLink requires server-signed cookie with UserID; SAML missing-cookie falls through to LOGIN (IdP-initiated legitimacy); email-conflict veto skipped on link legs; reconcile deliberately absent on link; no fresh mint on link; non-nil empty `possibleRequestIDs` (TD-INFRA-32); state-cookie redirect beats RelayState; IdP `auth_time` beats server clock (foot-gun C); reconcile-before-projection ordering (TD-FUNC-15); route-prefix config feeds the same Manager seams (`WithRedirectURL`/`WithSPMetadataURL`) — single-sourced or minted IdP URIs drift from mounted routes.

### 4e — SCIM transport — *port-design-gated; can run parallel to 4d*

- **Pre-work:** design `scim.UserStore`/`scim.GroupStore` ports in `tamper/scim` (Phase 3e's `ColumnMapping` precedent: the mapping IS the app's schema). Barista's `userName=email` projection, soft-disable DELETE, and `group_members` nesting stay inside its port implementations.
- **Scope:** the 16-route table + wrap + inner bulk router (`router.go:28-116`), dto/etag/bulk HTTP plumbing, discovery endpoints with capability flags **derived from mounted features** (fixing the advertised-200-vs-actual-100 maxResults drift at lift time), `resolveBaseURL`; `documentationURI` + auth-scheme text injected via `SCIMConfig`.
- **Barista deletes:** `handler/scim/` transport files; keeps the store-port implementations + its filter `ColumnMapping`.
- **Parity proof:** existing SCIM handler suite green over the ports; connector-validation golden responses (ServiceProviderConfig/ResourceTypes/Schemas) byte-diffed modulo the injected literals.
- **Security invariants:** RequireServiceAccount mutual exclusivity with RequireAuth per route group; SCIM envelope on auth failures; bulk inner-router excludes Bulk + Me (no recursion).

**Sequencing:** 4a → 4b → 4c → {4d, 4e}. Each ships a Barista façade to production before the next begins (phase discipline). The `RequireClusterAdmin`→PDP pre-work and the `ParseAssertion` pre-work can start any time.

---

## 3. The five hardest design decisions

### D1 — Adapter mounts over a port, not over `identity.Core` directly

**Tension:** the end-state sketch (`tamperespresso.Routes(tp)`) implies adapter-over-core, but Barista's `AuthService` adds real value between core and wire: TOTP-required config, the session-token verification for enroll (which `auth_service.go` owns even though `tamper/crypto` mints it), pre-delegation error-message preservation, recovery flows.
**Recommendation:** define the narrow `IdentityService` port (§1) and mount over it. Barista satisfies it with `AuthService` (near-zero adaptation). Ship a default implementation `tamperespresso.CoreIdentityService(core *identity.Core, ...)` so greenfield consumers get the doc-sketch experience — the port absorbs the TOTP-pending ownership split (session-token verify moves behind the port, one owner). This preserves the double-translation layer where it earns its keep and deletes it where it doesn't (mapping keys on `identity.Err*`, killing `validationMessage`'s prefix-strip glue).

### D2 — Wire contracts (DTO shapes + error-code strings) live in tamper as *versioned defaults*, byte-identical to Barista today

**Tension:** auth-routes wants them as adapter defaults; federation warns they're pinned SPA contracts; any tamper-side rename breaks every consumer's SPA.
**Recommendation:** tamper ships `AuthRes{token,user,totp_required,session_token}`, the TOTP envelopes, `LinkStartRes{authUrl}`, the provider-list DTO (including the `display_name` snake-case wrinkle), and the full error-code table (UNAUTHENTICATED, INVALID_CREDENTIALS, STEP_UP_REQUIRED, OIDC_/SAML_EMAIL_CONFLICT, LINK_CONFLICT, LAST_AUTH_METHOD, …) as an explicitly versioned `WireV1` default set — values copied byte-for-byte from Barista, so the delegation PRs are wire no-ops (the proven façade-parity bar). The `user` payload is app-injected (`ProjectUser` → `json.RawMessage`); `UserDTO` never enters tamper. Overrides via `Config.ErrorCodes`; any future change is `WireV2`, opt-in. Pinning tests for STEP_UP_REQUIRED and the SCIM envelope move INTO tamper; Barista keeps end-to-end tripwires.

### D3 — Audit seam: typed `EventSink` hook for vocabulary, mechanism wholly in tamper

**Tension:** emit *points* (flow instants, available data, JIT-created detection, capture-slot timing) only the route owner knows; emit *vocabulary* (action strings `auth.login`/`auth.stepup.denied`, ResourceAuth-vs-ResourceUser split, pinned After-payloads, CanonicalVersion3 inconsistency) is Barista's operational contract that greps and the `/admin/audit` SPA depend on.
**Recommendation:** the adapter owns the Auditor middleware, the capture slot, and fires a typed `EventSink` (`OnLogin{provider, jitCreated}`, `OnLink`, `OnStepUpDenied{endpoint, reason, requested…}`, `OnStepUpInitiated/Succeeded`, …) at each instant with everything it knows (actor, IP, request-id, resource-id). Barista's sink implementation maps to its exact current action strings, payload shapes, and CanonicalVersion stamping — reproduced byte-identically, quirks included (don't "fix" the missing CanonicalVersion3 on `auth.oidc.login` during the lift). Tamper may *document* a suggested default taxonomy for greenfield apps but never emits rows Barista's sink didn't shape. Parity bar: audit-row byte-diff per 4c/4d.

### D4 — Cookie branding stays app config; cookie *Path* and `__Host-` switching are derived, never free config

**Tension:** three cookie names are Barista brands (Phase 3a/3b precedent says names stay app-side), but two attributes are load-bearing security invariants with silent failure modes: `Path=/api/auth` is the CSRF fence and must equal the mount prefix; the `__Host-` prefix must track a single Secure toggle or upgrades strand browsers with mixed cookies.
**Recommendation:** `CookieConfig` takes base names + one `Secure` bool + TTL. The adapter derives: refresh-cookie `Path` from `Config.MountPrefix` (no independent setter exists — API-level impossibility, not documentation), effective state-cookie names via a `hostPrefixed(name, secure)` helper, `HttpOnly=true` and `SameSite=Lax` as non-configurable invariants, and clear-cookies with attribute parity by construction. `RequireAuthWS`'s subprotocol prefix is required config with **no default** — a tamper default would both break Barista's SPA wire contract and defeat the anti-cross-service-replay branding.

### D5 — Espresso response gaps: `Redirect`/`XML` ship in `tamper/espresso` now; error-with-cookies becomes an Espresso feature request

**Tension:** the hand-rolled `IntoResponse` types (`oidcRedirect`, `samlPostInitiated`, `xmlResponse`) and the USER_INACTIVE JSON-shaped-401 exist because Espresso v2 lacks Redirect/XML response types and its typed-error path can't carry Set-Cookie. Upstreaming is cleaner (flagship synergy) but serializes Phase 4 behind an Espresso release.
**Recommendation:** split by risk. (a) `Redirect{URL,Cookies}` + `XML{Body,ContentType}` ship in `tamper/espresso` immediately (collapsing the two identical redirect types), with an Espresso issue filed to absorb them in v2.5 — when that lands, tamper's become aliases. (b) The error-with-cookies gap is subtler: the workaround (success-envelope-shaped 401 + clear cookie) becomes the adapter's *standardized, tested* behavior for USER_INACTIVE-class failures — consumers get it right by default — AND it's filed as the next Barista→Espresso feature request in the F-05 lineage. Do not block Phase 4 on either Espresso change.

*(Also settled, lower difficulty: SPA redirect policy = `SanitizeRedirect` hook with deny-all-to-default nil behavior + optional tamper helper for the mechanical rules, per the Phase 3b precedent; SCIM dto/etag/bulk = tamper transport over app-implemented store ports, per §2 4e.)*

---

## 4. Explicit NON-goals for Phase 4

1. **`RequireClusterAdmin` as-is** — not lifted until the Barista-side `system.admin` PDP migration lands; lifting now drags the fixed-enum SystemRole model + group-promotion semantics into the framework.
2. **`RequireAppAccess` / project + tenant gates** (`preflight.go`) — TAMPER-DESIGN already rules project gates stay service-side; they ARE the authoritative service checks, and the stash is a domain type.
3. **TOTP email-recovery flow** — no identity-core equivalent; depends on mailer, `totp_recovery` table, rate-limit SQL, masked-email rendering. Stays Barista, co-mounted via `CoMount`. A future optional module (Mailer + RecoveryStore ports) is post-Phase-4.
4. **Admin provider-CRUD routes** (`/api/admin/identity-providers/*` etc.) — the Managers are tamper's (3c/3d) but the admin HTTP surface is the host app's job per the framework's "no admin UI" non-goal.
5. **Barista's user projection / EffectiveSystemRole / group model / SCIM user-mapping** — permanently app-side; the adapter only ever sees them through hooks and ports.
6. **koanf or any config-file awareness** — tamper takes plain structs; Barista's `refreshCookieFromConfig`-style translation stays in Barista (Phase-0 precedent).
7. **Other transport adapters** (chi, stdlib mux, gRPC) — Espresso is the first-class adapter; the core stays transport-agnostic but no second adapter ships in Phase 4.
8. **Registering into the host's `WithState` bag** — the adapter never touches `appstate.AppState`; deps ride in closures.
9. **Audit taxonomy standardization** — tamper does not promote `auth.*` action strings to cross-consumer wire commitments in Phase 4 (Decision 3); revisit only after a second real consumer exists.
10. **Fixing behavioral quirks during the lift** — the CanonicalVersion stamping inconsistency, the advertised-vs-actual SCIM maxResults drift (fixed as a flagged, tested change in 4e, not silently), and any error-message wording all reproduce byte-identically first; changes come as separate, versioned follow-ups. The two sanctioned lift-time fixes are `RequireAuthWS`→`VerifyAccess` and the `stepUpNow` global→per-instance clock, both called out in §2.

**Key file references:** `packages/tamper/TAMPER-DESIGN.md` (roadmap line 129 = this phase); `apps/barista/internal/api/middleware/auth.go`, `auth_ws.go`, `stepup.go`; `apps/barista/internal/api/handler/auth.go`, `oidc.go`, `saml.go`, `scim/router.go`; `apps/barista/internal/api/server.go` (composition root, step-up constants :33-45, auditor :96, mount blocks).