I have enough verified evidence. Key cross-checks against the actual code confirmed:

- ParseAssertion pre-work has **already landed** — `saml.go:405` calls `provider.ParseAssertion(...)`, and saml.go no longer imports crewjam (imports at `saml.go:3-25`). The 4d hard blocker is cleared.
- The AuthTime/ACR asymmetry is real: OIDC still has local `extractOIDCAuthTime`/`extractOIDCACR` (`oidc.go:1129,1156`) while SAML already uses tamper-owned `assertion.AuthnTime`/`assertion.ACR` (`saml.go:525-526`).
- `stepUpSatisfied` is a pure predicate with two in-repo callers today (`oidc.go:771`, `saml.go:551`).
- The three response types are de-facto already shared: `SAMLLogin` returns an `oidcRedirect`, not `samlPostInitiated` (`saml.go:221`).
- The SAML cookie Path trap is confirmed: comment says `/api/auth/saml/` (`saml.go:326-328`) but code sets `Path:"/"` (`saml.go:334`).
- CanonicalVersion3 quirk confirmed: set on step-up (`oidc.go:890,938`), absent on `auth.oidc.login` (`oidc.go:1014-1022`).
- The ratified plan §2 4d (`PHASE4-TRANSPORT-PLAN.md:266-272`) already commits to a FederationRoutes mount with `SanitizeRedirect` + group-reconcile + audit-sink hooks, and NON-goals #9/#10 (`:327-328`) forbid freezing `auth.*` taxonomy pre-second-consumer.

---

# Tamper Phase 4d — Boundary Decision

## Verdict: **MIDDLE** (verification spine + single post-verify hook), with primitives-only's clean lifts absorbed as the first sub-PR and full-route rejected.

The decider's rubric, scored against the code and the Phase-4 NON-goals:

| Axis | full-route | primitives-only | **middle** |
|---|---|---|---|
| **(a) Philosophy fidelity** ("owns mechanics+lifecycle, never the app's orchestration sequence or wire DTOs") | **Weak.** Promotes the exchange *sequence* into a framework contract (its own risk #3 calls this "the tell"); freezes an `EventSink` taxonomy and a `CallbackMode` enum. | **High**, by refusing the mount entirely. | **Highest that still lifts a mount.** Spine = mechanics; the whole post-verify sequence lives in ONE app hook, so tamper never dictates ordering back to Barista. |
| **(b) Genuine second-consumer reuse** | Surface-genuine but demand-speculative; author concedes `CallbackMode`/`EventSink` should be "tamper-internal-until-second-consumer." | **Cleanest honesty** (all 3 lifts pass), but strands Start/Callback/Exchange/ACS shells as re-hand-written per app. | **Best realized reuse.** Exposes `StartOIDCFlow`/`VerifyOIDCCallback` **standalone, separate from `Mount`** — a server-rendered consumer takes the verify helpers and skips Barista's SPA fragment handler. |
| **(c) Parity risk / blast radius** | Highest — `jitCreated` port bit changes the created-signal *source*; EventSink must carry Barista's full pinned payload superset. | Lowest — 3 pure/mechanical lifts. | Medium, **staged** — touches the CSRF-fence cookie Path bytes and the fragment handoff, but gated per sub-PR with byte-diffs. |
| **(d) Drags app wire-DTOs / audit vocab into tamper?** | **Yes, both** — WireV1 federation DTO family + `FederationEventSink` taxonomy (violates NON-goal #9). | **No** (nothing app-shaped moves). | **Minimal & sanctioned** — one token-envelope `ExchangeRes` as a byte-identical WireV1 default (plan D2), `user` stays `json.RawMessage`; provider-union DTO + audit vocabulary stay app-side. |

### Why middle beats primitives-only
Primitives-only has the tightest honesty argument, and I **adopt its three lifts verbatim as sub-PR 4d-1** (both other stances agree on them, and they are genuinely the lowest-risk motion in the whole phase). But as the *terminal* boundary it strands federation as the one auth surface that never got the 4c `AuthRoutes` treatment — an inconsistency in the framework's own story, and a walk-back of the ratified plan. The middle subsumes every primitives-only lift **and** adds the verification spine, at staged/gated risk. It dominates.

### Why middle beats full-route
Full-route's only real edge is maximal code deletion, and its own author dilutes the claim: the `CallbackMode` enum is "mechanism owned, shape configured — not a clean lifecycle abstraction," and the `FederationEventSink` must carry Barista's exact pinned After-payloads (`oidc.go:876-880,922-928`), making the "generic" events quietly Barista-shaped. That is precisely dragging app audit vocabulary into tamper's most-visible contract surface — barred by NON-goal #9 until a second consumer exists, and doubly risky under the #420/#422 HARD rule. The `jitCreated` port bit also changes the created-signal source (`oidc.go:782`) — a gratuitous audit-taxonomy parity hazard. Reject.

**The decisive architectural move:** expose the verify helpers *separately* from `Mount`, and hand the entire post-verify tail (upsert → reconcile → mint → audit → project → redirect) to a **single** `OnFederated*` hook. This keeps Barista's least-reusable, most-quirk-laden logic (created-detection, CanonicalVersion3, effective-role projection, email-conflict veto, group-reconcile ordering) **out of tamper's contract surface entirely**, while still deleting the RFC/browser-shaped mechanics. This is the exact opposite failure mode from full-route, which would thread that residue through 6 framework port methods.

**One sanctioned divergence from the ratified plan §1:** the federation upsert/link/mint calls do **not** become `IdentityService` port methods (`PHASE4-TRANSPORT-PLAN.md:98-103`). They stay as ordinary `AuthService` calls *inside the single hook*. Rationale: once the post-verify tail is conceded as app orchestration, promoting those to framework port methods only enlarges tamper's contract for zero framework use. The 4d deps tamper actually needs are just the two registry sources + state secret + cookie config + hooks.

---

## Concrete 4d execution plan

Sequenced by ascending risk; every sub-PR bundles `apps/barista` build + the fake-IdP integration harness (MEMORY HARD RULE, #420/#422 — a tamper-only green build is a false signal). Each is independently parity-provable and ships a Barista façade before the next begins.

### 4d-1 — Pure lifts + response types *(lowest risk, mechanical; = primitives-only's whole scope)*
Lift with **zero handler restructure**; Barista façades delegate.

```go
// tamper/espresso — papers over Espresso v2 response gaps (plan D5)
type Redirect struct{ URL string; Cookies []*http.Cookie }   // IntoResponse: cookies → Location → 302
type XML      struct{ Body []byte; ContentType string }        // default "application/samlmetadata+xml"

// tamper/espresso/stepup.go — beside RequireFreshAuth (consolidated in 4b)
func StepUpSatisfied(requestedMaxAge int64, requestedACR []string,
    deliveredAuthTime int64, deliveredACR string, now int64) bool

// tamper/oidc/claims.go — methods on the existing Claims type, closing the SAML symmetry
func (c *Claims) AuthTime(nowFn func() time.Time) int64 // float64|int64|json.Number coercion + nowFn().Unix() fallback
func (c *Claims) ACR(fallback string) string
```
- **Barista deletes:** `oidcRedirect` (`oidc.go:48-65`), `samlPostInitiated` (`saml.go:94-115`), `xmlResponse` (`saml.go:66-82`) collapse to `Redirect`/`XML`; `stepUpSatisfied` (`oidc.go:958-986`), `extractOIDCAuthTime`/`extractOIDCACR` (`oidc.go:1129-1161`) delegate.
- **Keeps:** `splitACRValuesCSV` (`oidc.go:311-323`) — leans app-side (encodes Barista's SPA comma-OR-space leniency matching the STEP_UP_REQUIRED envelope); leave unless 4d-2 needs it.
- **Parity:** `WriteResponse` byte-golden (Set-Cookie order, Location, 302) before/after; the `.Location`→`.URL` field rename must preserve identical output; move the coercion unit tests (all three number types) + the stepUpSatisfied truth-table into tamper, keep Barista delegation smoke tests.

### 4d-2 — OIDC verification spine *(medium)*
Lift the start + callback + exchange-verify mechanics as **standalone helpers**; Barista's `ExchangeOIDC` shrinks to `helper + inline app tail`.

```go
// tamper/espresso — handler-agnostic; a non-SPA consumer uses these WITHOUT Mount
func StartOIDCFlow(p *oidc.Provider, o StartOptions) (authURL string, stateCookie *http.Cookie, err error)
type StartOptions struct{ Redirect string; MaxAge int64; ACRValues []string; Mode oidc.Mode; UserID, CallingUserID string }
func VerifyOIDCCallback(p *oidc.Provider, code, state, cookieVal string,
    secret []byte, issuer string, now func() time.Time) (OIDCVerified, error)

type OIDCVerified struct {
    ProviderID string
    Claims     map[string]any          // verified ID-token raw claims (post VerifyIDToken)
    State      oidc.StateCookieClaims   // Mode/UserID/Requested*/CallingUserID/Redirect
}
```
- Folds in: sign+set (`oidc.go:248-267`), read+verify+provider/state cross-check (`oidc.go:649-667`), `Exchange`+`VerifyIDToken` (`oidc.go:672-688`), PKCE/nonce/step-up param forwarding incl. `coreoidcNonceOpt` and `prompt=login` (`oidc.go:269-289`), the `ModeLogin`-empty-cookie default (`oidc.go:695-698`), and the state-cookie Set-Cookie builders (`oidc.go:1048-1075`) over a `CookieConfig` + `hostPrefixed(name, secure)` helper (reuse 4c).
- **Parity:** fake-IdP auth-code harness green; audit-row byte-diff for `auth.oidc.login`/`provision` + step-up unchanged (tail still emits app-side this PR).

### 4d-3 — OIDC single hook + `Mount` shell *(medium-high; the cookie/wire machinery)*
```go
type FederationOutcome struct {
    Result   AuthResult // reuse 4c AuthResult{User, Tokens}; empty Tokens ⇒ link leg
    Redirect string
    Linked   bool       // EXPLICIT — never infer link-leg from empty Tokens
}
type FederationHooks struct {
    ProjectUser         func(context.Context, *identity.User) (json.RawMessage, error) // REUSE 4c hook
    SanitizeRedirect    func(raw string) string                                        // nil ⇒ deny→"/"
    OnFederatedExchange func(context.Context, OIDCVerified) (FederationOutcome, error) // upsert→reconcile→mint→audit→project
    Events              EventSink // step-up instants; app shapes+stamps CanonicalVersion
}
// WireV1 default — byte-identical to dto.OIDCExchangeRes; Token is NOT omitempty (link leg ships "token":"")
type ExchangeRes struct {
    Token    string          `json:"token"`
    User     json.RawMessage `json:"user"`
    Redirect string          `json:"redirect,omitempty"`
}
func (f *FederationRoutes) Mount(r *espresso.Router) // start/callback/exchange (+link-start); auto-wires state-cookie reader
```
- **Barista deletes:** the `ExchangeOIDC` orchestration shell + `dto.OIDCExchangeRes`; `CallbackOIDC` fragment builder (`oidc.go:598-627`) + `urlValue` (`oidc.go:1093`) move behind the shell with `OIDCLandingPath` + `SanitizeRedirect` injected. **Barista's `OnFederatedExchange` impl** contains, verbatim and app-side: `UpsertOIDCUser` → `ReconcileGroupMembership` → `IssueTokensForUserWithACR` → `emitOIDCAudit`/step-up → `effectiveRoleForUser` projection → `SanitizeRedirectPath` (`oidc.go:704-808`). The email-conflict veto stays inside `AuthService.UpsertOIDCUser`; tamper only maps the sentinel.
- **Parity:** HTTP golden-diff of `/exchange` — **both** mode branches, the link-branch literal `"token":""`, single-use `clearOIDCStateCookie`, Set-Cookie attribute parity.

### 4d-4 — SAML spine + single hook *(highest risk)*
```go
type SAMLVerified struct {
    ProviderID string
    Assertion  *saml.ParsedAssertion // already-validated tamper view (pre-work landed)
    State      saml.StateCookieClaims
    HasState   bool
    RelayState string
}
// hooks add:
OnFederatedAssertion func(context.Context, SAMLVerified) (FederationOutcome, error)
```
- Lifts: `SAMLLogin` start + `AuthnRequestOptions` forwarding (`saml.go:171-224`), ACS `ParseAssertion` + `AllowIdPInitiated` gate (`saml.go:405-413`), `readSAMLStateCookie` verify (`saml.go:586-606`), mode dispatch + the **missing-cookie→LOGIN fallthrough** invariant (`saml.go:453-459`), `SAMLMetadataHandler` (`saml.go:620-641`). `AllowIdPInitiated` injected as `FederationConfig` bool — **confirm it is static boot config, not DB-reloadable**, else keep it as a `RegistrySource` accessor.
- **Barista's `OnFederatedAssertion` impl** keeps: `AttributeMapping*` reads (`saml.go:416-431`), `LinkSAMLIdentity` vs `UpsertSAMLUser`, reconcile, mint, `emitSAMLLoginAudit`, redirect precedence (state-cookie beats RelayState, `saml.go:558-569`).
- **Parity:** ACS fake-IdP harness covering IdP-initiated fallthrough, link leg (no mint), and step-up; dedicated adapter tests for the missing-cookie→LOGIN invariant and CanonicalVersion3.

### 4d-5 — Route-registration collapse + residue confirmation
- `FederationRoutes.Mount` collapses the `server.go` registration blocks. **Explicitly leave app-side, co-mounted:** `ListOIDCProviders` union+sort (`oidc.go:94-149`), `lookupOIDCRegistry` (`oidc.go:160-172`), `UnlinkIdentity`/`ListIdentities` CRUD (`oidc.go:411-483`) — these carry cross-protocol merge policy and `IdentityRes` presentation, not federation spine. **This is the correction to the plan's overstated "~all of oidc.go + saml.go delete" (`PHASE4-TRANSPORT-PLAN.md:270`)** — expect a materially thinner but non-empty residue.
- **Parity:** full route-matrix parity test + container-mode DoD walk boots.

---

## Barista deletes vs keeps (net)

**Deletes:** `oidcRedirect`/`samlPostInitiated`/`xmlResponse`; `extractOIDCAuthTime`/`extractOIDCACR`/`stepUpSatisfied`; state-cookie sign/verify/set/clear glue; the OIDC start+callback+exchange-verify spine and SAML start+ACS-parse-gate spine; `dto.OIDCExchangeRes`; the `/api/auth/oidc/*` + `/api/auth/saml/*` registration blocks in `server.go`.

**Keeps (permanently app-side):** `effectiveRoleForUser` (`auth.go`, NON-goal #5); `GroupSvc.ReconcileGroupMembership` + the reconcile-before-projection ordering (`oidc.go:738-744,792-800`, TD-FUNC-15); the created-detection heuristic (`oidc.go:782`, `saml.go:541`); the entire audit taxonomy incl. the CanonicalVersion3-on-step-up-only quirk (via the app `EventSink`); the provider-union DTO + sort (`oidc.go:94-149`); Unlink/List CRUD; `SanitizeRedirectPath` allowlist (as the `SanitizeRedirect` hook); `internal/auth/oidc/redirect.go`; `jwtSecretFromConfig`/`refreshCookieFromConfig` koanf translation (NON-goal #6); the email-conflict veto inside `AuthService`.

---

## Security invariants requiring explicit tests

1. **IdP `auth_time` beats server clock** (foot-gun C). `Claims.AuthTime(nowFn)` must return the IdP value when present and fall back to `nowFn().Unix()` *only* on absence (`oidc.go:1129-1147`) — parity test covers `float64`, `int64`, **and** `json.Number` (a decoder with `UseNumber` yields the third; missing it silently weakens the step-up boundary).
2. **SAML state-cookie Path byte-parity.** The lift must reproduce the *actual bytes* `Path:"/"` (`saml.go:334`), **not the comment's** `/api/auth/saml/` (`saml.go:326`). Deriving Path from `MountPrefix` here is a behavior change masquerading as a refactor — pin as byte-diff or the cookie stops arriving (D4 silent-failure fence).
3. **`__Host-` switch tracks a single Secure toggle** (`oidc.go:1032-1037`, `saml.go:311-316`) — mixed cookies strand browsers across an HTTP→HTTPS upgrade.
4. **ModeLink requires a server-signed cookie carrying UserID** (`oidc.go:701-703`, `saml.go:475-477`); missing UserID → `INVALID_STATE`.
5. **SAML missing-cookie falls through to LOGIN** (IdP-initiated legitimacy, `saml.go:453-459`) — must NOT reject.
6. **Link leg: no fresh mint, reconcile skipped, email-conflict veto skipped** (`oidc.go:716`, `saml.go:482-503`). Guarded by the explicit `FederationOutcome.Linked` bool — a hook that mistakenly populates `Result.Tokens` on the link leg would leak an access token; a dedicated adapter test must assert the link response ships `"token":""` and no refresh cookie.
7. **Single-use state cookie** — clear-cookie queued on every exchange/ACS exit (`oidc.go:790`, `saml.go:537`).
8. **State-cookie redirect beats RelayState** (`saml.go:558-569`); both funnel through `SanitizeRedirect` (nil ⇒ deny-all-to-`/`).
9. **CanonicalVersion3 on step-up events only, absent on `auth.oidc.login`** — reproduced byte-identically by the app `EventSink`; tamper never emits a federation audit row itself (NON-goals #9/#10). Audit-row byte-diff is the gate.
10. **Provider/state cross-check** (`oidc.go:662-666`) — provider mismatch and state mismatch both → `INVALID_STATE`.