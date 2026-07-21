# TAMPER-DESIGN.md — the Tamper framework

> **Tamper** is an embeddable enterprise authentication + authorization +
> tamper-evident-audit framework for Go. It is being extracted from Barista,
> its flagship and proving ground — the same relationship Barista has to
> Espresso. This document is the durable home of the vision, the niche, the
> extraction playbook, and the phase roadmap. (Referenced by the repo-root
> `CLAUDE.md` and the package `doc.go`s.)

Module: `github.com/suryakencana007/barista/packages/tamper` (nested module,
consumed by Barista via `require` + `replace`; stays in-repo until the
identity core stabilizes, then becomes a repo-split candidate).

## What Tamper is (and is not)

A **library you embed in your binary**, not a server you run beside it. A Go
project imports Tamper and gets enterprise auth (sessions, MFA, federation),
an authorization decision point, and a hash-chained audit log — with SQLite
as the default store, in a single process, no sidecar.

Non-goals:

- **Not a hosted IdP / standalone server.** No admin UI — that's the host
  app's job (Barista's `/admin/*` SPA is the reference implementation).
- **No home-rolled crypto primitives.** Tamper composes vetted libraries
  (`golang-jwt/jwt`, `x/crypto` bcrypt + nacl/secretbox, `pquerna/otp`) and
  owns the *lifecycle* logic around them (rotation, revocation, envelope
  encryption, step-up freshness).
- **No CGO.** SQLite via `modernc.org/sqlite`; Postgres parity later,
  mirroring Barista's driver matrix.

## Niche — why this exists in a crowded field

| Space | Incumbents | Their model | Tamper's angle |
|---|---|---|---|
| AuthN servers | Keycloak, Ory Kratos/Hydra, Zitadel, Authentik, Casdoor | run-a-server IdP | embed in your binary; no extra deployable |
| AuthN SaaS/hybrid | WorkOS, SuperTokens | hosted / managed core | self-contained; no external dependency |
| AuthZ engines | OpenFGA, SpiceDB, Cerbos, OPA/Cedar | engine-first, often a sidecar | interface-first — engines are pluggable *behind* the `Authorizer` |
| Audit | bolt-on logging in all of the above | plain append logs | hash-chained, boot-verified, tamper-evident **native** |

Four differentiators, in priority order:

1. **Embeddable single-binary Go** — the QuickStack/Barista deployment ethos
   applied to auth.
2. **Authz-engine-agnostic** — start with SQL-RBAC, scale to ABAC/ReBAC
   without rewriting call sites (see the `Authorizer` spine below).
3. **Tamper-evident audit native** — the hash chain is a first-class
   subsystem, not an afterthought. It's the namesake.
4. **First-class Espresso middleware** — `tamper/espresso` adapter ships the
   mountable routes + guards (core stays transport-agnostic).

Honest risks (flagged at inception, still true): scope explosion, the
security/maintenance burden of an auth library, and strong incumbents. The
mitigations are a ruthless phase discipline (below), leaning on vetted
crypto, and Barista as a real production consumer keeping every phase honest.

## Current state — what has shipped

| Phase | PR | What | Status |
|---|---|---|---|
| 0a — skeleton | #401 | monorepo restructure; `packages/tamper` module + `crypto`/`audit` copied in, `authz` doc stub | ✅ shipped |
| 0b — crypto extraction | #402 | Barista **imports** `tamper/crypto`; `internal/auth/crypto.go` became a thin façade; 13 duplicate files deleted (−2106 lines) | ✅ shipped |
| 0c — audit extraction | #403 | Barista **imports** `tamper/audit`; `internal/audit/audit.go` became a façade; `internal/store/sqliteaudit` deleted in favor of `tamper/audit/sqlitestore` (−8666 lines) | ✅ shipped |
| — deploy validation | — | the real Docker release image builds against tamper and boots with the audit chain self-test OK + crypto live (register/login/refresh) | ✅ verified 2026-07-05 |

Shipped subpackages:

- **`crypto/`** — JWT issue/verify, bcrypt password hashing, refresh-token
  generate/hash, TOTP enroll/verify, KEK keyset + secretbox envelope
  encryption (the `rotate-kek` substrate).
- **`audit/`** — hash-chain core with per-row `canonical_version` dispatch
  (v2 legacy pipe / v3 length-prefixed), `Logger` + `SQLiteLogger` +
  `NoopLogger`, chain anchors (`chain_restart` / `chain_migrate`), in-place
  migration, `VerifyChainPostMigration` boot guard, and the
  `audit/sqlitestore` persistence layer.
- **`authz/`** — the `Authorizer` PDP interface (Check / CheckBulk /
  ListResources / ListSubjects), the built-in `RBAC` engine over a pluggable
  `BindingStore`, and `MemStore`. Phase 1 complete: Barista's cluster + org
  edge gates decide through it (`internal/authz` adapter).
- **`identity/`** — the identity core (Phase 2a): `Core` service with
  Register / Login (timing-parity rejections, TOTP gating) / Refresh
  (rotation with step-up ACR + auth_time carry-forward) / Logout /
  RevokeAllSessions ("sign out everywhere" — a capability Barista's schema
  anticipated but never wired), the TOTP lifecycle (Enroll one-shot +
  two-phase Start/Complete, Verify, recovery codes, Disable, Clear), and
  multi-IdP linking (Resolve/Provision/Link/Unlink/List), over a pluggable
  `identity.Store` with `MemStore` as the reference. App policy stays
  app-side: caller-supplied default ACR, `firstUser` bootstrap signal,
  `OnRegistered`/`OnProvisioned` hooks, and the email-collision veto
  (wedged between Resolve and Provision). Barista delegates all of it
  (Phases 2b/2c/2d).

## The extraction playbook (proven across Phase 0 → 4e — reuse it verbatim)

Every lift follows the same steps, and Barista stays green throughout:

1. **Copy** the subsystem into `packages/tamper/<pkg>` with its tests;
   prove standalone via `moon run tamper:build tamper:test`.
2. **Prove parity** — for state-bearing subsystems, byte-identical output
   against the original (the audit lift diffed chain hashes to EXIT 0).
3. **Façade** — Barista's `internal/<pkg>` becomes a thin re-export.
   **Types must be ALIASES (`type X = tamper.X`), not defined types.** This
   is load-bearing: Barista's boot guards do concrete type assertions
   (`logger.(*audit.SQLiteLogger)`); a defined-type re-export compiles but
   silently disables the exit-3 chain-integrity guard. Enforce with a
   compile-time guard (`var _ *tamper.SQLiteLogger = (*SQLiteLogger)(nil)`).
4. **Delete** the duplicated implementation. The façade keeps ~all call
   sites untouched.
5. **Move the tests with the mechanic — and prove they still bite.**
   This step is not bookkeeping; skipping it silently disarms coverage.
6. **Adversarially diff OLD vs NEW** — for a behavior-preserving lift, run
   the parity review (`.claude/workflows/parity-review.js`) before shipping.
   It has caught a real break the passing golden suite missed on EVERY 4e
   SCIM lift (4e-5b: a concurrent-write audit race; 4e-5c: a 400-vs-500
   member error + a validation-precedence inversion). The golden suite tests
   happy paths; the review hunts the doubly-malformed / infra-fault /
   concurrency edges it never exercises.

**Why step 5 exists (4d-5, the hard way).** `golangci-lint unused` does
NOT protect you here: **a test calling a function counts as usage.** So
when a lift moves production onto tamper, any app-side helper still
referenced by a test stays alive, stays green, and stops tracking
production — the tests keep the corpse warm and the linter quiet. The
coverage doesn't disappear, which would be noticed. It reports itself as
present while guarding nothing.

Two live examples, both found by mutation AFTER 4d-4c shipped green:

- Barista wiring `SameSite=Lax` for the SAML state cookie — **TD-FUNC-28
  verbatim**, the HIGH bug that silently killed link mode + step-up on
  every real IdP — compiled and passed **every test in the repo**, all 32
  SAML tests and 7 E2E legs included. Its regression guard was calling a
  vacated app-side builder.
- **Deleting tamper's cross-provider replay defense** — a security
  control — passed every test in BOTH modules. The check was implemented
  in tamper and guarded only in Barista, against the app-side copy.

The mechanical rule:

- After a lift, grep each vacated helper for **non-test** callers. Zero
  production callers + live tests = a corpse the tests are propping up.
  Delete it and repoint the test at the real path.
- Tests for a mechanic live in the module that OWNS the mechanic. A test
  left behind in the app tests the app's copy, definitionally.
- Prove it with a mutation, don't infer it: break the property in the
  PRODUCTION path and watch the test go red. **A mutant that fails to
  compile proves nothing** — verify it builds first, or a green suite is
  just measuring your typo.

The deeper form: an extraction moves the code but not automatically the
thing that was watching it. Ask "what was guarding this, and is it still
pointed at where the code went?" — the answer after 4d-4c was no, three
times, in a lift whose whole premise was that its instrument would catch
exactly this.

**Byte-parity is the contract, and improvements are a separate change (4e).**
A lift reproduces behavior byte-for-byte — same bytes, headers, status, error
envelope, audit-row payload. If you spot a genuine improvement, it is its own
tested, documented change, not smuggled in (the ONLY sanctioned lift-time
behavioral fix in 4e was the maxResults advertised-vs-enforced drift, and it
was called out + tested). The trap: **an adapter built one slice early can
carry an *intentional* deviation that stays invisible until a later slice
wires it into the request path.** 4e-2's SCIM group adapter returned 500 (not
the pre-lift 400) for a non-`ErrNotFound` member fault, flagged in a comment as
"stricter — and more correct"; it was dead code until 4e-5c put the adapter in
the request path, then a live parity break. Revert such deviations at
wire-time; re-propose the improvement separately.

**The audit crossing — tamper never emits (A3).** When a route that emits
audit lifts into tamper, the audit stays app-side, emitted BY THE PORT IMPL
(Barista: `internal/scimstore`): actor from ctx (`ActorFromContext`), After
from the impl's own post-write re-read, and transport-only facts threaded down
via a small `WriteMeta` on the write methods. Thread the pre-write `Before`
SNAPSHOT the transport already read for If-Match — do not let the impl take a
second read (it races a concurrent same-row write and persists a later-state
Before into the chain-hashed row; 4e-5b caught exactly this). A single
federation-style audit hook was considered + rejected for SCIM's ~10 actions;
per-method emission in the impl is cleaner. See `PHASE4E-SCIM-SKETCH.md` §4.

**Seams stay app-side.** Two precedents from Phase 0:

- Config adapters (Barista's `NewJWTService(cfg)` translates its koanf
  config into tamper's constructor args) — tamper never learns koanf.
- App-specific constants (Barista's ACR values stay `urn:barista:*` because
  they're persisted in `refresh_tokens.acr`; tamper takes ACR as opaque
  configurable values).

Validation bar per phase: `-race` tests green, `moon run barista:ci` green,
and — for anything touching auth or audit — the Docker deploy-artifact walk
(container mode) boots with the chain self-test OK.

## Roadmap — remaining phases

| Phase | What moves | Generalization needed |
|---|---|---|
| **1 — authz spine** | `Authorizer` PDP interface + RBAC engine over a pluggable `BindingStore`, generalized from Barista's fixed-enum roles + `group_roles` + cluster-ACL pattern. **1a (interface + engine + MemStore): shipped. 1b (Barista adapter): shipped** — `internal/authz` implements `BindingStore` over the real tables (no new SQL), registers Barista's hierarchy + policy, and the per-cluster HTTP-edge gates (`RequireClusterRole`) consult the PDP. The system-admin bypass inconsistency was fixed en route (both `EffectiveRole` legs now honor group-promoted admins via `EffectiveSystemRole`). | The scope taxonomy (system/org/project/cluster) becomes the *app's instantiation*, not hard-coded. Pairs with Barista's deferred custom-role RBAC (Option 4) — but the interface lands first over fixed-enum SQL-RBAC. |
| **2 — identity core** | users / credentials / refresh-session rotation + revocation / TOTP enrollment / `user_identities` multi-IdP linking, behind ONE `identity.Store` interface. Sub-phases: **2a (credentials + sessions core, standalone): shipped** — `tamper/identity` Core with Register/Login/Refresh/Logout/RevokeAllSessions, ACR carry-forward, timing-parity rejections, MemStore + suite. **2b (Barista delegation): shipped** — `internal/identity` Store adapter over the users+refresh_tokens sqlc surface (bootstrap-at-insert via the firstUser signal); `AuthService.Register/Login/Refresh/Logout/issueTokens` delegate to the core (~200 lines of flow logic deleted), error mapping onto `domain.Err*` preserved, `rebuildCore` keeps `WithTOTPRequired` + the Testing seams live via receiver closures; the full auth service suite passed UNCHANGED (the parity proof). **2c-core (TOTP into the core, standalone): shipped** — two-phase enrollment (staged pending → verify → promote + mint at the enrollment instant), one-shot enroll, verify, single-use recovery codes, code-gated disable + unconditional admin clear, all over an opaque sealed envelope (`WithKeySet`); Barista's legacy TEXT dual-write column stays the adapter's concern. **2c-delegate (shipped)**: AuthService's TOTP flows onto the core. **2d-core (multi-IdP linking, standalone): shipped** — `Identity` type; `ResolveByIdentity` (repeat sign-in: active-gate then last-login bump) + `ProvisionUserWithIdentity` (first sign-in: atomic user+identity via a tx-capable Store op, `OnProvisioned` hook) as a deliberate TWO-METHOD split so the app's email-collision veto wedges between them (never in the core); `Link` (idempotent same-user, `ErrLinkConflict` cross-user, unique-violation race re-fetch), `Unlink` (password-first last-auth-method guard + IDOR-as-NotFound), `ListIdentities`. **2d-delegate (shipped — Phase 2 COMPLETE)**: AuthService's UpsertOIDCUser/UpsertSAMLUser share `upsertFederatedUser` (core Resolve → app email veto → core Provision, with the lost-first-sign-in race folded onto `ErrOIDCEmailConflict`); Link/Unlink/List delegate with pre-delegation error strings preserved; org auto-enroll rides the `OnProvisioned` hook; `txInsertUserAndIdentity` deleted (the tx lives in the adapter's `ProvisionUserWithIdentity`); the email veto + group-reconcile + token-mint stay Barista. SCIM CRUD, `EffectiveSystemRole`, `GrantSystemRole`, step-up prefs stay Barista's app layer. | Extraction-map findings baked into 2a: the ACR default is caller-supplied (Barista's `urn:barista:` values are PERSISTED in refresh rows); the first-user bootstrap is the Store's `firstUser` insert signal + `OnRegistered` hook (breaks the AuthService↔OrgService cycle — org enrollment becomes a hook, role resolution stays app-side); the wide `users` row is handled by a core-projection `identity.User` the app's Store maps from its own row. |
| **3 — federation** | OIDC / SAML / SCIM provider services over the identity core. **3a (SAML SP protocol core): shipped** — `tamper/saml` lifts Barista's `internal/auth/saml` substrate (crewjam/saml v0.5.1 wrapping: IdP metadata fetch + parse, per-IdP `Provider`/`ProviderRegistry` construction with partialOK degradation, AuthnRequest building incl. step-up ForceAuthn/RequestedAuthnContext, assertion attribute/NameID helpers, HS256-signed state cookie with mandatory purpose discrimination). Two seams stayed app-side by design: **route shapes** (tamper takes `ProviderConfig.MetadataURL` as data; Barista's façade derives it from the ACS URL so `saml_providers.acs_url` remains the single source-of-truth column) and **cookie names** (the `barista_saml_state` brand is Barista's; tamper owns the claims format). Known scope limits recorded for a later slice: crewjam types surface in the public API (`Provider.SP`, `MetadataFetcher`, assertion helpers take `*crewjamsaml.Assertion`) — a tamper-owned `ParseAssertion` view would decouple the app's ACS handler; `SetMaxClockSkew` wraps crewjam's process-global (set-once-at-boot, 1h cap; per-provider skew impossible on v0.5.x). **3b (OIDC RP protocol core): shipped** — `tamper/oidc` lifts Barista's `internal/auth/oidc` substrate (coreos/go-oidc v3 + x/oauth2 wrapping: discovery + JWKS rotation, per-IdP `Provider`/`ProviderRegistry` with partialOK degradation, PKCE `Flow` randomness, ID-token verification with nonce/audience/expiry collapse onto `ErrIDTokenInvalid`, userinfo fetch+merge with ID-token-wins precedence on security fields, `ExtractGroups` claim normalisation, HS256 state cookie). Same two seams stayed app-side: **route shapes** (`ProviderConfig.RedirectURL` is data; Barista's façade derives base + `/api/auth/oidc/callback/<id>`, honoring partialOK for derivation failures) and **cookie names**; plus a third: the **SPA open-redirect allowlist** (`redirect.go`) is pure Barista routing policy and never entered the framework. The full test suite moved with it (fake-IdP harness + end-to-end auth-code-flow integration test). **3c-core (OIDC provider Manager, standalone): shipped** — `tamper/oidc.Manager` owns the store-backed provider lifecycle over a new `ProviderStore` port (Insert/Get/List/ListEnabled/Update/UpdateSealedSecret/Delete over `ProviderRecord`, secrets SEALED at the port boundary): CRUD with `crypto.KeySet` seal/open (plaintext only at the `ProviderDefinition` boundary), the TTL-cached live registry (double-checked locking, nil-sentinel-cached-symmetrically for multi-replica convergence, eager invalidate on same-process mutation, eager `Reload`, Year-9999 `PinRegistry` test seam), the `TestDiscovery` probe, and the rotate-KEK re-seal loop. App-side seams: validation policy runs BEFORE the Manager (Barista's `domain.OIDCProvider.Validate` + allow-insecure-issuer knob), the redirect mapping is `WithRedirectURL(func(id) string)`, audit stays at the handler. **3c-delegate (shipped)**: `IdentityProviderService` is now the Barista wrapper — domain validation policy + `domain.Err*` folding with pre-delegation messages + the `domain.OIDCProvider` boundary + `oidc.CallbackURL` route composition (single-sourced with the façade's derivation) — over the `internal/idp` sqlc `ProviderStore` adapter; `Testing()` seams (SetClock/SetOIDCDiscovery/SetRegistry) delegate to the Manager's seams; the CLI rotate pass wraps `RotateSealedSecrets`. **3d-core (SAML provider Manager, standalone): shipped** — `tamper/saml.Manager` mirrors the OIDC Manager's contract exactly (same caching/pin/rotate semantics) over its own `ProviderStore` port, with the SAML-specific seams: the SP signing KEY is the sealed material (cert is public PEM text), `ParseCertPEM`/`ParsePrivateKeyPEM` moved into tamper with the log-and-omit-per-provider rebuild resilience (one mis-provisioned IdP never takes the rest down), `WithMetadataFetcher` (registry rebuild + the `TestMetadata` probe, which preserves the `ErrMetadataFetchFailed`/`ErrMetadataInvalid` sentinel chain for `errors.Is` through app wrapping), `WithSPMetadataURL(func(id, acsURL) string)` route seam, and `WithAllowIDPInitiated`/`WithSkewTolerance` flow knobs (the process-global `SetMaxClockSkew` pin stays the APP's boot call). **3d-delegate (shipped — provider services fully extracted)**: `SAMLProviderService` is now the Barista wrapper — `domain.SAMLProvider` boundary + Validate (allow-insecure-metadata knob) + `domain.Err*` folding with pre-delegation messages + `authsaml.SPMetadataURL` route seam + the process-global `SetMaxClockSkew` boot pin — over the `internal/idp` SAMLStore adapter (attribute-mapping JSON round-trips through the real `domain.SAMLAttributeMapping` for byte-identical columns); `WithFlowOptions` rebuilds the Manager (rebuildCore pattern, test-seam overrides re-applied); `saml_provider_pem.go` deleted (parsers live in tamper); the shared `boolToInt64`/pinned-cache helpers left the service package. **3e (SCIM protocol substrate): shipped — PHASE 3 COMPLETE** — `tamper/scim` lifts Barista's `internal/auth/scim`: the filter engine (`Parse` over scim2/filter-parser/v2 with the `*FilterError` envelope; `Translate` AST→SQL-WHERE now takes a caller-supplied **`ColumnMapping`** — Attrs attr→column whitelist + eq-only `Special` SQL fragments with exactly one `?` for shapes like membership-EXISTS — the mapping IS the app's schema, tamper never names a table), the RFC 7644 §3.5.2 PATCH applier (Request/Operation/Apply/ParsePath incl. filtered value-paths + audit-time `RedactedOps`), and `DetectCycle` over the `GroupMemberQueries` port. Barista keeps `filter_schemas.go` (its users/group_members mapping, incl. the EXISTS join SQL as Special data) + `filter_test.go` (pins the mapping) + a façade `Translate(expr, Schema)` wrapper. The remaining SCIM surface (espresso handlers, dto/etag/bulk HTTP plumbing, AuthService user-store mapping) is transport + app mapping — **Phase 4 (`tamper/espresso`) material, not Phase 3**. | The biggest chunk. The services are already DB-decoupled via querier interfaces; the KEK envelope (client secrets, TOTP secrets) already lives in `tamper/crypto`. |
| **4 — transport** | `tamper/espresso` adapter: mountable auth routes (login / refresh / OIDC / SAML ACS / SCIM) + `RequireAuth` / `RequireFreshAuth` / `RequireServiceAccount` middleware. Full design + sub-phase plan: [`PHASE4-TRANSPORT-PLAN.md`](PHASE4-TRANSPORT-PLAN.md). **4a (identity middleware core): shipped** — `tamper/espresso` owns RequireAuth (identity-triple stash: id + typed claims + audit actor), RequireAuthWS (subprotocol smuggling; prefix is REQUIRED config — app wire contract + anti-replay branding; two sanctioned lift fixes: VerifyAccess unification so WS composes with fresh-auth gates, injectable IPExtractor), context accessors + the TD-AUDIT-07 capture slot, the generic named-slot cookie bridge, RemoteIP, and the Auditor mutation middleware. Barista's middleware package is a façade (aliases + var re-exports — context keys have ONE owner; the runtime tripwire test guards the diverged-keys failure mode that compiles clean) + the pre-4b holdovers (SA/step-up/role gates + private shims). Documented test seams `ContextWithUserID`/`ContextWithAccessClaims` replace private-key fabrication in tests. **4b (gate middleware): shipped** — after the pre-work PR moved `RequireClusterAdmin` onto the `system.admin` PDP action (with the deny-path-only `userExists` probe preserving the pinned 401-on-ghost-user SPA contract), tamper/espresso gained: the step-up engine (`RequireFreshAuth(+WithAudit)`, per-instance `WithStepUpClock` — second sanctioned fix — denied-event audit action injected as a param since vocabulary is the app's; STEP_UP_REQUIRED envelope byte-pinned in BOTH suites), `RequireServiceAccount` over the `ServiceAccountValidator` port (`Principal{ID,Name,Description,CreatedAt}` identity card, `ErrInvalidCredential` 401-vs-500 split, RFC 7644 §3.12 envelope), and **`RequireDecision`** — the generalized PDP-gate skeleton where the org two-check 404-leak flow and the ghost probe are configuration, deny-by-default with CONFIG_ERROR on misconfiguration. Barista's three role-gate files are now pure `DecisionGate` configuration + SPA deny writers. **4c (core auth routes): shipped** — `AuthRoutes` over the `IdentityService` port (register/login/me/refresh/logout + the TOTP ceremony); `WireV1` DTOs byte-copied with `User` as an app-owned `json.RawMessage` projection; cookie `Path` derived from `MountPrefix`; `USER_INACTIVE` cookies-on-error 401 standardized; a request-scoped wide-user slot preserving single-read projection semantics. **4d (federation routes): boundary decided** ([`PHASE4D-BOUNDARY-DECISION.md`](PHASE4D-BOUNDARY-DECISION.md)) — a judge-panel design pass chose the MIDDLE path (verification spine + a single post-verify hook) over both the full-route lift (rejected: drags the audit taxonomy + wire DTOs into the framework, violating non-goals #9/#10) and primitives-only (adopted as sub-PR 4d-1). Five sub-PRs, ascending risk. **4d-1 (pure lifts): shipped** — `tamper/espresso.Redirect`/`XML` IntoResponse types (the Espresso v2 response-gap shims, D5), `StepUpSatisfied` pure predicate, and OIDC `Claims.AuthTime(nowFn)`/`ACR(fallback)` methods mirroring the SAML `ParsedAssertion` view (closing the extractor asymmetry, with the float64/int64/json.Number coercion invariant pinned). Barista's `oidcRedirect`/`samlPostInitiated`/`xmlResponse` collapse to `Redirect`/`XML`; the extractors + `stepUpSatisfied` delegate. **4d-2 (OIDC verification spine): shipped** — `StartOIDCFlow` (PKCE/nonce randomness + signed state cookie + step-up-forwarding authorize URL) and `VerifyOIDCCallback` (state-cookie verify + provider/state cross-check + code exchange + ID-token verify) as **standalone helpers** (a non-SPA consumer uses them without `Mount`); a `StateCookieConfig` owns the `__Host-` switch + invariant attributes (the app supplies the brand + Path). Sentinels `ErrOIDCState`/`ErrOIDCExchange`/`ErrOIDCNoIDToken` (+ pass-through `oidc.ErrNonceMismatch`/`ErrIDTokenInvalid`) map to the app's INVALID_STATE/IDP_ERROR/INVALID_IDTOKEN/INVALID_NONCE codes. Barista's `StartOIDC`/`StartOIDCLink`/`ExchangeOIDC` verify-prefix delegate; the redirect allowlist + the whole post-verify business tail stay app-side. Next: 4d-3 hook+Mount → 4d-4 SAML → 4d-5 registration collapse. | Core stays transport-agnostic; Espresso is the first-class adapter (flagship synergy), others possible later. |

Phases land in order — each depends on the one before. No phase begins until
the previous one has a Barista façade in production.

## The `Authorizer` — the framework's spine (shipped, Phase 1a)

```go
// Subject / Resource are small comparable structs {Type, ID string} —
// opaque, app-defined; Tamper never hard-codes a taxonomy. Groups are NOT
// subjects: group indirection is the BindingStore's concern.
type Decision struct {
	Allowed bool
	Reason  string // for audit + debugging, never for control flow
}

type Authorizer interface {
	Check(ctx context.Context, sub Subject, act Action, res Resource) (Decision, error)
	CheckBulk(ctx context.Context, reqs []CheckRequest) ([]Decision, error)
	// Reverse queries — what the UI and audit surfaces need. unbounded
	// means "not limited to an enumerable set" (e.g. a system-wide role):
	// the caller owns the resource catalog and treats it as ALL.
	ListResources(ctx context.Context, sub Subject, act Action, resourceType string) (resources []Resource, unbounded bool, err error)
	ListSubjects(ctx context.Context, act Action, res Resource) (subjects []Subject, unbounded bool, err error)
}
```

The built-in `RBAC` engine evaluates a `Policy` — per-action OR-requirements
`{Type, Min Role}` against per-type ordered role ladders (`Hierarchy`) —
over a `BindingStore` that returns EFFECTIVE bindings. Shapes generalized
from Barista's production model, deliberately including its constraints:

- Effective role = **max rank** across direct + store-resolved indirect
  bindings (Barista: `EffectiveRole` = max(manual, group-derived)).
- Group indirection lives in the store, not the engine — Barista's nested
  groups confer NO effective roles today (all joins are
  `member_type='user'`), and an engine that walked group graphs would
  silently invent inheritance the app never had.
- Cross-scope implication is only "a global role satisfies a scoped action"
  (system cluster-admin → any cluster/org), modeled as a different-type
  requirement consulting `Resource{Type, ""}` — no scope-containment graph.
- Conjunctive gates (org membership as a *precondition* for project
  visibility) are NOT in the policy language — they stay app-side
  composition, keeping every rule auditable at a glance.
- Deny-by-default is contractual: unknown actions, unknown roles (rank 0),
  and store errors all resolve to deny; misconfigured policies fail at
  `NewRBAC` (boot), not as silent per-request denies.

Backend spectrum, in adoption order:

1. **SQL-RBAC (built-in default)** — the lift of Barista's fixed-enum roles,
   group→role grants, and per-cluster ACLs. Covers the 95% case.
2. **Cedar / Casbin** — in-process ABAC when policy-as-data is needed.
3. **OpenFGA / SpiceDB** — the ReBAC escape hatch for graph-shaped authz.

The rule that makes the spectrum work: **call sites depend on the interface,
never on a concrete engine.** That is exactly what keeps "no SpiceDB today"
(the Barista assessment — disproportionate for a single-binary SQLite app) a
cheap decision instead of a locked-in one: if a future consumer needs ReBAC,
the backend swaps and no call site changes.

## End-state integration (what a new project writes)

Shipped in Phase 6 (the standalone-packaging milestone). See
[`README.md`](./README.md) for the getting-started and
[`examples/quickstart`](./examples/quickstart) for a runnable version.

```go
// 1. Build the engines. JWT is required; everything else is optional and
//    nil-encodes "not configured". Fails at wiring, never per-request.
tp, err := tamper.New(tamper.Config{
	JWT:      crypto.JWTConfig{Secret: cfg.Secret, TTL: 15 * time.Minute, Issuer: "myapp"},
	KEKs:     []crypto.KEKEntry{{ID: 1, Key: cfg.KEKHex}},
	Audit:    tamper.AuditConfig{DBPath: "audit.db"},
	Identity: &tamper.IdentityConfig{Store: myStore, Options: []identity.Option{
		identity.WithDefaultACR("urn:myapp:auth:local-password"), // ACR is an identity Option, app-supplied + persisted
	}},
	Authz: pdp, // tamper.RBAC(...) / tamper.PermissionSet(...) build one
})
defer tp.Close()

// 2. Aggregate the HTTP surface. Routes returns the surfaces for the app to
//    register — there is NO Mount (each surface spans public + authed blocks;
//    Espresso's Use is positional). Identity is REQUIRED + app-supplied: a thin
//    adapter over identity.Core (Core has no Me lookup + no session-token TOTP).
surfaces, err := tamperespresso.Routes(tp, tamperespresso.RouteConfig{
	Auth:     tamperespresso.AuthRoutesConfig{MountPrefix: "/api/auth", Cookies: ..., ProjectUser: projectUser},
	Identity: myIdentityService,
})
r.Post("/api/auth/login", espresso.Doppio(surfaces.Auth.Login))
r.Get("/api/auth/me", surfaces.RequireAuth(espresso.HandlerCtx(surfaces.Auth.Me)))
// ... register the rest of surfaces.Auth (+ Federation/SAML/SCIM when configured)

dec, err := tp.Authz.Check(ctx, subj, "doc.delete", res) // SQL-RBAC today, swappable later
```

## Open items

- ~~`tamper/audit/sqlitestore` has no sqlc generator wired.~~ **Shipped
  (Phase 6 slice 1)**: `packages/tamper/sqlc.yaml` + a `moon run tamper:sqlc`
  target regenerate it (single-driver SQLite, so no build-tag re-injection),
  and `TestSchemaMigrationParity` now guards `schema.sql` against migration
  drift (the guard `schema.sql`'s header had long advertised but never had).
- **Phase 6 — standalone packaging: shipped.** The composition facade
  (`tamper.New(Config)` + `tamper/espresso.Routes(tp, RouteConfig)`), a
  `README.md`, and a runnable `examples/quickstart` all landed; `doc.go` was
  corrected to cover every shipped subpackage. One design correction vs the
  original sketch: `RouteConfig.Identity` is **required + app-supplied**, not
  defaulted to `tp.Identity` — `identity.Core` cannot satisfy the
  `IdentityService` port (no `Me`, no session-token TOTP ceremony, divergent
  return shapes), so the app wraps it (see the quickstart's `coreIdentity`).
  `v0.1.0` is tagged in place on the monorepo (`packages/tamper/v0.1.0`); the
  physical repo-split to a clean import path is a later milestone.
- ~~Phase 1 `Authorizer`: decide `Subject`/`Resource` representation~~
  **Settled (Phase 1a)**: small comparable structs `{Type, ID string}`;
  reverse queries return `(set, unbounded, err)` so global grants don't
  force the PDP to enumerate the app's resource catalog.
- ~~Phase 1b — Barista adapter~~ **Shipped**: `internal/authz` implements
  `BindingStore` over `users.system_role` + `cluster_user_roles` +
  `group_roles` (direct `group_members` only — nested groups confer
  nothing, guaranteed at the store layer), and `RequireClusterRole`
  consults the PDP. The system-admin bypass inconsistency was resolved by
  unifying both `ClusterACLService` legs on `EffectiveSystemRole`
  (group-promoted admins now work on the cluster path like everywhere
  else).
- ~~Phase 1c — org gate~~ **Shipped**: `org_members` bindings in the
  store, the three org tiers in the policy (`org.view` / `org.manage` /
  `org.own`, system bypass = EffectiveOrgRole's implicit owner), and
  `RequireOrgMember` consults the PDP via a **two-check flow** that
  preserves the cross-org leak rule: deny on `org.view` → 404
  ORG_NOT_FOUND (membership invisible), deny on the tier action → 403
  INSUFFICIENT_ORG_ROLE. Pattern note: "distinguish 404 from 403" maps
  onto the PDP as two actions, not a special decision shape.
- **Project gates stay service-side** (deliberate): project checks have
  no middleware seam — they ARE the authoritative in-handler/service
  checks (`GetWithRole` + `HasAtLeast`, implicit owner via
  `projects.owner_id`, org-membership precondition as an AND-composition
  the policy language deliberately excludes). Moving them means replacing
  service-layer authority, which is a Phase-2-adjacent decision, not an
  edge-gate migration.
- Repo split criteria: tag the first standalone `tamper` version once
  Phase 2 (identity core) has survived a full Barista release cycle.
  **Gate met**: Phase 2 shipped and Phases 3/4/5 built on top across
  multiple Barista releases, so `packages/tamper/v0.1.0` is cut in place.
  The remaining step — renaming the module to
  `github.com/suryakencana007/tamper` and splitting the repo — is deferred
  to its own milestone (it is breaking: every import + Barista's
  `require`/`replace` rewrites for only a cleaner import string).
