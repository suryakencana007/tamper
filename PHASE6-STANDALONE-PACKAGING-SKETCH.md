# Phase 6 — Standalone Packaging (design freeze)

> Status: **design freeze** (Slice 0). This is the gate doc for the packaging
> milestone. It records the facade design, the resolved forks, and the slice
> plan. Nothing below changes an existing tamper API — every addition is
> greenfield sugar over the per-subpackage constructors that already ship.

## Why this milestone

The extraction is *functionally* done: Phases 0–4 shipped `crypto`, `audit`,
`authz`, `identity`, `oidc`, `saml`, `scim`, and the `espresso` transport
adapter, and **Barista has zero reverse-dependency on the framework** — every
`packages/tamper` import flows one way. What's missing is the last mile that
makes tamper adoptable by a *new* project:

1. **No composition facade.** A greenfield consumer must hand-wire ~7
   subpackage constructors in the right dependency order. There is no
   `tamper.New()` / `Routes()` — the root package is `doc.go`-only.
2. **Stale root docs.** `doc.go` lists only `crypto` + `audit` as shipped and
   calls `authz` a "Phase 1 — next up" skeleton; it omits `identity`, `oidc`,
   `saml`, `scim`, `espresso` entirely. The `TAMPER-DESIGN.md:263–270`
   end-state snippet uses `router.Mount(...)`, which **does not compile**
   (Espresso has no `Mount`).
3. **No README / runnable example.** Nothing shows the real integration path.
4. **A sqlc gap.** `audit/sqlitestore` ships generated code but has no
   `sqlc.yaml` / regen target (flagged at `TAMPER-DESIGN.md:275–280` and in
   Barista's `sqlc.yaml`), and `audit/sqlitestore/schema.sql:6` advertises a
   `TestSchemaMigrationParity` guard that **does not exist**.
5. **No version tag.** Zero `packages/tamper/*` tags — external consumers have
   nothing to `go get`.

This milestone closes 1–5. It does **not** rename the module path or split the
repo — those are a separate, later milestone (see Forks below).

## Decisions (frozen)

### User forks — resolved 2026-07-21

| Fork | Decision |
|---|---|
| **(a) Dogfood strategy** | **Standalone example**, not a Barista refactor. Build `examples/quickstart` wiring `tamper.New` + `Routes` end-to-end; Barista's wiring is left as-is. Barista is the extraction *source*, not a clean consumer — it wires its own `service.NewAuthService` (`main.go:1354`) and `baristaauthz.New` PDP (`main.go:1408`), which the facade's `identity.Core` / bare-engine defaults deliberately don't match. Barista already proves the engines per-subpackage; a greenfield example is the honest dogfood, mirroring how Espresso ships its own example apps. |
| **(b) First-cut scope** | **In-monorepo, defer the split.** Ship the facade + `doc.go` refresh + README + example + tamper-side sqlc + a `v0.1.0` tag, all in the monorepo. The physical repo-split + module rename is a separate later milestone. Non-breaking; Barista's `require`/`replace` (`apps/barista/go.mod:213,215`) is unchanged. |
| **(c) Versioning** | **Tag `packages/tamper/v0.1.0` in place** after the facade + example + docs land. Go's nested-module convention resolves the subdir tag (`go.mod` lives at `packages/tamper/go.mod`); no split is needed to tag. `v0.x` signals "API not frozen." |
| **(d) Eventual clean module path** | **`github.com/suryakencana007/tamper`** (mirrors Espresso's own `/espresso/v2` path). Decided now for an unambiguous split milestone, but **executed only at the split**. `v0.1.0` ships on the nested `github.com/suryakencana007/barista/packages/tamper` path, and the README says so explicitly. |

### Engineering calls — decided without a fork (recorded for the reviewer)

- **(e) `Authz` + `Identity` are nil-optional interface fields**, not
  Config-builds-from-stores. The app may pre-build its PDP / identity service
  and drop it in; greenfield users get one-liners via thin
  `tamper.RBAC(store, h, p)` / `tamper.PermissionSet(store)` helpers that
  *return* an `authz.Authorizer`. This keeps the flagship (which brings its
  own `baristaauthz.New` and `AuthService`) inside the contract.
- **(f) Surfaces-only, no `Register` helper** in the first cut. `Routes`
  returns `*Surfaces`; the app writes its own `r.Get`/`r.Post`. A single
  `Register(r, *Surfaces)` cannot express Barista's real ordering (public
  block → `r.Use(RequireAuth)` snapshot → per-cluster decision gates →
  `RequireServiceAccount` wrap), and SCIM is raw `net/http` while
  Auth/Fed/SAML are Espresso-typed. YAGNI until a second consumer asks.
- **(g) Audit stays port-emitted (A3).** `Provider` exposes `tp.Audit`;
  `Routes` threads it **down** into SCIM / federation port-impl construction —
  it does **not** wrap those surfaces in an `Auditor`. Centralizing emission at
  the transport would re-read state and break the byte-identical audit rows the
  lift preserved (`scim/store.go` `WriteMeta.Before` single-read invariant).
  The `Auditor` stays for the app's *own* espresso mutation routes.
- **(h) Close the sqlc gap** (Slice 1): add `packages/tamper/sqlc.yaml` +
  moon target + the advertised-but-missing `TestSchemaMigrationParity` test.

## The facade — two additive layers

Neither layer changes an existing API. Both are greenfield sugar over the
per-subpackage constructors.

### Layer 1 — root `tamper` package: the engine bundle (boot-once)

```go
package tamper

// Config is the single boot input. Store impls + policy stay app-supplied leaves.
type Config struct {
    // JWT required. New() validates Secret!="" and returns an error
    // (crypto.NewJWTService panics on empty; New guards first).
    JWT crypto.JWTConfig // {Secret, TTL, Issuer}

    // KEKs seal at-rest secrets (identity TOTP envelope, OIDC/SAML provider
    // secrets, app webhook secrets). Empty => tp.KeySet==nil, mirroring
    // crypto.NewKeySet's (nil,nil) contract; callers gate "sealing configured"
    // on tp.KeySet!=nil exactly as today.
    KEKs       []crypto.KEKEntry
    WriteKeyID uint8

    // Audit: DBPath!="" => SQLite hash-chain logger; "" => Noop. Always non-nil.
    Audit struct {
        DBPath      string
        EmailLookup audit.EmailLookup // optional
    }

    // Authz: app supplies a BUILT PDP. Optional; nil leaves tp.Authz nil and
    // RequireDecision unusable. Greenfield helpers tamper.RBAC(store,h,p) /
    // tamper.PermissionSet(store) return an authz.Authorizer to drop in here.
    Authz authz.Authorizer

    // Identity: OPTIONAL engine build. Store!=nil => New builds identity.Core
    // (jwt+keyset auto-threaded) exposed as tp.Identity. Apps with a richer
    // service (Barista's AuthService) leave this nil and pass their own
    // IdentityService to Routes instead (Fork a rationale).
    Identity *struct {
        Store   identity.Store
        Options []identity.Option // WithRefreshTTL/WithTOTPRequired/WithDefaultACR/WithHooks...
    }

    // OIDC/SAML: OPTIONAL federation engines. Store nil => manager nil =>
    // Routes skips the surface. RedirectURL / SPMetadataURL are the
    // manager-REQUIRED options — validated at New().
    OIDC *struct {
        Store       oidc.ProviderStore
        RedirectURL string        // oidc.WithRedirectURL (required for non-empty registry)
        TTL         time.Duration // oidc.WithTTL
    }
    SAML *struct {
        Store             saml.ProviderStore
        SPMetadataURL     string        // saml.WithSPMetadataURL (required)
        TTL               time.Duration
        AllowIDPInitiated bool
        SkewTolerance     time.Duration
    }
}

// Provider is the constructed engine bag. Every field mirrors a subpackage
// constructor's output; nils encode "not configured" the same way the
// subpackages already do.
type Provider struct {
    JWT      *crypto.JWTService // always
    KeySet   *crypto.KeySet     // nil when KEKs empty
    Audit    audit.Logger       // always non-nil (Noop fallback)
    Authz    authz.Authorizer   // nil unless Config.Authz set
    Identity *identity.Core     // nil unless Config.Identity.Store set
    OIDC     *oidc.Manager      // nil unless Config.OIDC.Store set
    SAML     *saml.Manager      // nil unless Config.SAML.Store set
}

func New(cfg Config) (*Provider, error) // fail-at-wiring: bundles the ~7 constructors
```

`New()` runs the DAG rooted at `JWTService` + `KeySet`:
`JWT → KeySet → {Audit, Identity.Core(jwt,keyset), OIDC.Manager(keyset), SAML.Manager(keyset)}`;
`Authz` passes through. Validation mirrors each `NewXxx` (empty secret, empty
`OIDC.RedirectURL` when `Store` set, empty `SAML.SPMetadataURL` when `Store`
set, …), so a misconfig **fails boot, never a per-request deny**.

### Layer 2 — `tamper/espresso`: the transport aggregator (respects A10 — no `Mount`)

```go
package espresso

// RouteConfig carries the transport-layer policy the engines can't own.
type RouteConfig struct {
    // --- Auth surface (always built) ---
    MountPrefix     string // "/api/auth"; cookie Path derives from this
    Cookies         CookieConfig
    ProjectUser     func(context.Context, *identity.User) json.RawMessage // required, app DTO
    IdentityService IdentityService // REQUIRED, app-supplied (see correction below)
    // optional: ValidationMessage, OnAuthenticated, OnTOTPEnrolledViaSession
    //
    // CORRECTION (Slice 3, as-built): this was sketched as "defaults to
    // tp.Identity when nil", but that is INFEASIBLE — identity.Core cannot
    // satisfy IdentityService: it has no Me (user-by-id; Core hides its Store),
    // no session-token TOTP trio (IssueTOTPPending/VerifyTOTPPending/
    // EnrollTOTPViaSession — that ceremony token is app policy), and its
    // Register/Login/Refresh return (User, Tokens, error) not (AuthResult,
    // error). So Identity is REQUIRED and the app wraps identity.Core (the
    // quickstart's coreIdentity adapter shows the ~90-line shape).

    // --- Federation policy (used only when tp.OIDC!=nil). Registry hook is
    //     AUTO-WIRED from tp.OIDC.GetRegistry; app supplies the tail. ---
    Federation *struct {
        LandingPath         string
        StateSecret         []byte
        StateCookie         StateCookieConfig // SameSite must be explicit
        OnFederatedExchange func(context.Context, *oidc.Provider, OIDCVerified) (FederationOutcome, error) // required
        SanitizeRedirect    func(string) string
        CallingUserID       func(context.Context) string
    }

    // --- SAML policy (used only when tp.SAML!=nil) ---
    SAML *struct {
        StateCookie          StateCookieConfig // SameSite=None under Secure (cross-site ACS POST)
        OnFederatedAssertion func(context.Context, *saml.Provider, SAMLVerified) (SAMLOutcome, error)
        LinkRedirect         func(providerID string) string // required for LinkStart
        SanitizeRedirect     func(string) string
    }

    // --- SCIM (raw net/http shape; used only when set) ---
    SCIM *struct {
        SCIMConfig                        // Prefix/BaseURL/BulkMax/MaxResults/...
        Users           scim.UserStore    // required; port impl emits audit (A3)
        Groups          scim.GroupStore   // required
        ServiceAccounts ServiceAccountValidator
    }
}

// Surfaces bundles what the app registers. NO Mount: each surface spans
// public+authed blocks and Espresso's Use is positional, so one Mount can't
// express Barista's real wiring.
type Surfaces struct {
    Auth       *AuthRoutes       // always
    Federation *FederationRoutes // nil when tp.OIDC==nil
    SAML       *SAMLRoutes       // nil when tp.SAML==nil
    SCIM       *SCIMRoutes       // nil when RouteConfig.SCIM==nil
    Auditor    *Auditor          // for the app's OWN espresso mutation routes

    // Bound middleware (engine already applied):
    RequireAuth           func(http.Handler) http.Handler
    RequireAuthWS         func(subprotoPrefix string) func(http.Handler) http.Handler
    RequireServiceAccount func(http.Handler) http.Handler // nil unless SCIM set
    // RequireDecision stays a per-gate app closure (DecisionGate is app policy).
}

func Routes(tp *tamper.Provider, cfg RouteConfig) (*Surfaces, error)
```

`Routes()` constructs each `NewXxxRoutes` from `tp` + `cfg`, auto-wires
`FederationHooks.Registry = tp.OIDC.GetRegistry` /
`SAMLHooks.Registry = tp.SAML.GetRegistry`, threads `tp.Audit` **down** into
SCIM / federation port-impl construction (A3 — it does *not* wrap SCIM in an
`Auditor`), and returns the surfaces. **The app writes `r.Get`/`r.Post`
itself.** No `Register(r, *Surfaces)` convenience in the first cut — the
example demonstrates explicit registration, which is the only shape that
expresses public/authed/gated blocks (Fork f).

### What the app still supplies (unchanged by the facade)

1. All `Store` impls (identity / authz / oidc / saml / scim) — leaves.
2. The espresso `*Router` and every route path + `r.Get`/`r.Post` call (A10).
3. Policy hooks: `ProjectUser`, `OnFederatedExchange`, `OnFederatedAssertion`,
   `SanitizeRedirect`, `LinkRedirect`, `DecisionGate` deny-writers,
   `EmailLookup`.
4. Its own `IdentityService` adapter when richer than `Core` — Barista wraps
   `*service.AuthService`, folding `domain.Err*` → `identity.Err*`. The facade
   does **not** force `Core`.
5. `ServiceAccountValidator`.
6. Audit *emission* at the port impls (A3).
7. The type-**alias** re-export façades (context keys must have one owner — the
   exit-3 chain-guard hazard).
8. Barista-specific ACR config + the three audit boot guards
   (`bootstrapAuditChainRestart` / `Migrate` + `VerifyChainPostMigration`
   exit-3, `main.go:1283–1315`) — product behavior, not framework; stays in
   `main.go`.

## Doc corrections this milestone lands

- **`TAMPER-DESIGN.md:263–270`** — the `router.Mount("/api/auth",
  tamperespresso.Routes(tp))` snippet is replaced with the **surfaces-return**
  shape (`Routes` returns `*Surfaces`; the app registers them explicitly).
  `Mount` does not exist in Espresso.
- **`doc.go`** — rewritten to cover Phases 1–4: `authz`, `identity`, `oidc`,
  `saml`, `scim`, `espresso` are all **shipped**, not "skeleton / next up."
- **`TAMPER-DESIGN.md:275–280` Open items** — sqlc marked DONE, facade marked
  SHIPPED, and the split-gate evidence pinned to the concrete `vX.Y.0` in which
  Phase 2 landed.

## Slice plan (each shippable + testable; design-gated on this doc)

- **Slice 0 — Design freeze.** *This doc.* Records the facade shapes, resolves
  Forks a/b/c/d. Ship = the doc. Gate for everything below.
- **Slice 1 — Truth-up + sqlc hygiene** (no public API; pure win). (a) Rewrite
  `doc.go` for Phases 1–4. (b) Add `packages/tamper/sqlc.yaml` (engine=sqlite,
  v1.30.0, emit flags matching the audit gen output; single-driver, so no
  tag-injection wrapper) + a plain `sqlc generate` moon target. (c) Write the
  missing `TestSchemaMigrationParity` test. Gate: regen-and-diff is
  byte-identical; the parity test passes; `moon run tamper:sqlc` green.
  Independent of the facade.
- **Slice 2 — Provider facade** (root `tamper`). `New(Config) (*Provider,
  error)` + `Config`/sub-configs, bundling the ~7 constructors as the DAG.
  Fail-at-wiring validation mirroring each `NewXxx`. Ship the
  `tamper.RBAC` / `tamper.PermissionSet` helpers (Fork e). Unit tests only,
  zero Barista touch: `New` builds each engine; nil-optionality; each
  validation error.
- **Slice 3 — Routes aggregator** (`tamper/espresso`). `Routes(tp, RouteConfig)
  (*Surfaces, error)` returning the 4 surfaces + `Auditor` + bound middleware,
  no `Mount`. Auto-wire the registry hooks; thread `tp.Audit` into the port
  impls (A3, not an `Auditor` wrap); handle the espresso-typed-vs-raw-net/http
  SCIM split. No `Register` (Fork f). Unit tests: `Surfaces` fields
  populated/nil per `RouteConfig`; `RequireServiceAccount` nil unless SCIM.
- **Slice 4 — Dogfood example** (`examples/quickstart`). A runnable
  `example_test.go` (+ optional minimal `main`) wiring `tamper.New` +
  `Routes` against a SQLite-backed `identity.Store` + `identity.Core`,
  registering the surfaces on a real espresso `Router`, exercising
  register → login → me → refresh through `httptest` end-to-end. **This is the
  dogfood** that substitutes for a Barista refactor (Fork a) and the source the
  README derives from.
- **Slice 5 — README + version tag + doc reconcile.** Derive `README.md` from
  the Slice-4 example (getting-started + the corrected surfaces-return snippet).
  Update `TAMPER-DESIGN.md` Open items + pin the split-gate evidence. Cut
  `packages/tamper/v0.1.0` (in-place subdir tag; Barista's `replace`
  unchanged). Ship = installable `v0.1.0` + adoptable docs.
- **(DEFERRED — own milestone)** Physical repo-split / module-path rename to
  `github.com/suryakencana007/tamper` + optional Barista adoption of the
  `Provider` bundle. Explicitly out of this first cut (Fork b).

## Versioning + module path

- **Now:** tag `packages/tamper/v0.1.0` in place (Slice 5). Go resolves the
  nested-module tag against `packages/tamper/go.mod`. `v0.x` = API not frozen.
- **Barista:** keeps its `require` +
  `replace ... => ../../packages/tamper` (`apps/barista/go.mod:213,215`)
  unchanged — the tag is for external consumers, Barista still builds from the
  workspace.
- **Later (deferred milestone):** rename the module path to
  `github.com/suryakencana007/tamper`, rewriting every internal import + the
  Barista `require`/`replace`. The README written this milestone states the
  nested path is temporary and names the successor.

## Non-goals (this milestone)

- No repo-split / module-path rename (deferred).
- No Barista refactor onto the facade (Fork a = example; Barista adoption is
  deferred).
- No `Register(r, *Surfaces)` helper (Fork f; add only on a real second
  consumer).
- No new engine behavior — the facade is pure composition over shipped
  constructors.

## Gates

- Slice 1: `sqlc generate` byte-identical diff; `TestSchemaMigrationParity`
  passes; `moon run tamper:sqlc` + `tamper:test` green.
- Slices 2–4: `moon run tamper:test` (race) + `tamper:lint` green; the
  Slice-4 example test proves the facade compiles + works against the real API.
- Slice 5: `go get` of the `v0.1.0` tag resolves for an external module (smoke
  the README snippet).
