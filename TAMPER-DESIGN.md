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
- **`authz/`** — doc stub only. Phase 1, next up.

## The extraction playbook (proven twice — reuse it verbatim)

Every lift follows the same four steps, and Barista stays green throughout:

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
| **1 — authz spine** | `Authorizer` PDP interface + SQL-RBAC backend, lifted from Barista's fixed-enum roles + `group_roles` + cluster-ACL pattern | The scope taxonomy (system/org/project/cluster) becomes the *app's instantiation*, not hard-coded. Pairs with Barista's deferred custom-role RBAC (Option 4) — but the interface lands first over fixed-enum SQL-RBAC. |
| **2 — identity core** | users / credentials / refresh-session rotation + revocation / TOTP enrollment / `user_identities` multi-IdP linking, behind a store interface with the sqlite impl as default | Barista's sqlc queries lift nearly wholesale; ACR values configurable (the seam already exists in the façade). |
| **3 — federation** | OIDC / SAML / SCIM provider services over the identity core | The biggest chunk. The services are already DB-decoupled via querier interfaces; the KEK envelope (client secrets, TOTP secrets) already lives in `tamper/crypto`. |
| **4 — transport** | `tamper/espresso` adapter: mountable auth routes (login / refresh / OIDC / SAML ACS / SCIM) + `RequireAuth` / `RequireFreshAuth` / `RequireServiceAccount` middleware | Core stays transport-agnostic; Espresso is the first-class adapter (flagship synergy), others possible later. |

Phases land in order — each depends on the one before. No phase begins until
the previous one has a Barista façade in production.

## The `Authorizer` — the framework's spine (Phase 1 sketch)

```go
// Subject / Action / Resource are opaque, app-defined identifiers.
// Tamper never hard-codes a resource taxonomy.
type Decision struct {
	Allowed bool
	Reason  string // for audit + debugging, never for control flow
}

type Authorizer interface {
	Check(ctx context.Context, sub Subject, act Action, res Resource) (Decision, error)
	CheckBulk(ctx context.Context, reqs []CheckRequest) ([]Decision, error)
	// Reverse queries — what the UI and audit surfaces need.
	ListResources(ctx context.Context, sub Subject, act Action, typ ResourceType) ([]Resource, error)
	ListSubjects(ctx context.Context, act Action, res Resource) ([]Subject, error)
}
```

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

```go
tp, err := tamper.New(tamper.Config{
	Store:  tampersqlite.Open("auth.db"),
	JWT:    tamper.JWTConfig{Secret: cfg.Secret, TTL: 15 * time.Minute},
	ACR:    tamper.ACRConfig{Password: "urn:myapp:auth:local-password"},
})

router.Mount("/api/auth", tamperespresso.Routes(tp)) // login/refresh/OIDC/SAML/SCIM
router.Use(tamperespresso.RequireAuth(tp))

dec, err := tp.Authz.Check(ctx, subj, "doc.delete", res) // SQL-RBAC today, swappable later
```

## Open items

- `tamper/audit/sqlitestore` has no sqlc generator wired (schema is
  byte-identical to Barista's original today; no drift yet). Add a
  tamper-side sqlc config + moon target — or document manual regen — before
  the audit schema next changes. Flagged in Barista's `sqlc.yaml`.
- Phase 1 `Authorizer`: decide `Subject`/`Resource` representation (string
  ids vs typed structs) against the reverse-query requirements before
  writing the interface.
- Repo split criteria: tag the first standalone `tamper` version once
  Phase 2 (identity core) has survived a full Barista release cycle.
