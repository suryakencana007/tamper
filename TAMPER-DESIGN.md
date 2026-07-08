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
  `BindingStore`, and `MemStore` (reference store + test double). Phase 1a —
  engine shipped; the Barista adapter (1b) is the remaining leg.

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
| **1 — authz spine** | `Authorizer` PDP interface + RBAC engine over a pluggable `BindingStore`, generalized from Barista's fixed-enum roles + `group_roles` + cluster-ACL pattern. **1a (interface + engine + MemStore): shipped. 1b (Barista adapter): shipped** — `internal/authz` implements `BindingStore` over the real tables (no new SQL), registers Barista's hierarchy + policy, and the per-cluster HTTP-edge gates (`RequireClusterRole`) consult the PDP. The system-admin bypass inconsistency was fixed en route (both `EffectiveRole` legs now honor group-promoted admins via `EffectiveSystemRole`). | The scope taxonomy (system/org/project/cluster) becomes the *app's instantiation*, not hard-coded. Pairs with Barista's deferred custom-role RBAC (Option 4) — but the interface lands first over fixed-enum SQL-RBAC. |
| **2 — identity core** | users / credentials / refresh-session rotation + revocation / TOTP enrollment / `user_identities` multi-IdP linking, behind a store interface with the sqlite impl as default | Barista's sqlc queries lift nearly wholesale; ACR values configurable (the seam already exists in the façade). |
| **3 — federation** | OIDC / SAML / SCIM provider services over the identity core | The biggest chunk. The services are already DB-decoupled via querier interfaces; the KEK envelope (client secrets, TOTP secrets) already lives in `tamper/crypto`. |
| **4 — transport** | `tamper/espresso` adapter: mountable auth routes (login / refresh / OIDC / SAML ACS / SCIM) + `RequireAuth` / `RequireFreshAuth` / `RequireServiceAccount` middleware | Core stays transport-agnostic; Espresso is the first-class adapter (flagship synergy), others possible later. |

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
