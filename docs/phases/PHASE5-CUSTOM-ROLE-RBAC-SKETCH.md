# Phase 5 — Custom-Role RBAC (Authorizer Option-4)

> Status: **DESIGN FREEZE (Slice 0)**. Decision provenance: the user chose this
> milestone on 2026-07-19 after Phase 4 (transport) completed, and answered the
> four load-bearing product forks (below). This doc gates the implementation the
> way `PHASE4E-SCIM-SKETCH.md` / `PHASE4D-BOUNDARY-DECISION.md` gated theirs.
> No code lands until this is reviewed.

## 1. What this is

Barista's authorization runs on the tamper `Authorizer` PDP
(`packages/tamper/authz/authz.go`) with exactly one engine behind it: a
**rank-ladder RBAC** (`rbac.go`) — roles are fixed Go-const enums at four
scopes (system / org / project / cluster), "permissions" are hardcoded dotted
verbs, and `/admin/roles` is a read-only reference hub. There is **no
role-definition or permission table anywhere**.

"Custom-role RBAC" = operator-defined roles as **named permission-sets**, stored
as data, assignable per resource, evaluated behind the **unchanged** `Authorizer`
interface. This is the "Option-4" that the Phase-1 authz design
(`TAMPER-DESIGN.md`) built the pluggable-engine seam to anticipate — the call
sites depend on the interface, never a concrete engine, so the engine can be
swapped with zero call-site churn.

## 2. Scope (the four forks, as decided)

| Fork | Decision | Consequence |
|---|---|---|
| **Target scope** | **Cluster/infra ACLs only** | The cluster-first pilot IS the deliverable. Org/project/system stay enum-based. **No** deferred project service-authority migration is committed. |
| **Catalog granularity** | **Coarse first** | Seed the catalog from today's cluster verbs (`cluster.view`/`deploy`/`manage`). Finer keys are a purely additive later move. |
| **Combinator** | **Purely additive union** | Effective permissions = union of every built-in + custom role a subject holds (group grants included). System-admin becomes an explicit `*` superuser key. **No** deny/negative grants. |
| **SCIM provisioning** | **Manual-only** | `source='manual'` on custom-role rows for forward-compat, but no SCIM wiring. |

### Why coarse-first still delivers value

With three coarse cluster verbs the rank ladder can only express three roles —
each a **downward-closed** prefix: viewer `{view}` ⊂ deployer `{view,deploy}` ⊂
admin `{view,deploy,manage}`. The value of custom roles even at this granularity
is the **non-downward-closed** subsets the ladder *cannot* represent:

- `{view, manage}` — administer ACLs / set defaults but **cannot deploy
  workloads** (a separation-of-duty auditor/operator).
- `{view, deploy}` without `manage` — already exists as the deployer rank, so
  it's not new; the genuinely new roles are the ones that skip a middle rung.

That is exactly the class of role operators ask for and today cannot have. If a
concrete need appears for finer control (e.g. split `cluster.manage` into
`cluster.acl.grant` / `cluster.setdefault` / `cluster.delete`), that is an
**additive** catalog change — a new key + its enforcement site — not a redesign.

### Explicit non-goals (OUT of Phase 5)

- Org / project / system **custom** roles (those scopes keep fixed enums).
- Migrating **project** authority onto the PDP (project checks stay service-side
  — owner-implicit via `projects.owner_id`, the org-membership AND-precondition,
  the 404-vs-403 cross-org leak rule). Custom roles never reach service-side
  checks; the cluster pilot deliberately avoids this.
- **Deny / negative** grants and cross-role composition constraints.
- **SCIM** provisioning of custom roles or their assignments.
- **Finer** permission keys beyond the seeded coarse verbs.
- Any Cedar/Casbin/OpenFGA/SpiceDB backend — SpiceDB stays disproportionate
  (breaks single-binary + SQLite); the interface already permits it later if a
  real consumer appears.

## 3. Engine: a set-based `PermissionSet` Authorizer (subsumes the rank ladder)

**The rank engine cannot be extended to do this.** `RBAC.effective()`
(`rbac.go:184`) returns the **max rank** across a subject's bindings, and `Check`
allows when that rank `>= req.Min`'s rank (`rbac.go:59`). That comparator
*assumes downward-closure* — a rank-N role implies every permission at rank ≤ N —
so it structurally cannot represent "grant `view` + `manage` but not `deploy`."

**Sets subsume ranks.** Model each role as a **set of permission keys**; a
`Check(sub, act, res)` allows iff `act` is in the **union** of the permission
sets of every role the subject holds on `res` (plus global roles). A ladder role
is just the set of all keys at-or-below its rank, and a higher ladder role's set
is a superset of a lower one's — so one set engine reproduces **every** shipped
decision AND admits arbitrary custom subsets.

### 3.1 New engine + new store port (both additive; `RBAC` untouched)

Add to `packages/tamper/authz`:

- **`PermissionSet`** — a second `Authorizer` implementation. Pure
  set-membership evaluator; holds no taxonomy. `Check` = "is `act` in the
  effective permission set for `(sub, res)`?". Deny-by-default preserved:
  unknown action ⇒ not in any set ⇒ deny (nil error); store error ⇒ error
  (callers treat as deny). `CheckBulk` loops `Check`. `ListResources` /
  `ListSubjects` get set-shaped reverse queries (§3.3).
- **`PermissionStore`** — the engine's port, a sibling to `BindingStore`. It
  returns **effective permission keys**, not roles — role→keys resolution,
  built-in+custom union, group indirection, and the `*` superuser all live
  **store-side**, exactly as group indirection lives in `BindingStore` today
  (`store.go:15-25` — "an engine that walked group graphs itself would silently
  invent inheritance the application never had"). The engine stays a dumb,
  auditable set test.

`RBAC` and `BindingStore` are **not modified** — they remain the framework's
default engine for other consumers. Phase 5 adds a parallel engine; Barista
repoints its own `internal/authz.New` at it (Slice 3).

Proposed `PermissionStore` shape (final signatures settled in Slice 1):

```go
// PermissionStore supplies the PermissionSet engine with EFFECTIVE permission
// keys. Like BindingStore, all indirection (group grants, built-in enum role
// → key expansion, custom role_permissions rows, the '*' superuser) is the
// store's concern; the engine only tests membership. Safe for concurrent use.
type PermissionStore interface {
    // PermissionsFor returns the union of permission keys sub holds on exactly
    // res (same Type AND ID; an empty ID is the global/type-level query). A
    // returned "*" means superuser — the engine treats it as "every key".
    PermissionsFor(ctx context.Context, sub Subject, res Resource) (PermissionSetResult, error)

    // ResourcesWithPermission enumerates concrete resources (ID != "") of the
    // given type on which sub holds key. Fuel for ListResources. unbounded=true
    // when a global grant (e.g. '*') makes the set non-enumerable.
    ResourcesWithPermission(ctx context.Context, sub Subject, key string, resourceType string) (resources []Resource, unbounded bool, err error)

    // SubjectsWithPermission enumerates subjects holding key on exactly res.
    // Fuel for ListSubjects.
    SubjectsWithPermission(ctx context.Context, key string, res Resource) ([]Subject, error)
}

// PermissionSetResult carries the effective key set plus the superuser flag so
// the engine never has to string-scan for "*".
type PermissionSetResult struct {
    Keys       map[string]struct{}
    Superuser  bool // '*': allow any key on this resource
}
```

### 3.2 Byte-parity construction (built-ins reproduce the ladders exactly)

Barista's `internal/authz.New` builds **one** Authorizer used for **all four
scopes' actions** (`policy.go:176`), so the `PermissionSet` engine must
reproduce **cluster, org, AND system** decisions byte-identically — not just
cluster. The Barista `PermissionStore` adapter seeds every built-in role's key
set as the downward-closure of its rank under the shipped `Policy()`
(`policy.go:102`):

| Built-in role (scope) | Seeded permission-key set |
|---|---|
| `cluster-viewer` | `{cluster.view}` |
| `cluster-deployer` | `{cluster.view, cluster.deploy}` |
| `cluster-admin` | `{cluster.view, cluster.deploy, cluster.manage}` |
| `org-member` | `{org.view}` |
| `org-admin` | `{org.view, org.manage}` |
| `org-owner` | `{org.view, org.manage, org.own}` |
| system `cluster-admin` (global `{system,""}`) | `*` (superuser) |
| system `user` | `{}` |

The system bypass — today an OR-requirement on the `{system,""}` singleton that
satisfies every cluster + org action + `system.admin` (`policy.go:103-138`) — maps
to the single `*` key on the system role, which the engine treats as "every key."

> **The bypass does not disappear — it RELOCATES, and that is the sharpest trap
> in this design.** Today the system→cluster and system→org containment is
> declared *once* (the `systemBypass` Requirement literal, `policy.go:103-106`,
> reused across all 7 actions) and the **RBAC engine** performs the cross-scope
> redirect (`rbac.go:50-53`: when `req.Type != res.Type`, re-query
> `Resource{Type: req.Type}`). Barista's current `BindingStore` is oblivious —
> `clusterBindings` reads only `cluster_user_roles` + `group_roles`, never the
> system role. In the set model there is no `Policy` and no engine redirect, so
> **`PermissionsFor(sub, res)` MUST itself fold the global system `*` into every
> resource-scoped query — cluster, org, AND system** — or the bypass silently
> vanishes. This is imperative scope-containment in the adapter, and it is
> exactly the "adapter carries a latent deviation invisible until wired" (4e-2)
> trap. A naive `PermissionsFor(sub, cluster:c1)` = "keys from cluster-scoped
> roles only" would DENY an inline system cluster-admin who has no
> `cluster_user_roles` row, where RBAC ALLOWS via the bypass.

**Custom cluster roles** contribute their `role_permissions` rows (subsets of
`{cluster.view, cluster.deploy, cluster.manage}`) to the same union.

Byte-parity holds because with **no custom-role rows present**, `PermissionsFor`
returns exactly the built-in sets above (including the folded-in global `*` per
the box above), and `key ∈ union` ⟺ `max-rank ≥ req.Min` for every shipped
`(action, requirement)` pair. No shipped action has two *same-type* alternatives
(each is one same-type `Requirement` + `systemBypass`), so the only cross-scope
interaction is the bypass — which the fold handles.

Two-layer gate:

- **Slice 1 (framework)** — a scope-agnostic golden replay: run `RBAC` and
  `PermissionSet` over the same synthetic fixture and assert identical
  `Decision.Allowed` for every `(subject, action, resource)` cell. This proves
  the *engine* equivalence; it cannot see the Barista bypass fold (that's adapter
  code).
- **Slice 3 (Barista adapter)** — **reuse `internal/authz/authz_test.go`'s
  existing parity fixture UNCHANGED**. It already pins the Finding-1 bypass cases
  that a naive adapter would break: `authz_test.go:154` (`alice`, inline system
  cluster-admin, `cluster.manage` on `c2` with **no** cluster row → allow), `:155`
  (`dave`, group-promoted system admin → allow), and `TestCheck_OrgTiers:271-272`
  (`alice`/`dave` pass `org.own` on `org1` **without** being org members). If the
  new `PermissionStore` adapter fails to fold `*`, these three go red — which is
  exactly the guard we want. Do not rewrite this fixture; a lift that "moves" its
  tests into a friendlier shape is how the bypass would slip through.

> **`Decision.Reason` differs between engines — confirmed harmless.** The
> interface contract states Reason "MUST NOT be used for control flow"
> (`authz.go:46-52`), so the parity gate asserts `Allowed` only. Verified: nothing
> in `apps/barista` persists `Decision.Reason` — it is read solely in test
> assertions (`authz_test.go:166,281`); no audit row or structured log carries it
> (the other `.Reason` hits — `deployment_pipeline.go`, `stepup.go` — are
> unrelated fields). The engine swap is invisible to audit.

### 3.3 Reverse queries

`ListResources(sub, act, type)` becomes `ResourcesWithPermission(sub, key=act,
type)`, unioned across the subject's roles; `*` ⇒ `unbounded=true`. `ListSubjects`
becomes `SubjectsWithPermission` (RBAC always returns `unbounded=false` here —
SQL enumerates global holders — so the port omits the flag and the engine
hardcodes `false`, faithfully).

**These reverse queries have ZERO production callers** — grep confirms
`Authz.ListResources` / `ListSubjects` / `CheckBulk` are exercised only by
`internal/authz/authz_test.go` + the tamper framework tests. The production
cluster-list filter that shows a non-admin only their granted clusters is
`ClusterACLService.ReachableClusters` (`internal/service/cluster_acl_service.go:363`)
— **service-side SQL that never calls the PDP** — so the engine swap cannot affect
it. Reverse-query parity is therefore **framework-parity-only**; keep it green,
but no production surface rides on it. (Earlier drafts wrongly claimed the
cluster-list filter rode on `ListResources` — it does not.)

**Determinism:** `RBAC` sorts `ListResources` by `Resource.ID` (`rbac.go:136`) and
`ListSubjects` by `(Type, ID)` (`rbac.go:171`), and the parity tests assert
positional output (`authz_test.go:185`). The set engine unions into maps
(order-undefined), so its reverse queries MUST re-sort with the identical
comparators or those tests break.

## 4. Persistence (additive; separate grant tables for union)

Additive-only, cluster-scope first. **Built-in assignments keep their
CHECK-constrained enum columns** (`cluster_user_roles.role`, `group_roles.role`
— both `CHECK (role IN ('cluster-admin','cluster-deployer','cluster-viewer'))`).
Custom roles get their own catalog + grant tables so nothing is rebuilt and a
subject can hold **multiple** custom roles (union):

```sql
-- The catalog of operator-defined roles.
CREATE TABLE role_definitions (
    id           TEXT PRIMARY KEY,
    scope        TEXT NOT NULL CHECK (scope IN ('cluster')),  -- widen additively later
    name         TEXT NOT NULL,          -- stable slug, unique per scope
    display_name TEXT NOT NULL,
    source       TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual')),  -- 'scim' added later
    created_by   TEXT NOT NULL DEFAULT '',
    created_at   DATETIME NOT NULL,
    updated_at   DATETIME NOT NULL,
    UNIQUE (scope, name)
);

-- The permission-key subset each custom role grants. The CHECK is
-- defense-in-depth mirroring the built-in enum columns (cluster_user_roles.role
-- etc. carry an in-DB CHECK, sqlite/schema.sql:212): it structurally EXCLUDES
-- the '*' superuser key, so no writer bug, bulk-import, or direct SQL can seat a
-- custom '*' grant — only the in-code system cluster-admin seed may ever hold '*'.
-- Widen this CHECK additively when the catalog grows.
CREATE TABLE role_permissions (
    role_definition_id TEXT NOT NULL REFERENCES role_definitions(id) ON DELETE CASCADE,
    permission_key     TEXT NOT NULL
        CHECK (permission_key IN ('cluster.view', 'cluster.deploy', 'cluster.manage')),
    PRIMARY KEY (role_definition_id, permission_key)
);

-- Custom-role ASSIGNMENTS — separate from cluster_user_roles so built-in enum
-- grants are untouched and a (cluster,user) pair can hold several custom roles.
CREATE TABLE cluster_user_custom_roles (
    cluster_id         TEXT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    user_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_definition_id TEXT NOT NULL REFERENCES role_definitions(id) ON DELETE CASCADE,
    created_at         DATETIME NOT NULL,
    created_by         TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (cluster_id, user_id, role_definition_id)
);

CREATE TABLE group_custom_roles (
    group_id           TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    cluster_id         TEXT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    role_definition_id TEXT NOT NULL REFERENCES role_definitions(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, cluster_id, role_definition_id)
);
```

The **permission catalog itself** (the set of enforceable keys —
`cluster.view/deploy/manage` for the pilot) is **fixed in code**, not a table:
you cannot enforce a permission the code never checks. `role_permissions.permission_key`
is validated against that in-code catalog at write time.

**Dual-driver tax (easy to forget):** the DDL above is **SQLite-flavored**. Every
new table needs the full sqlite + postgres migration + sqlc regen in **both**
`internal/store/sqlite` **and** `internal/store/postgres` (the driver matrix CI
enforces; both trees confirmed present). The Postgres half must use `TIMESTAMPTZ`
for `created_at`/`updated_at` (not SQLite's `DATETIME` — see
`postgres/schema.sql:200`); the CHECK/PK/FK carry over. The engine touches no SQL,
but the schema does.

## 5. Blast radius

- **The real `Authz.Check` call sites are in tamper, not middleware.**
  `RequireClusterRole` / `RequireOrgMember` / `RequireClusterAdmin`
  (`internal/api/middleware/*`) are thin wrappers; the actual `Check` calls live
  in `packages/tamper/espresso/decision.go:106` (visibility action) + `:125`
  (tier action) — and `RequireOrgMember` calls `Check` **twice** per request
  (visibility→404 then tier→403, the cross-org leak rule). `RequireDecision`
  depends only on `Decision.Allowed` + error-means-deny, both of which the new
  engine honors, so these are **unchanged** — but they are the consumers, so any
  behavior drift shows up here.
- **The swap point is SINGULAR** — the sole production construction of the
  `Authorizer` is `cmd/barista/main.go:1408` (`baristaauthz.New(store.Queries)`
  → `state.Authz` at `:1782`); `internal/authz.New` (`policy.go:176`) is that
  one factory, and handler tests wire through the same seam
  (`handler/test_helpers_test.go:62`). Slice 3 changes exactly this one line:
  `NewRBAC(...)` → `NewPermissionSet(NewPermissionStore(q), <seeded catalog>)`.
  Verified there is no second `Authorizer` impl or constructor.
- **Service-side project checks untouched** (out of scope) — they never consulted
  the PDP.
- The new CRUD + SPA surfaces (Slices 4–5) are net-new; they don't alter existing
  authz decisions.

## 6. Slice plan (cluster-only; no project slice)

| Slice | What | Size | Gate |
|---|---|---|---|
| **0** | **This doc** — design freeze. | S | user review |
| **1** | Framework `PermissionSet` engine + `PermissionStore` port in `packages/tamper/authz`. Union membership, `*` superuser, deny-by-default. **Byte-parity golden replay** vs `RBAC` over the 4-scope fixture. Framework-only, tests in tamper. | L | parity replay green; `RBAC` untouched |
| **2** | Additive schema (§4) + in-code catalog + seed; sqlite+postgres migrations + sqlc in **both** stores. Tables **dormant** — zero behavior change. | M | driver-matrix CI; independently shippable |
| **3** | Pilot swap: repoint `internal/authz.New` (the single site, `main.go:1408`) to `PermissionSet`. The `PermissionStore` adapter's `PermissionsFor` is a **5-way union**: `cluster_user_roles`→built-in keys ∪ `group_roles`→built-in keys ∪ `cluster_user_custom_roles`→`role_permissions` ∪ `group_custom_roles`→`role_permissions` ∪ **the global system `*` folded into every scoped query** (Finding 1). **Parity gate = reuse `authz_test.go`'s fixture UNCHANGED** (proves system+org+cluster unchanged, incl. the bypass cases :154/:155/:271-272); new tests cover custom cluster roles (esp. the non-downward-closed `{view,manage}`). Edge gates untouched. | L | parity fixture reused + new-role tests |
| **4** | `RoleDefinitionService` + handlers: create/edit/delete custom cluster roles (permission-picker fed by the in-code catalog), assign/unassign on a cluster. `system.admin`-gated, deny-by-default, audit crossing (`role.create/update/delete/assign` — actor from ctx, port-impl emits per A3). Usable via API before any UI. | L | `-race`; audit guards mutation-proven |
| **5** | SPA: replace read-only `/admin/roles` with a role-builder (create/edit + permission picker + assign-on-cluster-ACL). Tests move with it. | M | web:check |

Each slice is independently shippable and testable. **Tests move with every
lift** (`feedback_lift_moves_tests_too` — a lift that leaves its guards behind
silently stops tracking production). Adapters carry latent deviations invisible
until wired into the request path (the 4e-2 lesson) — the Slice-1 byte-parity
replay + the Slice-3 parity gate are the defense.

## 7. Risks & the lessons to carry

- **Union-superset surprise (accepted).** Two custom roles can combine into a
  superset neither was designed for — the price of union over rank-max's
  single-winner clarity. The user accepted this; it's the natural additive model
  and keeps "why allowed?" answerable as "this key is in some held role."
- **`*` superuser must not leak.** Only the system `cluster-admin` role seeds
  `*`. A Slice-3 test must assert no custom role can ever be granted `*` (the
  write-side catalog validation rejects `*` as a permission key).
- **Deny-by-default is a hard contract** (`authz.go:66-69`) — preserved: an empty
  effective set denies; an unknown key denies; a store error is an error (deny).
- **Reason-in-audit — confirmed clean** — nothing persists `Decision.Reason`
  (§3.2); the engine swap is invisible to audit.
- **The bypass fold is the highest-risk adapter code (Finding 1)** — `PermissionsFor`
  MUST union the global system `*` into every scoped query; the mandatory reuse of
  `internal/authz/authz_test.go`'s bypass fixture cases (§3.2) is the guard.
- **Dual-driver tax** — the schema, not the engine, carries the sqlite+postgres
  cost; don't forget the postgres half.
- **Catalog is a one-way door** — every key added is a permanent enforcement
  site + audit vocabulary entry. Coarse-first keeps that surface minimal.

## 8. Open for review

This freeze reflects the four decided forks. If review reverses any of them —
especially catalog granularity (whether three coarse cluster verbs are
expressive enough to be worth shipping) — Slices 1–2 change shape, so raise it
here before Slice 1 starts.
