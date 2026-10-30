# Tenant hierarchy — Agent Implementation Manifest

> **Status: DRAFT — for review. Not a committed phase. No implementation until
> [`ADR-0001`](ADR-0001-tenant-hierarchy-platform-tenantgroup-org.md) is Accepted.**
>
> Companion to [`ADR-0001-tenant-hierarchy-platform-tenantgroup-org.md`](ADR-0001-tenant-hierarchy-platform-tenantgroup-org.md),
> which holds the *why* and the locked mechanism (eager per-tenant
> provisioning). This file holds the *what*, in the fixed schema
> [`PHASE7-AGENT-MANIFEST.md`](PHASE7-AGENT-MANIFEST.md) established, so one
> slice can be executed at a time.
>
> Scope: the **application layer**. tamper core changes: **none**. The proving
> ground is a rebuilt `examples/tenanthierarchy`, the same status
> `examples/multitenant` has for Phase 8 — a reference implementation a real
> app vendors, not shipped tamper code.

## Baseline

- Branch base: `origin/main` at `deb890e` (includes Phase 8 + Phase 8b).
- Governing docs: `ADR-0001` (mechanism), `PHASE8B-AUTHZ-TENANT-SKETCH.md`
  (tenant-scoped authz), `PHASE8-PLATFORM-ADMIN-SKETCH.md` (enter flow),
  `tech-debt.md` TD-04, `CLAUDE.md` standing rules.

## Status

| Milestone | Slices | State |
|---|---|---|
| M1 — storage + provisioning | 9a-1, 9a-2, 9a-3 | not started |
| M2 — request path | 9b-1, 9b-2 | not started |
| M3 — integrity | 9c-1, 9c-2 | not started |

Nothing is implemented. `examples/tenanthierarchy` was deleted (the pre-Phase-8b
draft); 9a-1 recreates it around the new mechanism.

## How to use this file

**One slice per PR. Never batch slices.** Work strictly in order; `depends_on`
is a hard gate.

For every slice, in this order:

1. Read the `ADR-0001` sections named in `design_ref`; read the sketches.
2. Read every path in `reads` before writing anything in `writes`.
3. Implement. `invariants` outrank the task description.
4. Write the tests. Run the `mutation` proofs: break the property in the
   **production** path, confirm the test goes red, revert. **A mutant that
   fails to compile proves nothing — verify it builds first.**
5. Run `verify`. All commands pass.
6. Check every DoD line. An unchecked line means the slice is not done.

**Global rules, every slice:**

- **tamper core: zero changes.** No table, column, migration or new port in
  tamper. The app names its own tables; tamper still names none.
- **No wrapper `BindingStore` that returns ancestor bindings.** A returned
  binding's `Tenant` MUST be the scope asked for (`authz/store.go`).
- **No cross-scope OR.** A single-resource authorization decision is asked in
  one scope: the organization. A tenant-group-scope check is a navigation
  helper only, never the PDP (ADR-0001 §3.4).
- **Scope is the organization.** The tenant-group is the subject's **home
  tenant**, never a route scope.
- Every store this app adds runs `authz/tenanttest.RunBindingStoreLeakSuite`.
- Every slice's `verify` also runs `go build ./...` at the repo root: the new
  package imports `espresso`/`identity`, so a cross-package break must fail here,
  not in a later slice.
- **Rule 6:** every guard ships with a test that makes it fire.
- **Rule 7:** an improvement spotted en route is a separate change.
- **Deny discipline:** 401 at the tenant gate, 404 for an in-group invisible
  org, 403 for an under-ranked role, and **every error is deny**.
- Stop and ask a human if a slice cannot be done without violating an
  invariant. That is a bug in this manifest, not a licence to deviate.

---

## Slice 9a-1 — hierarchy store + idempotent writer

```yaml
id: 9a-1
milestone: M1
risk: MEDIUM
depends_on: []
design_ref: "ADR §2, §3.1, §3.3, §3.7"
```

**Goal.** A store that holds the two kinds of binding row the mechanism needs —
the **intent** row (scope = tenant-group) and the **materialized** rows (scope
= each child organization) — with atomic, idempotent writes. Reads satisfy
`authz.BindingStore`. Nothing provisions yet. Storage per decision 1: one table.

**reads**
- `authz/store.go` — the isolation contract, word for word
- `authz/memstore.go` — `Grant`/`Revoke`, concurrency conventions
- `authz/tenanttest/tenanttest.go` — `RunBindingStoreLeakSuite`, `BindingHarness`
- `examples/multitenant/store.go` — the example's store conventions
- `tenant/id.go` — `tenant.ID`, `Single`, zero value

**writes**
- `examples/tenanthierarchy/doc.go` — package doc: app-layer, ADR-0001, no
  tamper core change
- `examples/tenanthierarchy/store.go` — `Store`, `NewStore`, the writer
- `examples/tenanthierarchy/store_test.go` — write tests + leak harness

**new symbols**

```go
// BindingKey identifies one row. Idempotence is defined on the full key.
type BindingKey struct {
    Scope   tenant.ID
    Subject authz.Subject
    Res     authz.Resource
    Role    authz.Role
}

// Store is an authz.BindingStore (read) plus atomic, idempotent writes.
type Store struct { /* ... */ }

func NewStore() *Store

// authz.BindingStore (read) — delegate or implement directly.
func (s *Store) BindingsFor(ctx context.Context, scope tenant.ID, sub authz.Subject, res authz.Resource) ([]authz.Binding, error)
func (s *Store) BindingsForSubject(ctx context.Context, scope tenant.ID, sub authz.Subject, resourceType string) ([]authz.Binding, error)
func (s *Store) BindingsOnResource(ctx context.Context, scope tenant.ID, res authz.Resource) ([]authz.Binding, error)

// Writes. Grant twice with the same key = one row. Revoke of an absent key
// is a no-op. Apply is all-or-nothing.
func (s *Store) Grant(ctx context.Context, b authz.Binding) error
func (s *Store) Revoke(ctx context.Context, key BindingKey) error
func (s *Store) Apply(ctx context.Context, fn func(tx Tx) error) error

type Tx interface {
    Grant(ctx context.Context, b authz.Binding) error
    Revoke(ctx context.Context, key BindingKey) error
}

// BindingWriter is what the Provisioner (9a-2) depends on, so a SQL adapter
// can replace the in-memory store without touching provisioning logic.
type BindingWriter interface {
    Grant(ctx context.Context, b authz.Binding) error
    Revoke(ctx context.Context, key BindingKey) error
    Apply(ctx context.Context, fn func(tx Tx) error) error
}
```

**invariants**
- `Grant` is idempotent on `BindingKey`: the same key twice is one row.
- `Apply` is atomic: an error inside `fn` leaves the store exactly as it was.
- Reads satisfy the `authz/store.go` isolation contract: only rows whose
  `Tenant == scope`, and only for the exact subject asked.
- An unset scope (`!tenant.ID.Valid()`) is `authz.ErrTenantRequired`, matching
  the port's rule; the app does not invent its own error.

**tests**
- `RunBindingStoreLeakSuite` green against `Store` (harness seeds via `Grant`).
- Grant idempotence: grant the same key twice, assert one row.
- Revoke of an absent key: no error, no change.
- `Apply` rollback: a `fn` that grants then returns an error leaves no row.
- Unset scope → `ErrTenantRequired` on read and write.

**mutation**
- Make `Grant` append without keying on `BindingKey`. The idempotence test
  MUST go red.
- Make `Apply` write through instead of staging. The rollback test MUST go red.

**verify**
```sh
go test -race ./examples/tenanthierarchy/...
go vet ./examples/tenanthierarchy/...
```

**dod**
- [ ] Leak suite green against `Store`
- [ ] Both mutation proofs recorded in the PR body with the failing test named
- [ ] No tamper file outside `examples/tenanthierarchy/` changed
- [ ] Package doc states the app-layer scope and cites ADR-0001

---

## Slice 9a-2 — `Provisioner`: grant/revoke + `RoleMap`

```yaml
id: 9a-2
milestone: M1
risk: HIGH
depends_on: [9a-1]
design_ref: "ADR §3.2, §3.3, §4.3"
```

**Goal.** The heart of the mechanism. Granting "admin of tenant-group X" writes
one **intent** row in scope X and **one materialized binding per child org**,
translated through `RoleMap`, in one atomic apply. Revoking removes both. Shape
per decision 2; one transaction per decision 3.

**reads**
- `examples/tenanthierarchy/store.go` (9a-1)
- `authz/policy.go` — role ladders are per resource type; `rank` fail-closed
- `authz/rbac.go` — how a binding is matched (`effective`)

**writes**
- `examples/tenanthierarchy/hierarchy.go` — `OrgHierarchy` port
- `examples/tenanthierarchy/rolemap.go` — `RoleMap`, `translate`
- `examples/tenanthierarchy/provisioner.go` — `Provisioner`, `NewProvisioner`,
  `GrantGroupAdmin`, `RevokeGroupAdmin`
- `examples/tenanthierarchy/provisioner_test.go`

**new symbols**

```go
// OrgHierarchy is the app-owned parentage port. tamper's tenant.Store does
// NOT expose this (ParentID is reserved there).
type OrgHierarchy interface {
    ParentOf(ctx context.Context, orgID string) (groupID string, ok bool, err error)
    ChildrenOf(ctx context.Context, groupID string) (orgIDs []string, err error)
}

// RoleMap: role held on a tenant-group -> role conferred on each child org.
// A role absent from the map does NOT expand (fail closed).
type RoleMap map[authz.Role]authz.Role
func (m RoleMap) translate(r authz.Role) (authz.Role, bool)

type Provisioner struct { /* writer, hier, roles */ }

func NewProvisioner(w BindingWriter, h OrgHierarchy, roles RoleMap) (*Provisioner, error)

// GrantGroupAdmin writes the intent row (scope = group) and one binding per
// child org (scope = org, resource = {organization, org}, role = translate).
func (p *Provisioner) GrantGroupAdmin(ctx context.Context, sub authz.Subject, group tenant.ID, role authz.Role) error

// RevokeGroupAdmin removes the intent row and every materialized binding.
func (p *Provisioner) RevokeGroupAdmin(ctx context.Context, sub authz.Subject, group tenant.ID) error
```

**provisioning rules**
- `NewProvisioner` errors on nil writer, nil hierarchy, or empty `RoleMap`.
  Misconfiguration fails at construction (standing rule 4).
- The subject's home tenant MUST equal `group`; otherwise error, not a write.
- `GrantGroupAdmin`: in one `Apply` — write the intent row at
  `{Scope: group, Subject: sub, Resource: {tenant_group, group}, Role: role}`,
  then for every child `o`, write
  `{Scope: o, Subject: sub, Resource: {organization, o}, Role: translate(role)}`.
  If `translate` fails, the **whole apply fails** — never an intent without its
  expansion.
- `RevokeGroupAdmin`: in one `Apply`, remove every materialized binding for
  `sub` under every child of `group`, plus the intent row.
- The materialized binding is **concrete**: `{organization, <org>}` in the
  org's scope — the exact shape a direct org-admin grant has (decision 2). A
  global binding in the org scope satisfies nothing the org route checks.

**invariants**
- A granted group admin has a binding in **every** child org; a revoked one has
  none.
- `translate` fail-closed: an unmapped role produces **no** materialized
  binding and fails the grant.
- No binding is written outside the scope of the resource it grants on.
- Error means no partial state: `Grant`/`Revoke` are atomic through `Apply`.
- One transaction per operation, no automatic chunking (decision 3). If the
  projected write count exceeds `MaxProvisionRows` (default 100_000), the
  operation errors; the operator runs the idempotent `SyncGroup` in bounded
  batches. The cap is a loud stop, never a silent split.

**tests**
- Grant on a group with 3 children writes 1 intent + 3 bindings, roles translated.
- Grant with an unmapped role → error, **zero** rows written.
- Grant twice → still 1 intent + 3 bindings (idempotent).
- Revoke → 0 rows for that subject in the group and its children.
- Subject home tenant ≠ group → error, no write.
- Reverse query: `BindingsForSubject(childScope, sub, "organization")` returns
  the materialized binding; `BindingsFor(childScope, sub, {organization, child})`
  returns it; the intent row is **not** visible in `childScope`.

**mutation**
- In `GrantGroupAdmin`, skip `translate` and pass the group role through. The
  unmapped-role test (`zero rows written`) MUST go red.
- In `GrantGroupAdmin`, write the intent row but not the children. The
  "binding in every child" test MUST go red.
- In `RevokeGroupAdmin`, remove only the intent row. The revoke test MUST go red.

**verify**
```sh
go test -race ./examples/tenanthierarchy/...
```

**dod**
- [ ] All three mutation proofs recorded in the PR body with failing tests named
- [ ] `NewProvisioner` rejects nil writer / nil hierarchy / empty `RoleMap`
- [ ] No cross-scope row: a child-scope read never returns the intent row
- [ ] RoleMap fail-closed proven by a test

---

## Slice 9a-3 — org membership changes re-sync every grant

```yaml
id: 9a-3
milestone: M1
risk: HIGH
depends_on: [9a-2]
design_ref: "ADR §3.3, §3.7, §4.3"
```

**Goal.** Adding, moving or removing an organization updates every existing
group-admin grant for the affected group(s) in the same transaction. This is
the slice that makes silent drift possible if done wrong — hence HIGH.

**reads**
- `examples/tenanthierarchy/provisioner.go` (9a-2)
- `authz/store.go` — `BindingsOnResource` is how the intent rows are read back

**writes**
- `examples/tenanthierarchy/provisioner.go` — `AddOrg`, `MoveOrg`, `RemoveOrg`
- `examples/tenanthierarchy/membership_change_test.go`

**new symbols**

```go
// AddOrg attaches an existing org to a group and extends every grant of that
// group onto it. Atomic.
func (p *Provisioner) AddOrg(ctx context.Context, group, org tenant.ID) error

// MoveOrg detaches org from `from` (removing the from-group grants' access)
// and attaches it to `to` (extending the to-group grants). Atomic.
func (p *Provisioner) MoveOrg(ctx context.Context, org, from, to tenant.ID) error

// RemoveOrg detaches an org from its group and removes every binding in its
// scope that a group grant produced. Atomic.
func (p *Provisioner) RemoveOrg(ctx context.Context, org, group tenant.ID) error

// GroupAdmins reads the intent rows of a group (scope = group, resource =
// {tenant_group, group}) so a membership change knows whose grants to extend.
func (p *Provisioner) GroupAdmins(ctx context.Context, group tenant.ID) ([]authz.Binding, error)
```

**invariants**
- After `AddOrg`, every current group admin has a binding in the new org, with
  its translated role. Zero exceptions.
- After `MoveOrg`, the from-group admins have **no** binding in the org and the
  to-group admins have one. Both halves, one transaction.
- After `RemoveOrg`, the org scope holds no binding produced by a group grant.
- A membership change with no admins is a no-op that still succeeds.
- Every operation is atomic; a failure leaves no half-applied state.

**tests**
- Grant two admins to a group (different roles), `AddOrg`, assert each got the
  right translated role in the new org.
- `MoveOrg`: assert from-group admin lost access **and** to-group admin gained
  it, in the same operation.
- `RemoveOrg`: assert the org scope is clean.
- Add an org to a group with zero admins → success, no rows.
- Idempotence: `AddOrg` twice → one binding per admin.

**mutation**
- In `MoveOrg`, skip the "remove from `from`" half. The leak test (from-admin
  still has access) MUST go red.
- In `AddOrg`, silently skip an admin whose role is unmapped (`continue`
  instead of failing the operation). The 9a-2 contract test "an unmapped role
  fails the op", extended to `AddOrg`, MUST go red.

**verify**
```sh
go test -race ./examples/tenanthierarchy/...
```

**dod**
- [ ] Move tests both halves (lose + gain) in one assertion
- [ ] Mutation proofs recorded with failing tests named
- [ ] No operation can leave a half-applied membership change

---

## Slice 9b-1 — membership is derived, `EnterTenant` works

```yaml
id: 9b-1
milestone: M2
risk: HIGH
depends_on: [9a-1, 9a-2]
design_ref: "ADR §3.2, §3.3, §3.5; PHASE8 §4"
```

**Goal.** A tenant-group admin can enter a child org. Membership is **derived**
from the intent rows plus parentage — no second materialized set, no drift.
Keying per decision 4.

**reads**
- `identity/membership.go` — `MembershipStore`, `EnterTenant`, `EnterableTenants`
- `identity/core.go` — how `IsMember` is called; error handling
- `examples/multitenant/enter.go`, `enter_test.go` — the enter route precedent
- `espresso/tenantgate.go` — `RequireTenantAllowEntered`, `EnteredFromContext`

**writes**
- `examples/tenanthierarchy/membership.go` — `MembershipStore`
- `examples/tenanthierarchy/membership_test.go`

**new symbols**

```go
// Membership is an identity.MembershipStore backed by the intent rows and the
// OrgHierarchy port. Nothing is materialized.
type Membership struct { /* writer/store (read), hier */ }

func NewMembership(store authz.BindingStore, hier OrgHierarchy) *Membership

var _ identity.MembershipStore = (*Membership)(nil)

// IsMember(userID, org) = an intent row exists in scope ParentOf(org) for
// userID. ParentOf error or "no parent" = false (deny), never an error read
// as allow.
func (m *Membership) IsMember(ctx context.Context, userID string, target tenant.ID) (bool, error)

// MembershipsFor lists every child of every group where userID has an intent.
func (m *Membership) MembershipsFor(ctx context.Context, userID string) ([]tenant.ID, error)
```

**invariants**
- `IsMember` is true iff a group grant covers the org; it is never true from an
  unrelated group.
- A `OrgHierarchy` error is returned, and the caller (`EnterTenant`) treats it
  as deny (Phase 8 §4 step 4).
- No membership table exists; removing the intent immediately removes the
  ability to enter (the token window is Phase 8's `EnterTenant` TTL).
- `MembershipsFor` never returns a tenant the user cannot actually enter.
- Membership keys on the user id alone: the deployment relies on
  globally-unique user ids, the same assumption `identity.Store.UserByID` makes
  (decision 4).

**tests**
- Admin of `tg-acme` → `IsMember(bob, org-1)` true for every child; false for
  `org-4` (another group) and for an unknown org.
- A user with no intent → false everywhere.
- `EnterTenant` end-to-end: bob's home session (tid = group) enters `org-1`,
  returns an access token with `tid=org-1`, `htid=tg-acme`.
- `IsMember` error path: a hierarchy that errors → `IsMember` returns the
  error, and `EnterTenant` does not mint.
- Removing the group grant → `IsMember` false; a fresh `EnterTenant` is
  refused.

**mutation**
- In `IsMember`, return true when `ParentOf` reports no parent (unknown/root
  org). The "false for unknown org" test MUST go red.
- In `IsMember`, read the intent from **any** scope rather than the resolved
  group. The "false for org-4" test MUST go red.

**verify**
```sh
go test -race ./examples/tenanthierarchy/...
```

**dod**
- [ ] No membership table introduced; membership is a read over intent rows
- [ ] `EnterTenant` integration test asserts `htid=tg-acme` on the entered token
- [ ] Both mutation proofs recorded with failing tests named

---

## Slice 9b-2 — espresso wiring + HTTP integration (no wrapper store)

```yaml
id: 9b-2
milestone: M2
risk: HIGH
depends_on: [9b-1]
design_ref: "ADR §3.2, §3.4, §3.5, §4.2, §6"
```

**Goal.** The whole stack on the wire: `RequireAuth → RequireTenantAllowEntered
→ DecisionGate`, scope = organization, group admin accepted as a guest, `authz.RBAC`
over the plain store. No wrapper, no cross-scope OR.

**reads**
- `espresso/decision.go` — `DecisionGate`, `Tenant`, `AllowEntered`, `TenantFromRoutedContext`
- `espresso/tenantgate.go` — `RequireTenantAllowEntered`
- `espresso/audit.go` — `Auditor.For`, `MutationContext`
- `examples/multitenant/main.go` — router shape, store adapters

**writes**
- `examples/tenanthierarchy/main.go` — router, policies, handlers
- `examples/tenanthierarchy/httptest_test.go` — the integration suite

**new symbols**

```go
// routeTenant resolves the ORGANIZATION the route is scoped to, from the
// path. The tenant gate pins what this returns. Passing
// TenantFromRoutedContext to the gate would be circular: nothing has pinned
// the tenant yet, so it would resolve (zero, false) and 401 every request.
func routeTenant(r *http.Request) (tenant.ID, bool) {
    id := r.PathValue("org_id")
    if id == "" {
        return tenant.ID{}, false
    }
    return tenant.New(id), true
}
```

**wiring rules**

```go
router.Use(tamperespresso.RequireAuth(jwtSvc))
org.Use(
  tamperespresso.RequireTenantAllowEntered(routeTenant),       // pins the org
  tamperespresso.RequireDecision(tamperespresso.DecisionGate{
    Authorizer:       engine,                                  // authz.RBAC over Store
    Tenant:           tamperespresso.TenantFromRoutedContext,  // reads the pinned org
    AllowEntered:     true,                                    // group admin is a guest
    SubjectType:      "user",
    ResourceType:     "organization",
    ResourceIDFrom:   "org_id",
    Action:           "org:manage",
    VisibilityAction: "org:view",
    WriteNotVisible:  notFound,                                // 404
    WriteDenied:      forbidden,                               // 403
  }),
)
```

- `TenantFromRoutedContext` belongs on the **DecisionGate** (it reads the
  tenant the gate pinned), never on the gate itself. A gate fed with its own
  output refuses every request: nothing has pinned the tenant when it runs.
- The `/enter` route is the Phase 8 flow (`examples/multitenant/enter.go`); it
  is reused, not redesigned here.
- The org route MUST NOT call `Authorizer.Check` itself with a second scope.
- No type in this package may satisfy `authz.BindingStore` except `Store`
  (9a-1) — a wrapper returning ancestor bindings is the failure this whole
  design exists to prevent.

**invariants**
- Scope at the gate is the **organization**; the entered subject carries home
  tenant = group (`espresso/decision.go`).
- Cross-group / unknown / root org → 401 at the tenant gate, byte-identical to
  an invalid token.
- In-group org the subject cannot see → 404; visible but under-ranked → 403.
- Every `Authorizer` error → deny, never allow.
- Group admin reaches **every** child org of the group with **one** entered
  token; a sibling group's org is 401.

**tests**
- Group admin (home `tg-acme`) enters `org-1` → `POST /orgs/org-1/...` 200.
- Same token on `org-2`, `org-3` → 200 (one token, many orgs).
- Same token on `org-4` (other group) → 401.
- Same token on an unknown org and on a root org → 401.
- Org admin (direct binding) on own org → 200; on sibling in the same group
  without a binding → 404.
- A visible-but-under-ranked role → 403.
- A `Single`/unentered platform-admin token on an org route → 401.
- `ListSubjects(org)` includes the group admin (via the materialized binding).
- A spy `Authorizer` records the scope of every `Check`: exactly one is made,
  in the org scope.

**mutation**
- Set `AllowEntered: false`. The cross-org 200 tests MUST go red.
- Point `DecisionGate.Tenant` at the **group** instead of the org. The scope
  assertions and the audit-scope test MUST go red.
- Wrap the `Authorizer` in a spy that records each `Check` scope, and add a
  second `Check` with the group scope in the handler OR'd into the response.
  The test asserting the recorded scopes are exactly `[org-1]` MUST go red.

**verify**
```sh
go test -race ./examples/tenanthierarchy/...
```

**dod**
- [ ] One entered token reaches all three child orgs; sibling group is 401
- [ ] 404/403/401 discipline asserted at the wire
- [ ] Mutation proofs recorded with failing tests named
- [ ] A spy test proves exactly one `Authorizer.Check`, in the org scope

---

## Slice 9c-1 — reconciliation guard + `SyncGroup`

```yaml
id: 9c-1
milestone: M3
risk: HIGH
depends_on: [9a-3, 9b-2]
design_ref: "ADR §3.7, §6, §7; CLAUDE.md rule 6"
```

**Goal.** The guard that makes eager provisioning safe. `Reconcile` compares
the intent rows (× parentage) against the materialized rows and reports **both**
missing and orphan bindings. `SyncGroup` repairs, idempotently and explicitly.
A boot guard fails loudly; a test proves the guard fires. Status per decision 5.

**reads**
- `examples/tenanthierarchy/provisioner.go` (9a-2, 9a-3)
- `authz/tenanttest/tenanttest.go` — harness/seed conventions
- `CLAUDE.md` rule 6 — guard plus a test that fires

**writes**
- `examples/tenanthierarchy/reconcile.go` — `Reconcile`, `SyncGroup`, `Drift`
- `examples/tenanthierarchy/reconcile_test.go` — including a seeded-drift test

**new symbols**

```go
// Drift is the difference between what the intent + parentage require and what
// the store holds.
type Drift struct {
    Missing []authz.Binding // intent covers it, no binding exists
    Orphan  []authz.Binding // binding exists, no intent covers it
}
func (d Drift) Empty() bool

// Reconcile computes drift, group by group. It reads the intent rows
// (scope = group) and the materialized rows (scope = each child), and applies
// RoleMap in Go (the map is not expressible in SQL).
func (p *Provisioner) Reconcile(ctx context.Context) (Drift, error)

// SyncGroup makes group's materialized rows match intent × children.
// Idempotent. Explicit call only.
func (p *Provisioner) SyncGroup(ctx context.Context, group tenant.ID) error

// Guard is a boot-time check: a non-empty Drift is an error naming a few
// offending rows.
func Guard(ctx context.Context, p *Provisioner) error
```

**invariants**
- `Reconcile` detects **both** directions: a missing binding (access gap) and
  an orphan binding (access too broad). A guard that only checks one is not the
  guard.
- `SyncGroup` is idempotent and converges: `Reconcile` after `SyncGroup` is
  empty.
- `Guard` **fails** on non-empty drift. It does **not** auto-repair — silent
  repair hides the bug that caused the drift.
- The guard's "should exist" set accounts for suspended orgs (they still should
  have bindings; suspension is a request gate, TD-06, not a binding change).

**tests**
- Clean state → `Reconcile` empty, `Guard` nil.
- Seeded **missing** drift (delete a materialized row) → non-empty `Missing`;
  `Guard` errors. **This is the rule-6 test.**
- Seeded **orphan** drift (insert a binding with no intent) → non-empty
  `Orphan`; `Guard` errors.
- Role drift (materialized role ≠ translate(intent role)) → detected.
- `SyncGroup` repairs both; `Reconcile` empty afterwards; running `SyncGroup`
  twice converges.

**mutation**
- Make `Reconcile` check only `Missing`. The orphan test MUST go red.
- Make `Guard` call `SyncGroup` and return nil. The seeded-drift test MUST go
  red — a guard that repairs silently is not a guard.

**verify**
```sh
go test -race ./examples/tenanthierarchy/...
```

**dod**
- [ ] Guard fires on seeded missing drift (rule 6)
- [ ] Guard fires on seeded orphan drift
- [ ] Guard does not auto-repair; `SyncGroup` is explicit and idempotent
- [ ] Both mutation proofs recorded with failing tests named

---

## Slice 9c-2 — audit for provisioning and org mutations

```yaml
id: 9c-2
milestone: M3
risk: MEDIUM
depends_on: [9b-2]
design_ref: "ADR §3.6; PHASE8 §3"
```

**Goal.** Provisioning (grant/revoke, org membership change) is recorded, and an
org mutation by a group admin audits with the correct scope and actor tenant. One
chain. Authority per decision 6.

**reads**
- `espresso/audit.go` — `Auditor.For`, `MutationContext`
- `audit/audit.go` — `Event`, `Actor`, `ActorType`
- `examples/multitenant/enter.go` — how the example records entry

**writes**
- `examples/tenanthierarchy/audit.go` — the provisioning sink
- `examples/tenanthierarchy/audit_test.go`

The example has no audit DB (Phase 8's note), so the proof uses a fake
`audit.Logger` that captures events. There is no chain-of-hash assertion here —
only the event's scope, actor tenant, and type.

**rules**
- A provisioning operation emits an event whose actor is the **operator** (the
  subject performing the grant), and whose scope is the **group** being granted
  over.
- An org mutation performed by a group admin audits with `Event.TenantID` = the
  **organization** (the routed scope) and `Actor.TenantID` = the **tenant-group**
  (the home tenant, from `htid`).
- One chain. No per-group chain. Level (platform / tenant-group / org admin) is
  read from scope + role, **never** from `actor.subject_type`.
- Only a platform admin may grant/revoke a group admin or change an org's group
  membership; a group admin manages org resources, not its own grant list
  (decision 6).

**tests**
- Grant group admin → one event, scope = group, actor = operator.
- Revoke → one event.
- A group-admin mutation on an org route → event scope = org, actor tenant = group
  (assert via the example's audit sink).
- Provisioning and org-mutation events go to the **same** sink instance (assert
  one sink is constructed, not one per group).

**mutation**
- Set the org-mutation event scope to the group. The scope assertion test MUST
  go red.
- Stamp the admin level into `Actor.Type` (e.g.
  `audit.ActorType("tenant_group_admin")`). The test asserting
  `Actor.Type == audit.ActorTypeUser` for a tenant-group admin's org mutation
  MUST go red.

**verify**
```sh
go test -race ./examples/tenanthierarchy/...
```

**dod**
- [ ] Org-mutation audit scope = org, actor tenant = group, asserted
- [ ] Provisioning events audited; still one chain
- [ ] Both mutation proofs recorded with failing tests named

---

## Non-goals (explicitly out of this manifest)

- **IdP inheritance, entitlements, domains.** TD-04 says decide each axis
  separately; this manifest decides **roles** only. Whether a parent's IdP
  serves a child is still the open product question (`PHASE7` sketch §8 item 3).
- **Impersonation** (TD-07), **tenant lifecycle** (TD-05), **suspension
  enforcement** (TD-06).
- **More than three levels.** The expansion is single-level here; a recursive
  hierarchy is a separate design (ADR §9).
- **Barista.** Not kept compiling against `main` (standing rule 1, TD-27); the
  proving ground is the example.

## Decisions (resolved 2026-10-30)

These were open when the manifest was first drafted. They are decided; the
slices below assume the answers.

### 1 — Storage: one table (9a-1)

One `authz_binding` table holds both kinds of row:

- **intent** — scope = tenant-group, `Resource{tenant_group, <group>}`, the
  group role;
- **materialized** — scope = organization, `Resource{organization, <org>}`, the
  mapped org role.

The intent row is the source of truth, the materialized rows are the projection,
and `Reconcile` compares them. A separate intent table is allowed **only** if it
is the sole authority and every binding row is derived from it; never keep two
independent sources. Rich intent metadata (`granted_by`, `reason`, `at`) goes in
a side table keyed by the intent row's key, not in an authority of its own.

### 2 — Materialized shape: concrete `{organization, <org>}` (9a-2)

Not a free choice — it is what the engine matches. `authz/rbac.go` consults the
singleton `{Type, ""}` only when a requirement's `Type` differs from the
resource's; for a same-type requirement it calls `effective` on the concrete
resource and keeps only `b.Resource == res`. So an org-admin grant is a binding
on `{organization, <org>}` in that org's scope. A global binding in the org
scope would satisfy nothing the org route checks.

### 3 — Transactions: one, fail loud past a cap (9a-2)

Provisioning is **one transaction per operation**. No automatic chunking: a
partial write is exactly the drift the guard exists to catch. The store exposes
a `MaxProvisionRows` cap (default 100_000); an operation whose projected writes
exceed it returns an error, and the operator runs the idempotent `SyncGroup` in
bounded batches followed by `Reconcile`. The cap is a loud stop, never a silent
split.

### 4 — Membership keys on the user id alone (9b-1)

`identity.Store.UserByID(ctx, id)` already resolves a user by id with no tenant,
and `EnterTenant` derives the home tenant from that row. The deployment
therefore already relies on **globally-unique user ids**; the app's membership
keys on `(userID, target)`, and `MembershipsFor(userID)` scans groups for that
id. If an app ever allows the same id in two tenants, the port cannot
disambiguate — a documented constraint, not a port change.

### 5 — Status does not touch bindings (9c-1)

Suspending a group or an org does **not** add, remove or alter bindings. The
projection is a function of intent × parentage only. Enforcement is a request
gate (TD-06, `RequireActiveTenant`); un-suspension resumes instantly with no
re-sync. `Reconcile` ignores `Status` — a suspended org still must have its
bindings. The token window (a valid entered token outliving a suspension by up
to `WithEnterTenantTTL`) is Phase 8's known limit.

### 6 — Only a platform admin grants; same chain (9c-2)

Writes are outside the PDP (Phase 8b §6). Only a **platform admin** may
grant/revoke a group admin or change an org's group; a group admin manages the
orgs' resources, not its own grant list. The operation runs on the group's route
(the platform admin has entered the group), so the audit event's scope is the
**group** and its actor tenant is **platform**, on the single existing chain.

## Definition of done — whole manifest

- [ ] Every slice merged one PR at a time, in order
- [ ] Every mutation proof recorded with the failing test named
- [ ] `RunBindingStoreLeakSuite` green against `Store`
- [ ] Guard fires on both drift directions, and does not auto-repair
- [ ] No tamper core change; `git diff --stat` touches only `examples/tenanthierarchy/` and docs
- [ ] ADR-0001 moved from `Proposed` to `Accepted`
