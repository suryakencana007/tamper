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

**All seven slices landed.** M1, M2 and M3 are complete.

| Milestone | Slices | State |
|---|---|---|
| M1 — storage + provisioning | 9a-1, 9a-2, 9a-3 | done — #65, #66, #69 |
| M2 — request path | 9b-1, 9b-2 | done — #70, #71 |
| M3 — integrity | 9c-1, 9c-2 | done — #72, #73 |

`examples/tenanthierarchy` holds the whole mechanism: store with per-origin
provenance, provisioning, derived membership, the espresso-wired HTTP surface
(`http.go`), reconciliation and audit.

Amendments the code reviews produced, already folded into the blocks below:

- **9a-1** — per-origin provenance (a row is deleted only when its last origin
  goes) and `Tx` reads (an `Apply` callback reads and writes atomically).
- **9a-2/9a-3** — the revoke and the membership changes read inside the `Apply`;
  a parentage precondition (`ErrParentMismatch`) makes a misordered membership
  change loud.
- **9b-1** — membership takes an `IntentReader` (origin-scoped reads), not
  `authz.BindingStore`; the subject type is configurable.
- **9b-2** — **one entered token per organization** (the scope is the org, ADR
  §3.1); the wiring lives in `http.go`, and the gate's subject type is an
  option.
- **9c-1** — `BindingSource` (read + write), `Store.IntentGroups` +
  `Store.GroupOrigins`, and a guard message that names the org.
- **9c-2** — `PlatformGate` for decision 6, and one audit sink for provisioning
  and org mutations.

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

// Origin names what justifies a row. A row can have several: a direct grant
// and a group grant can produce the identical binding, and revoking one must
// not remove the other. The row goes only when its last origin does.
// (Review amendment B1; ADR-0001 decision 1's side table.)
type Origin string
const OriginDirect Origin = "direct"
func GroupOrigin(group tenant.ID) Origin

// Store is an authz.BindingStore (read) plus atomic, idempotent, per-origin
// writes. It holds the group-scope INTENT row and the org-scope MATERIALIZED
// rows in one keyed set, with a per-row origin set.
type Store struct { /* rows + per-row origin sets */ }

func NewStore() *Store

// authz.BindingStore (read)
func (s *Store) BindingsFor(ctx context.Context, scope tenant.ID, sub authz.Subject, res authz.Resource) ([]authz.Binding, error)
func (s *Store) BindingsForSubject(ctx context.Context, scope tenant.ID, sub authz.Subject, resourceType string) ([]authz.Binding, error)
func (s *Store) BindingsOnResource(ctx context.Context, scope tenant.ID, res authz.Resource) ([]authz.Binding, error)

// Writes. Grant/Revoke are the OriginDirect convenience over
// GrantFrom/RevokeFrom, which touch a named origin. A second identical
// (key, origin) is idempotent; the row is removed when its last origin goes.
func (s *Store) Grant(ctx context.Context, b authz.Binding) error
func (s *Store) GrantFrom(ctx context.Context, b authz.Binding, origin Origin) error
func (s *Store) Revoke(ctx context.Context, key BindingKey) error
func (s *Store) RevokeFrom(ctx context.Context, key BindingKey, origin Origin) error
func (s *Store) Apply(ctx context.Context, fn func(tx Tx) error) error

// Tx is the read+write view an Apply callback works against. Reads see the
// staged view, so a callback can read-then-write atomically.
// (Review amendment M1.)
type Tx interface {
    Grant(ctx context.Context, b authz.Binding) error
    GrantFrom(ctx context.Context, b authz.Binding, origin Origin) error
    Revoke(ctx context.Context, key BindingKey) error
    RevokeFrom(ctx context.Context, key BindingKey, origin Origin) error
    BindingsFor(ctx context.Context, scope tenant.ID, sub authz.Subject, res authz.Resource) ([]authz.Binding, error)
    BindingsForSubject(ctx context.Context, scope tenant.ID, sub authz.Subject, resourceType string) ([]authz.Binding, error)
    BindingsOnResource(ctx context.Context, scope tenant.ID, res authz.Resource) ([]authz.Binding, error)
}

// BindingWriter is what the Provisioner (9a-2) depends on, so a SQL adapter
// can replace the in-memory store without touching provisioning logic.
type BindingWriter interface {
    Grant(ctx context.Context, b authz.Binding) error
    GrantFrom(ctx context.Context, b authz.Binding, origin Origin) error
    Revoke(ctx context.Context, key BindingKey) error
    RevokeFrom(ctx context.Context, key BindingKey, origin Origin) error
    Apply(ctx context.Context, fn func(tx Tx) error) error
}
```

**invariants**
- `Grant` is idempotent on `BindingKey`: the same key twice is one row.
- A row carries a set of **origins**, and is deleted only when its last origin
  goes. A direct grant and a group grant on the same binding coexist; revoking
  one leaves the other. Revoking an origin a row does not carry is a no-op.
- `Apply` is atomic: an error inside `fn` leaves the store exactly as it was.
- A `Tx` read sees the callback's own staged writes.
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
- Provenance: a direct grant survives a group-origin revoke, and goes when its
  own origin does; `GrantFrom` is idempotent; a revoke of an absent origin is a
  no-op.
- A `Tx` sees its own staged writes.

**mutation**
- Make `Grant` append without keying on `BindingKey`. The idempotence test
  MUST go red.
- Make `Apply` write through instead of staging. The rollback test MUST go red.
- Remove the per-origin ref count (revoke deletes the row outright). The
  "direct survives a group-origin revoke" test MUST go red.

**verify**
```sh
go test -race ./examples/tenanthierarchy/...
go vet ./examples/tenanthierarchy/...
```

**dod**
- [x] Leak suite green against `Store`
- [x] Both mutation proofs recorded in the PR body with the failing test named
- [x] No tamper file outside `examples/tenanthierarchy/` changed
- [x] Package doc states the app-layer scope and cites ADR-0001
- [x] Provenance tests: direct survives group-origin revoke; absent-origin no-op
- [x] `Tx` reads see staged writes

**Landed:** #65 (commit `8185786`). Provenance and `Tx` reads were added during
the review of that PR.

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
- `RevokeGroupAdmin`: in one `Apply`, read the subject's rows through the `Tx`
  (so the read and the removal are one atomic step) and call
  `RevokeFrom(key, GroupOrigin(group))` for the intent row and every
  materialized binding under the group's children. Removing by origin leaves a
  **direct** grant on the same binding in place; only rows the group alone
  justified disappear.
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
- A **direct** grant on the same binding survives a group revoke, both for an
  org binding and for a grant on the group resource itself (review B1).

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
- [x] All three mutation proofs recorded in the PR body with failing tests named
- [x] `NewProvisioner` rejects nil writer / nil hierarchy / empty `RoleMap`
- [x] No cross-scope row: a child-scope read never returns the intent row
- [x] RoleMap fail-closed proven by a test
- [x] Direct grant survives a group revoke on the same binding (B1)
- [x] `RevokeGroupAdmin` reads inside `Apply` (M1)

**Landed:** #66 (commit `838f898`). The revoke semantics were tightened during
the review of that PR: `NewProvisioner` takes a `BindingWriter` (reads are on
the `Tx`), and the revoke removes by origin.

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

**new symbols**

```go
// IntentReader is the store surface a derived membership needs. It is NOT
// authz.BindingStore: membership must read the INTENT rows, which only an
// origin-scoped read exposes, and a direct grant on the group resource is not
// a group grant. (*Store implements it.)
type IntentReader interface {
    BindingsFrom(ctx context.Context, scope tenant.ID, origin Origin) ([]authz.Binding, error)
    IntentGroupsForSubject(ctx context.Context, subjectType, userID string) ([]tenant.ID, error)
}

type Membership struct { /* store IntentReader, hier OrgHierarchy, userType string */ }
func NewMembership(store IntentReader, hier OrgHierarchy, opts ...MembershipOption) *Membership
func WithUserSubjectType(subjectType string) MembershipOption // default "user"

var _ identity.MembershipStore = (*Membership)(nil)
func (m *Membership) IsMember(ctx context.Context, userID string, target tenant.ID) (bool, error)
func (m *Membership) MembershipsFor(ctx context.Context, userID string) ([]tenant.ID, error)

// Store, in addition:
func (s *Store) IntentGroupsForSubject(ctx context.Context, subjectType, userID string) ([]tenant.ID, error)
```

**invariants**
- `IsMember` is true iff a **user** intent row covers the org; never from an
  unrelated group, and never from another subject type sharing the id.
- A root org (no parent) and an unknown org have no group, so `false`.
- A `OrgHierarchy` error is returned; `EnterTenant` treats it as deny.
- No membership table exists; removing the intent immediately removes the
  ability to enter (the token window is Phase 8's `EnterTenant` TTL).
- Membership keys on the user id alone: the deployment relies on
  globally-unique user ids (decision 4).
- `NewMembership` panics on a nil store, a nil hierarchy, or an empty subject
  type.

**tests**
- `IsMember` true for every child; false for another group, an unknown org, and
  a user with no intent.
- A `service_account` sharing the id is not a membership; `WithUserSubjectType`
  makes another type count.
- `EnterTenant` end to end: bob's home session enters `org-1` → token
  `tid=org-1`, `htid=tg-acme`; refused after revoke; no mint on a hierarchy
  error.

**mutation**
- Return true when `ParentOf` reports no parent → the unknown-org case goes red.
- Answer from any scope instead of the resolved group → the other-group case
  goes red.

**verify**
```sh
go test -race ./examples/tenanthierarchy/...
go build ./...
```

**dod**
- [x] No membership table; membership is a read over intent rows
- [x] `EnterTenant` integration test asserts `htid=tg-acme` on the entered token
- [x] Both mutation proofs recorded with failing tests named
- [x] Subject type is matched, not just the id

**Landed:** #70.

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
→ DecisionGate`, scope = organization, group admin accepted as a guest,
`authz.RBAC` over the plain store. No wrapper store, no cross-scope OR.

**new symbols**

```go
// RouteTenant resolves the ORGANIZATION from the org path parameter. It is the
// resolver for the tenant gate; TenantFromRoutedContext there would be
// circular (nothing has pinned the tenant when the gate runs).
func RouteTenant(r *http.Request) (tenant.ID, bool)

// OrgGate wires RequireAuth -> RequireTenantAllowEntered(RouteTenant) ->
// DecisionGate{Tenant: TenantFromRoutedContext, AllowEntered: true}.
func OrgGate(jwt *crypto.JWTService, engine authz.Authorizer,
    action, visibility authz.Action,
    notVisible, denied tamperespresso.DenyWriter,
    opts ...OrgGateOption) func(http.Handler) http.Handler

// WithOrgSubjectType sets the subject type OrgGate and PlatformGate build.
func WithOrgSubjectType(subjectType string) OrgGateOption
```

**scope rule (amended during review)**
- The scope is the **organization** (ADR §3.1). A Phase 8 entered token names
  exactly one `tid`, so a group admin reaches every child org with **one entered
  token per org**. The earlier "one token, many orgs" line was wrong and is
  retracted.

**tests**
- Group admin reaches `org-1`/`org-2`/`org-3`, each with its own entered token.
- A token for `org-1` is 401 on its **sibling** `org-2`, on another group's org,
  and on an unknown org.
- A home (unentered) token on an org route is 401.
- Direct org admin 200; an unbind org-2 user 404; a group viewer 403.
- A scope spy proves every `Check` is in the org scope (two-check flow), never
  in a group scope.
- `ListSubjects(org)` lists the group admin.

**mutation**
- `AllowEntered: false` → the group-admin reach test goes red.
- `DecisionGate.Tenant` pointed at the group → the reach test goes red.
- A second `Check` in the group scope → the scope-spy test goes red.

**verify**
```sh
go test -race ./examples/tenanthierarchy/...
go build ./...
```

**dod**
- [x] One entered token per org reaches that org; a sibling org is 401
- [x] 404/403/401 discipline asserted at the wire
- [x] Mutation proofs recorded with failing tests named
- [x] No `Authorizer.Check` outside the organization scope (scope spy)

**Landed:** #71.

---

## Slice 9c-1 — reconciliation guard + `SyncGroup`

```yaml
id: 9c-1
milestone: M3
risk: HIGH
depends_on: [9a-3, 9b-2]
design_ref: "ADR §3.7, §6, §7; CLAUDE.md rule 6"
```

**Goal.** The guard that makes eager provisioning safe: compare intent ×
parentage against the materialized rows, report **both** missing and orphan
drift, repair only on an explicit, idempotent call.

**new symbols**

```go
var ErrDrift = errors.New("tenanthierarchy: binding drift")

type Drift struct { Missing, Orphan []authz.Binding }
func (d Drift) Empty() bool

func (p *Provisioner) Reconcile(ctx context.Context) (Drift, error)
func (p *Provisioner) SyncGroup(ctx context.Context, group tenant.ID) error
func Guard(ctx context.Context, p *Provisioner) error

// BindingSource is what the Provisioner now takes: read + write. Reconciliation
// reads OUTSIDE a transaction to report drift; the write paths read via the Tx.
type BindingSource interface {
    authz.BindingStore
    BindingWriter
    BindingsFrom(ctx context.Context, scope tenant.ID, origin Origin) ([]authz.Binding, error)
    IntentGroups(ctx context.Context) ([]tenant.ID, error)
    GroupOrigins(ctx context.Context) ([]tenant.ID, error)
}
```

**invariants**
- Drift has **two** directions; a guard that checks one is not the guard.
- Groups are enumerated from intent rows **and** from the origins rows carry, so
  a group whose intent row was lost is still reconciled.
- A direct grant carries another origin, so it is neither expected nor actual.
- Status does not matter: a suspended org still needs its bindings (decision 5).
- `SyncGroup` reconciles **inside** the `Apply`, so the drift it acts on and the
  repair are one atomic step; it is idempotent and capped.
- `Guard` reports and stops. It never repairs: silent repair hides the cause.
- The guard's message names the scope, resource, subject and role.

**tests**
- Clean → empty drift, `Guard` nil.
- Missing, orphan, role drift and orphan-after-intent-lost are each detected.
- `SyncGroup` repairs both directions and is idempotent.
- `Guard` does not repair (rule-6 witness).
- `SyncGroup` past the cap refuses and repairs nothing.

**mutation**
- Reconcile only `Missing` → the orphan tests go red.
- `Guard` repairs silently → the guard witness goes red.

**verify**
```sh
go test -race ./examples/tenanthierarchy/...
go build ./...
```

**dod**
- [x] Guard fires on seeded missing drift (rule 6)
- [x] Guard fires on seeded orphan drift
- [x] Guard does not auto-repair; `SyncGroup` is explicit and idempotent
- [x] Both mutation proofs recorded with failing tests named

**Landed:** #72 (the review of which added `GroupOrigins`, the scope-bearing
guard message, and the in-transaction reconcile).

---

## Slice 9c-2 — audit for provisioning and org mutations

```yaml
id: 9c-2
milestone: M3
risk: MEDIUM
depends_on: [9b-2]
design_ref: "ADR §3.6; PHASE8 §3"
```

**Goal.** Provisioning is recorded on the single chain, and an org mutation by a
group admin audits with the organization as scope and the tenant-group as the
actor's home tenant.

**new symbols**

```go
const (
    ActionGrantGroupAdmin  audit.Action = "tenanthierarchy.group_admin.grant"
    ActionRevokeGroupAdmin audit.Action = "tenanthierarchy.group_admin.revoke"
    ActionAddOrg           audit.Action = "tenanthierarchy.org.add"
    ActionMoveOrg          audit.Action = "tenanthierarchy.org.move"
    ActionRemoveOrg        audit.Action = "tenanthierarchy.org.remove"
)

// EventLogger is the slice of audit.Logger provisioning needs.
type EventLogger interface { Log(ctx context.Context, e audit.Event) (audit.Event, error) }
func WithAudit(logger EventLogger) ProvisionerOption

// PlatformGate is the untenanted system-scope surface; only a platform admin
// passes (decision 6).
func PlatformGate(jwt *crypto.JWTService, engine authz.Authorizer, platform tenant.ID,
    action authz.Action, denied tamperespresso.DenyWriter,
    opts ...OrgGateOption) func(http.Handler) http.Handler
```

**rules**
- A provisioning event's scope (`Event.TenantID`) is the **tenant-group** being
  granted over; its actor is the **operator** from the context.
- An org mutation performed by a group admin audits `Event.TenantID` = the
  **organization** and `Actor.TenantID` = the **tenant-group**.
- One chain, one sink. Level is read from scope + role, **never** stamped into
  `Actor.Type`.
- Emission is best-effort (the `espresso.Auditor` posture): the store write has
  already committed, so an audit failure is reported, not undone.
- Only a platform admin may grant/revoke a group admin or change an org's group
  membership (decision 6).

**tests**
- Grant and revoke emit one event each: scope = group, actor = operator,
  `Actor.Type = user`.
- All five provisioning actions emit with the right scope and resource id.
- A group-admin org mutation audits scope = org, actor tenant = group.
- Provisioning and org mutations land in **one** sink.
- An audit failure does not fail or undo the grant; audit off is supported.
- `PlatformGate`: platform admin 200; a tenant-group admin's token 401.

**mutation**
- Mount `Auditor.For` outside the tenant gate → the org-scope test goes red
  (scope `""`).
- Stamp the admin level into `Actor.Type` → the provisioning test goes red.

**verify**
```sh
go test -race ./examples/tenanthierarchy/...
go build ./...
```

**dod**
- [x] Org-mutation audit scope = org, actor tenant = group, asserted
- [x] Provisioning events audited; still one chain (one sink)
- [x] Both mutation proofs recorded with failing tests named
- [x] Decision 6 has a gate (`PlatformGate`)

**Landed:** #73.

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

- [x] Every slice merged one PR at a time, in order (#65, #66, #69, #70, #71, #72, #73)
- [x] Every mutation proof recorded in its PR body with the failing test named
- [x] `RunBindingStoreLeakSuite` green against `Store`
- [x] Guard fires on both drift directions, and does not auto-repair
- [x] No tamper core change; every PR touched only `examples/tenanthierarchy/` (plus `TENANT-HIERARCHY-MANIFEST.md` in the docs PRs)
- [ ] **ADR-0001 moved from `Proposed` to `Accepted`** — owner decision, deliberately
  left open. The mechanism is implemented and green; flipping the ADR status is a
  product sign-off, not a code change, and should happen in its own one-line PR.

## Follow-ups (not part of this manifest)

- `tech-debt.md` TD-04 should point its roles workaround at the code as it now
  stands (`Store` + `Provisioner` + `Guard`), and record that the **IdP,
  entitlement and domain axes are still open** — this manifest decided roles only.
- `Auditor.For` reads path params through espresso's `extractor`, while
  `DecisionGate` reads `r.PathValue`. Harmless with an espresso router (it sets
  both), but worth documenting beside the audit wiring.
- A SQL adapter for `BindingSource` — the in-memory store is linear-scan by
  design; a real deployment needs the indexed table and the same leak suite.
