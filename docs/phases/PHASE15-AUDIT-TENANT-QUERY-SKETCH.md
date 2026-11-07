# Phase 15 — Query the audit log per tenant (TD-11)

Status: **accepted 2026-11-05; implemented in #112 (15b) and #114 (the composite index
that issue #113 option 2 asked for)**. The proposal's wording was rejected in §2 and the
reasons are kept there; the measured numbers that changed the design are in issue #113.

TD-11 was a P2 gap, not a defect: nothing was wrong with the rows. What was missing was a
way to *ask a question* about them. This sketch is short because the design is one decision
plus its consequences, and the decision is about zero values.

---

## 1. Re-verification, per `/slice` step 1

| The item says | Verified |
|---|---|
| *"`audit.Filter` has no tenant field (`audit/audit.go:364`)"* | **True, but the line is stale**: `Filter` starts at `audit/audit.go:324`. It carries `Since`/`Until`, `ActorUserID`, `ActorEmail`, `Action`, `ClusterIDs`-era scope, `Limit`, `Cursor` — and no tenant |
| *"`ListScoped` filters on `clusterIDs`"* | **True** — `audit/audit_sqlite.go:341`, a concept inherited from Barista; orthogonal to tenancy and stays |
| *"the only per-tenant path is `ExportForTenant`, which returns every row with no paging"* | **True** — `audit/export.go:97` |

So the item is accurate as written, and the impact is real: a console cannot ask *"activity
in tenant X this week"* or *"platform-admin actions inside any tenant"* without pulling the
whole export into memory.

One thing the item does **not** say, found while checking §4: the rows already carry both
columns — `tenant_id` (the scope) and `actor_tenant_id` — with the distinction documented in
the schema itself (`schema.sql:39-48`). Only the *filter* is missing. That is why this phase
is small: the data model is finished.

---

## 2. The decision that shapes everything: zero is not `Single`

`Filter` gains two fields, both `tenant.ID`:

```go
type Filter struct {
	// … existing fields …

	// TenantID limits rows to one tenant's LOG — Event.TenantID, the row's scope.
	TenantID tenant.ID
	// ActorTenantID limits rows to one tenant's ACTORS — Actor.TenantID, the
	// tenant the actor was acting in. The two differ for a cross-tenant entry:
	// a platform admin (actor tenant = platform) acting in acme has
	// TenantID=acme and ActorTenantID=platform, so "what did platform staff do
	// inside any customer tenant" is ActorTenantID=platform AND TenantID unset.
	//
	// What it CANNOT tell you: whether the admin acted as themselves (an entered
	// token) or as a customer's user (an impersonated token). Both mint `htid`,
	// and ActorTenantID() answers `htid` for both (crypto/jwt.go:394-399), so the
	// actor tenant is the human's home in each case. That distinction lives in the
	// `act` claim at WRITE time and in the `impersonation.start`/`.end` bracket rows
	// — not in this filter. An A.8.15 review that needs it filters by those actions.
	ActorTenantID tenant.ID
}
```

Both are `tenant.ID` rather than `string` for the reason the type exists: **the zero value
must be distinguishable from the single-tenant value.** A `string` would make `""` mean
both "no filter" and "rows whose scope is the empty tenant", and one of the two callers
would silently get the other's answer.

With `tenant.ID`:

| Filter value | Meaning |
|---|---|
| zero `ID` (`tenant.ID{}`) | **no filter** — every row the other fields allow |
| `tenant.Single` | rows whose `Event.TenantID` is `""` — the single-tenant deployment's own log |
| `tenant.New("acme")` | rows scoped to acme |
| an **invalid** id (e.g. `tenant.New("")`) | cannot happen: `New("")` returns the zero value, which is "no filter" |

That last line is the part worth being explicit about: `tenant.New("")` is *the zero ID*,
so a caller who forgot to thread a tenant through gets **no filter** rather than an empty
result. The proposal in `../tasks/tech-debt.md` asks for the opposite — *"an unset value means 'no
filter' only when the caller says so explicitly"* — and this sketch **rejects** that
wording, because `tenant.ID` already makes "explicit" structural: the caller writes nothing
for "no filter" and writes `tenant.Single` for the empty tenant. A second opt-in flag would
give the same fact two spellings.

**Reader-side contract, not writer-side:** filters only narrow *which rows are returned*.
They never widen: a caller without access to a tenant's export gets the same `ErrNotFound`
discipline `ExportForTenant` already has (see §4).

---

## 3. What the two fields must not do

- **They must not change the query's meaning for existing callers**, and they must not
  *break* them either. Adding fields to an exported struct is compatible for **keyed**
  literals and incompatible for **unkeyed** ones — Go allows unkeyed literals from other
  packages, so a caller writing `audit.Filter{t0, t1, "u-1", ...}` would stop compiling.
  None exist in this repo (the only literals are `Filter{}`), so the risk is external.
  It is recorded rather than papered over: **this is why 15b is a minor-version change
  with a note, not a "purely additive" one.** Every call site that leaves the new fields
  zero keeps the behaviour it has today, and that is a test.
- **They must not displace `clusterIDs`.** `ListScoped` keeps its own filter; the two
  compose with AND. Removing the cluster path is a different item (it is Barista's
  vocabulary, not tamper's), and this phase does not touch it.
- **They must not become a bulk export.** Paging stays what it is: `Filter` already carries
  the window and `Page` the cursor. If the row set is large, the answer is the existing
  paging, not a new streaming API. *"Export every row of tenant X"* stays
  `ExportForTenant`'s job, and it is explicitly the unbounded one.

---

## 4. Isolation, and the one new failure mode

Querying by tenant is a **read across the tenant boundary** by definition — that is the
point. So the discipline is about who may ask, and it belongs where it already is: the
application's console routes, behind whatever gate they mount. tamper supplies the filter
and nothing else.

Two mechanical properties, both testable:

- **A filter cannot be satisfied by another tenant's row.** `TenantID=acme` returns no row
  whose `Event.TenantID` is `globex` — asserted by seeding two tenants and checking the
  total, not by trusting the SQL.
- **The indexes, corrected against the schema.** The first draft of this section said the
  slice would *add* a tenant index. It exists already:
  `idx_events_tenant_id ON events (tenant_id) WHERE tenant_id <> ''`
  (`audit/internal/sqlitestore/schema.sql:62`). Two consequences, both worth stating
  because neither is obvious from the item:

  - **A partial index is not used by equality alone**, and this is the finding that
    changes the SQL. Measured with `EXPLAIN QUERY PLAN` against the real schema:

    | Query | Plan |
    |---|---|
    | `WHERE tenant_id = 'acme'` | `SCAN events` |
    | `WHERE tenant_id = 'acme' AND tenant_id <> ''` | `SEARCH events USING INDEX idx_events_tenant_id (tenant_id=?)` |

    So the scope filter must carry the **redundant** `AND tenant_id <> ''` term. Without
    it the feature ships and every console query full-scans the log — the exact outcome
    §4 exists to prevent. The redundancy is not noise: it is what lets the planner prove
    the index's predicate.
  - **`tenant.Single` is served by no index at all**, deliberately: its rows have
    `tenant_id = ''`, which the partial predicate excludes. Accepted — in a single-tenant
    deployment every row has `''`, so there is nothing to filter, and an index would
    exist only to speed up a query that returns the table.
  - **`actor_tenant_id` has no index at all**, so `Filter.ActorTenantID` — the field that
    answers *"what did platform staff do inside customers' tenants"* — would scan. The
    slice **adds** `idx_events_actor_tenant_id ON events (actor_tenant_id) WHERE
    actor_tenant_id <> ''`, with a plan test, because that query is the console's.

Without that second index the feature ships and the interesting query times out — which is
how *"we can query per tenant"* becomes *"we cannot query per tenant in practice"*.

---

## 5. Tests and mutation proofs

| Test | Mutant |
|---|---|
| `TenantID=acme` returns acme's rows only | drop the WHERE term |
| `TenantID=acme` returns nothing from globex even when the other filters match | filter in memory after the page is read |
| `TenantID=tenant.Single` returns the `""`-scoped rows — and NOT every row | treat `Single` as unset |
| zero `TenantID` returns every row (existing behaviour preserved) | treat zero as `Single` |
| `ActorTenantID=platform` + `TenantID` unset returns cross-tenant admin rows, which `TenantID=platform` does not | compare against `Event.TenantID` only |
| the query plan uses `idx_events_actor_tenant_id` for `ActorTenantID` | ship without it (the plan test fails) |
| the plan for `TenantID=acme` is a `SEARCH … USING INDEX`, not a `SCAN` | omit the `AND tenant_id <> ''` term — the filter still works, only the plan changes, which is why this must be asserted and not eyeballed |
| page 2 of a filtered list stays inside the tenant (`Filter.Cursor` + `TenantID` compose) | drop the filter when a cursor is present |
| the bound arguments stay aligned: adding a tenant term does not shift the existing scope/window bindings | append the tenant argument in the wrong position (the classic positional-bind bug, and it fails silently by matching the wrong column) |
| the scope filter uses `idx_events_tenant_id` for a named tenant | (and a note, not a test: `tenant.Single` scans by the partial predicate, deliberately) |
| `Page` paging still applies inside a tenant filter | ignore the window when a tenant filter is set |

---

## 6. Slices

1. **15a — this sketch**, accepted, with §2's rejection of the proposal's wording recorded.
2. **15b — `audit`**: the two fields, the query terms, the index, the plan test.
3. **15c — docs**: TD-11 closed in `../tasks/tech-debt.md`, `../design/flow.md`'s audit row, `CHANGELOG`. No
   migration: this is additive and the audit format does not change.

---

## 7. What this does not do

- It does not add a streaming/export-by-tenant API. `ExportForTenant` stays the unbounded
  one, and the console uses `List` with a tenant filter plus paging.
- It does not change `clusterIDs`/`ListScoped`, or the canonical payload, or
  `canonical_version`.
- It does not decide *who* may query across tenants. That is the application's gate, and
  `../tasks/tech-debt.md`'s "What is ready to use" already points at the two tools for it
  (`RequireDecision` with its 404-vs-403 split, and `Event.TenantID` separate from
  `Actor.TenantID`).
- It does not touch TD-12 (a service account has one tenant) or TD-13 (2FA policy per
  role); both need a product decision first.
