# Phase 7 — handoff to the Barista + Docker machine

Everything in Phase 7 was developed on a machine with **neither Barista nor the
Docker deploy pipeline**. This file is the list of things that could not be
verified there, what was run instead, and the exact commands to close them.

Read it as a list of *unverified claims*, not a checklist of chores. Each item
names a DoD line that is deliberately still unticked.

---

## 0. Status — run on the Barista + Docker machine, 2026-08-09

All four items below were executed. Three closed clean. **One failed, and it
found a real regression** — which is the outcome this file existed to make
possible.

| Item | DoD line | Result |
|---|---|---|
| 2.1 | Barista CI green, zero adapter diff | **FAILED** — 4 tests, one root cause. See §2.5. |
| 2.2 | Boot verify on a real Barista DB | **CLOSED** — byte parity, mutation-proved |
| 2.3 | Docker deploy-artifact boots, chain self-test OK | **CLOSED** — `69 events across 3 segments` |
| 2.4 | `-race` on the full suite | **CLOSED** — 16/16 packages, 0 races |

**The headline: migration 005 breaks external callers of the exported
`audit/sqlitestore` package.** Barista's identity adapter needed zero changes —
the additive-first promise held there — but four Barista tests that were green
on `v0.2.5` go red on the Phase 7 tip. Full analysis in **§2.5**. That is an
invariant-1 violation and it blocks the `7l-1` flip until it is answered.

Two corrections to what this file used to say, both found by running it:

- The boot log line is
  `barista: audit boot-time chain integrity check OK (N events across M segments, Xms)`,
  not `audit chain self-test OK count=… segments=…`. §2.3 below is corrected.
- `moon run barista:walk` is the **Playwright** DoD smoke harness, which boots
  via `go run` against a scratch `walk-audit.db`. It is not a Docker walk.
  §2.3 is "build the deploy image and boot it", and that is what was run.

---

## 1. Branch layout

Branches are **linearly stacked** — each is based on the one above it, in
manifest order. The tip therefore contains everything.

```
main
 └─ phase7/7a-1-tenant-package
     └─ phase7/amend-7a2-gating
         └─ phase7/7b-1-tenant-id-fields
             └─ phase7/7a-2-tenanttest-harness
                 └─ phase7/7b-2-tenant-scoped-core
                     └─ phase7/7b-3-examples-multitenant
                         └─ phase7/7c-1-tid-claim
                             └─ … (7c-2, 7d-1, 7e-1, 7e-2, 7f-1, 7f-2,
                                    7g-1, 7g-2, 7h-1)
                                 └─ phase7/decide-audit-chain-open-item-1
                                     └─ phase7/7k-1-rate-limiting
                                         └─ phase7/7j-1-invitations
                                             └─ phase7/answer-iso27001-revisit-condition
                                                 └─ phase7/7i-1-audit-canonical-v4
                                                     └─ fix/audit-chain-single-writer   ← tip
```

To reproduce the whole state:

```sh
git fetch origin
git checkout fix/audit-chain-single-writer
```

One branch per slice is deliberate (the manifest's "one slice per PR, never
batch"). Review them individually; the tip is only for running the checks
below in one pass.

---

## 2. What could not be verified here

### 2.1 Barista CI — deferred for the whole phase

**DoD line, appearing in most slices:** *"Barista CI green with zero diff in
its adapter."*

**What stood in for it.** `identity/legacy_adapter_test.go` — a hand-written
adapter that implements `identity.Store` and deliberately does **not** embed
`MemStore`, so it fails to compile the moment the core reaches for a
tenant-scoped method it should not. Plus a golden port-call trace, added after
an adversarial review found that an extra pre-flight read in the provision
path compiled and left all 15 packages green.

That is a good proxy. It is not Barista.

```sh
# in the Barista workspace
moon run barista:ci
git -C <barista> diff --stat -- '*identity*'   # expect: empty
```

The contract is **zero diff in Barista's identity adapter**. A non-empty diff
means the additive-first promise leaked, and the slice that caused it is wrong
— not Barista.

### RUN 2026-08-09 — adapter contract HELD, CI RED

Barista at `32ad4bb`, pointed at the Phase 7 tip via a local `replace`
(reverted afterwards; Barista's tree is untouched).

- `go build ./...` — **clean**. Barista compiles against Phase 7 with no
  source change.
- `git diff --stat -- '*identity*'` — **empty**. The adapter contract held.
- `moon run barista:ci` — **RED** (`49m 25s`). Everything passed except
  `barista:test`: web install/build/test/check, `vulncheck` (0 called
  vulnerabilities), `lint` (0 issues), `build`.

Four tests failed, all with one root cause, none in the identity adapter:

| Package | Test |
|---|---|
| `cmd/barista` | `TestBootstrapAuditChainMigrate_FullCycle` |
| `cmd/barista` | `TestAuditVerifyCLI_MixedChain` |
| `cmd/barista` | `TestAuditVerifyCLI_FilterByVersion` |
| `internal/audit` | `TestLoadFixture_AuditChainV1_DuplicateID` |

Attributed, not assumed — each was run under `-run` with `-v`, `=== RUN`
confirmed present (per §5's third sharp edge), on both versions:

```
v0.2.5                        -> all 4 PASS
v0.2.6-0.20260809034721-e00ba94e4f2e -> all 4 FAIL
```

Diagnosis in **§2.5**.

### 2.2 `7i-1` — boot verify on a real Barista audit DB

**DoD line:** *"Boot verify green on a real Barista DB post-migration."*

Migration `005_tenant_v4.sql` adds eight columns and one index and **rewrites
zero rows**. Every pre-existing row keeps its own `canonical_version` and its
own stored hash. That is asserted locally by
`TestV4_PreExistingRowsKeepTheirHash` and by a v3 hash pin captured from the
pre-slice commit — but only against synthetic chains.

A real Barista DB has v2 rows, chain-restart anchors, a chain-migrate marker
and a retention-pruned prefix. That combination does not exist in the fixtures.

```sh
cp <barista-audit>.db /tmp/audit-before.db

# 1. Hash inventory BEFORE.
sqlite3 /tmp/audit-before.db \
  "SELECT id, canonical_version, hex(hash) FROM events ORDER BY at, canonical_version, id;" \
  > /tmp/hashes-before.txt

# 2. Boot once against a copy so migration 005 applies.
cp /tmp/audit-before.db /tmp/audit-after.db
#    …run the Barista boot path, or any tamper caller that opens this DB…

# 3. Hash inventory AFTER, and diff. THIS MUST BE EMPTY.
sqlite3 /tmp/audit-after.db \
  "SELECT id, canonical_version, hex(hash) FROM events ORDER BY at, canonical_version, id;" \
  > /tmp/hashes-after.txt
diff /tmp/hashes-before.txt /tmp/hashes-after.txt && echo "BYTE PARITY OK"

# 4. Boot verify must walk the whole chain clean.
#    audit.VerifyChainPostMigration(ctx, logger) -> nil error
```

**Expected:** the diff is empty and the walk passes. Barista is single-tenant,
so `SQLiteLoggerOptions.Tenancy` is false, **no v4 anchor is emitted, and not a
single v4 row is written.** If any v4 row appears on a Barista DB, that is the
bug — report it rather than working around it.

### RUN 2026-08-09 — CLOSED

Source DB: `barista/.dev/audit.db`, 69 rows — **1× v2, 68× v3, two
`system.audit.chain_restart` anchors and one `system.audit.chain_migrate`
marker**, migrations 001-004 applied, 005 pending. Exactly the combination the
fixtures could not reach.

| Check | Result |
|---|---|
| Hash inventory before vs after 005 | **diff empty** — all 69 rows keep their stored hash |
| `VerifyChainPostMigration` | `count=69 segments=3`, nil error |
| v4 rows written | **0** — tenancy false, so no anchor, as designed |
| Anchors / total rows after | 3 / 69 — unchanged |
| Idempotency | second boot changes nothing |

**Mutation proof** (the walk is not vacuous): flipping one byte of a mid-chain
row's stored hash produced **exit 3** at index 30, naming the row, both hashes,
and the `barista audit migrate-force` recovery pointer.

**Extra, beyond the DoD — the v4 anchor path on a real DB.** With
`Tenancy: true` plus `SQLiteLogger.BootstrapChainV4`, on a copy of the same DB:
the anchor is emitted exactly once (`emitted=true`, then `false`), and its
`prev_hash` is the **real latest hash** `F5FC…65CF`, not the zero sentinel that
would fail the boot gate. `count 69→70`, `segments 3→4`, and all 69
pre-existing rows stay byte-identical. The mixed v2/v3/v4 chain walks clean.

> Note: the harness must call `BootstrapChainV4` explicitly. Opening the DB
> with `Tenancy: true` alone emits nothing — the first attempt here proved
> nothing until the bootstrap call was added.

### 2.3 `7i-1` — Docker deploy-artifact walk

**DoD line:** *"Docker deploy-artifact walk boots with chain self-test OK."*

```sh
# build + boot the deploy artifact, then confirm the boot log line
#   "barista: audit boot-time chain integrity check OK (N events across M segments, Xms)"
```

`segments` should be **unchanged** from the pre-migration boot on a
single-tenant DB. An increment means a v4 anchor was emitted where it should
not have been — see 2.2.

### RUN 2026-08-09 — CLOSED

`deploy/Dockerfile` states tamper is "a normal versioned dependency fetched by
`go mod download` from the module proxy — no in-tree source, no replace
directive", so the image **cannot** see a local tamper. Honouring that rather
than editing the Dockerfile: the proxy resolves the Phase 7 tip to a real
pseudo-version, so the bump is an ordinary `go get`.

```sh
go get github.com/suryakencana007/tamper@e00ba94e4f2ea4d00da6b542e7d0f4597a8583ea
#   => v0.2.6-0.20260809034721-e00ba94e4f2e   (0 replace directives)
docker build -f deploy/Dockerfile -t barista:phase7 .          # 105MB, exit 0
docker run -v <data>:/data -e BARISTA_AUTH_JWT_SECRET=… \
           -e BARISTA_DB_PATH=/data/barista.db \
           -e BARISTA_AUDIT_DBPATH=/data/audit.db barista:phase7
```

Done in a throwaway `git worktree` so the bump never touched Barista's tree.
The container was given the **pre-migration** DB, so the image itself performed
migration 005 — a real deploy, not a replay.

```
barista: audit chain migration: already migrated; skipping
barista: audit boot-time chain integrity check OK (69 events across 3 segments, 2ms)
barista 0.0.0-dev listening on :8080
```

`segments=3`, **unchanged**. After the containerised migration: 69 rows, **0 v4
rows**, 3 anchors, and the hash inventory is byte-identical to the original.

### 2.4 `-race` on the full suite

Run locally on `crypto`, `identity`, `espresso`, `audit`, `examples/scim`
(mingw gcc, `CGO_ENABLED=1`). Worth one full-suite pass on a machine with a
working toolchain by default:

```sh
CGO_ENABLED=1 go test -race ./... -count=1
```

### RUN 2026-08-09 — CLOSED

`CGO_ENABLED=1 go test -race ./... -count=1` with mingw gcc on PATH:
**16/16 packages ok, zero failures, zero data races.**

---

## 2.5 THE FINDING — migration 005 breaks external `sqlitestore` callers

This is what the Barista gate was for, and it is why deferring it for the whole
phase was expensive. It is a **tamper defect**, not a Barista one.

**Mechanism.**

1. Migration 005 adds six columns as `BLOB NOT NULL DEFAULT x''`:
   `row_salt`, `c_actor_email`, `c_actor_name`, `c_actor_ip`, `c_before`,
   `c_after`.
2. `audit/sqlitestore` is a **public, importable package** — not `internal/`.
   Its sqlc-generated `InsertEvent` **names every column** (§5, sharp edge 2),
   so a `DEFAULT` never applies.
3. tamper coerces nil→empty with `nonNilBytes`, but **only in its own `Log`
   path** (`audit/audit_sqlite.go:325-330`). The exported
   `sqlitestore.Queries.InsertEvent` does no coercion at all.
4. Therefore any external caller building `InsertEventParams` as a struct
   literal — which is the only way — leaves all six fields as nil `[]byte`,
   which the driver sends as six explicit NULLs, and the insert dies with
   `NOT NULL constraint failed: events.row_salt (1299)`.

**Why this is invariant 1, violated.** The caller never touches tenancy. It
passes no tenant, sets no option, and wants exactly pre-Phase-7 behavior. It
compiled before and it compiles now — so the compiler cannot catch it — and it
fails at runtime. That is the same shape as the `CountUsers` trap the manifest
singles out: *"compiles, passes, ships, and surfaces months later."* Here it
surfaced only because a real consumer's suite was finally run.

**Scope.** The four failing tests are test-only code, but the broken surface is
production API. Any consumer doing a direct `InsertEvent` — a backfill script,
an importer, a migration tool — breaks identically. Barista's tests are simply
the only callers that exist today.

**Do not fix it inside a slice** (rule 7 / 4e). It needs its own change, with a
decision between at least:

- **A.** Drop `NOT NULL` from the six columns and coerce NULL→empty on read.
  Smallest blast radius; changes 005, which has now been applied to real DBs,
  so it needs a 006 rather than an edit.
- **B.** Keep the schema, override the six fields in `sqlc.yaml` to a type
  whose `driver.Valuer` renders nil as `x''`. Fixes every caller at once
  without touching SQL. `COALESCE(?, x'')` is **not** an option — §5 records
  that it degrades the params to `Column20 interface{}`.
- **C.** Declare `audit/sqlitestore` non-public and move it under `internal/`.
  Honest about intent, but it is a breaking change for anyone already
  importing it, and it does not help before `7l-1`.

Whatever is chosen, the regression test belongs in tamper: construct
`InsertEventParams` as a bare struct literal, insert, and require success.
There is no such test today, which is exactly why this reached a consumer.

**This blocks `7l-1`.** Its gate includes "Barista migrated in the same release
cycle", and Barista cannot go green on the Phase 7 tip until this is answered.

---

## 3. Checks that DID pass here, for contrast

Do not re-litigate these; they are covered and the tests are in the tree.

```sh
go build ./... && go vet ./...
go test ./... -count=1          # 16 packages
golangci-lint run ./...         # 0 issues
sqlc generate && git diff --exit-code audit/sqlitestore/   # generated layer is reproducible
```

Mutation proofs: 14 for `7i-1`, 11 for `7j-1`, 9 for `7k-1`, 4 for the
single-writer fix — each applied to the production path, compile-verified, and
confirmed to turn a **named test that actually ran** red. The per-slice PR
bodies list them.

---

## 4. Open decisions — do not start these without a human

1. **`7l-1` — the M6 default flip (v0.4.0).** Folds `TenantScopedStore` into
   `Store`, deletes the fallback and the boot assertion, and makes `TenantID`
   required. This is the deliberate breaking change and a release decision.
2. **The audit-chain revisit condition.** Answered against ISO/IEC 27001 and
   found **not triggered** (sketch §8 item 1). It stays recorded because ISO
   27001 A.5.34 defers to applicable PII law: selling into a GDPR-covered
   market under DPAs can revive it. If it does, re-run the analysis already
   written rather than starting a new one.

---

## 5. Known sharp edges found during the phase

Recorded because each cost real time and none is obvious from the code.

- **`sqlc` silently truncates generated SQL around multi-byte characters.** An
  em dash in a query-file comment produced a stray `C;` and a query ending in
  `canonical_versio`. Keep `audit/sqlitestore/queries/*.sql` comments
  **ASCII-only**; there is a note in the file saying so.
- **A SQL column `DEFAULT` does not apply when the column is named in the
  INSERT.** sqlc always names every column, so a Go nil slice arrives as an
  explicit NULL and trips `NOT NULL`. Coerced at the Go boundary
  (`nonNilBytes`). `COALESCE(?, x'')` in the query is *not* a fix — sqlc
  degrades those parameters to `Column20 interface{}`.
- **`go test -run` through a non-POSIX shell.** A mutation harness passing
  `-run '^Name$'` with the quotes intact matched zero tests, exited 0, and
  reported six healthy guards as all-surviving. Always assert the test
  actually ran (`=== RUN`), never just the exit code.
- **`-race` needs `CGO_ENABLED=1` and a gcc on PATH.** mingw at
  `C:\ProgramData\mingw64\mingw64\bin` on the dev machine; session shells need
  it prepended.
