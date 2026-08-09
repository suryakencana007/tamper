# Phase 7 — handoff to the Barista + Docker machine

Everything in Phase 7 was developed on a machine with **neither Barista nor the
Docker deploy pipeline**. This file is the list of things that could not be
verified there, what was run instead, and the exact commands to close them.

Read it as a list of *unverified claims*, not a checklist of chores. Each item
names a DoD line that is deliberately still unticked.

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

### 2.3 `7i-1` — Docker deploy-artifact walk

**DoD line:** *"Docker deploy-artifact walk boots with chain self-test OK."*

```sh
# build + boot the deploy artifact, then confirm the boot log line
#   "audit chain self-test OK  count=… segments=…"
```

`segments` should be **unchanged** from the pre-migration boot on a
single-tenant DB. An increment means a v4 anchor was emitted where it should
not have been — see 2.2.

### 2.4 `-race` on the full suite

Run locally on `crypto`, `identity`, `espresso`, `audit`, `examples/scim`
(mingw gcc, `CGO_ENABLED=1`). Worth one full-suite pass on a machine with a
working toolchain by default:

```sh
CGO_ENABLED=1 go test -race ./... -count=1
```

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
