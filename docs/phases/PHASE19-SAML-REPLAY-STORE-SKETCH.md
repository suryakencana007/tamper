# Phase 19 — a shared `AssertionReplayStore` for multi-replica SAML (#137)

**Slice 19a — the design freeze.** Code lands in 19b, after this sketch is merged, because `saml` is
one of the frozen packages (`docs/tasks/tech-debt.md` §Process limits).

## 1. The gap, and why it is not a footnote

`saml` ships exactly one implementation of the ledger: `NewMemAssertionReplayStore()`, documented
"for a single process". `BuildProvider`'s own doc tells the caller to pass **"a shared store for
multiple replicas"** — and no such store exists. So every multi-replica deployment writes one, and
the thing it must get right is not obvious from the interface's shape:

> `ConsumeAssertion` is reached only after the signature and timing are verified, so the ledger
> cannot be flooded without valid assertions — but it is the ONLY thing standing between two
> replicas and the same assertion being accepted twice. Two replicas that disagree do not produce
> an error; they produce a second session.

That is the failure this slice exists to make unavailable.

## 2. What the port already decides (do not redesign it)

`saml/replay.go:83` is unusually specific, and the sketch keeps every part of it:

- **The zero return of a broken implementation is `(false, nil)` = "replay" = reject.** The
  signature was chosen so a half-written implementation fails CLOSED. An implementation that cannot
  tell "fresh" from "failed" must return an error, never `true`.
- **One atomic statement**: `INSERT ... ON CONFLICT DO NOTHING`, report `rows-affected == 1`.
  Read-then-write is the bug the interface is shaped to prevent, and a transaction that reads first
  is the same bug with more ceremony.
- **The key is opaque** (64 hex chars) and must not be parsed. Stored verbatim.
- **`expiresAt` is for garbage collection**, and GC is "the app's existing infrastructure, not a
  method on this port". The port does not grow a `Purge` method in this slice.

## 3. The decision

Ship **`saml.NewSQLiteAssertionReplayStore(dbPath string, opts ...SQLiteReplayOption) (*SQLiteAssertionReplayStore, error)`**,
mirroring `audit.NewSQLiteLogger`'s shape (a path, not a `*sql.DB`, so the schema and the pragmas
are the library's business and the app owns the file).

Schema, applied at construction (`CREATE TABLE IF NOT EXISTS`):

```sql
CREATE TABLE IF NOT EXISTS saml_assertion_replay (
    key        TEXT    PRIMARY KEY,   -- opaque, 64 hex chars, stored verbatim
    expires_at INTEGER NOT NULL       -- unix seconds; GC boundary, never compared for correctness
);
CREATE INDEX IF NOT EXISTS saml_assertion_replay_expires_at ON saml_assertion_replay (expires_at);
```

`ConsumeAssertion` is one statement, with the outcome read from `rows-affected`:

```sql
INSERT INTO saml_assertion_replay (key, expires_at) VALUES (?, ?) ON CONFLICT(key) DO NOTHING;
```

Pragmas: `busy_timeout=5000`, and WAL is **not** forced — a deployment sharing a file across
replicas on one host is the case this serves, and a WAL file adds a second artefact to back up for
no gain here. The comment says so rather than leaving it to taste.

## 4. Why GC is safe, checked rather than assumed

`replayExpiry` (`saml/replay.go:160`) computes
`max(now, IssueInstant) + MaxIssueDelay + MaxClockSkew`, floored at `now + MaxClockSkew`: it is the
instant after which **no process will accept that assertion again**, because crewjam's validity
window has closed. So a row purged at `expires_at` cannot re-admit a replay — the assertion it
guards is no longer usable. The in-memory store already relies on exactly this: its inline sweep
deletes expired keys and would happily accept the same key afterwards.

That is also why `expires_at` is **never** consulted for correctness: comparing it during
`ConsumeAssertion` would be a second, weaker answer to a question the signature check already owns.
A stale row that was never purged yields "replay" — the safe direction.

`PurgeExpiredBefore(ctx, t) (int, error)` is exposed on the **concrete type** for the app's
scheduler, because the interface deliberately has no such method.

## 5. Failure modes, and which way each one falls

| Condition | Behaviour |
|---|---|
| Two replicas consume the same key | exactly one `(true, nil)`; the loser `(false, nil)` — **the test that matters** |
| The database is unreachable | error → the caller answers 503 `ErrReplayStoreUnavailable`. **Never** `(false, nil)` silently, and never `true` |
| The key already exists but expired | `(false, nil)` — replay. The safe direction; GC cleans it later |
| A caller passes a key of another width | stored as given; the port says opaque, and a validating store would be inventing a rule the interface disclaims |

## 6. Tests and mutation proofs (slice 19b)

- **Two store instances over one file** — the feature's whole assertion. Sequential and concurrent
  (N goroutines across both instances): exactly one `true`, and the total of `true`s is 1.
- A closed/removed database returns an **error**, and the caller path answers `ErrReplayStoreUnavailable`
  (asserted through `ParseAssertion`, not only at the store).
- `PurgeExpiredBefore` removes only rows before `t`; a subsequent consume of a purged key is `true`
  again — and the test says why that is safe (the assertion is outside its window).
- Mutants: read-then-write instead of one statement (must fail the concurrency test); ignoring
  `rows-affected` (always `true`); swallowing the error into `(false, nil)` (must fail the outage
  test).

## 7. What this does not do

- **No Redis, no Postgres, no interface for other backends.** One implementation for the case that
  exists; the port is already the extension point.
- **No purge scheduling.** `PurgeExpiredBefore` is a tool; when to call it is operational, and a
  library that decided it would be inventing a deployment policy.
- **No change to the in-memory store or the port.**
- **Not a claim about host-level sharing.** SQLite over a network filesystem is out of scope, and
  the doc comment will say so: share the file between processes on one host, or implement the port
  for a real database.
