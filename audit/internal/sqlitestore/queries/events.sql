-- name: InsertEvent :exec
INSERT INTO events (
    id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
    action, resource_type, resource_id, cluster_id, request_id,
    before_json, after_json, prev_hash, hash, canonical_version,
    tenant_id, actor_tenant_id, row_salt,
    c_actor_email, c_actor_name, c_actor_ip, c_before, c_after
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetLatestHash :one
-- v1.8 follow-up #2: canonical_version DESC is the deterministic
-- tiebreaker for same-at rows. See audit_sqlite.go latestHash() docs.
SELECT hash FROM events ORDER BY at DESC, canonical_version DESC, id DESC LIMIT 1;

-- name: GetLatestAt :one
-- v1.8 follow-up #3: returns the most-recent event's `at` value, used by
-- NewSQLiteLogger to initialize the in-memory monotonic-at watermark on
-- open. See audit_sqlite.go SQLiteLogger.lastAt docs.
SELECT at FROM events ORDER BY at DESC, canonical_version DESC, id DESC LIMIT 1;

-- name: ListEventsAll :many
SELECT
    id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
    action, resource_type, resource_id, cluster_id, request_id,
    before_json, after_json, prev_hash, hash, canonical_version,
    tenant_id, actor_tenant_id, row_salt,
    c_actor_email, c_actor_name, c_actor_ip, c_before, c_after
FROM events
ORDER BY at DESC, id DESC
LIMIT ?;

-- name: ListEventsBefore :many
SELECT
    id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
    action, resource_type, resource_id, cluster_id, request_id,
    before_json, after_json, prev_hash, hash, canonical_version,
    tenant_id, actor_tenant_id, row_salt,
    c_actor_email, c_actor_name, c_actor_ip, c_before, c_after
FROM events
WHERE at < ?
   OR (at = ? AND id < ?)
ORDER BY at DESC, id DESC
LIMIT ?;

-- name: ListEventsByActor :many
SELECT
    id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
    action, resource_type, resource_id, cluster_id, request_id,
    before_json, after_json, prev_hash, hash, canonical_version,
    tenant_id, actor_tenant_id, row_salt,
    c_actor_email, c_actor_name, c_actor_ip, c_before, c_after
FROM events
WHERE actor_user_id = ?
ORDER BY at DESC, id DESC
LIMIT ?;

-- name: ListEventsByResource :many
SELECT
    id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
    action, resource_type, resource_id, cluster_id, request_id,
    before_json, after_json, prev_hash, hash, canonical_version,
    tenant_id, actor_tenant_id, row_salt,
    c_actor_email, c_actor_name, c_actor_ip, c_before, c_after
FROM events
WHERE resource_type = ? AND resource_id = ?
ORDER BY at DESC, id DESC
LIMIT ?;

-- name: ListEventsByRequest :many
SELECT
    id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
    action, resource_type, resource_id, cluster_id, request_id,
    before_json, after_json, prev_hash, hash, canonical_version,
    tenant_id, actor_tenant_id, row_salt,
    c_actor_email, c_actor_name, c_actor_ip, c_before, c_after
FROM events
WHERE request_id = ?
ORDER BY at DESC, id DESC
LIMIT ?;

-- name: ListEventsForVerify :many
-- v1.8 Sprint 0 follow-up (TD-AUDIT-12): canonical_version ASC is the
-- deterministic tiebreaker for same-at rows. See verify_boot.go's
-- package docs for the rationale + observed flake rate.
SELECT
    id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
    action, resource_type, resource_id, cluster_id, request_id,
    before_json, after_json, prev_hash, hash, canonical_version,
    tenant_id, actor_tenant_id, row_salt,
    c_actor_email, c_actor_name, c_actor_ip, c_before, c_after
FROM events
ORDER BY at ASC, canonical_version ASC, id ASC;

-- name: ListEventsByCanonicalVersion :many
-- Returns every event at the given canonical_version in chain-ascending
-- order. Used by VerifyLegacy(N, "") - the v1.4 fix shape (TD-AUDIT-10)
-- closes the walk-window-scoping issue where loaded fixture events
-- with older timestamps fell behind the walker's starting point.
SELECT
    id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
    action, resource_type, resource_id, cluster_id, request_id,
    before_json, after_json, prev_hash, hash, canonical_version,
    tenant_id, actor_tenant_id, row_salt,
    c_actor_email, c_actor_name, c_actor_ip, c_before, c_after
FROM events
WHERE canonical_version = ?
ORDER BY at ASC, id ASC;

-- name: GetEventByID :one
-- Used by the --from-id walker-anchor flag (v1.4 - TD-AUDIT-10). Looks
-- up a single event by id so VerifyLegacy can validate the row exists
-- + carries the expected canonical_version before walking from it.
SELECT
    id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
    action, resource_type, resource_id, cluster_id, request_id,
    before_json, after_json, prev_hash, hash, canonical_version,
    tenant_id, actor_tenant_id, row_salt,
    c_actor_email, c_actor_name, c_actor_ip, c_before, c_after
FROM events
WHERE id = ?;

-- name: ListEventsForVerifyFromChainRestart :many
-- Walks the chain segment starting at the most-recent
-- system.audit.chain_restart row. The dispatcher picks the row's
-- (at, id), then this query returns every event from that row forward
-- (inclusive) in ascending chain order. Used by `barista audit verify`
-- to walk the v1.0+ chain when older-shape rows still live alongside.
SELECT
    id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
    action, resource_type, resource_id, cluster_id, request_id,
    before_json, after_json, prev_hash, hash, canonical_version,
    tenant_id, actor_tenant_id, row_salt,
    c_actor_email, c_actor_name, c_actor_ip, c_before, c_after
FROM events
WHERE at > ? OR (at = ? AND id >= ?)
ORDER BY at ASC, id ASC;

-- name: GetLatestChainRestart :one
-- Returns the most-recent chain-restart event. Caller passes the
-- action string (audit.ActionAuditChainRestart) so sqlc doesn't
-- see the dotted literal inline. Used by `barista audit verify`
-- to identify the latest chain genesis row when multiple
-- canonical-version segments live in the same DB.
SELECT
    id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
    action, resource_type, resource_id, cluster_id, request_id,
    before_json, after_json, prev_hash, hash, canonical_version,
    tenant_id, actor_tenant_id, row_salt,
    c_actor_email, c_actor_name, c_actor_ip, c_before, c_after
FROM events
WHERE action = ?
ORDER BY at DESC, canonical_version DESC, id DESC
LIMIT 1;

-- name: GetLatestChainRestartAtVersion :one
-- Returns the most-recent chain-restart event at a specific
-- canonical_version. Used by `barista audit verify --legacy
-- --canonical-version=N` to walk the v1.0 (canonical_version=2)
-- segment in isolation when both v2 + v3 genesis rows are present.
SELECT
    id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
    action, resource_type, resource_id, cluster_id, request_id,
    before_json, after_json, prev_hash, hash, canonical_version,
    tenant_id, actor_tenant_id, row_salt,
    c_actor_email, c_actor_name, c_actor_ip, c_before, c_after
FROM events
WHERE action = ? AND canonical_version = ?
ORDER BY at DESC, id DESC
LIMIT 1;

-- name: ListEventsNonClusterScoped :many
-- Returns audit rows that aren't scoped to any cluster (cluster_id =
-- '': auth.*, system.*, anything the middleware emits without stamping
-- a cluster_id). Used as the degenerate-case fallback by the v1.1 task
-- 04 ListScoped path when the caller has zero reachable clusters - the
-- code-side IN clause cannot bind a zero-element slice, so we route
-- to this query instead.
SELECT
    id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
    action, resource_type, resource_id, cluster_id, request_id,
    before_json, after_json, prev_hash, hash, canonical_version,
    tenant_id, actor_tenant_id, row_salt,
    c_actor_email, c_actor_name, c_actor_ip, c_before, c_after
FROM events
WHERE cluster_id = ''
ORDER BY at DESC, id DESC
LIMIT ?;

-- name: ListEventsNonClusterScopedBefore :many
-- Cursor-paginated variant of ListEventsNonClusterScoped.
SELECT
    id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
    action, resource_type, resource_id, cluster_id, request_id,
    before_json, after_json, prev_hash, hash, canonical_version,
    tenant_id, actor_tenant_id, row_salt,
    c_actor_email, c_actor_name, c_actor_ip, c_before, c_after
FROM events
WHERE cluster_id = ''
  AND (at < ? OR (at = ? AND id < ?))
ORDER BY at DESC, id DESC
LIMIT ?;

-- name: CountAuditEventsByActionSince :many
-- v1.2 Sprint 2 task 03: digest body source. Counts events grouped by
-- action, filtered to occurred_at > since. Sorted desc-by-count so the
-- digest body's first lines are the noisiest actions. Used by the
-- AuditDigestService.composeDigest path; the scheduler iterates
-- opted-in cluster-admin users and calls this with their last_at
-- (or users.created_at on first emit).
--
-- v1.2 emits to system-cluster-admins only so the query is unscoped;
-- per-cluster-scoped digests for cluster-deployer tier are v1.3 (would
-- add a cluster_id IN (?...) clause, same shape as the v1.1 task 04
-- ListScoped code path).
SELECT action, COUNT(*) AS count
FROM events
WHERE at > ?
GROUP BY action
ORDER BY count DESC, action ASC;

-- name: CountChainRestartV2 :one
-- Used by the boot path to decide whether to insert the v1.0 chain
-- restart genesis row. Caller passes the canonical version (2) to
-- count. Zero count on a fresh v1.0 boot (or a v0.9 upgrade) means
-- the boot path will insert the genesis row; non-zero means a prior
-- boot already inserted it.
SELECT COUNT(*) FROM events WHERE canonical_version = ?;

-- name: CountEventsByCanonicalVersion :many
-- Returns per-canonical-version row counts across the whole audit DB.
-- Used by `barista audit verify` to print the distribution summary
-- ("canonical_version=2: 3, canonical_version=3: 9") after a clean
-- walk, so operators can sanity-check what segment shapes their DB
-- carries. Sorted by canonical_version ASC so the output is stable.
SELECT canonical_version, COUNT(*) AS event_count
FROM events
GROUP BY canonical_version
ORDER BY canonical_version ASC;

-- name: PruneOlderThan :execrows
DELETE FROM events WHERE at < ?;

-- name: CountEvents :one
SELECT COUNT(*) FROM events;

-- name: UpdateEventHash :exec
-- Used by the v1.5 audit-chain encoder migration (audit.MigrateLegacyV2Hashes).
-- Writes the recomputed hash + prev_hash for a single existing event,
-- leaving every other column unchanged. The migration walks v=2 rows
-- in chain order; each row's recomputed hash becomes the next row's
-- prev_hash so the migrated chain stays self-consistent.
--
-- Idempotent on re-run: the WHERE id = ? clause matches at most one
-- row; re-running with the same hash + prev_hash is a no-op write.
UPDATE events
SET hash = ?, prev_hash = ?
WHERE id = ?;

-- name: CountEventsByAction :one
-- Counts every row whose action column equals the given string. Used by
-- HasChainMigrate (v1.5 task 01) to check for an existing
-- system.audit.chain_migrate marker on boot so the encoder migration is
-- idempotent across pod restarts.
SELECT COUNT(*) FROM events WHERE action = ?;

-- name: DeleteEventByID :exec
-- Used by the v1.5 load-fixture ConflictForce policy. Removes a single
-- event by id (idempotent: zero-row deletes are not errors at the
-- sqlc level). Operators invoking `barista --load-fixture
-- --on-conflict=force` against an iterated fixture file rely on this
-- to clear prior partial-load rows before re-inserting. Closes
-- TD-INFRA-19 (v1.4 walk Step 71).
DELETE FROM events WHERE id = ?;

-- name: ListEventsByTenant :many
-- Phase 7 (7i-1): the tenant-scoped export projection. Oldest first: an
-- export is read as a narrative, unlike the paged admin views which are
-- newest-first. Ordering mirrors the verify walk's tiebreak so an export
-- and a chain walk agree on row order.
SELECT
    id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
    action, resource_type, resource_id, cluster_id, request_id,
    before_json, after_json, prev_hash, hash, canonical_version,
    tenant_id, actor_tenant_id, row_salt,
    c_actor_email, c_actor_name, c_actor_ip, c_before, c_after
FROM events
WHERE tenant_id = ?
ORDER BY at ASC, canonical_version ASC, id ASC;

-- name: RedactEventPII :exec
-- Phase 7 (7i-1): erasure in place. Clears the plaintext and ZEROES the
-- salt; the c_* commitment columns are deliberately untouched because
-- they are what the canonical payload hashed, so changing them would
-- break the chain in exactly the way the commitment scheme avoids.
-- Scoped to canonical_version=4: a pre-v4 row hashed its PII directly,
-- so there is nothing to redact without breaking its hash.
-- NOTE: keep these comments ASCII-only. sqlc mis-computes byte offsets
-- around multi-byte characters and silently TRUNCATES the generated SQL
-- (it produced "canonical_versio" and a stray "C;" from an em dash).
UPDATE events
SET actor_email = '',
    actor_name  = '',
    actor_ip    = '',
    before_json = '',
    after_json  = '',
    row_salt    = x''
WHERE id = ? AND canonical_version = 4;
