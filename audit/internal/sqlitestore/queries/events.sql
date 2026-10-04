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

-- name: GetEventByID :one
-- Looks up a single event by id. RedactEvent uses it to tell a row
-- that does not exist from a lookup that failed.
SELECT
    id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
    action, resource_type, resource_id, cluster_id, request_id,
    before_json, after_json, prev_hash, hash, canonical_version,
    tenant_id, actor_tenant_id, row_salt,
    c_actor_email, c_actor_name, c_actor_ip, c_before, c_after
FROM events
WHERE id = ?;

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

-- name: PruneOlderThan :execrows
DELETE FROM events WHERE at < ?;

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

-- name: GetFirstEventNotAtVersion :one
-- Returns the canonical_version of one row that is NOT at the given
-- version, or no row when every row is. NewSQLiteLogger uses it to
-- refuse a DB that holds rows this package cannot verify. LIMIT 1, so
-- it stops at the first such row; on a DB where every row is at the
-- given version it still reads the whole table, because nothing
-- indexes canonical_version.
SELECT canonical_version
FROM events
WHERE canonical_version <> ?
LIMIT 1;
