-- v1.1 Sprint 2 task 04: cluster_id column for per-cluster scoped
-- audit views. Closes the v0.6 / v0.7 / v0.8 / v0.9 / v1.0
-- carry-forward note "cluster-deployer / cluster-viewer should see
-- only audit events for clusters they have ACLs on".
--
-- The /admin/audit endpoint stays system-cluster-admin gated, but the
-- query layer narrows WITHIN the admin set: a cluster-deployer who
-- happens to also be cluster-admin sees only events scoped to their
-- reachable clusters. system-cluster-admin (system role) keeps the
-- unscoped view.
--
-- The column is NOT NULL DEFAULT '' so pre-v1.1 rows backfill to
-- empty. Empty cluster_id means "not cluster-scoped" — visible to all
-- callers (conservative behaviour: better to leak slightly than to
-- hide audit events from users who should see them).
--
-- Hash-chain note: cluster_id does NOT enter the canonical-payload
-- hash. It's a query-time filter, not part of integrity. Existing v3
-- chain rows verify cleanly under their stored hashes — no chain
-- restart needed.
--
-- Backfill: cluster-scoped event types (app.*, deployment.*,
-- cluster.*, cluster_acl.*, group.role.*, webhook.*) typically carry
-- the cluster_id in their `before` / `after` JSON snapshots; extract
-- via SQLite's json_extract for the backfill. Rows without an
-- extractable cluster_id stay empty (visible to all callers).
--
-- Re-running this migration is a no-op:
--   * the ADD COLUMN fails on re-application via the schema_migrations
--     guard in open.go (we record this file's name there);
--   * the UPDATE matches nothing the second time because cluster_id is
--     no longer empty on backfilled rows.

ALTER TABLE events ADD COLUMN cluster_id TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_events_cluster_id ON events (cluster_id) WHERE cluster_id <> '';

UPDATE events
SET cluster_id = COALESCE(
    json_extract(after_json,  '$.cluster_id'),
    json_extract(before_json, '$.cluster_id'),
    ''
)
WHERE (action LIKE 'app.%'
   OR action LIKE 'deployment.%'
   OR action LIKE 'cluster.%'
   OR action LIKE 'cluster_acl.%'
   OR action LIKE 'group.role.%'
   OR action LIKE 'webhook.%')
  AND cluster_id = '';
