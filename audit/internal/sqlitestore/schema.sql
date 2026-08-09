-- schema.sql — single source of truth for the audit DB schema.
-- Mirrors migrations/001_events.sql. sqlc reads this file to derive
-- the Go model types; runtime applies the migrations in order.
--
-- Keep these in sync — there's a CI check (go test
-- ./packages/tamper/audit/sqlitestore/... -run TestSchemaMigrationParity)
-- that asserts they match.

-- Column order matches the SELECT projection used by every read query
-- so sqlc reuses the single Event model type rather than generating
-- per-query row structs. Migration 004 added cluster_id to the live
-- schema via ALTER TABLE (which appends to the end); this file pins the
-- logical column order for sqlc's typegen — the runtime SELECT lists
-- below match this order explicitly.
CREATE TABLE events (
    id                TEXT NOT NULL PRIMARY KEY,
    at                DATETIME NOT NULL,
    actor_user_id     TEXT NOT NULL DEFAULT '',
    actor_email       TEXT NOT NULL DEFAULT '',
    actor_ip          TEXT NOT NULL DEFAULT '',
    actor_type        TEXT NOT NULL DEFAULT 'user',
    actor_name        TEXT NOT NULL DEFAULT '',
    action            TEXT NOT NULL,
    resource_type     TEXT NOT NULL,
    resource_id       TEXT NOT NULL DEFAULT '',
    -- cluster_id is the per-cluster scope marker (v1.1 task 04).
    -- Empty string = "not cluster-scoped" (auth.*, system.* events) and
    -- is visible to all callers. Non-empty = filtered by the caller's
    -- reachable cluster set when the system-cluster-admin gate is open
    -- to a non-system-admin caller. NOT part of the canonical-payload
    -- hash; purely a query-time filter.
    cluster_id        TEXT NOT NULL DEFAULT '',
    request_id        TEXT NOT NULL DEFAULT '',
    before_json       TEXT NOT NULL DEFAULT '',
    after_json        TEXT NOT NULL DEFAULT '',
    prev_hash         BLOB NOT NULL,
    hash              BLOB NOT NULL,
    canonical_version INTEGER NOT NULL DEFAULT 1,
    -- Phase 7 (migration 005). tenant_id is the row's SCOPE and IS part
    -- of the canonical payload at canonical_version=4 — unlike
    -- cluster_id above, because a tenant is the trust boundary rather
    -- than a visibility filter inside one. actor_tenant_id is the
    -- actor's home tenant, a different fact (see 005_tenant_v4.sql).
    -- row_salt + c_* implement redactable PII commitments: the c_*
    -- columns are what v4 hashes, so nulling the plaintext and zeroing
    -- the salt erases the value without breaking the chain.
    tenant_id         TEXT NOT NULL DEFAULT '',
    actor_tenant_id   TEXT NOT NULL DEFAULT '',
    row_salt          BLOB NOT NULL DEFAULT x'',
    c_actor_email     BLOB NOT NULL DEFAULT x'',
    c_actor_name      BLOB NOT NULL DEFAULT x'',
    c_actor_ip        BLOB NOT NULL DEFAULT x'',
    c_before          BLOB NOT NULL DEFAULT x'',
    c_after           BLOB NOT NULL DEFAULT x''
);

CREATE INDEX events_at_desc_idx ON events (at DESC, id);
CREATE INDEX events_actor_user_idx ON events (actor_user_id);
CREATE INDEX events_resource_idx ON events (resource_type, resource_id);
CREATE INDEX events_request_idx ON events (request_id);
CREATE INDEX idx_events_cluster_id ON events (cluster_id) WHERE cluster_id <> '';
CREATE INDEX idx_events_tenant_id ON events (tenant_id) WHERE tenant_id <> '';
