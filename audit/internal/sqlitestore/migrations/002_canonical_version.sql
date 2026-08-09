-- v1.0 Sprint 0 task 01: actor_type + canonical_version columns for
-- the audit hash-chain v1.0 split.
--
-- v0.6/v0.7/v0.8/v0.9 events were canonicalised with the Actor's
-- (UserID, Email, IP) tuple. v1.0 introduces an explicit Actor.Type
-- field (user / service_account / system) so SCIM-driven mutations
-- emitted under a service-account token aren't falsely attributed
-- to "some user." Including Type in the canonical payload changes
-- the hash bytes, so v1.0 first boot inserts a
-- `system.audit.chain_restart` row with prev_hash=zero and
-- canonical_version=2 — Verify walks forward from that row,
-- treating it as the new chain genesis.
--
-- Existing v0.9 rows default to canonical_version=1 (pre-v1.0
-- canonical shape) and actor_type='user'. The v0.9 chain rows
-- remain in the table and are still verifiable in isolation under
-- the v0.9 canonical shape; the production `barista audit verify`
-- walks forward from the most-recent canonical_version=2 row.
ALTER TABLE events ADD COLUMN actor_type        TEXT NOT NULL DEFAULT 'user';
ALTER TABLE events ADD COLUMN canonical_version INTEGER NOT NULL DEFAULT 1;
