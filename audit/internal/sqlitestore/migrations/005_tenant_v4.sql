-- Phase 7 slice 7i-1: canonical_version=4 — the tenant enters the hash,
-- and PII moves to redactable commitments.
--
-- THIS MIGRATION REWRITES ZERO EXISTING ROWS. Every column below is
-- additive with a NOT NULL DEFAULT, so pre-v4 rows backfill to empty and
-- keep their stored canonical_version and their stored hash, forever.
-- That is the non-negotiable part: a v3 row re-canonicalised as v4
-- breaks the chain, so the migration must not touch one.
--
-- Contrast migration 004 deliberately. cluster_id was added with an
-- explicit note that it does NOT enter the canonical payload — "a
-- query-time filter, not part of integrity" — and so needed no chain
-- restart. tenant_id is the opposite case and needs the opposite
-- treatment: a cluster is a visibility scope inside one trust domain,
-- whereas a tenant IS the trust boundary. An unhashed tenant column can
-- be re-attributed from one customer to another without breaking
-- anything, and evidence that can be silently re-attributed is not
-- evidence. Hence a new canonical version rather than another
-- outside-the-hash column.
--
-- The chain-restart anchor for v4 is NOT emitted here. It is emitted
-- through Logger.Log at boot (see migration.go, bootstrapAuditChainV4),
-- because the anchor's prev_hash must be the REAL latest hash — the
-- zero sentinel is true only on an empty table and would fail the boot
-- gate on any populated DB. SQL cannot compute that.
--
--   tenant_id        the row's SCOPE: whose log this event belongs in.
--   actor_tenant_id  the ACTOR's home tenant. Different fact: a support
--                    engineer in tenant A acting on tenant B's resource
--                    has actor_tenant_id=A and tenant_id=B. Exports
--                    filter on tenant_id; filtering on the actor's
--                    tenant silently omits exactly the cross-tenant
--                    admin actions a customer most wants to see.
--   row_salt         per-row salt for the PII commitments. 32 random
--                    bytes on a v4 row, empty on pre-v4 rows, and ALL
--                    ZEROES once the row has been redacted.
--   c_*              the commitments themselves: H(salt || field ||
--                    value). These are what the v4 canonical payload
--                    hashes, in place of the plaintext, so erasure
--                    (null the plaintext, zero the salt, keep these 32
--                    bytes) leaves the chain verifiable.
--
-- Re-running is a no-op: open.go's schema_migrations guard records this
-- file's name, and the ADD COLUMNs would fail on re-application anyway.

ALTER TABLE events ADD COLUMN tenant_id       TEXT NOT NULL DEFAULT '';
ALTER TABLE events ADD COLUMN actor_tenant_id TEXT NOT NULL DEFAULT '';
ALTER TABLE events ADD COLUMN row_salt        BLOB NOT NULL DEFAULT x'';
ALTER TABLE events ADD COLUMN c_actor_email   BLOB NOT NULL DEFAULT x'';
ALTER TABLE events ADD COLUMN c_actor_name    BLOB NOT NULL DEFAULT x'';
ALTER TABLE events ADD COLUMN c_actor_ip      BLOB NOT NULL DEFAULT x'';
ALTER TABLE events ADD COLUMN c_before        BLOB NOT NULL DEFAULT x'';
ALTER TABLE events ADD COLUMN c_after         BLOB NOT NULL DEFAULT x'';

-- Partial index, matching the cluster_id precedent: a single-tenant
-- deployment carries '' on every row and gains nothing from indexing it.
CREATE INDEX idx_events_tenant_id ON events (tenant_id) WHERE tenant_id <> '';
