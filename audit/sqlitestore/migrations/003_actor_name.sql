-- v1.1 Sprint 0 task 00: actor_name column for the audit-actor schema
-- completion (closes TD-AUDIT-03 + TD-AUDIT-04).
--
-- v1.0 left a cosmetic wart on the audit log's actor wire shape:
-- `audit.ActorService(saID, saName)` + `audit.ActorSystem(name)` both
-- stuffed the subsystem name into the `actor_email` column because the
-- Actor struct had no proper Name field. v1.1 adds a first-class
-- `actor_name` column + Actor.Name field; system + service_account rows
-- carry the name there, users keep their email in actor_email.
--
-- Backfill semantics:
--   * For rows with actor_type IN ('system', 'service_account') whose
--     actor_name is still '' AND whose actor_email was used as the
--     name carrier (non-empty), copy actor_email → actor_name, then
--     clear actor_email on those same rows so the going-forward shape
--     is consistent.
--   * User rows leave actor_name = ''; their actor_email is the right
--     rendering already.
--
-- This is a one-shot, idempotent backfill: re-running this migration
-- (e.g. after a manual schema_migrations row deletion) produces the
-- same end state — the WHERE clauses match nothing the second time
-- because actor_name is already populated + actor_email is already
-- cleared.
--
-- Hash-chain note: the canonical-payload hash on existing v1.0 rows
-- (canonical_version=2) does NOT change. Those rows stay verifiable
-- under the v2 shape via `barista audit verify --legacy
-- --canonical-version=2`. v1.1's first boot inserts a new
-- `system.audit.chain_restart` row with `canonical_version=3` so
-- `barista audit verify` walks forward from that genesis.

ALTER TABLE events ADD COLUMN actor_name TEXT NOT NULL DEFAULT '';

-- Step 1 — promote actor_email → actor_name for system + service_account
-- rows that pre-date this migration.
UPDATE events
SET actor_name = actor_email
WHERE actor_type IN ('system', 'service_account')
  AND actor_name = ''
  AND actor_email <> '';

-- Step 2 — clear actor_email on the rows where we just promoted the
-- value. system + service_account rows shouldn't carry an email value
-- going forward.
UPDATE events
SET actor_email = ''
WHERE actor_type IN ('system', 'service_account')
  AND actor_name <> ''
  AND actor_email = actor_name;
