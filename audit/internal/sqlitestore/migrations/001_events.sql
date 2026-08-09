-- 001_events.sql — append-only audit-log schema. The whole audit DB
-- file (separate from the main barista.db) holds only this table; no
-- other tables join against it. Keeps audit retention + backup cadence
-- independent from the main DB.
--
-- Hash-chain integrity: each row's `hash` is sha256(prev_hash ||
-- canonical_payload). prev_hash for the very first event is 32 zero
-- bytes. Verify() walks the chain in (at, id) order and recomputes.
--
-- Indexes are sized for the v0.6 SOC2-on-ramp scope (≤ 100k events
-- per 90-day window). For larger volumes, partition by month
-- in a later migration.

CREATE TABLE IF NOT EXISTS events (
    -- Caller-supplied UUID. The middleware uses request_id when
    -- available so audit row ID + access-log line + structured-log
    -- request_id all align.
    id            TEXT NOT NULL PRIMARY KEY,

    -- UTC timestamp at insert time. Stored as RFC3339Nano string
    -- (DATETIME affinity in SQLite is interpreted as TEXT/REAL/INTEGER;
    -- we use TEXT for human-readable dump + grep).
    at            DATETIME NOT NULL,

    -- Actor — empty user_id/email for system actors (e.g. the
    -- daily retention prune emits with actor "system").
    actor_user_id TEXT NOT NULL DEFAULT '',
    actor_email   TEXT NOT NULL DEFAULT '',
    actor_ip      TEXT NOT NULL DEFAULT '',

    -- Action — dotted lowercase: "<resource>.<verb>" or
    -- "<resource>.<sub>.<verb>" (e.g. cluster.member.grant).
    action        TEXT NOT NULL,

    -- Resource — empty for actions that don't target a specific
    -- resource (e.g. auth.login).
    resource_type TEXT NOT NULL,
    resource_id   TEXT NOT NULL DEFAULT '',

    -- Originating HTTP request_id (espresso plumbs this through
    -- *espresso.Error, so audit + access-log + error frames share
    -- the same correlation token). Empty for non-HTTP actors
    -- (system goroutines, CLI subcommand).
    request_id    TEXT NOT NULL DEFAULT '',

    -- before / after JSON snapshots. Strings (TEXT) rather than BLOB
    -- so SQLite full-text dumps remain greppable. Empty string means
    -- "not applicable" (Before for create, After for delete).
    before_json   TEXT NOT NULL DEFAULT '',
    after_json    TEXT NOT NULL DEFAULT '',

    -- Hash chain. prev_hash for the first event is 32 zero bytes.
    -- BLOB columns to avoid base64 expansion at rest.
    prev_hash     BLOB NOT NULL,
    hash          BLOB NOT NULL
);

-- (at desc) for "show me the most-recent events" — the SPA's default
-- list query.
CREATE INDEX IF NOT EXISTS events_at_desc_idx ON events (at DESC, id);

-- (actor_user_id) for "what did Alice do" filters.
CREATE INDEX IF NOT EXISTS events_actor_user_idx ON events (actor_user_id);

-- (resource_type, resource_id) for "show me the history of project X".
CREATE INDEX IF NOT EXISTS events_resource_idx ON events (resource_type, resource_id);

-- (request_id) for "show me everything tied to this request" — useful
-- when correlating an audit event with a regular log line.
CREATE INDEX IF NOT EXISTS events_request_idx ON events (request_id);
