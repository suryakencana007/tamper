-- 007: an index for the console's cross-tenant question (TD-11).
--
-- "What did platform staff do inside our customers' tenants?" is
-- `actor_tenant_id = ?` with no scope filter (audit.Filter.ActorTenantID). The
-- rows that answer it are the ones where the actor's tenant differs from the
-- row's scope, and until this index that query scanned the whole log.
--
-- A PARTIAL index, like idx_events_tenant_id (migration 005) and
-- idx_events_not_v4 (006), for the same reason: rows whose actor has no tenant
-- are the single-tenant deployment's, where the question cannot arise, so they
-- need not be indexed.
--
-- The caller must ALSO carry the literal predicate, exactly as 006 explains:
-- SQLite uses a partial index only when the query's WHERE implies the index's,
-- and it cannot prove `actor_tenant_id <> ''` from a bound parameter. That is
-- why audit.filterWhere adds both terms — measured, not assumed: with the
-- equality alone the plan is `SCAN events`, and no test of the RESULTS can
-- tell the difference.

CREATE INDEX idx_events_actor_tenant_id ON events (actor_tenant_id) WHERE actor_tenant_id <> '';
