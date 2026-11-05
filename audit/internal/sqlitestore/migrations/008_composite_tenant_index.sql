-- 008: replace the single-column tenant index with a composite (TD-11, issue #113
-- option 2).
--
-- The filter searches by tenant and orders by (at DESC, id DESC) for keyset paging.
-- With a single-column index the planner had to sort EVERY matching row before LIMIT
-- could stop, so a page cost grew with the tenant's row count and the cursor pruned
-- nothing. Measured on a 20k-row tenant: 1844us -> 13us, and the deep page 2519us ->
-- 15us, because the index now returns the rows in the order the query asks for and
-- `at < ?` is applied INSIDE it.
--
-- REPLACED, not joined: the composite supersedes the single-column index, so the file
-- grows ~13% rather than ~19% and the write path pays once. The name is kept because
-- every reference (including the plan test) means "the index for tenant_id".
--
-- Still PARTIAL over `tenant_id <> ''`, which keeps single-tenant rows out of it — and
-- means a tenant.Single page still scans (asserted in
-- TestListPlan_TenantSingleStillScans; see issue #113 option 4). The caller must keep
-- carrying the redundant `AND tenant_id <> ''` predicate, exactly as migrations 006 and
-- 007 explain: SQLite uses a partial index only when the WHERE implies its predicate.

DROP INDEX idx_events_tenant_id;

CREATE INDEX idx_events_tenant_id ON events (tenant_id, at DESC, id DESC) WHERE tenant_id <> '';
