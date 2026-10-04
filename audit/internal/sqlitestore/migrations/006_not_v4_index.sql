-- 006: an index for the check NewSQLiteLogger runs on every open.
--
-- The audit package reads and writes canonical_version=4 only. At open
-- it asks whether the table holds a row at any other version, and
-- refuses the file if it does. Without an index that question is a
-- scan of the whole table, on every process start.
--
-- A PARTIAL index over exactly the rows the question is about. On a
-- healthy DB every row is v4, so the index is empty and the check
-- reads nothing; it costs nothing to maintain, because no row Log
-- writes ever enters it. The predicate must stay a literal 4: SQLite
-- uses a partial index only when the query's WHERE implies the
-- index's, and it cannot prove that through a bound parameter.

CREATE INDEX idx_events_not_v4 ON events (canonical_version) WHERE canonical_version <> 4;
