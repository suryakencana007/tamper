package sqlitestore

import (
	"database/sql"
	"embed"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// schema.sql is sqlc's single source of truth for the audit-DB model types;
// the runtime instead applies migrations/*.sql in order (see open.go). The
// two must describe the SAME table, or sqlc's generated Event model drifts
// from what the running DB actually has. This embed lets the parity test
// build a DB straight from the sqlc input and compare it against a
// migration-built DB.
//
//go:embed schema.sql
var schemaFS embed.FS

// TestSchemaMigrationParity asserts schema.sql (sqlc's typegen input) and the
// runtime migrations build the SAME events table — same columns (name / type /
// NOT NULL / default / PK) and same indexes.
//
// The comparison is ORDER-INDEPENDENT by design. schema.sql pins cluster_id in
// its logical mid-table position (so the sqlc Event model field order matches
// the read-query SELECT projections), whereas migration 004 adds cluster_id via
// ALTER TABLE, which appends it to the end. Column POSITION therefore differs on
// purpose; column SET, types, and indexes must not.
//
// This is the guard advertised in schema.sql's header comment. Its failure mode
// is the real hazard: a future migration adds a column but nobody updates
// schema.sql (or vice versa), and sqlc silently generates against a stale
// schema.
func TestSchemaMigrationParity(t *testing.T) {
	t.Parallel()

	migrated := openMigratedDB(t)
	schema := openSchemaDB(t)

	// --- columns ---
	migCols := tableColumns(t, migrated)
	schCols := tableColumns(t, schema)
	assertMapsEqual(t, "column", schCols, migCols)

	// --- indexes ---
	migIdx := tableIndexes(t, migrated)
	schIdx := tableIndexes(t, schema)
	assertMapsEqual(t, "index", schIdx, migIdx)
}

// openMigratedDB builds a fresh audit DB via the production Open path (which
// runs applyMigrations), so the test compares against exactly what the runtime
// constructs.
func openMigratedDB(t *testing.T) *sql.DB {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "migrated.db"))
	if err != nil {
		t.Fatalf("Open (migrated): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store.DB
}

// openSchemaDB builds a fresh DB by executing schema.sql — sqlc's input —
// directly, with no migrations.
func openSchemaDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "schema.db") + "?_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open schema DB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	body, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		t.Fatalf("read schema.sql: %v", err)
	}
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatalf("exec schema.sql: %v", err)
	}
	return db
}

// tableColumns returns name -> canonical spec ("type notnull=N dflt=X pk=N")
// for every column of the events table, keyed by name so the comparison is
// order-independent.
func tableColumns(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info(events)`)
	if err != nil {
		t.Fatalf("PRAGMA table_info: %v", err)
	}
	defer func() { _ = rows.Close() }()

	cols := make(map[string]string)
	for rows.Next() {
		var (
			cid     int
			name    string
			typ     string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		dfltStr := "NULL"
		if dflt.Valid {
			dfltStr = dflt.String
		}
		cols[name] = fmt.Sprintf("type=%s notnull=%d dflt=%s pk=%d", typ, notnull, dfltStr, pk)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("table_info rows: %v", err)
	}
	if len(cols) == 0 {
		t.Fatal("events table has no columns — schema not created?")
	}
	return cols
}

// tableIndexes returns index-name -> normalized CREATE INDEX sql for every
// index on the events table. The implicit PRIMARY-KEY autoindex has NULL sql in
// both DBs and normalizes to "", so it compares equal. Normalization drops the
// `IF NOT EXISTS` the migrations carry (schema.sql omits it) and collapses
// whitespace, so index parity turns on structure, not incidental text.
func tableIndexes(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.Query(
		`SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'events'`,
	)
	if err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	defer func() { _ = rows.Close() }()

	idx := make(map[string]string)
	for rows.Next() {
		var name string
		var ddl sql.NullString
		if err := rows.Scan(&name, &ddl); err != nil {
			t.Fatalf("scan sqlite_master: %v", err)
		}
		idx[name] = normalizeDDL(ddl)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("sqlite_master rows: %v", err)
	}
	return idx
}

// normalizeDDL strips `IF NOT EXISTS`, a trailing `;`, and collapses all
// whitespace runs to single spaces so schema.sql-declared and migration-declared
// indexes compare on structure alone.
func normalizeDDL(ddl sql.NullString) string {
	if !ddl.Valid {
		return ""
	}
	s := strings.ReplaceAll(ddl.String, "IF NOT EXISTS ", "")
	s = strings.TrimSuffix(strings.TrimSpace(s), ";")
	return strings.Join(strings.Fields(s), " ")
}

// assertMapsEqual reports every key that differs between the schema-built and
// migration-built views, so a drift failure names the offending column/index.
func assertMapsEqual(t *testing.T, kind string, fromSchema, fromMigrations map[string]string) {
	t.Helper()
	seen := make(map[string]struct{}, len(fromSchema)+len(fromMigrations))
	for k := range fromSchema {
		seen[k] = struct{}{}
	}
	for k := range fromMigrations {
		seen[k] = struct{}{}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		s, inSchema := fromSchema[k]
		m, inMig := fromMigrations[k]
		switch {
		case !inSchema:
			t.Errorf("%s %q present in migrations but MISSING from schema.sql (migrations: %s)", kind, k, m)
		case !inMig:
			t.Errorf("%s %q present in schema.sql but MISSING from migrations (schema.sql: %s)", kind, k, s)
		case s != m:
			t.Errorf("%s %q differs:\n  schema.sql:  %s\n  migrations:  %s", kind, k, s, m)
		}
	}
}
