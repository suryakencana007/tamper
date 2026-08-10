package sqlitestore

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// openBare opens a DB the way Open does but WITHOUT running migrations,
// so each test drives applyMigrationsFrom against exactly the FS it built.
func openBare(t *testing.T) *sql.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "audit.db") +
		"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func tableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name,
	).Scan(&n); err != nil {
		t.Fatalf("sqlite_master: %v", err)
	}
	return n > 0
}

func migrationRecorded(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM schema_migrations WHERE name=?`, name,
	).Scan(&n); err != nil {
		t.Fatalf("schema_migrations: %v", err)
	}
	return n > 0
}

// TestApplyMigrations_FailedFileLeavesNoTrace is the regression guard for
// #24. A multi-statement migration that dies partway must roll back
// WHOLE: no statement's effect survives and no schema_migrations row is
// written. Before the per-migration transaction existed, each statement
// autocommitted individually — statement 1 here would have survived, and
// because real migrations are not replayable (005's ADD COLUMNs cannot
// take IF NOT EXISTS), the next boot would re-run into "duplicate
// column" forever. The property under test is exactly "a crashed
// migration is indistinguishable from one that never started".
func TestApplyMigrations_FailedFileLeavesNoTrace(t *testing.T) {
	t.Parallel()
	db := openBare(t)

	broken := fstest.MapFS{
		"migrations/001_boom.sql": &fstest.MapFile{Data: []byte(`
			CREATE TABLE half_applied (id TEXT PRIMARY KEY);
			THIS IS NOT SQL;
		`)},
	}
	err := applyMigrationsFrom(db, broken)
	if err == nil {
		t.Fatal("a migration containing invalid SQL applied without error")
	}
	if !strings.Contains(err.Error(), "001_boom.sql") {
		t.Errorf("error does not name the failing file: %v", err)
	}

	// The heart of #24: statement 1 must NOT have survived statement 2's
	// failure, and nothing may have been recorded.
	if tableExists(t, db, "half_applied") {
		t.Error("the failed migration's first statement survived; the file did not run in one transaction")
	}
	if migrationRecorded(t, db, "001_boom.sql") {
		t.Error("a failed migration was recorded as applied")
	}
}

// TestApplyMigrations_RetryAfterFailureIsClean is the recoverability half:
// after a failed attempt, fixing the file and booting again must succeed
// with no manual SQL — which is only possible because the failure left
// the pre-migration state intact.
func TestApplyMigrations_RetryAfterFailureIsClean(t *testing.T) {
	t.Parallel()
	db := openBare(t)

	name := "migrations/001_two_steps.sql"
	broken := fstest.MapFS{name: &fstest.MapFile{Data: []byte(`
		ALTER TABLE nope ADD COLUMN x TEXT;
	`)}}
	if err := applyMigrationsFrom(db, broken); err == nil {
		t.Fatal("migration against a missing table applied without error")
	}

	// Same file name, fixed body — the shape of "ship a corrected image
	// and restart the pod". This is what a half-applied 005 could never do.
	fixed := fstest.MapFS{name: &fstest.MapFile{Data: []byte(`
		CREATE TABLE nope (id TEXT PRIMARY KEY);
		ALTER TABLE nope ADD COLUMN x TEXT;
	`)}}
	if err := applyMigrationsFrom(db, fixed); err != nil {
		t.Fatalf("retry after a failed migration did not apply cleanly: %v", err)
	}
	if !tableExists(t, db, "nope") {
		t.Fatal("fixed migration did not apply")
	}
	if !migrationRecorded(t, db, "001_two_steps.sql") {
		t.Fatal("fixed migration was not recorded")
	}
}

// TestApplyMigrations_AppliedFilesAreNotReRun pins the idempotency the
// runner always promised: a recorded migration is skipped, even if
// re-running it would fail (as every unreplayable file would).
func TestApplyMigrations_AppliedFilesAreNotReRun(t *testing.T) {
	t.Parallel()
	db := openBare(t)

	name := "migrations/001_once.sql"
	once := fstest.MapFS{name: &fstest.MapFile{Data: []byte(`
		CREATE TABLE once_only (id TEXT PRIMARY KEY);
	`)}}
	if err := applyMigrationsFrom(db, once); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	// Second pass over the same FS: CREATE TABLE without IF NOT EXISTS
	// would fail if the runner re-ran it. It must be skipped instead.
	if err := applyMigrationsFrom(db, once); err != nil {
		t.Fatalf("re-open re-ran an already-recorded migration: %v", err)
	}
}
