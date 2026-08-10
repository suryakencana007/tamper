// Package sqlitestore holds the SQLite-backed storage for the audit
// log (closes the v0.4/v0.5-deferred non-goal). Separate from the main
// internal/store/sqlite package so the audit DB lives in its own file
// (default /var/lib/barista/audit.db) and can be backed up / rotated
// / pruned independently from the main barista.db.
//
// The package is deliberately minimal: schema + sqlc-generated
// queries + Open/Close. The chain logic + Logger interface live in
// internal/audit; that package wraps a *Queries from here to provide
// the audit.Logger surface.
package sqlitestore

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store bundles an open *sql.DB with its sqlc *Queries for the audit
// DB. The DB is opened at the configured path with WAL + a 5-second
// busy_timeout so short-write contention from concurrent audit emits
// doesn't surface as SQLITE_BUSY (parallel to TD-CORR-06's main-DB
// concern).
type Store struct {
	DB      *sql.DB
	Queries *Queries
}

// Open opens (or creates) the audit DB at dbPath, runs the embedded
// migrations in lexicographic order, and returns a Store wrapping
// the connection + sqlc queries.
//
// Empty dbPath returns an error — the caller should construct an
// audit.NoopLogger instead when audit is disabled, rather than
// passing through to Open with an empty path.
func Open(dbPath string) (*Store, error) {
	if dbPath == "" {
		return nil, errors.New("sqlitestore: dbPath is empty")
	}

	dsn := fmt.Sprintf(
		"file:%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)",
		dbPath,
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlitestore: open %q: %w", dbPath, err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlitestore: ping: %w", err)
	}
	if err := applyMigrations(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{DB: db, Queries: New(db)}, nil
}

// Close closes the underlying database. Safe to call on a nil Store.
func (s *Store) Close() error {
	if s == nil || s.DB == nil {
		return nil
	}
	return s.DB.Close()
}

// applyMigrations is the same shape as the main store's migration
// runner — schema_migrations table + lexicographic file order +
// idempotent re-application. Kept as a copy rather than shared with
// the main store package to avoid an import dependency that would
// couple the two DB lifecycles.
func applyMigrations(db *sql.DB) error {
	return applyMigrationsFrom(db, migrations)
}

// applyMigrationsFrom is applyMigrations over an explicit fs.FS, so the
// atomicity tests can feed it a deliberately broken migration. Production
// always passes the embedded set.
func applyMigrationsFrom(db *sql.DB, fsys fs.FS) error {
	if _, err := db.Exec(
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			name       TEXT PRIMARY KEY,
			applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
	); err != nil {
		return fmt.Errorf("sqlitestore: create schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(fsys, "migrations")
	if err != nil {
		return fmt.Errorf("sqlitestore: read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		var applied int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, name,
		).Scan(&applied); err != nil {
			return fmt.Errorf("sqlitestore: check migration %s: %w", name, err)
		}
		if applied > 0 {
			continue
		}
		body, err := fs.ReadFile(fsys, "migrations/"+name)
		if err != nil {
			return fmt.Errorf("sqlitestore: read migration %s: %w", name, err)
		}
		if err := applyOne(db, name, string(body)); err != nil {
			return err
		}
	}
	return nil
}

// applyOne runs a single migration file AND its schema_migrations row in
// one transaction, so a crash at any point — mid-file or between apply
// and record — rolls back to the exact pre-migration state and the next
// boot retries cleanly.
//
// This is load-bearing, not tidiness (#24). The runner's contract is
// idempotent re-application, and 005_tenant_v4.sql structurally cannot
// honour it: SQLite has no ALTER TABLE ... ADD COLUMN IF NOT EXISTS, so
// eight of its nine statements are unreplayable. Before this transaction
// existed, each statement autocommitted individually; a process killed
// mid-file left columns half-added, every subsequent boot re-ran the file
// into "duplicate column name", and the store could never open again
// without manual SQL. SQLite's DDL is fully transactional, so the fix is
// exactly this shape and nothing more.
func applyOne(db *sql.DB, name, body string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("sqlitestore: begin migration %s: %w", name, err)
	}
	// Rollback after a successful Commit is a no-op (sql.ErrTxDone).
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(body); err != nil {
		return fmt.Errorf("sqlitestore: apply migration %s: %w", name, err)
	}
	if _, err := tx.Exec(
		`INSERT INTO schema_migrations (name) VALUES (?)`, name,
	); err != nil {
		return fmt.Errorf("sqlitestore: record migration %s: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlitestore: commit migration %s: %w", name, err)
	}
	return nil
}
