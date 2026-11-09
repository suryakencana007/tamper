package saml

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// SQLiteAssertionReplayStore is an AssertionReplayStore shared between processes on one host — the
// "shared store for multiple replicas" BuildProvider's doc asks for, and which did not exist.
//
// Two replicas that disagree about freshness do not produce an error: they produce a second
// session. That is what this type exists to prevent, and it prevents it the only way that works
// across processes — by letting the DATABASE arbitrate. ConsumeAssertion is a single INSERT whose
// outcome is the row count; there is no read before the write, because a read followed by a write
// is exactly the race the port's contract was shaped to make impossible.
//
// Scope, stated rather than implied: SQLite over a network filesystem is not supported. Share the
// file between processes on one machine, or implement the port against a real database — the port
// is the extension point and this is one implementation of it.
//
// GC is the application's infrastructure, as the port says. PurgeExpiredBefore is here as a tool
// for the app's scheduler; the port deliberately has no such method. Purging is safe because
// expiresAt (see replayExpiry) is the instant after which no process accepts the assertion again.
type SQLiteAssertionReplayStore struct {
	db *sql.DB
}

// SQLiteReplayOption configures a SQLiteAssertionReplayStore.
type SQLiteReplayOption func(*sqliteReplayConfig)

type sqliteReplayConfig struct {
	busyTimeout time.Duration
}

// WithSQLiteReplayBusyTimeout sets how long a write waits for another process's lock before it
// gives up. Giving up is an ERROR and therefore fails closed (the caller answers 503), but on a
// busy deployment it is worth raising rather than discovering as log noise.
func WithSQLiteReplayBusyTimeout(d time.Duration) SQLiteReplayOption {
	return func(c *sqliteReplayConfig) { c.busyTimeout = d }
}

// NewSQLiteAssertionReplayStore opens (and migrates) the ledger at dbPath.
//
// WAL is NOT forced, unlike the audit chain: this table is written once per login and read never,
// and a WAL file is a second artefact to back up and reconcile for no gain here. busy_timeout IS
// set, because two processes sharing the file will collide and a collision must wait rather than
// surface as a 503.
func NewSQLiteAssertionReplayStore(dbPath string, opts ...SQLiteReplayOption) (*SQLiteAssertionReplayStore, error) {
	if dbPath == "" {
		return nil, fmt.Errorf("saml: replay store: a database path is required")
	}
	cfg := sqliteReplayConfig{busyTimeout: 5 * time.Second}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}

	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(%d)", dbPath, cfg.busyTimeout.Milliseconds())
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("saml: replay store: open %s: %w", dbPath, err)
	}
	// One connection per process: SQLite serialises writers anyway, so a pool buys nothing but
	// intra-process lock contention. Cross-process contention is the case that matters, and the
	// busy_timeout above is what handles it.
	db.SetMaxOpenConns(1)

	s := &SQLiteAssertionReplayStore{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLiteAssertionReplayStore) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS saml_assertion_replay (
	key        TEXT    PRIMARY KEY,
	expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS saml_assertion_replay_expires_at ON saml_assertion_replay (expires_at);`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("saml: replay store: migrate: %w", err)
	}
	return nil
}

// ConsumeAssertion implements AssertionReplayStore: one statement, outcome from rows-affected.
//
// On any error it returns an ERROR, never a bare false and never true: the port's rule is that a
// store which cannot tell "fresh" from "failed" must fail closed, and the caller turns that into
// ErrReplayStoreUnavailable → 503.
func (s *SQLiteAssertionReplayStore) ConsumeAssertion(ctx context.Context, key string, expiresAt time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO saml_assertion_replay (key, expires_at) VALUES (?, ?) ON CONFLICT(key) DO NOTHING`,
		key, expiresAt.UTC().Unix())
	if err != nil {
		return false, fmt.Errorf("saml: replay store: consume: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("saml: replay store: rows affected: %w", err)
	}
	return n == 1, nil
}

// PurgeExpiredBefore deletes rows whose window closed before t and reports how many. It is for the
// application's scheduler — the port has no such method on purpose.
//
// Safe because expiresAt is the instant after which no process will accept that assertion again
// (see replayExpiry): a purged key can be "consumed" a second time only by an assertion that is
// already outside its validity window, which the signature and timing checks reject first.
func (s *SQLiteAssertionReplayStore) PurgeExpiredBefore(ctx context.Context, t time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM saml_assertion_replay WHERE expires_at < ?`, t.UTC().Unix())
	if err != nil {
		return 0, fmt.Errorf("saml: replay store: purge: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("saml: replay store: rows affected: %w", err)
	}
	return int(n), nil
}

// Close releases the database handle.
func (s *SQLiteAssertionReplayStore) Close() error { return s.db.Close() }
