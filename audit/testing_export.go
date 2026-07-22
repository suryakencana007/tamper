package audit

import (
	"database/sql"

	"github.com/suryakencana007/tamper/audit/sqlitestore"
)

// SQLiteAuditQueriesForTest exposes the underlying sqlitestore.Queries
// handle on a SQLiteLogger so cmd/barista CLI tests can seed fixture
// rows via direct InsertEvent calls (Logger.Log always writes
// canonical_version=3 rows, which is wrong for v1.0 fixture replay).
//
// EXPORTED FOR TESTS ONLY. Production code should NEVER reach into the
// logger's internals; the Logger interface is the entire public API.
// Named SQLiteAuditQueriesForTest (not for the audit package's own
// tests) because the audit package's tests are in-package and can
// reach `l.store.Queries` directly — this export is for OTHER
// packages' tests (cmd/barista in particular). The "ForTest" suffix
// surfaces the intent in callers.
func SQLiteAuditQueriesForTest(l *SQLiteLogger) *sqlitestore.Queries {
	if l == nil || l.store == nil {
		return nil
	}
	return l.store.Queries
}

// SQLiteAuditDBForTest exposes the underlying *sql.DB on a SQLiteLogger
// so cmd/barista CLI tests can run ad-hoc SELECT/UPDATE statements
// (tamper injection, prev_hash inspection) without round-tripping
// through Logger.List. Production code uses Logger.List + the
// store.Queries handle.
//
// EXPORTED FOR TESTS ONLY. See SQLiteAuditQueriesForTest for the
// pattern rationale.
func SQLiteAuditDBForTest(l *SQLiteLogger) *sql.DB {
	if l == nil || l.store == nil {
		return nil
	}
	return l.store.DB
}
