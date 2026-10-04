package audit

import (
	"context"
	"database/sql"
)

// InsertEventDirectForTest writes a row exactly as given, bypassing Log's
// chain computation, so a test can seed a row Log would never write: a broken
// link, a wrong hash, a canonical_version with no encoder.
//
// EXPORTED FOR TESTS ONLY. Production code must go through Logger.Log — this
// writes whatever it is handed, including a chain that does not verify. That
// is the point: the tamper-detection tests need to be able to write a bad row.
//
// It takes an audit.Event, deliberately. The previous seam handed callers the
// generated sqlitestore.Queries, which made tamper's SQLite schema part of the
// public API — and that is exactly how #20 happened: migration 005 added six
// NOT NULL columns, and every outside caller's struct literal silently became
// six NULLs. Callers now speak Event, the same neutral record the rest of the
// package speaks, and the columns are nobody else's business.
func InsertEventDirectForTest(ctx context.Context, l *SQLiteLogger, e Event) error {
	if l == nil || l.store == nil {
		return errEmptyDBPath
	}
	return l.insertEventDirect(ctx, e)
}

// SQLiteAuditDBForTest exposes the underlying *sql.DB on a SQLiteLogger so
// other packages' tests can run ad-hoc SELECT/UPDATE statements (tamper
// injection, prev_hash inspection) without round-tripping through Logger.List.
//
// EXPORTED FOR TESTS ONLY. This one returns a stdlib type and leaks no schema,
// so it survives the audit/internal move — a caller that wants to corrupt a
// row on purpose has to write the SQL itself, which is honest about what it
// is doing.
func SQLiteAuditDBForTest(l *SQLiteLogger) *sql.DB {
	if l == nil || l.store == nil {
		return nil
	}
	return l.store.DB
}
