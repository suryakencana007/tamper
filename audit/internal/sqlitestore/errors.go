package sqlitestore

import (
	"errors"

	sqlitedriver "modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"
)

// IsUniqueViolation reports whether err is a SQLite uniqueness violation
// from the audit DB. The audit chain ALWAYS lives in a SQLite database
// (packages/tamper/audit/sqlitestore), independent of the main store's driver
// (sqlite vs postgres, selected by build tag) -- so this classifier is
// driver-agnostic and carries NO build tag. It must NOT be replaced by the
// main store's facade store.IsUniqueViolation: under a `-tags postgres`
// build that facade checks for the Postgres SQLSTATE 23505, which never
// matches a SQLite constraint error coming from this DB.
//
// Mirrors internal/store/sqlite/errors.go: SQLITE_CONSTRAINT_UNIQUE (2067)
// and SQLITE_CONSTRAINT_PRIMARYKEY (1555) both mean "row already exists".
// The audit fixture loader's id-conflict skip/force policy relies on this
// (the events.id PRIMARY KEY is the conflicting column).
func IsUniqueViolation(err error) bool {
	var se *sqlitedriver.Error
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code() {
	case sqlitelib.SQLITE_CONSTRAINT_UNIQUE,
		sqlitelib.SQLITE_CONSTRAINT_PRIMARYKEY:
		return true
	}
	return false
}
