package sqltypes

import (
	"database/sql/driver"
	"fmt"
)

// Blob is a []byte that never marshals to SQL NULL.
//
// It exists because of a specific, silent failure mode. The v4 columns added
// by migration 005 (row_salt and the five c_* PII commitments) are
// `BLOB NOT NULL DEFAULT x''`, and a column DEFAULT only applies when the
// INSERT omits the column — but sqlc always names every column, so the
// DEFAULT is unreachable. A plain []byte field left at its zero value is
// therefore sent as an explicit NULL and the insert dies with
// `NOT NULL constraint failed`.
//
// That matters because InsertEventParams is public API. Any caller outside
// this module builds it as a struct literal, which is the only way to build
// it, and a struct literal written before v4 existed cannot possibly set
// fields that did not exist. Such a caller compiles cleanly against both the
// old and the new tamper and fails only at run time — the exact shape of
// defect Phase 7's standing rule 1 exists to prevent, since the caller never
// asked for tenancy at all.
//
// Coercing at the Go boundary fixes every caller at once, including the ones
// that are not written yet, and without rewriting a single row. The
// alternative — relaxing NOT NULL — is not available: SQLite cannot alter a
// column constraint in place, so it would mean rebuilding the events table
// and copying every row of an append-only hash chain, which is precisely what
// migration 005 was designed never to do.
//
// `COALESCE(?, x'')` in the query is not a fix either; sqlc degrades those
// parameters to `interface{}` (recorded in PHASE7-HANDOFF.md §5).
type Blob []byte

// Value implements driver.Valuer. A nil Blob becomes an empty byte string,
// never NULL. This is the whole point of the type.
func (b Blob) Value() (driver.Value, error) {
	if b == nil {
		return []byte{}, nil
	}
	return []byte(b), nil
}

// Scan implements sql.Scanner. A NULL read back — possible on rows written
// before this type existed — reads as empty rather than nil, so a round trip
// through the database is stable.
//
// The driver may reuse its buffer after Scan returns, so the bytes are
// copied rather than aliased.
func (b *Blob) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*b = Blob{}
	case []byte:
		cp := make(Blob, len(v))
		copy(cp, v)
		*b = cp
	case string:
		*b = Blob(v)
	default:
		return fmt.Errorf("sqltypes: cannot scan %T into Blob", src)
	}
	return nil
}
