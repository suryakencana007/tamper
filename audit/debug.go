package audit

import (
	"github.com/suryakencana007/barista/packages/tamper/audit/sqlitestore"
)

// StoreForDebug exposes the underlying audit store for the
// cmd/barista `audit dump-v2` diagnostic. Not part of the stable API
// surface; only used during the v1.5 walk Step 81 investigation.
func (l *SQLiteLogger) StoreForDebug() *sqlitestore.Store {
	return l.store
}

// FromRowForDebug exposes fromRow for diagnostic dumping.
func FromRowForDebug(r sqlitestore.Event) Event {
	return fromRow(r)
}

// CanonicalPayloadV2ForDebug exposes canonicalPayloadLegacyV2 for
// diagnostic dumping.
func CanonicalPayloadV2ForDebug(e Event, prevHash []byte) []byte {
	return canonicalPayloadLegacyV2(e, prevHash)
}
