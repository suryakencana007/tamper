package audit

// CanonicalPayloadV2ForDebug exposes canonicalPayloadLegacyV2 so an operator
// dump can recompute a v2 row's hash and show stored-vs-recomputed side by
// side. That is the tool the boot guard's chain-mismatch error points at, so
// it is a supported surface, not a leftover.
//
// It survived the audit/internal move because it takes an Event and returns
// bytes: it exposes the ENCODING, which is the thing a forensic caller
// legitimately needs to reproduce, and not the storage layout.
//
// Its two former neighbours did not survive, and the difference is the whole
// point. StoreForDebug returned *sqlitestore.Store and FromRowForDebug took a
// sqlitestore.Event, so between them they made the generated row type part of
// the public API — which is what let migration 005 break an outside caller
// (#20). The capability they served is now SQLiteLogger.ListByCanonicalVersion,
// which answers in neutral Events.
func CanonicalPayloadV2ForDebug(e Event, prevHash []byte) []byte {
	return canonicalPayloadLegacyV2(e, prevHash)
}
