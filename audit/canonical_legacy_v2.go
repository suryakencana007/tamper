package audit

import (
	"encoding/hex"
	"strconv"
	"strings"
)

// canonicalPayloadLegacyV2 reproduces the v1.0 (canonical_version=2)
// canonical-payload encoding so v1.0-era chain segments verify cleanly
// under post-v1.1 verifiers.
//
// Encoding: SHA-256 input is the fields below joined by a single
// pipe ('|'):
//
//	prev_hash_hex | at_unix_nanos | actor.type | actor.name |
//	action | resource_type | resource_id | cluster_id | data_json
//
// Field notes:
//
//   - prev_hash is hex-encoded so the joined buffer is purely text
//     (matches v1.0's encoder).
//
//   - at is encoded as a base-10 int64 string of `e.At.UnixNano()` (v1.4
//     — closes TD-AUDIT-09). v1.3 and earlier used
//     `e.At.UTC().Format(time.RFC3339Nano)`; that encoding lost
//     sub-microsecond precision through SQLite TEXT round-trip, so the
//     v1.0 bootstrap chain-restart row that landed via `time.Now()` was
//     unverifiable at index 0 on real installs. The v3 encoder
//     (canonicalPayloadV3) has always used `UnixNano()` for the same
//     reason; aligning the v=2 encoder matches that pattern.
//
//     Wire-compat note: this is technically a wire break vs the v1.0
//     binary, but v1.0 itself was using the same modernc.org/sqlite
//     driver, so the actual on-disk format was already precision-
//     truncated. The "RFC3339Nano matches v1.0 exactly" claim was
//     theoretical; UnixNano() matches the actual round-trip behavior.
//     The v1.0-chain.json fixture's stored hashes were regenerated under
//     this encoder in v1.4 — a one-time fixture chore, not an
//     operator-facing break, because production-v1.0 chain segments are
//     a v1.1 chain-restart row away from the verifier (Verify defaults
//     to walking the v3 segment forward).
//
//   - actor.type defaults to ActorTypeUser when empty (matches the
//     SQLite column DEFAULT 'user' + the v1.0 fromRow loader path).
//
//   - data_json is the After snapshot JSON (v1.0's emission shape:
//     mutation events stored the post-state as data_json; Before
//     stayed empty). When After is nil we emit the empty string,
//     matching v1.0's SQL column default.
//
// The collision class on '|'-containing free-text fields is real but
// v1.0 shipped this shape; we accept the constraint to preserve
// walkability of pre-v1.1 chain segments. Operators concerned about
// retroactive pipe-collision attacks should archive the v1.0 segment
// pre-upgrade.
//
// This function is referenced by canonicalPayloadForVersion when
// dispatching on canonical_version=2; NEW rows are written under
// canonical_version=3 (length-prefixed) by Logger.Log, so this code
// path is read-only at runtime — it exists so `barista audit verify
// --legacy --canonical-version=2` can walk a v1.0-shape chain segment.
func canonicalPayloadLegacyV2(e Event, prevHash []byte) []byte {
	actorType := string(e.Actor.Type)
	if actorType == "" {
		actorType = string(ActorTypeUser)
	}
	// v1.0 emission shape: `data_json` carried the After snapshot. The
	// Before snapshot wasn't part of the canonical payload at v1.0 — it
	// landed only in the before_json column for diagnostic queries.
	dataJSON := string(e.After)
	fields := []string{
		hex.EncodeToString(prevHash),
		// v1.4 (TD-AUDIT-09): UnixNano() int64 string is precision-stable
		// through SQLite TEXT round-trip. The v3 encoder uses the same
		// shape (binary BigEndian int64); the v=2 encoder keeps the
		// pipe-separated string form so the rest of the legacy layout
		// stays intact.
		strconv.FormatInt(e.At.UnixNano(), 10),
		actorType,
		e.Actor.Name,
		string(e.Action),
		string(e.ResourceType),
		e.ResourceID,
		e.ClusterID,
		dataJSON,
	}
	return []byte(strings.Join(fields, "|"))
}
