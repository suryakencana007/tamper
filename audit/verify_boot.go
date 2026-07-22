package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/suryakencana007/tamper/audit/sqlitestore"
)

// VerifyBootResult summarises a VerifyChainPostMigration walk. Count
// is the number of rows walked (matches the audit_events table row
// count modulo any retention prune just before boot); Segments is the
// number of chain segments observed — distinct (at, id) anchors marked
// by `system.audit.chain_restart` or `system.audit.chain_migrate`
// rows, plus 1 for the initial implicit segment if the chain doesn't
// open with a restart marker.
//
// The boot-path caller logs both numbers so operators see chain shape
// at every restart. They're not part of the "did the walk pass?"
// contract — that's captured by the (nil error) return.
type VerifyBootResult struct {
	Count    int
	Segments int
}

// VerifyChainPostMigration walks every audit chain row in
// (at ASC, canonical_version ASC, id ASC) order, recomputes each
// row's hash under its declared canonical_version, and returns a
// non-nil error wrapping the first index where the stored prev_hash
// + hash linkage diverges from the recomputed value. Returns nil on
// a clean chain.
//
// Ordering tie-break rationale: `canonical_version ASC` is the middle
// key (v1.8 Sprint 0 follow-up; TD-AUDIT-12). Two `time.Now()` calls
// inside the boot bootstraps (bootstrapAuditChainRestart +
// bootstrapAuditChainMigrate) can return identical `at` values on
// low-resolution clocks — observed ~25% flake rate on Windows during
// v1.8 Sprint 1 development. Without the tiebreak, a v=3 chain_restart
// anchor whose id sorts lexically smaller than the preceding v=2 rows
// could land BEFORE them in the walk; the guard would then re-hash
// v=2 rows under the v=3 encoder + spuriously fire. With
// canonical_version ASC injected between at + id, same-at rows are
// always ordered v=2 before v=3, preserving chain-segment order. id
// ASC remains the final deterministic tiebreaker.
//
// Honors chain segment boundaries — rows with
// action="system.audit.chain_restart" or "system.audit.chain_migrate"
// reset the prev_hash anchor for the next row, mirroring
// walkChain's existing dispatch. A segment boundary's own hash MUST
// still match its recomputed value under its canonical_version
// (the row itself is hashed before resetting the rolling prev_hash
// for the next row), so an in-place tamper of a boundary row's
// stored hash is still caught.
//
// Idempotent + cheap (~50ms per 100 rows on typical hardware).
// Bounded by the caller's ctx; returns ctx.Err() on cancellation /
// timeout. The boot path wraps a 5s timeout per
// config.AuditVerifyBootConfig.Timeout — see cmd/barista/main.go::run.
//
// On mismatch, the returned error wraps:
//   - the failing row's id, at, and canonical_version,
//   - the stored vs recomputed hash (hex-encoded for log readability),
//   - a recovery pointer at `barista audit migrate-force` /
//     `barista audit dump-v2`.
//
// Idempotency contract: the function only READS rows (no UPDATEs, no
// emits). Re-running on the same DB produces the same result
// byte-for-byte. The audit log isn't mutated by this walk.
//
// v1.8 Sprint 0 (TD-AUDIT-12) — closes the v1.5/v1.6/v1.7 carried-
// forward debt for the chain-integrity-on-boot guard. See
// roadmaps/v1.8.0/tasks/00-audit-chain-original-boot-forensic.md.
func VerifyChainPostMigration(ctx context.Context, logger Logger) (VerifyBootResult, error) {
	if logger == nil {
		return VerifyBootResult{}, nil
	}
	// NoopLogger has no chain to verify — short-circuit cleanly.
	if _, ok := logger.(NoopLogger); ok {
		return VerifyBootResult{}, nil
	}
	sl, ok := logger.(*SQLiteLogger)
	if !ok {
		// Unknown Logger implementation; can't introspect. Skip without
		// erroring — mirrors the bootstrapAuditChainRestart /
		// bootstrapAuditChainMigrate posture so tests that swap a
		// custom Logger don't break boot.
		return VerifyBootResult{}, nil
	}
	return verifyChainPostMigrationStore(ctx, sl)
}

// verifyChainPostMigrationStore is the testable inner shell. Takes the
// SQLiteLogger directly so unit tests can seed rows + walk without
// the Logger-interface dispatch overhead. The public surface
// (VerifyChainPostMigration) gates the type assertion at the boundary.
func verifyChainPostMigrationStore(ctx context.Context, sl *SQLiteLogger) (VerifyBootResult, error) {
	if sl == nil || sl.store == nil {
		return VerifyBootResult{}, nil
	}

	// Honor ctx upfront so a cancelled caller doesn't even hit SQLite.
	if err := ctx.Err(); err != nil {
		return VerifyBootResult{}, err
	}

	// Walk every event in (at ASC, id ASC) order. This is the same
	// query Verify() uses for its pre-v1.0 fallback path, so the row
	// ordering is identical to the established verify semantics.
	rows, err := sl.store.Queries.ListEventsForVerify(ctx)
	if err != nil {
		return VerifyBootResult{}, fmt.Errorf("audit verify boot: list events: %w", err)
	}
	if len(rows) == 0 {
		return VerifyBootResult{}, nil
	}

	// segments counts distinct chain anchors. Each chain_restart /
	// chain_migrate row marks the start of a new segment. A chain that
	// opens without an anchor at row 0 still gets a segment for the
	// implicit "from genesis" prefix.
	//
	// Practical examples:
	//   - greenfield v1.5+ install: row 0 is the v=2 chain_restart
	//     anchor → segments=1.
	//   - v1.4 → v1.5 upgrade: row 0 is the v=2 chain_restart from
	//     v1.0-era boot, somewhere later a chain_migrate marker lands
	//     → segments=2.
	//   - pre-v1.0 segment (no anchors at all): rows exist but no
	//     anchor row → segments=1 (implicit).
	segments := 0
	prev := make([]byte, HashSize)

	for i, r := range rows {
		// Cooperative cancellation point — every row checks ctx so
		// the 5s boot timeout reliably interrupts a pathological
		// chain walk.
		if err := ctx.Err(); err != nil {
			return VerifyBootResult{}, err
		}

		e := fromRow(r)

		// Linkage check from event 1 onward. Row 0's PrevHash is the
		// chain baseline (zeroes on an unpruned chain; the deleted
		// predecessor's hash after a retention prune — either is OK,
		// the recompute check still proves no one edited the surviving
		// rows). For non-zero i, e.PrevHash must equal the rolling
		// prev we're tracking.
		if i == 0 {
			prev = e.PrevHash
		} else if !bytesEqual(e.PrevHash, prev) {
			return VerifyBootResult{Count: i, Segments: segments}, newChainMismatchError(
				i, e, prev, nil, // recomputed left nil — this is a linkage failure, not a hash one.
				"prev_hash does not match prior row's hash",
			)
		}

		// Recompute under the row's own canonical_version. Mirrors
		// walkChain's per-row-version dispatch (without the
		// canonicalVersion-override branch — boot-time verify always
		// honors the per-row column, which is what the in-place tamper
		// proof needs).
		payload, perr := canonicalPayloadForVersion(e, prev, e.CanonicalVersion)
		if perr != nil {
			return VerifyBootResult{Count: i, Segments: segments}, newChainMismatchError(
				i, e, prev, nil,
				fmt.Sprintf("unknown canonical_version=%d: %v", e.CanonicalVersion, perr),
			)
		}
		h := sha256.New()
		h.Write(prev)
		h.Write(payload)
		recomputed := h.Sum(nil)

		if !bytesEqual(recomputed, e.Hash) {
			return VerifyBootResult{Count: i, Segments: segments}, newChainMismatchError(
				i, e, prev, recomputed,
				"stored hash does not match recomputed hash",
			)
		}

		// Bump segment counter on every chain anchor (including i=0
		// when the chain opens with one). The row itself still hashes
		// under its declared version above, so an in-place tamper of
		// an anchor's stored hash is still caught by the recompute
		// check.
		if isChainAnchorAction(Action(r.Action)) {
			segments++
		}

		prev = recomputed
	}

	// Pre-v1.0 chains (no anchor at all) still count as one implicit
	// segment so callers don't see segments=0 on a non-empty chain.
	if segments == 0 {
		segments = 1
	}

	return VerifyBootResult{Count: len(rows), Segments: segments}, nil
}

// isChainAnchorAction reports whether the given action string marks a
// chain segment boundary. v1.0+ inserts a `system.audit.chain_restart`
// row at first boot; v1.5+ inserts a `system.audit.chain_migrate`
// marker after the legacy v=2 hash-recompute. Both reset the chain
// anchor for subsequent rows (in the sense that operators reading the
// audit log treat them as logical segment boundaries) but the
// rolling-prev-hash linkage still threads through them — see walkChain
// for the same dispatch shape.
func isChainAnchorAction(a Action) bool {
	return a == ActionAuditChainRestart || a == ActionAuditChainMigrate
}

// ChainMismatchError is the structured failure returned by
// VerifyChainPostMigration. The PR-description sensitivity proof in
// v1.8 Task 00 grep's for the row id + canonical_version + the
// recovery pointer string this carries.
//
// Implements error + provides typed accessors so the boot path (or
// future operator-facing tooling) can format the fields without
// re-parsing the message string.
type ChainMismatchError struct {
	// Index is the 0-based offset of the failing row in the
	// (at ASC, id ASC) walk.
	Index int
	// RowID is the audit_events.id of the failing row.
	RowID string
	// RowAt is the failing row's `at` column (RFC3339Nano in the
	// error message; the struct keeps the original time.Time-shaped
	// string for fidelity).
	RowAt string
	// CanonicalVersion is the failing row's declared canonical_version.
	CanonicalVersion int
	// StoredHashHex is hex(r.Hash) — what's persisted in the DB.
	StoredHashHex string
	// RecomputedHashHex is hex(VerifyChainPostMigration's recompute).
	// Empty when the failure is a linkage break (prev_hash mismatch),
	// not a hash mismatch.
	RecomputedHashHex string
	// PrevHashHex is hex(prevHash) — the rolling prev the walk
	// expected the row to chain onto.
	PrevHashHex string
	// StoredPrevHashHex is hex(r.PrevHash) — what the row stores.
	StoredPrevHashHex string
	// Reason is the human-readable failure mode (one of:
	//   "stored hash does not match recomputed hash",
	//   "prev_hash does not match prior row's hash",
	//   "unknown canonical_version=N: ...").
	Reason string
}

// Error formats the structured failure into the operator-visible
// message — kept stable for sensitivity-proof grep parity across
// v1.8+ cycles.
func (e *ChainMismatchError) Error() string {
	return fmt.Sprintf(
		"audit verify boot: chain mismatch at index %d (id=%q at=%s canonical_version=%d): %s "+
			"(stored_hash=%s recomputed_hash=%s prev=%s stored_prev=%s); "+
			"recover with `barista audit migrate-force` (inspect first with `barista audit dump-v2`)",
		e.Index, e.RowID, e.RowAt, e.CanonicalVersion, e.Reason,
		e.StoredHashHex, e.RecomputedHashHex, e.PrevHashHex, e.StoredPrevHashHex,
	)
}

// newChainMismatchError constructs the structured failure from the
// loop's in-scope state. recomputed may be nil for the linkage-break
// case — the error's RecomputedHashHex stays empty in that case.
func newChainMismatchError(index int, e Event, prev []byte, recomputed []byte, reason string) error {
	mismatch := &ChainMismatchError{
		Index:             index,
		RowID:             e.ID,
		RowAt:             e.At.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		CanonicalVersion:  e.CanonicalVersion,
		StoredHashHex:     hex.EncodeToString(e.Hash),
		PrevHashHex:       hex.EncodeToString(prev),
		StoredPrevHashHex: hex.EncodeToString(e.PrevHash),
		Reason:            reason,
	}
	if recomputed != nil {
		mismatch.RecomputedHashHex = hex.EncodeToString(recomputed)
	}
	return mismatch
}

// IsChainMismatch reports whether err originates from
// VerifyChainPostMigration's chain-integrity failure. Used by boot
// wiring + tests that want to assert "this specific failure mode" vs
// other errors (ctx cancel, SQL failure, etc.).
func IsChainMismatch(err error) bool {
	var m *ChainMismatchError
	return errors.As(err, &m)
}

// Compile-time assertion: SQLiteLogger.verifyChainPostMigrationStore
// is the inner shell used by VerifyChainPostMigration. Lives here
// (not at audit_sqlite.go) so the test surface for the boot guard
// stays grouped in verify_boot.go.
var _ = (*sqlitestore.Queries)(nil)
