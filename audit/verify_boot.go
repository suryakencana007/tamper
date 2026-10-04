package audit

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
)

// VerifyBootResult summarises a VerifyChainPostMigration walk. Count
// is the number of rows walked. It is for the boot log; whether the
// walk passed is the error return.
type VerifyBootResult struct {
	Count int
}

// VerifyChainPostMigration is the boot-time chain check. It walks every
// audit row in (at ASC, canonical_version ASC, id ASC) order, recomputes
// each row's hash, and returns a *ChainMismatchError for the first row
// whose stored prev_hash or hash does not match. Returns nil on a clean
// chain.
//
// It differs from Logger.Verify in what it reports: Verify answers
// "tamper, at index N", this names the row, its stored and recomputed
// hashes, and why it failed, so a boot log is enough to start from.
//
// It only reads. It is bounded by ctx and returns ctx.Err() on
// cancellation or timeout, so the caller can put a deadline on boot.
//
// A nil logger, the NoopLogger, and a Logger implementation this
// package does not ship all return a zero result and no error: there is
// no chain here to walk.
func VerifyChainPostMigration(ctx context.Context, logger Logger) (VerifyBootResult, error) {
	if logger == nil {
		return VerifyBootResult{}, nil
	}
	if _, ok := logger.(NoopLogger); ok {
		return VerifyBootResult{}, nil
	}
	sl, ok := logger.(*SQLiteLogger)
	if !ok {
		return VerifyBootResult{}, nil
	}
	return verifyChainPostMigrationStore(ctx, sl)
}

// verifyChainPostMigrationStore is the walk behind
// VerifyChainPostMigration, taking the SQLiteLogger directly.
func verifyChainPostMigrationStore(ctx context.Context, sl *SQLiteLogger) (VerifyBootResult, error) {
	if sl == nil || sl.store == nil {
		return VerifyBootResult{}, nil
	}
	if err := ctx.Err(); err != nil {
		return VerifyBootResult{}, err
	}

	rows, err := sl.store.Queries.ListEventsForVerify(ctx)
	if err != nil {
		return VerifyBootResult{}, fmt.Errorf("audit verify boot: list events: %w", err)
	}

	var prev []byte
	for i, r := range rows {
		// Checked per row so a boot deadline interrupts a long walk.
		if err := ctx.Err(); err != nil {
			return VerifyBootResult{}, err
		}

		e := fromRow(r)

		// Row 0's PrevHash is the chain baseline: zeroes on an unpruned
		// chain, the deleted predecessor's hash after a retention prune.
		// From row 1 on, PrevHash must equal the previous row's hash.
		if i == 0 {
			prev = e.PrevHash
		} else if !bytesEqual(e.PrevHash, prev) {
			return VerifyBootResult{Count: i}, newChainMismatchError(
				i, e, prev, nil, // recomputed left nil — this is a linkage failure, not a hash one.
				"prev_hash does not match prior row's hash",
			)
		}

		payload, perr := canonicalPayloadForVersion(e, prev, e.CanonicalVersion)
		if perr != nil {
			return VerifyBootResult{Count: i}, newChainMismatchError(
				i, e, prev, nil,
				fmt.Sprintf("unknown canonical_version=%d: %v", e.CanonicalVersion, perr),
			)
		}
		recomputed := hashChainLink(prev, payload)
		if !bytesEqual(recomputed, e.Hash) {
			return VerifyBootResult{Count: i}, newChainMismatchError(
				i, e, prev, recomputed,
				"stored hash does not match recomputed hash",
			)
		}
		prev = recomputed
	}

	return VerifyBootResult{Count: len(rows)}, nil
}

// ChainMismatchError is the structured failure returned by
// VerifyChainPostMigration. The fields are exported so the boot path
// or operator tooling can format them without parsing the message.
type ChainMismatchError struct {
	// Index is the 0-based offset of the failing row in the walk.
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
// message.
func (e *ChainMismatchError) Error() string {
	return fmt.Sprintf(
		"audit verify boot: chain mismatch at index %d (id=%q at=%s canonical_version=%d): %s "+
			"(stored_hash=%s recomputed_hash=%s prev=%s stored_prev=%s)",
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
