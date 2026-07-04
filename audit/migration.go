package audit

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/suryakencana007/barista/packages/tamper/audit/sqlitestore"
)

// MigrationResult summarises a MigrateLegacyV2Hashes call. RowsScanned
// is the count of v=2 rows the migration walked (zero on greenfield
// installs); RowsUpdated is the count whose stored hash didn't match
// the recomputed hash and was overwritten.
//
// RowsUpdated is typically equal to RowsScanned on a pre-v1.4 install
// (every row's hash was computed under the old encoder), and zero on a
// greenfield install or any DB whose only v=2 row was already written
// under the current UnixNano-based encoder (e.g. the v=2 chain-restart
// row inserted by `bootstrapAuditChainRestart` on a v1.4+ boot).
//
// Skipped is true when bootstrapAuditChainMigrate found the boot-level
// idempotency marker (system.audit.chain_migrate row) already present
// and short-circuited before calling MigrateLegacyV2Hashes. The method
// itself never sets Skipped — the boot-path wrapper uses it to log a
// distinct line. MigrateLegacyV2Hashes is safe to call repeatedly; the
// second call just rewrites every row's hash to the same bytes
// (RowsUpdated=0 after the first migration converges the chain).
type MigrationResult struct {
	RowsScanned int
	RowsUpdated int
	Skipped     bool
}

// MigrateLegacyV2Hashes walks every canonical_version=2 row in the
// audit DB in chain-ascending order (oldest first), recomputes each
// row's hash via the current canonicalPayloadForVersion(e, prev, 2),
// and UPDATEs the row when the recomputed hash differs from the stored
// hash. Each row's recomputed hash is then used as the prev_hash for
// the next iteration so the migration produces a self-consistent
// chain.
//
// Function-level idempotency: re-running the migration against an
// already-migrated DB writes zero rows (every recomputed hash matches
// the stored hash, so the UPDATE branch is skipped). Boot-level
// idempotency (don't re-run + re-emit the marker on every pod restart)
// lives in cmd/barista/main.go::bootstrapAuditChainMigrate via the
// HasChainMigrate check.
//
// Concurrency: takes the SQLiteLogger's mu lock for the full migration
// so concurrent Logger.Log emissions can't race the recompute. Boot
// path runs the migration BEFORE the HTTP server starts so the lock
// contention is theoretical — but the guard is cheap insurance against
// future "run the migration mid-flight" call sites.
//
// Returns the (RowsScanned, RowsUpdated) summary so the caller can
// emit a marker row + log a summary line. Returns a non-nil error if
// the underlying SQL queries fail; partial migrations are NOT rolled
// back. The per-row UPDATE is idempotent on re-run, so a mid-migration
// crash leaves the DB in a half-migrated state the next boot resumes
// cleanly.
//
// v1.5 Sprint 1 task 01 — closes TD-AUDIT-11.
//
// v1.8 Sprint 0 forensic note (TD-AUDIT-12): three reproduction
// scenarios captured in internal/audit/forensic_v18_test.go (partial
// encoder change, mid-migration interrupt, Docker layer cache reuse).
// None reproduce the original v1.5.0-dev "rows 0-4 identical prev_hash"
// observable shape — the migration as written is correct under every
// in-process scenario tested. The v1.8 VerifyChainPostMigration
// boot guard is therefore the residual safety net: any corruption
// that leaves the chain in an inconsistent state — regardless of
// mechanism — fails-fast at the next boot via cmd/barista/main.go::run.
// See roadmaps/v1.8.0/TECH_DEBT.md TD-AUDIT-12 §Forensic findings.
func (l *SQLiteLogger) MigrateLegacyV2Hashes(ctx context.Context) (MigrationResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	rows, err := l.store.Queries.ListEventsByCanonicalVersion(ctx, int64(CanonicalVersion2))
	if err != nil {
		return MigrationResult{}, fmt.Errorf("audit migration: list v=2 rows: %w", err)
	}

	result := MigrationResult{RowsScanned: len(rows)}
	if len(rows) == 0 {
		return result, nil
	}

	// Genesis: the first row's prev_hash is HashSize zero bytes
	// (matches the `latestHash()` sentinel + the `seedPreV14V2Row` test
	// helper + the schema's NOT NULL constraint on prev_hash).
	prevHash := make([]byte, HashSize)
	for i := range rows {
		r := &rows[i]
		e := fromRow(*r)
		payload, perr := canonicalPayloadForVersion(e, prevHash, CanonicalVersion2)
		if perr != nil {
			return result, fmt.Errorf("audit migration: row %d (id=%s): canonical payload: %w", i, r.ID, perr)
		}
		h := sha256.New()
		h.Write(prevHash)
		h.Write(payload)
		recomputed := h.Sum(nil)
		// v1.5 walk Step 81 diagnostic: log per-iteration state so we
		// can see what the migration actually wrote vs what ended up
		// stored. Temporary.
		log.Printf("audit migration trace: i=%d id=%s prevHash=%x recomputed=%x storedHash=%x match=%t",
			i, r.ID, prevHash, recomputed, r.Hash, bytesEqual(recomputed, r.Hash))
		if !bytesEqual(recomputed, r.Hash) {
			log.Printf("audit migration trace: i=%d UPDATE id=%s SET hash=%x prev_hash=%x",
				i, r.ID, recomputed, prevHash)
			if err := l.store.Queries.UpdateEventHash(ctx, sqlitestore.UpdateEventHashParams{
				ID:       r.ID,
				Hash:     recomputed,
				PrevHash: prevHash,
			}); err != nil {
				return result, fmt.Errorf("audit migration: row %d (id=%s): update: %w", i, r.ID, err)
			}
			result.RowsUpdated++
		}
		prevHash = recomputed
	}
	return result, nil
}

// RehashChainInPlace walks every audit chain row in
// (at ASC, canonical_version ASC, id ASC) order, recomputes each
// row's hash under its declared canonical_version, and UPDATEs both
// the row's hash AND prev_hash so the chain is left self-consistent.
//
// This differs from MigrateLegacyV2Hashes in two ways:
//
//   - Scope: walks ALL canonical_versions, not just v=2. Required to
//     recover the cross-segment corruption mode TD-AUDIT-12 surfaced
//     in v1.8 — where a v=2 hash migration left the immediately-
//     following v=3 chain_restart anchor with a stale prev_hash. The
//     v=2-only migrate walks ONE row + skips the broken v=3 row,
//     never re-threading the boundary.
//   - Mutation shape: always writes BOTH prev_hash + hash, even on
//     rows whose stored hash matches recomputation. This is the
//     re-threading guarantee — after RehashChainInPlace returns, every
//     row's stored prev_hash matches the previous row's recomputed
//     hash. MigrateLegacyV2Hashes' shape ("UPDATE only on hash
//     mismatch") is insufficient because the cross-segment break has
//     a row whose hash is internally consistent under its OWN
//     (wrong) prev_hash.
//
// Used by `barista audit migrate-force` (v1.8 walk-fix) as the
// operator-driven recovery tool the v1.8 boot-time chain integrity
// guard's error message points at. The boot guard catches v=3 chain
// corruption (not just v=2), so migrate-force must recover v=3
// corruption too — that's what this function delivers.
//
// Idempotent on re-run: a clean chain produces zero writes (every
// recomputed hash matches stored + every prev_hash matches the prior
// row's recomputed hash, so both columns are written unconditionally
// but the row content doesn't change). Concurrent Logger.Log
// emissions can't race the recompute — the function holds the
// SQLiteLogger's mu lock for the full walk.
//
// On partial failure (SQL error mid-walk), already-rewritten rows
// stay rewritten — they're internally consistent under the new
// chain, so a re-run resumes cleanly from where the failure
// interrupted.
//
// Returns the (RowsScanned, RowsUpdated) summary. RowsUpdated counts
// rows whose (prev_hash, hash) tuple actually changed; rows whose
// stored values already matched the recomputed values aren't
// double-counted.
//
// v1.8 walk-fix — TD-AUDIT-12 closure.
func (l *SQLiteLogger) RehashChainInPlace(ctx context.Context) (MigrationResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	rows, err := l.store.Queries.ListEventsForVerify(ctx)
	if err != nil {
		return MigrationResult{}, fmt.Errorf("audit rehash chain: list events: %w", err)
	}

	result := MigrationResult{RowsScanned: len(rows)}
	if len(rows) == 0 {
		return result, nil
	}

	// Genesis: the first row's prev_hash is HashSize zero bytes. Same
	// invariant as MigrateLegacyV2Hashes' genesis row.
	prevHash := make([]byte, HashSize)
	for i := range rows {
		r := &rows[i]
		e := fromRow(*r)
		payload, perr := canonicalPayloadForVersion(e, prevHash, e.CanonicalVersion)
		if perr != nil {
			return result, fmt.Errorf("audit rehash chain: row %d (id=%s, canonical_version=%d): canonical payload: %w",
				i, r.ID, e.CanonicalVersion, perr)
		}
		h := sha256.New()
		h.Write(prevHash)
		h.Write(payload)
		recomputed := h.Sum(nil)

		// Whether either column changed determines RowsUpdated. The
		// UPDATE itself runs unconditionally so the re-threading
		// guarantee holds — partial-match rows (e.g., hash matches
		// but prev_hash is stale, exactly the dev-DB TD-AUDIT-12 shape)
		// still get their prev_hash rewritten.
		if !bytesEqual(recomputed, r.Hash) || !bytesEqual(prevHash, r.PrevHash) {
			if err := l.store.Queries.UpdateEventHash(ctx, sqlitestore.UpdateEventHashParams{
				ID:       r.ID,
				Hash:     recomputed,
				PrevHash: prevHash,
			}); err != nil {
				return result, fmt.Errorf("audit rehash chain: row %d (id=%s): update: %w", i, r.ID, err)
			}
			log.Printf("audit rehash trace: i=%d id=%s canonical_version=%d UPDATE prev_hash=%x hash=%x",
				i, r.ID, e.CanonicalVersion, prevHash, recomputed)
			result.RowsUpdated++
		}
		prevHash = recomputed
	}
	return result, nil
}

// HasChainMigrate reports whether the audit DB already contains a row
// with action=system.audit.chain_migrate. Used by
// cmd/barista/main.go::bootstrapAuditChainMigrate to short-circuit on a
// re-boot of an already-migrated DB.
//
// Mirrors the existing HasChainRestartV2 / HasChainRestartV3 shape:
// counts rows by action string and returns true when the count is
// non-zero. Cheap — backed by an indexed column lookup on a tiny
// table.
//
// v1.5 Sprint 1 task 01 — closes TD-AUDIT-11.
func (l *SQLiteLogger) HasChainMigrate(ctx context.Context) (bool, error) {
	n, err := l.store.Queries.CountEventsByAction(ctx, string(ActionAuditChainMigrate))
	if err != nil {
		return false, fmt.Errorf("audit: count chain-migrate rows: %w", err)
	}
	return n > 0, nil
}
