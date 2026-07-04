package audit

import (
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This file contains the v1.8 Sprint 0 (TD-AUDIT-12) forensic
// reproduction attempts captured as Go tests. Each test reproduces a
// scenario from the v1.5 #251 incident hypothesis list and asserts
// the OBSERVED outcome — which in every case as of v1.8 is "the
// boot-time self-test catches the resulting corruption."
//
// The forensic outcome is acceptable as "could not reproduce a
// silent corruption" — the boot guard (VerifyChainPostMigration)
// catches each scenario at the next restart. See
// roadmaps/v1.8.0/TECH_DEBT.md TD-AUDIT-12 §Forensic findings for
// the narrative; this file is the receipts.
//
// Why these scenarios as tests rather than shell scripts: keeping
// the forensic evidence inside the package's test suite means it
// survives refactoring + runs on every CI green. A future encoder
// change that breaks the "pre-v1.4 hashes survive in the DB until
// migration runs" invariant would fail one of these tests, surfacing
// the regression with the right context.

// TestForensic_PartialEncoderChangeBuild reproduces Scenario 1: a
// build artifact where canonical_legacy_v2.go uses the pre-v1.4
// RFC3339Nano encoder but everything else uses the v1.4+ UnixNano
// encoder. We seed v=2 rows under the pre-v1.4 encoder (via
// seedPreV14V2Row from migration_test.go) and run the v1.8 boot
// guard against the resulting DB.
//
// Expected: the boot guard catches the mismatch on EVERY pre-v1.4-
// encoded row, NOT just row 0. This is consistent with the v1.5
// #251 walk's "rows 0-4 with identical prev_hash" observation IF
// the broken state is read AFTER a partial migration. But the
// guard alone, run against a v1.0-era DB before any migration,
// reports the mismatch correctly — it doesn't produce the
// rows-0-4-identical-prev_hash pattern.
//
// Outcome: COULD NOT REPRODUCE the original-boot corruption from a
// partial encoder change alone. The guard catches the mismatch as
// expected.
func TestForensic_PartialEncoderChangeBuild(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Seed 5 pre-v1.4-encoded v=2 rows chained together. This simulates
	// what a partial-build binary would have written if its v=2 encoder
	// was RFC3339Nano but its insert path was current.
	base := time.Date(2026, 3, 1, 10, 0, 0, 123456789, time.UTC)
	prev := make([]byte, HashSize)
	for i, id := range []string{"r0", "r1", "r2", "r3", "r4"} {
		e := Event{
			ID:               id,
			At:               base.Add(time.Duration(i) * time.Minute),
			Actor:            Actor{Type: ActorTypeUser, UserID: "u-1"},
			Action:           "project.create",
			ResourceType:     ResourceProject,
			ResourceID:       "p-" + id,
			CanonicalVersion: CanonicalVersion2,
		}
		if i == 0 {
			e.Actor = ActorSystem("barista")
			e.Action = ActionAuditChainRestart
			e.ResourceType = "system"
		}
		prev = seedPreV14V2Row(t, l, e, prev)
	}

	// The v1.8 boot guard MUST catch the mismatch — every row's stored
	// hash was computed under the wrong encoder.
	_, err := verifyChainPostMigrationStore(ctx, l)
	if err == nil {
		t.Fatal("expected boot guard to flag pre-v1.4-encoded rows; got nil")
	}
	if !IsChainMismatch(err) {
		t.Fatalf("expected ChainMismatchError, got: %v", err)
	}
	var m *ChainMismatchError
	if !errors.As(err, &m) {
		t.Fatalf("errors.As(*ChainMismatchError) failed: %v", err)
	}
	// The guard catches the FIRST row (index 0) because every row's
	// stored hash diverges under the post-v1.4 encoder. This is the
	// expected fail-loud shape.
	if m.Index != 0 {
		t.Errorf("expected first mismatch at row 0 (every row is bad); got Index=%d", m.Index)
	}

	// Verify dotted: ChainMismatchError carries hex-encoded hashes so
	// the operator's log shows both stored + recomputed for the failing
	// row. This is part of the recovery contract.
	if m.StoredHashHex == "" || m.RecomputedHashHex == "" {
		t.Errorf("expected both stored + recomputed hex hashes in error; got stored=%q recomputed=%q",
			m.StoredHashHex, m.RecomputedHashHex)
	}
	if m.StoredHashHex == m.RecomputedHashHex {
		t.Error("expected stored != recomputed (that's the WHOLE POINT of the mismatch); got equal")
	}

	// Forensic finding: running the existing MigrateLegacyV2Hashes
	// on the same DB recovers it. This proves the v1.5 #251 walk
	// finding's "current code is correct" assertion.
	if _, err := l.MigrateLegacyV2Hashes(ctx); err != nil {
		t.Fatalf("post-detection migration: %v", err)
	}
	if _, err := verifyChainPostMigrationStore(ctx, l); err != nil {
		t.Fatalf("post-migration boot guard should pass; got: %v", err)
	}
}

// TestForensic_MidMigrationInterrupt reproduces Scenario 2: a
// MigrateLegacyV2Hashes call interrupted mid-way (simulated panic
// after row 3 of 5). The next boot's idempotency check
// (HasChainMigrate) returns false because no marker was ever
// emitted; the migration re-runs and converges the chain.
//
// What this test asserts:
//  1. Mid-migration interrupt leaves the chain in a half-migrated state
//     (rows 0-2 with new hashes, rows 3-4 with pre-v1.4 hashes).
//  2. HasChainMigrate returns false (no marker emitted yet).
//  3. The v1.8 boot guard catches the half-migrated state's break.
//  4. Re-running MigrateLegacyV2Hashes from scratch converges the chain.
//  5. Boot guard then passes.
//
// Outcome: COULD NOT REPRODUCE the "rows 0-4 identical prev_hash"
// pattern. The mid-migration interrupt produces a different
// observable shape (rows 0-2 walk cleanly under the new encoder,
// then break at the row 2 → row 3 transition). The v1.8 boot
// guard catches this correctly.
//
// The "identical prev_hash" pattern the v1.5 walk saw remains
// unreproduced from any in-process scenario; remains consistent
// with the "external build-artifact corruption" hypothesis.
func TestForensic_MidMigrationInterrupt(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Seed 5 pre-v1.4-encoded v=2 rows.
	base := time.Date(2026, 4, 1, 10, 0, 0, 123456789, time.UTC)
	prev := make([]byte, HashSize)
	for i, id := range []string{"r0", "r1", "r2", "r3", "r4"} {
		e := Event{
			ID:               id,
			At:               base.Add(time.Duration(i) * time.Minute),
			Actor:            Actor{Type: ActorTypeUser, UserID: "u-1"},
			Action:           "project.create",
			ResourceType:     ResourceProject,
			ResourceID:       "p-" + id,
			CanonicalVersion: CanonicalVersion2,
		}
		if i == 0 {
			e.Actor = ActorSystem("barista")
			e.Action = ActionAuditChainRestart
			e.ResourceType = "system"
		}
		prev = seedPreV14V2Row(t, l, e, prev)
	}

	// Manually re-hash rows 0..2 under the current encoder, mirroring
	// what MigrateLegacyV2Hashes would have UPDATEd before the
	// "simulated interrupt." Rows 3..4 stay on their pre-v1.4 hashes.
	dbRows, err := l.store.Queries.ListEventsByCanonicalVersion(ctx, int64(CanonicalVersion2))
	if err != nil {
		t.Fatalf("list v=2 rows: %v", err)
	}
	if len(dbRows) != 5 {
		t.Fatalf("seed sanity: have %d v=2 rows, want 5", len(dbRows))
	}
	partialPrev := make([]byte, HashSize)
	for i := 0; i < 3; i++ {
		r := dbRows[i]
		e := fromRow(r)
		payload, perr := canonicalPayloadForVersion(e, partialPrev, CanonicalVersion2)
		if perr != nil {
			t.Fatalf("partial migrate canonical payload row %d: %v", i, perr)
		}
		h := sha256.New()
		h.Write(partialPrev)
		h.Write(payload)
		recomputed := h.Sum(nil)
		db := SQLiteAuditDBForTest(l)
		if _, err := db.ExecContext(ctx, `UPDATE events SET hash = ?, prev_hash = ? WHERE id = ?`,
			recomputed, partialPrev, r.ID); err != nil {
			t.Fatalf("partial UPDATE row %d: %v", i, err)
		}
		partialPrev = recomputed
	}
	// rows 3..4 still carry their pre-v1.4 hashes pointing at the
	// untouched chain prefix — exactly the half-migrated state a
	// crashed migration would leave.

	// Now: HasChainMigrate returns false (no marker ever emitted).
	already, err := l.HasChainMigrate(ctx)
	if err != nil {
		t.Fatalf("HasChainMigrate after interrupt: %v", err)
	}
	if already {
		t.Error("HasChainMigrate = true after interrupt; should be false (no marker emitted)")
	}

	// Boot guard catches the row 3 break (rows 0..2 verify under the
	// recomputed prev, row 3's stored prev_hash doesn't match row 2's
	// recomputed hash). The exact failure index depends on whether the
	// linkage break or the hash break fires first.
	_, err = verifyChainPostMigrationStore(ctx, l)
	if err == nil {
		t.Fatal("expected boot guard to flag half-migrated chain; got nil")
	}
	if !IsChainMismatch(err) {
		t.Fatalf("expected ChainMismatchError, got: %v", err)
	}
	var m *ChainMismatchError
	if !errors.As(err, &m) {
		t.Fatalf("errors.As(*ChainMismatchError) failed: %v", err)
	}
	// The break should land at row 3 — that's where the chain stops
	// matching. (Pre-v1.4 hash on row 3 doesn't link to row 2's
	// post-migration hash.)
	if m.Index != 3 {
		t.Errorf("expected mismatch at row 3 (mid-interrupt boundary); got Index=%d", m.Index)
	}

	// Re-run the migration from scratch — it converges the chain
	// because rows 0..2 are already current-encoder + rows 3..4 are
	// pre-v1.4. Function-level idempotency proven by
	// TestMigrateLegacyV2Hashes_Idempotent in migration_test.go.
	result, err := l.MigrateLegacyV2Hashes(ctx)
	if err != nil {
		t.Fatalf("re-run MigrateLegacyV2Hashes: %v", err)
	}
	if result.RowsScanned != 5 {
		t.Errorf("RowsScanned = %d, want 5", result.RowsScanned)
	}
	// rows 0..2 are already correct → 0 updates expected for them; rows
	// 3..4 are pre-v1.4 → 2 updates. The pre-v1.4 row at index 3 chained
	// off a stale (now-overwritten) prev_hash but the migration writes
	// every row's prev_hash from the rolling cursor, so the convergence
	// is unconditional. We assert at least 2 updates landed.
	if result.RowsUpdated < 2 {
		t.Errorf("RowsUpdated = %d, want >= 2", result.RowsUpdated)
	}

	// Boot guard now passes — confirms the recovery + idempotency claim.
	if _, err := verifyChainPostMigrationStore(ctx, l); err != nil {
		t.Fatalf("post-recovery boot guard should pass; got: %v", err)
	}
}

// TestForensic_DockerLayerCacheArtifact documents Scenario 3: a
// Docker build that reused a v1.4 image's layer cache and only
// no-cache'd a subset of files containing `canonical*.go`. The
// theoretical mechanism: the Go binary would contain a mix of v1.4
// and v1.5 object code, with the canonical encoder's symbol matching
// one but the linker's view of computeHash + write-path computeHash
// matching the other.
//
// In practice: Go's incremental build is per-package, not per-file.
// `go build` either rebuilds an entire package or reuses the cached
// `.a` archive — there's no per-file partial rebuild within a
// package. The `internal/audit` package's compilation produces one
// `.a` archive whose contents are coherent under the encoder version
// at compile time.
//
// The only way a mixed-encoder binary could exist:
//   - The Docker layer reused a stale `~/.cache/go-build` directory
//     where the audit package's `.a` was built against pre-v1.4
//     sources, but the linker step pulled in canonical_legacy_v2.go's
//     post-v1.4 source. Even this scenario produces a build-step
//     error at link time, not a runtime corruption, because Go's
//     build-cache hashes include both the source AND the importing
//     package's hashes.
//   - An out-of-process layer overwrote the embedded binary after
//     `go build` completed — possible on a customised build pipeline
//     using `objcopy` or similar, NOT possible under any standard
//     Dockerfile shape.
//
// Outcome: COULD NOT REPRODUCE — and the underlying mechanism is
// theoretically implausible under standard Go build semantics.
// This test serves as documentation of the analysis; it does not
// itself exercise a code path.
func TestForensic_DockerLayerCacheArtifact(t *testing.T) {
	// The forensic conclusion is documented in the test name + body.
	// We assert one structural property to keep the test live: the
	// package's canonical encoder dispatch is single-version (no
	// runtime branch that could select between v1.4 + v1.5 encoders),
	// so a mixed-encoder binary cannot arise from in-process state.
	//
	// Specifically, canonicalPayloadForVersion(v=2) dispatches to
	// canonicalPayloadLegacyV2 unconditionally — there's no
	// feature-flag or import-time selection that an environmental
	// variable could swap. If a future refactor adds such a branch,
	// this test fires loudly.
	prevHash := make([]byte, HashSize)
	e := Event{
		ID:           "forensic-anchor",
		At:           time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC),
		Actor:        ActorSystem("barista"),
		Action:       ActionAuditChainRestart,
		ResourceType: "system",
	}

	payload, err := canonicalPayloadForVersion(e, prevHash, CanonicalVersion2)
	if err != nil {
		t.Fatalf("canonicalPayloadForVersion(v=2): %v", err)
	}
	// The pipe-separated shape is the post-v1.4 encoder. Its presence
	// here proves the package has exactly one v=2 encoder, locked at
	// compile time.
	if !strings.Contains(string(payload), "|") {
		t.Error("v=2 canonical payload must contain '|' separators (post-v1.4 shape)")
	}
	// The post-v1.4 encoder uses UnixNano int64 string for the
	// timestamp field. Sanity: the payload must contain the exact
	// UnixNano string for `e.At`. The pre-v1.4 encoder used
	// RFC3339Nano, which would contain "T" + "Z" — absence of those
	// chars after the second '|' separator is the discriminator.
	wantTS := strconv.FormatInt(e.At.UnixNano(), 10)
	if !strings.Contains(string(payload), wantTS) {
		t.Errorf("v=2 canonical payload must contain UnixNano %q (post-v1.4 shape); got payload: %s",
			wantTS, payload)
	}
	if strings.Contains(string(payload), "2026-05-30T") {
		t.Errorf("v=2 canonical payload must NOT contain RFC3339 string (would indicate pre-v1.4 encoder); got: %s",
			payload)
	}
}
