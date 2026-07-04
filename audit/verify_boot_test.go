package audit

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/suryakencana007/barista/packages/tamper/audit/sqlitestore"
)

// TestVerifyChainPostMigration_CleanV3Only confirms a chain composed
// only of v=3 rows (the post-v1.1 default) walks cleanly. This is the
// dominant shape for any install whose first boot was v1.1+.
func TestVerifyChainPostMigration_CleanV3Only(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Emit a chain-restart anchor at v=3 (mirrors what
	// bootstrapAuditChainRestart writes) + 4 normal mutations.
	base := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	if _, err := l.Log(ctx, Event{
		ID:           "boot-cr-v3",
		At:           base,
		Actor:        ActorSystem("barista"),
		Action:       ActionAuditChainRestart,
		ResourceType: "system",
	}); err != nil {
		t.Fatalf("Log chain-restart v3: %v", err)
	}
	for i, id := range []string{"a", "b", "c", "d"} {
		if _, err := l.Log(ctx, Event{
			ID:           id,
			At:           base.Add(time.Duration(i+1) * time.Second),
			Actor:        Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
			Action:       "project.create",
			ResourceType: ResourceProject,
			ResourceID:   "p-" + id,
		}); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	result, err := verifyChainPostMigrationStore(ctx, l)
	if err != nil {
		t.Fatalf("VerifyChainPostMigration on clean v=3 chain: %v", err)
	}
	if result.Count != 5 {
		t.Errorf("Count = %d, want 5", result.Count)
	}
	// Chain opens with the chain_restart anchor at row 0 → 1 segment.
	if result.Segments != 1 {
		t.Errorf("Segments = %d, want 1", result.Segments)
	}
}

// TestVerifyChainPostMigration_CleanV2Segment confirms a chain segment
// at v=2 (the v1.0-era shape) walks cleanly post-MigrateLegacyV2Hashes.
// Mirrors the operator scenario: a v1.0 install upgraded to v1.5+,
// migration ran, boot guard runs next.
func TestVerifyChainPostMigration_CleanV2Segment(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Seed the v1.0-chain.json fixture via Logger.Log under the current
	// v=2 encoder so the fixture rows verify under their stored hashes
	// (the fixture rounds-trip cleanly through canonicalPayloadLegacyV2
	// per TestCanonicalPayloadLegacyV2_FixtureRoundTrip).
	rows := loadV10ChainFixture(t)
	for _, r := range rows {
		e := fixtureRowToEvent(t, r)
		// Logger.Log fills PrevHash + Hash; clear so the fixture's
		// pre-computed values don't override.
		e.PrevHash = nil
		e.Hash = nil
		if _, err := l.Log(ctx, e); err != nil {
			t.Fatalf("Log fixture %s: %v", r.ID, err)
		}
	}

	result, err := verifyChainPostMigrationStore(ctx, l)
	if err != nil {
		t.Fatalf("VerifyChainPostMigration on v=2 segment: %v", err)
	}
	if result.Count != len(rows) {
		t.Errorf("Count = %d, want %d", result.Count, len(rows))
	}
	// The fixture's first row is `system.audit.chain_restart` (the v1.0
	// genesis) → 1 segment anchored at row 0.
	if result.Segments != 1 {
		t.Errorf("Segments = %d, want 1", result.Segments)
	}
}

// TestVerifyChainPostMigration_CorruptV2Row deliberately corrupts a
// v=2 row's prev_hash and asserts the guard catches it at the right
// index + returns a ChainMismatchError carrying the row id. This is
// the unit-level mirror of the v1.8 DoD Step 101 sensitivity proof.
func TestVerifyChainPostMigration_CorruptV2Row(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Seed 4 v=2 rows via Logger.Log so they land under the current
	// (post-v1.4) encoder + chain forward through latestHash.
	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	ids := []string{"v2-restart", "evt-a", "evt-b", "evt-c"}
	for i, id := range ids {
		e := Event{
			ID:               id,
			At:               base.Add(time.Duration(i) * time.Second),
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
		if _, err := l.Log(ctx, e); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	// Sanity: pre-corruption walk is clean.
	if _, err := verifyChainPostMigrationStore(ctx, l); err != nil {
		t.Fatalf("pre-corruption walk should be clean; got: %v", err)
	}

	// Corrupt evt-b's prev_hash directly via the test-export DB handle.
	// Mirror the operator's `sqlite3 UPDATE` recipe in DoD Step 101.
	tamper := make([]byte, HashSize)
	for i := range tamper {
		tamper[i] = 0xAA
	}
	db := SQLiteAuditDBForTest(l)
	if db == nil {
		t.Fatal("SQLiteAuditDBForTest returned nil")
	}
	if _, err := db.ExecContext(ctx, `UPDATE events SET prev_hash = ? WHERE id = ?`, tamper, "evt-b"); err != nil {
		t.Fatalf("UPDATE prev_hash: %v", err)
	}

	// Post-corruption walk should fail at evt-b's index (2 — 0=restart,
	// 1=evt-a, 2=evt-b).
	_, err := verifyChainPostMigrationStore(ctx, l)
	if err == nil {
		t.Fatal("expected ChainMismatchError, got nil")
	}
	if !IsChainMismatch(err) {
		t.Errorf("err = %v, want a ChainMismatchError", err)
	}
	var mismatch *ChainMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("errors.As(*ChainMismatchError) failed; err=%v", err)
	}
	if mismatch.Index != 2 {
		t.Errorf("Index = %d, want 2", mismatch.Index)
	}
	if mismatch.RowID != "evt-b" {
		t.Errorf("RowID = %q, want evt-b", mismatch.RowID)
	}
	if mismatch.CanonicalVersion != CanonicalVersion2 {
		t.Errorf("CanonicalVersion = %d, want %d", mismatch.CanonicalVersion, CanonicalVersion2)
	}
	// Recovery pointer must appear in the rendered message — the boot
	// path logs Err.Error() verbatim and operators grep for it.
	if msg := err.Error(); !contains(msg, "barista audit migrate-force") {
		t.Errorf("error message missing recovery pointer; got: %s", msg)
	}
}

// TestVerifyChainPostMigration_MidChainCorruption confirms detection at
// an arbitrary mid-chain index. Seeds 6 rows + corrupts row index 4's
// stored hash (the more interesting "hash mismatch" path vs the
// linkage-break path in the prior test).
func TestVerifyChainPostMigration_MidChainCorruption(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	base := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	ids := []string{"cr-v3", "a", "b", "c", "d", "e"}
	for i, id := range ids {
		e := Event{
			ID:           id,
			At:           base.Add(time.Duration(i) * time.Second),
			Actor:        Actor{Type: ActorTypeUser, UserID: "u-1"},
			Action:       "project.create",
			ResourceType: ResourceProject,
			ResourceID:   "p-" + id,
		}
		if i == 0 {
			e.Actor = ActorSystem("barista")
			e.Action = ActionAuditChainRestart
			e.ResourceType = "system"
		}
		if _, err := l.Log(ctx, e); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	// Flip a single bit in row index 4's stored hash (== id "d").
	db := SQLiteAuditDBForTest(l)
	var existing []byte
	if err := db.QueryRowContext(ctx, `SELECT hash FROM events WHERE id = ?`, "d").Scan(&existing); err != nil {
		t.Fatalf("SELECT hash: %v", err)
	}
	tampered := append([]byte(nil), existing...)
	tampered[0] ^= 0x01
	if _, err := db.ExecContext(ctx, `UPDATE events SET hash = ? WHERE id = ?`, tampered, "d"); err != nil {
		t.Fatalf("UPDATE hash: %v", err)
	}

	_, err := verifyChainPostMigrationStore(ctx, l)
	if err == nil {
		t.Fatal("expected ChainMismatchError on mid-chain hash flip, got nil")
	}
	var mismatch *ChainMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("errors.As(*ChainMismatchError) failed; err=%v", err)
	}
	if mismatch.Index != 4 {
		t.Errorf("Index = %d, want 4 (row id=d is the 5th seeded)", mismatch.Index)
	}
	if mismatch.RowID != "d" {
		t.Errorf("RowID = %q, want d", mismatch.RowID)
	}
	if mismatch.Reason == "" {
		t.Error("Reason is empty; want non-empty failure-mode description")
	}
}

// TestVerifyChainPostMigration_CtxCancellation confirms the walk
// honors ctx cancellation. Seeds a chain + cancels the ctx before
// invoking; the walk should return ctx.Err() without inspecting rows.
func TestVerifyChainPostMigration_CtxCancellation(t *testing.T) {
	parent := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Seed a few rows so the walk has something to look at if the
	// cancellation check didn't fire.
	base := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	for i, id := range []string{"a", "b", "c"} {
		if _, err := l.Log(parent, Event{
			ID:           id,
			At:           base.Add(time.Duration(i) * time.Second),
			Actor:        Actor{Type: ActorTypeUser, UserID: "u-1"},
			Action:       "project.create",
			ResourceType: ResourceProject,
			ResourceID:   "p-" + id,
		}); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	ctx, cancel := context.WithCancel(parent)
	cancel() // cancel BEFORE calling — the walk must fail-fast.

	_, err := verifyChainPostMigrationStore(ctx, l)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	// Sanity: a cancellation is NOT a chain mismatch.
	if IsChainMismatch(err) {
		t.Error("IsChainMismatch(ctx.Canceled) = true, want false")
	}
}

// TestVerifyChainPostMigration_Timeout confirms the walk respects a
// ctx deadline. The test seeds a small chain + a 1ns timeout; the walk
// should return DeadlineExceeded on the very first ctx check.
func TestVerifyChainPostMigration_Timeout(t *testing.T) {
	parent := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// A handful of rows so the walk has something to traverse.
	base := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	for i, id := range []string{"a", "b", "c", "d", "e"} {
		if _, err := l.Log(parent, Event{
			ID:           id,
			At:           base.Add(time.Duration(i) * time.Second),
			Actor:        Actor{Type: ActorTypeUser, UserID: "u-1"},
			Action:       "project.create",
			ResourceType: ResourceProject,
			ResourceID:   "p-" + id,
		}); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	ctx, cancel := context.WithTimeout(parent, 1*time.Nanosecond)
	defer cancel()
	// Give the deadline a moment to actually expire so the
	// ctx.Err() check fires deterministically rather than racing
	// the SQL round-trip.
	time.Sleep(2 * time.Millisecond)

	_, err := verifyChainPostMigrationStore(ctx, l)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
	if IsChainMismatch(err) {
		t.Error("IsChainMismatch(DeadlineExceeded) = true, want false")
	}
}

// TestVerifyChainPostMigration_EmptyChain confirms a fresh audit DB
// with zero rows walks cleanly without error. This is the greenfield-
// install + audit-disabled-then-enabled path.
func TestVerifyChainPostMigration_EmptyChain(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	result, err := verifyChainPostMigrationStore(ctx, l)
	if err != nil {
		t.Fatalf("VerifyChainPostMigration on empty chain: %v", err)
	}
	if result.Count != 0 {
		t.Errorf("Count = %d, want 0", result.Count)
	}
	if result.Segments != 0 {
		t.Errorf("Segments = %d, want 0", result.Segments)
	}
}

// TestVerifyChainPostMigration_IdempotentAcrossReRuns confirms re-
// running the walk on the same DB produces identical (Count, Segments)
// + identical nil-vs-error outcomes. The function reads only — no
// UPDATEs — so successive calls must converge byte-for-byte. Protects
// against future refactors that try to "auto-repair" silently.
func TestVerifyChainPostMigration_IdempotentAcrossReRuns(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Clean chain.
	base := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	for i, id := range []string{"cr", "a", "b", "c"} {
		e := Event{
			ID:           id,
			At:           base.Add(time.Duration(i) * time.Second),
			Actor:        Actor{Type: ActorTypeUser, UserID: "u-1"},
			Action:       "project.create",
			ResourceType: ResourceProject,
			ResourceID:   "p-" + id,
		}
		if i == 0 {
			e.Actor = ActorSystem("barista")
			e.Action = ActionAuditChainRestart
			e.ResourceType = "system"
		}
		if _, err := l.Log(ctx, e); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	first, err := verifyChainPostMigrationStore(ctx, l)
	if err != nil {
		t.Fatalf("first walk: %v", err)
	}
	second, err := verifyChainPostMigrationStore(ctx, l)
	if err != nil {
		t.Fatalf("second walk: %v", err)
	}
	if first != second {
		t.Errorf("walk diverged: first=%+v second=%+v", first, second)
	}

	// Confirm no rows were UPDATEd by the walk — the rolling-prev-hash
	// is in-memory only. Spot-check via direct SQL: hashes are bytewise
	// unchanged.
	db := SQLiteAuditDBForTest(l)
	rows, err := db.QueryContext(ctx, `SELECT id, hash FROM events ORDER BY at ASC, id ASC`)
	if err != nil {
		t.Fatalf("SELECT hashes: %v", err)
	}
	defer func() { _ = rows.Close() }()
	type pair struct {
		id   string
		hash []byte
	}
	var observed []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.id, &p.hash); err != nil {
			t.Fatalf("scan: %v", err)
		}
		observed = append(observed, p)
	}
	if len(observed) != 4 {
		t.Fatalf("row count = %d, want 4", len(observed))
	}
}

// TestVerifyChainPostMigration_NoopLogger confirms the public surface
// gates on the logger type — a NoopLogger short-circuits to nil
// without panicking on the SQLite-specific internals.
func TestVerifyChainPostMigration_NoopLogger(t *testing.T) {
	ctx := context.Background()
	result, err := VerifyChainPostMigration(ctx, NewNoopLogger())
	if err != nil {
		t.Fatalf("VerifyChainPostMigration(NoopLogger): %v", err)
	}
	if result.Count != 0 || result.Segments != 0 {
		t.Errorf("NoopLogger walk should be zero-result; got %+v", result)
	}

	// Nil-logger guard (defensive — main.go always passes non-nil but
	// future call sites might not).
	result, err = VerifyChainPostMigration(ctx, nil)
	if err != nil {
		t.Fatalf("VerifyChainPostMigration(nil): %v", err)
	}
	if result.Count != 0 || result.Segments != 0 {
		t.Errorf("nil-logger walk should be zero-result; got %+v", result)
	}
}

// TestListEventsForVerify_SameAtMixedVersions_OrdersV2BeforeV3 pins
// the v1.8 Sprint 0 follow-up ORDER BY tie-break. When two rows share
// an identical `at` (a real possibility on low-resolution clocks —
// observed ~25% on Windows during v1.8 Sprint 1 development when two
// `time.Now()` calls inside the boot bootstraps collided), the
// ListEventsForVerify query MUST order them by canonical_version ASC
// so v=2 rows sort BEFORE v=3 rows at the same instant.
//
// Without the tie-break, a v=3 chain_restart anchor with a lexically-
// smaller id could sort BEFORE v=2 rows that conceptually predate it;
// the boot guard then walks v=2 rows under the v=3 encoder + the
// recompute spuriously fires.
//
// This test deliberately uses direct INSERTs (bypassing Logger.Log)
// so the row ids + at + canonical_version are pinned exactly. Hashes
// + prev_hashes are zero — the query under test orders rows; it
// doesn't walk the chain. The chain-walk behavior is covered by the
// other tests in this file.
func TestListEventsForVerify_SameAtMixedVersions_OrdersV2BeforeV3(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)
	db := SQLiteAuditDBForTest(l)
	if db == nil {
		t.Fatal("SQLiteAuditDBForTest returned nil")
	}

	// Both rows share an identical `at`. The v=3 row gets a lexically-
	// SMALLER id ("aaa-v3") than the v=2 row ("zzz-v2") so the pre-fix
	// ORDER BY (at ASC, id ASC) would sort v=3 FIRST. The post-fix
	// ORDER BY (at ASC, canonical_version ASC, id ASC) reorders them
	// to v=2 FIRST regardless of id, matching chain-segment order.
	at := time.Date(2026, 5, 31, 10, 0, 0, 0, time.UTC)
	zero := make([]byte, HashSize)
	insert := `INSERT INTO events (
		id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
		action, resource_type, resource_id, cluster_id, request_id,
		before_json, after_json, prev_hash, hash, canonical_version
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if _, err := db.ExecContext(ctx, insert,
		"aaa-v3", at, "u-1", "", "", "user", "",
		"project.create", "project", "p-x", "", "",
		"", "", zero, zero, CanonicalVersion3,
	); err != nil {
		t.Fatalf("INSERT v=3 row: %v", err)
	}
	if _, err := db.ExecContext(ctx, insert,
		"zzz-v2", at, "u-1", "", "", "user", "",
		"project.create", "project", "p-y", "", "",
		"", "", zero, zero, CanonicalVersion2,
	); err != nil {
		t.Fatalf("INSERT v=2 row: %v", err)
	}

	rows, err := l.store.Queries.ListEventsForVerify(ctx)
	if err != nil {
		t.Fatalf("ListEventsForVerify: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("row count = %d, want 2", len(rows))
	}
	if rows[0].CanonicalVersion != CanonicalVersion2 {
		t.Errorf("rows[0].CanonicalVersion = %d, want %d (v=2 must sort before v=3 at the same `at`)",
			rows[0].CanonicalVersion, CanonicalVersion2)
	}
	if rows[0].ID != "zzz-v2" {
		t.Errorf("rows[0].ID = %q, want %q (v=2 row must be first regardless of lexical id order)",
			rows[0].ID, "zzz-v2")
	}
	if rows[1].CanonicalVersion != CanonicalVersion3 {
		t.Errorf("rows[1].CanonicalVersion = %d, want %d", rows[1].CanonicalVersion, CanonicalVersion3)
	}
	if rows[1].ID != "aaa-v3" {
		t.Errorf("rows[1].ID = %q, want %q", rows[1].ID, "aaa-v3")
	}
}

// TestGetLatestHash_SameAtMixedVersions_PicksV3OverV2 pins the v1.8
// follow-up #2 ORDER BY tie-break on the WRITE path. Mirror image of
// TestListEventsForVerify_SameAtMixedVersions_OrdersV2BeforeV3
// (which pins the verify-path tie-break).
//
// When two rows share an identical `at` (Windows clock-collision case
// surfaced during v1.9 Task 00's harness boot), GetLatestHash MUST
// return the v=3 row's hash — NOT the v=2 row's. Without the
// canonical_version DESC tiebreak, SELECT ORDER BY at DESC, id DESC
// would pick whichever UUID sorted lexically higher at the same at,
// sometimes returning the v=2 chain_restart's hash instead of the
// v=3 row inserted later in chain order. That would corrupt the next
// Logger.Log emission's prev_hash and trip the v1.8 boot guard at
// the next boot.
//
// This test uses direct INSERTs (bypassing Logger.Log) so the row
// ids + at + canonical_version are pinned exactly. The v=2 row's id
// is deliberately lexically-LARGER than the v=3 row's so the
// pre-fix `at DESC, id DESC` ordering would return the v=2 hash
// (the wrong answer).
func TestGetLatestHash_SameAtMixedVersions_PicksV3OverV2(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)
	db := SQLiteAuditDBForTest(l)
	if db == nil {
		t.Fatal("SQLiteAuditDBForTest returned nil")
	}

	at := time.Date(2026, 5, 31, 12, 49, 6, 0, time.UTC)
	v2Hash := make([]byte, HashSize)
	v3Hash := make([]byte, HashSize)
	for i := range v2Hash {
		v2Hash[i] = 0x22 // distinctive byte for v=2 hash
		v3Hash[i] = 0x33 // distinctive byte for v=3 hash
	}
	zero := make([]byte, HashSize)
	insert := `INSERT INTO events (
		id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
		action, resource_type, resource_id, cluster_id, request_id,
		before_json, after_json, prev_hash, hash, canonical_version
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	// v=2 row with LARGER lexical id (would win at DESC, id DESC if
	// canonical_version weren't the tiebreaker).
	if _, err := db.ExecContext(ctx, insert,
		"zzz-v2-restart", at, "system", "", "", "system", "barista",
		"system.audit.chain_restart", "system", "", "", "",
		"", "", zero, v2Hash, CanonicalVersion2,
	); err != nil {
		t.Fatalf("INSERT v=2 row: %v", err)
	}

	// v=3 row with SMALLER lexical id. Same at as the v=2 row.
	if _, err := db.ExecContext(ctx, insert,
		"aaa-v3-restart", at, "system", "", "", "system", "barista",
		"system.audit.chain_restart", "system", "", "", "",
		"", "", v2Hash, v3Hash, CanonicalVersion3,
	); err != nil {
		t.Fatalf("INSERT v=3 row: %v", err)
	}

	gotHash, err := l.latestHash(ctx)
	if err != nil {
		t.Fatalf("latestHash: %v", err)
	}
	if !bytesEqual(gotHash, v3Hash) {
		t.Errorf("latestHash returned wrong row's hash at same `at`.\n"+
			"  got=%x (v=2 row 'zzz-v2-restart')\n"+
			"  want=%x (v=3 row 'aaa-v3-restart')\n"+
			"  → canonical_version DESC tie-break is NOT being honored",
			gotHash, v3Hash)
	}
}

// TestLog_MonotonicAt_SameAtCollisionGetsBumped pins the v1.8
// follow-up #3 monotonic-at enforcement in Logger.Log. Two Log calls
// with the SAME `e.At` value (the Windows clock-collision case
// observed during v1.9 walk pre-flight) must produce rows with
// strictly monotonic stored `at` values — the second row's at gets
// bumped by 1 nanosecond.
//
// Without this bump, when both rows ALSO share canonical_version
// (e.g., v=3 chain_restart + v=3 chain_migrate on boot), the
// verify-path walker's id-ASC tiebreak picks arbitrary UUID order
// that may not match chain-linkage order — boot guard fires
// spuriously on a fresh DB.
//
// PR #293 + #300 fixed same-`at` ordering on the verify + write
// SELECT paths. This test pins the third (and final) leg — the
// write path's at-stamping itself.
func TestLog_MonotonicAt_SameAtCollisionGetsBumped(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	at := time.Date(2026, 5, 31, 11, 5, 44, 33981300, time.UTC)
	first := Event{
		ID:               "first",
		At:               at,
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainRestart,
		ResourceType:     "system",
		CanonicalVersion: CanonicalVersion3,
	}
	second := Event{
		ID:               "second",
		At:               at, // deliberately same as first
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainMigrate,
		ResourceType:     "system",
		CanonicalVersion: CanonicalVersion3,
	}

	stored1, err := l.Log(ctx, first)
	if err != nil {
		t.Fatalf("Log first: %v", err)
	}
	stored2, err := l.Log(ctx, second)
	if err != nil {
		t.Fatalf("Log second: %v", err)
	}

	if !stored1.At.Equal(at) {
		t.Errorf("first row's at should pass through unchanged: got %v, want %v", stored1.At, at)
	}
	if !stored2.At.After(stored1.At) {
		t.Errorf("second row's at must be strictly AFTER first's; got first=%v second=%v",
			stored1.At, stored2.At)
	}
	if stored2.At.Sub(stored1.At) != time.Nanosecond {
		t.Errorf("second row's at should be bumped by exactly 1ns; got delta=%v",
			stored2.At.Sub(stored1.At))
	}

	// Post-condition: full chain walks clean via the boot guard. The
	// monotonic-at bump means same-canonical_version rows no longer
	// collide on (at, canonical_version), so the id-ASC tiebreak
	// becomes irrelevant.
	if _, err := verifyChainPostMigrationStore(ctx, l); err != nil {
		t.Errorf("post-bump chain should verify clean; got: %v", err)
	}
}

// TestLog_MonotonicAt_NewSQLiteLogger_PrimesFromDB pins the
// process-restart half of v1.8 follow-up #3 — when a new
// SQLiteLogger opens a DB that already has rows, lastAt is primed
// from the latest row's `at`. Otherwise a process restart could
// stamp a row with `e.At < latestRow.at`, breaking monotonicity
// across process boundaries.
func TestLog_MonotonicAt_NewSQLiteLogger_PrimesFromDB(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "audit.db")

	// First logger: seed a row at a known `at`, then close so the
	// SQLite file is released for the second logger to open.
	l1Iface, err := NewSQLiteLogger(dbPath, SQLiteLoggerOptions{})
	if err != nil {
		t.Fatalf("NewSQLiteLogger #1: %v", err)
	}
	l1 := l1Iface.(*SQLiteLogger)
	at := time.Date(2026, 5, 31, 11, 5, 44, 33981300, time.UTC)
	if _, err := l1.Log(ctx, Event{
		ID:               "seed",
		At:               at,
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainRestart,
		ResourceType:     "system",
		CanonicalVersion: CanonicalVersion2,
	}); err != nil {
		t.Fatalf("Log seed: %v", err)
	}
	_ = l1.Close()

	// Open a SECOND SQLiteLogger against the SAME DB file. This
	// simulates a process restart. lastAt should be primed from
	// the row above.
	l2Iface, err := NewSQLiteLogger(dbPath, SQLiteLoggerOptions{})
	if err != nil {
		t.Fatalf("NewSQLiteLogger #2: %v", err)
	}
	defer func() { _ = l2Iface.Close() }()
	l2 := l2Iface.(*SQLiteLogger)

	if !l2.lastAt.Equal(at) {
		t.Errorf("lastAt should be primed from DB's latest row: got %v, want %v",
			l2.lastAt, at)
	}

	// Now Log on l2 with the SAME at — should be bumped by 1ns
	// even though l2 has zero in-process state about prior Logs.
	stored, err := l2.Log(ctx, Event{
		ID:               "post-restart",
		At:               at, // deliberately equal to the seed
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainMigrate,
		ResourceType:     "system",
		CanonicalVersion: CanonicalVersion3,
	})
	if err != nil {
		t.Fatalf("Log post-restart: %v", err)
	}
	if !stored.At.After(at) {
		t.Errorf("post-restart row's at must be strictly AFTER the primed lastAt; got %v vs primed %v",
			stored.At, at)
	}
}

// contains is a local stand-in for strings.Contains to keep the
// import set minimal (the audit package already uses crypto/sha256 +
// encoding/hex + errors + testing + time). Defined here rather than
// reach for strings just for one call site.
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// Silence unused-import linter when SQLiteAuditQueriesForTest paths
// aren't exercised here. The verify_boot test surface uses
// SQLiteAuditDBForTest for tamper injection but not the Queries
// handle directly — keep the import live by referencing it.
var _ = (*sqlitestore.Queries)(nil)
