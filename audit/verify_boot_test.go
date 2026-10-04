package audit

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// seedChain logs one ordinary event per id, one second apart, and
// returns the logger.
func seedChain(t *testing.T, ids ...string) *SQLiteLogger {
	t.Helper()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)
	base := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	for i, id := range ids {
		if _, err := l.Log(context.Background(), Event{
			ID:           id,
			At:           base.Add(time.Duration(i) * time.Second),
			Actor:        Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
			Action:       "project.create",
			ResourceType: ResourceProject,
			ResourceID:   "p-" + id,
		}); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}
	return l
}

// requireMismatch asserts err is a *ChainMismatchError at the given row.
func requireMismatch(t *testing.T, err error, index int, rowID string) *ChainMismatchError {
	t.Helper()
	if err == nil {
		t.Fatal("expected a ChainMismatchError, got nil")
	}
	var mismatch *ChainMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("errors.As(*ChainMismatchError) failed; err=%v", err)
	}
	if !IsChainMismatch(err) {
		t.Error("IsChainMismatch = false for a ChainMismatchError")
	}
	if mismatch.Index != index {
		t.Errorf("Index = %d, want %d", mismatch.Index, index)
	}
	if mismatch.RowID != rowID {
		t.Errorf("RowID = %q, want %q", mismatch.RowID, rowID)
	}
	if mismatch.Reason == "" {
		t.Error("Reason is empty; want a failure-mode description")
	}
	return mismatch
}

// A chain written through Log walks clean, and Count is the row count.
func TestVerifyChainPostMigration_CleanChain(t *testing.T) {
	ctx := context.Background()
	l := seedChain(t, "a", "b", "c", "d", "e")

	result, err := VerifyChainPostMigration(ctx, l)
	if err != nil {
		t.Fatalf("VerifyChainPostMigration on a clean chain: %v", err)
	}
	if result.Count != 5 {
		t.Errorf("Count = %d, want 5", result.Count)
	}
}

// A flipped bit in one row's stored hash is reported at that row, with
// both hashes in the error.
func TestVerifyChainPostMigration_MidChainCorruption(t *testing.T) {
	ctx := context.Background()
	l := seedChain(t, "a", "b", "c", "d", "e", "f")

	db := SQLiteAuditDBForTest(l)
	var existing []byte
	if err := db.QueryRowContext(ctx, `SELECT hash FROM events WHERE id = ?`, "e").Scan(&existing); err != nil {
		t.Fatalf("SELECT hash: %v", err)
	}
	tampered := append([]byte(nil), existing...)
	tampered[0] ^= 0x01
	if _, err := db.ExecContext(ctx, `UPDATE events SET hash = ? WHERE id = ?`, tampered, "e"); err != nil {
		t.Fatalf("UPDATE hash: %v", err)
	}

	_, err := VerifyChainPostMigration(ctx, l)
	mismatch := requireMismatch(t, err, 4, "e")
	if mismatch.RecomputedHashHex == "" || mismatch.RecomputedHashHex == mismatch.StoredHashHex {
		t.Errorf("a hash mismatch must carry both hashes, and they must differ: stored=%s recomputed=%s",
			mismatch.StoredHashHex, mismatch.RecomputedHashHex)
	}
	if !strings.Contains(err.Error(), `id="e"`) {
		t.Errorf("the message should name the failing row, got %q", err)
	}
}

// An edit to a hashed field breaks that row's own hash.
func TestVerifyChainPostMigration_ContentEdit(t *testing.T) {
	ctx := context.Background()
	l := seedChain(t, "a", "b", "c")

	if _, err := SQLiteAuditDBForTest(l).ExecContext(ctx,
		`UPDATE events SET resource_id = 'forged' WHERE id = 'b'`); err != nil {
		t.Fatalf("UPDATE: %v", err)
	}
	_, err := VerifyChainPostMigration(ctx, l)
	requireMismatch(t, err, 1, "b")
}

// A row whose prev_hash no longer points at its predecessor is a linkage
// failure: there is no recomputed hash to show.
func TestVerifyChainPostMigration_LinkageBreak(t *testing.T) {
	ctx := context.Background()
	l := seedChain(t, "a", "b", "c")

	if _, err := SQLiteAuditDBForTest(l).ExecContext(ctx,
		`UPDATE events SET prev_hash = ? WHERE id = 'c'`, make([]byte, HashSize)); err != nil {
		t.Fatalf("UPDATE: %v", err)
	}
	_, err := VerifyChainPostMigration(ctx, l)
	mismatch := requireMismatch(t, err, 2, "c")
	if mismatch.RecomputedHashHex != "" {
		t.Errorf("a linkage failure carries no recomputed hash, got %s", mismatch.RecomputedHashHex)
	}
	if !strings.Contains(mismatch.Reason, "prev_hash") {
		t.Errorf("Reason = %q, want it to name prev_hash", mismatch.Reason)
	}
}

// After a retention prune the first surviving row points at a deleted
// predecessor. That is the chain baseline, not a failure.
func TestVerifyChainPostMigration_PrunedChainIsClean(t *testing.T) {
	ctx := context.Background()
	l := seedChain(t, "a", "b", "c", "d")

	cutoff := time.Date(2026, 5, 28, 10, 0, 2, 0, time.UTC) // removes a and b
	if n, err := l.PruneOlderThan(ctx, cutoff); err != nil || n != 2 {
		t.Fatalf("PruneOlderThan: n=%d err=%v, want 2 rows", n, err)
	}
	result, err := VerifyChainPostMigration(ctx, l)
	if err != nil {
		t.Fatalf("boot guard on a pruned chain: %v", err)
	}
	if result.Count != 2 {
		t.Errorf("Count = %d, want 2", result.Count)
	}
}

// The walk honors ctx cancellation and returns ctx.Err() without
// reporting a chain mismatch.
func TestVerifyChainPostMigration_CtxCancellation(t *testing.T) {
	l := seedChain(t, "a", "b", "c")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel BEFORE calling — the walk must fail fast.

	_, err := VerifyChainPostMigration(ctx, l)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if IsChainMismatch(err) {
		t.Error("IsChainMismatch(ctx.Canceled) = true, want false")
	}
}

// The walk respects a ctx deadline, which is how a caller bounds boot.
func TestVerifyChainPostMigration_Timeout(t *testing.T) {
	l := seedChain(t, "a", "b", "c", "d", "e")

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	// Let the deadline expire so the ctx.Err() check fires
	// deterministically rather than racing the SQL round-trip.
	time.Sleep(2 * time.Millisecond)

	_, err := VerifyChainPostMigration(ctx, l)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
	if IsChainMismatch(err) {
		t.Error("IsChainMismatch(DeadlineExceeded) = true, want false")
	}
}

// A fresh audit DB with zero rows walks clean.
func TestVerifyChainPostMigration_EmptyChain(t *testing.T) {
	l := newSQLiteLoggerForTest(t)

	result, err := VerifyChainPostMigration(context.Background(), l)
	if err != nil {
		t.Fatalf("VerifyChainPostMigration on an empty chain: %v", err)
	}
	if result.Count != 0 {
		t.Errorf("Count = %d, want 0", result.Count)
	}
}

// The walk only reads: two runs give the same result and leave every
// stored hash as it was.
func TestVerifyChainPostMigration_ReadsOnly(t *testing.T) {
	ctx := context.Background()
	l := seedChain(t, "a", "b", "c", "d")

	hashes := func() map[string]string {
		rows, err := SQLiteAuditDBForTest(l).QueryContext(ctx, `SELECT id, hash, prev_hash FROM events`)
		if err != nil {
			t.Fatalf("SELECT hashes: %v", err)
		}
		defer func() { _ = rows.Close() }()
		out := map[string]string{}
		for rows.Next() {
			var id string
			var hash, prev []byte
			if err := rows.Scan(&id, &hash, &prev); err != nil {
				t.Fatalf("scan: %v", err)
			}
			out[id] = HashHex(hash) + "|" + HashHex(prev)
		}
		return out
	}
	before := hashes()

	first, err := VerifyChainPostMigration(ctx, l)
	if err != nil {
		t.Fatalf("first walk: %v", err)
	}
	second, err := VerifyChainPostMigration(ctx, l)
	if err != nil {
		t.Fatalf("second walk: %v", err)
	}
	if first != second {
		t.Errorf("walk diverged: first=%+v second=%+v", first, second)
	}

	after := hashes()
	if len(after) != 4 {
		t.Fatalf("row count = %d, want 4", len(after))
	}
	for id, want := range before {
		if after[id] != want {
			t.Errorf("row %s changed during a read-only walk: %s -> %s", id, want, after[id])
		}
	}
}

// A NoopLogger and a nil logger have no chain; both return a zero result.
func TestVerifyChainPostMigration_NoopLogger(t *testing.T) {
	ctx := context.Background()
	result, err := VerifyChainPostMigration(ctx, NewNoopLogger())
	if err != nil {
		t.Fatalf("VerifyChainPostMigration(NoopLogger): %v", err)
	}
	if result.Count != 0 {
		t.Errorf("NoopLogger walk should be zero-result; got %+v", result)
	}

	result, err = VerifyChainPostMigration(ctx, nil)
	if err != nil {
		t.Fatalf("VerifyChainPostMigration(nil): %v", err)
	}
	if result.Count != 0 {
		t.Errorf("nil-logger walk should be zero-result; got %+v", result)
	}
}

// Two Log calls with the SAME `at` must be stored with strictly
// increasing `at` values: the second is bumped by one nanosecond. The
// verify walks order rows by `at`, so two rows sharing one would be
// walked in id order rather than in the order they were chained.
func TestLog_MonotonicAt_SameAtCollisionGetsBumped(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	at := time.Date(2026, 5, 31, 11, 5, 44, 33981300, time.UTC)
	// "z" then "a": id order is the reverse of chain order, so a walk
	// that fell back to the id tiebreak would break the linkage.
	stored1, err := l.Log(ctx, Event{ID: "z-first", At: at, Actor: ActorSystem("boot"), Action: "system.start"})
	if err != nil {
		t.Fatalf("Log first: %v", err)
	}
	stored2, err := l.Log(ctx, Event{ID: "a-second", At: at, Actor: ActorSystem("boot"), Action: "system.ready"})
	if err != nil {
		t.Fatalf("Log second: %v", err)
	}

	if !stored1.At.Equal(at) {
		t.Errorf("first row's at should pass through unchanged: got %v, want %v", stored1.At, at)
	}
	if stored2.At.Sub(stored1.At) != time.Nanosecond {
		t.Errorf("second row's at should be bumped by exactly 1ns; got delta=%v",
			stored2.At.Sub(stored1.At))
	}
	if _, err := VerifyChainPostMigration(ctx, l); err != nil {
		t.Errorf("post-bump chain should verify clean; got: %v", err)
	}
	if vr, err := l.Verify(ctx); err != nil || vr.Tamper {
		t.Errorf("post-bump chain should pass Verify; got %+v err=%v", vr, err)
	}
}

// A new SQLiteLogger over a DB that already has rows primes its
// watermark from the latest row, so the bump also holds across a
// process restart.
func TestLog_MonotonicAt_NewSQLiteLogger_PrimesFromDB(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "audit.db")

	l1Iface, err := NewSQLiteLogger(dbPath, SQLiteLoggerOptions{})
	if err != nil {
		t.Fatalf("NewSQLiteLogger #1: %v", err)
	}
	at := time.Date(2026, 5, 31, 11, 5, 44, 33981300, time.UTC)
	if _, err := l1Iface.Log(ctx, Event{ID: "seed", At: at, Actor: ActorSystem("boot"), Action: "system.start"}); err != nil {
		t.Fatalf("Log seed: %v", err)
	}
	_ = l1Iface.Close()

	l2Iface, err := NewSQLiteLogger(dbPath, SQLiteLoggerOptions{})
	if err != nil {
		t.Fatalf("NewSQLiteLogger #2: %v", err)
	}
	defer func() { _ = l2Iface.Close() }()
	l2 := l2Iface.(*SQLiteLogger)

	if !l2.lastAt.Equal(at) {
		t.Errorf("lastAt should be primed from the DB's latest row: got %v, want %v", l2.lastAt, at)
	}

	stored, err := l2.Log(ctx, Event{ID: "post-restart", At: at, Actor: ActorSystem("boot"), Action: "system.ready"})
	if err != nil {
		t.Fatalf("Log post-restart: %v", err)
	}
	if !stored.At.After(at) {
		t.Errorf("post-restart row's at must be strictly AFTER the primed lastAt; got %v vs primed %v",
			stored.At, at)
	}
}
