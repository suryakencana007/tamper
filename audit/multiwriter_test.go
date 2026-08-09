package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Multi-writer chain integrity.
//
// Appending to a hash chain is read-latest-hash, compute, insert — a
// read-modify-write. It is atomic only if something makes it so, and
// until the BEGIN IMMEDIATE transaction in Log the only thing was an
// IN-PROCESS mutex. A pooled deployment is usually multi-replica, so
// that was a chain fork waiting for the second pod.
//
// Under ISO 27001 A.8.15 the chain IS the tamper-protection control, so
// this is not a latent risk to schedule — a control that fails under the
// deployment's own topology is a nonconformity an auditor can reproduce.

// twoReplicas returns two loggers over the SAME database file. Separate
// *sql.DB, separate pools, separate mutexes and watermarks — which is
// exactly what two processes have.
func twoReplicas(t *testing.T) (*SQLiteLogger, *SQLiteLogger) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	mk := func() *SQLiteLogger {
		l, err := NewSQLiteLogger(dbPath, SQLiteLoggerOptions{})
		if err != nil {
			t.Fatalf("NewSQLiteLogger: %v", err)
		}
		t.Cleanup(func() { _ = l.Close() })
		sl, ok := l.(*SQLiteLogger)
		if !ok {
			t.Fatalf("NewSQLiteLogger returned %T", l)
		}
		return sl
	}
	return mk(), mk()
}

// TestMultiWriter_ConcurrentLoggersKeepTheChainIntact is the regression.
//
// Before the transaction this failed with stored_prev=000...0: one
// writer read an empty table while another had already inserted, so two
// rows claimed the same predecessor and the boot verify reported tamper
// on a database nobody had tampered with.
func TestMultiWriter_ConcurrentLoggersKeepTheChainIntact(t *testing.T) {
	ctx := context.Background()
	a, b := twoReplicas(t)
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	const n = 40
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l := a
			if i%2 == 1 {
				l = b
			}
			<-start
			_, errs[i] = l.Log(ctx,
				makeEvent(fmt.Sprintf("e-%02d", i), base.Add(time.Duration(i)*time.Millisecond),
					Action("auth.login")))
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Log %d failed: %v", i, err)
		}
	}

	res, err := verifyChainPostMigrationStore(ctx, a)
	if err != nil {
		t.Fatalf("TWO REPLICAS FORKED THE CHAIN (walked %d rows): %v\n\n"+
			"The chain append is not serialised: both writers read the same "+
			"latest hash and both inserted against it.", res.Count, err)
	}
	if res.Count != n {
		t.Errorf("walked %d rows, want %d — an append was lost", res.Count, n)
	}
}

// TestMultiWriter_NoTwoRowsShareAPredecessor states the fork directly
// rather than through the verify walk's error string. Two rows with the
// same prev_hash IS the fork; the walk is only how it is noticed.
func TestMultiWriter_NoTwoRowsShareAPredecessor(t *testing.T) {
	ctx := context.Background()
	a, b := twoReplicas(t)
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 30 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l := a
			if i%2 == 1 {
				l = b
			}
			<-start
			_, _ = l.Log(ctx, makeEvent(fmt.Sprintf("e-%02d", i),
				base.Add(time.Duration(i)*time.Millisecond), Action("auth.login")))
		}(i)
	}
	close(start)
	wg.Wait()

	rows, err := a.store.Queries.ListEventsForVerify(ctx)
	if err != nil {
		t.Fatalf("ListEventsForVerify: %v", err)
	}
	seen := map[string]string{}
	for _, r := range rows {
		key := fmt.Sprintf("%x", r.PrevHash)
		if other, dup := seen[key]; dup {
			t.Fatalf("rows %s and %s both claim predecessor %s — the chain is forked",
				other, r.ID, key[:16])
		}
		seen[key] = r.ID
	}
}

// TestMultiWriter_AtStaysStrictlyIncreasing. The monotonic-`at`
// watermark was in-process too, so a second replica could mint a
// timestamp at or behind one already on disk. The verify walk orders by
// (at, canonical_version, id), so a non-monotonic `at` reorders the walk
// away from chain-linkage order and the chain reads as broken.
//
// The A.8.17 caveat, recorded where someone will find it: `at` is NOT a
// pure synchronised clock reading. It is the caller's timestamp, bumped
// forward on collision to preserve chain order. That is defensible and
// load-bearing, but it is an adjusted value, not an observation.
func TestMultiWriter_AtStaysStrictlyIncreasing(t *testing.T) {
	ctx := context.Background()
	a, b := twoReplicas(t)
	// Every event asks for the SAME instant, which is the worst case: a
	// low-resolution clock under two writers.
	same := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 24 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l := a
			if i%2 == 1 {
				l = b
			}
			<-start
			_, _ = l.Log(ctx, makeEvent(fmt.Sprintf("e-%02d", i), same, Action("auth.login")))
		}(i)
	}
	close(start)
	wg.Wait()

	rows, err := a.store.Queries.ListEventsForVerify(ctx)
	if err != nil {
		t.Fatalf("ListEventsForVerify: %v", err)
	}
	if len(rows) != 24 {
		t.Fatalf("got %d rows, want 24", len(rows))
	}
	for i := 1; i < len(rows); i++ {
		if !rows[i].At.After(rows[i-1].At) {
			t.Errorf("row %d (%s) at %v does not follow row %d (%s) at %v; two "+
				"replicas minted the same instant and the walk order no longer "+
				"matches chain order",
				i, rows[i].ID, rows[i].At, i-1, rows[i-1].ID, rows[i-1].At)
		}
	}
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyChainPostMigrationStore(ctx, a); err != nil {
		t.Fatalf("chain broken under same-instant concurrent writes: %v", err)
	}
}

// TestMultiWriter_FailedAppendReleasesTheWriteLock: a rejected event
// must not leave the connection holding SQLite's write lock, or the next
// append blocks until the pool discards it.
func TestMultiWriter_FailedAppendReleasesTheWriteLock(t *testing.T) {
	ctx := context.Background()
	a, _ := twoReplicas(t)
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	// canonical_version=1 is rejected AFTER the transaction opens.
	if _, err := a.Log(ctx, Event{
		ID: "v1-row", At: base, Action: Action("auth.login"),
		CanonicalVersion: CanonicalVersion1,
	}); err == nil {
		t.Fatal("a canonical_version=1 row was accepted")
	}

	done := make(chan error, 1)
	go func() {
		_, err := a.Log(ctx, makeEvent("after", base.Add(time.Second), Action("auth.login")))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the append after a failed one errored: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the append after a failed one BLOCKED; the rolled-back " +
			"transaction did not release SQLite's write lock")
	}
}
