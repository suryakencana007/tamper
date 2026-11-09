package saml

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The feature's ENTIRE assertion: two store instances over one file, and the same key accepted
// exactly once. Everything else in this file is secondary to these two tests.
func TestSQLiteReplayStore_TwoInstancesConsumeOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.db")
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)

	first := newSQLiteStore(t, path)
	second := newSQLiteStore(t, path)

	fresh, err := first.ConsumeAssertion(ctx, "k1", exp)
	if err != nil || !fresh {
		t.Fatalf("first consume = %v, %v; want true, nil", fresh, err)
	}
	fresh, err = second.ConsumeAssertion(ctx, "k1", exp)
	if err != nil {
		t.Fatalf("second instance errored: %v", err)
	}
	if fresh {
		t.Fatal("the SECOND instance accepted an assertion the first had consumed — this is the " +
			"two-sessions bug the port exists to prevent")
	}
}

func TestSQLiteReplayStore_ConcurrentAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.db")
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)

	stores := []*SQLiteAssertionReplayStore{newSQLiteStore(t, path), newSQLiteStore(t, path)}
	var accepted int64
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fresh, err := stores[i%len(stores)].ConsumeAssertion(ctx, "race", exp)
			if err != nil {
				t.Errorf("goroutine %d: %v", i, err)
				return
			}
			if fresh {
				atomic.AddInt64(&accepted, 1)
			}
		}(i)
	}
	wg.Wait()

	if got := atomic.LoadInt64(&accepted); got != 1 {
		t.Fatalf("%d callers were told the assertion was fresh, want exactly 1 — the database must "+
			"arbitrate, not the callers", got)
	}
}

// An outage is an ERROR, and the port's contract says the caller ignores the bool and fails closed.
// A store that returned (false, nil) here would look like a replay — wrong, but safe. One that
// returned (true, nil) would accept the assertion. Both are worse than an error, and this asserts
// the error.
func TestSQLiteReplayStore_OutageIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.db")
	s := newSQLiteStore(t, path)
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	fresh, err := s.ConsumeAssertion(context.Background(), "k", time.Now().Add(time.Hour))
	if err == nil {
		t.Fatalf("a closed store returned (%v, nil) — it must return an error so the caller can "+
			"fail closed with ErrReplayStoreUnavailable", fresh)
	}
	if fresh {
		t.Error("a broken store reported the assertion as fresh")
	}

	// And the caller's side of that contract is already pinned: replay_test.go asserts that a
	// ledger failure reaches ParseAssertion as ErrReplayStoreUnavailable (→ 503), so this store
	// returning an error is the only missing half.
}

func TestSQLiteReplayStore_PurgeExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.db")
	ctx := context.Background()
	now := time.Now()
	s := newSQLiteStore(t, path)

	if _, err := s.ConsumeAssertion(ctx, "old", now.Add(-time.Minute)); err != nil {
		t.Fatalf("consume old: %v", err)
	}
	if _, err := s.ConsumeAssertion(ctx, "new", now.Add(time.Hour)); err != nil {
		t.Fatalf("consume new: %v", err)
	}

	n, err := s.PurgeExpiredBefore(ctx, now)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 1 {
		t.Fatalf("purged %d rows, want 1 — only the row whose window closed", n)
	}

	// Still-live keys are untouched by a purge.
	fresh, err := s.ConsumeAssertion(ctx, "new", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("consume after purge: %v", err)
	}
	if fresh {
		t.Error("purging removed a row whose window had NOT closed — a replay would be accepted")
	}
}

// The key is opaque: 64 hex chars in practice, but the port says implementations must not parse
// it, and this one does not — it stores whatever it is given. Asserted so that a future
// "validation" cannot be added without noticing it contradicts the contract.
func TestSQLiteReplayStore_StoresTheKeyVerbatim(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.db")
	ctx := context.Background()
	s := newSQLiteStore(t, path)

	const odd = "not-a-hex-key; the port says opaque"
	if fresh, err := s.ConsumeAssertion(ctx, odd, time.Now().Add(time.Hour)); err != nil || !fresh {
		t.Fatalf("consume = %v, %v", fresh, err)
	}
	if fresh, err := s.ConsumeAssertion(ctx, odd, time.Now().Add(time.Hour)); err != nil || fresh {
		t.Fatalf("a key with punctuation was not remembered (fresh=%v, err=%v)", fresh, err)
	}
}

func TestNewSQLiteReplayStore_RefusesAnEmptyPath(t *testing.T) {
	if _, err := NewSQLiteAssertionReplayStore(""); err == nil {
		t.Fatal("an empty path was accepted — it would open a temporary database nothing shares")
	}
}

func newSQLiteStore(t *testing.T, path string) *SQLiteAssertionReplayStore {
	t.Helper()
	s, err := NewSQLiteAssertionReplayStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteAssertionReplayStore(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

var _ AssertionReplayStore = (*SQLiteAssertionReplayStore)(nil)
var _ = errors.Is
