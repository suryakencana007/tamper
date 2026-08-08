package crypto

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Slice 7k-1 — token-bucket mechanics.
//
// Every test drives a fake clock. A limiter tested by sleeping is a
// limiter tested flakily: the sleep is a lower bound the scheduler is
// free to overshoot, and the resulting suite either flakes on a loaded
// CI box or is padded until it is slow enough not to.

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	// A fixed instant, not time.Now: the bucket arithmetic must not
	// depend on when the suite runs.
	return &fakeClock{t: time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// newTestBucket returns a bucket on a controllable clock.
func newTestBucket(t *testing.T, rate int, per time.Duration, burst int) (Throttle, *fakeClock) {
	t.Helper()
	clk := newFakeClock()
	tb, ok := NewTokenBucket(rate, per, burst).(*tokenBucket)
	if !ok {
		t.Fatalf("NewTokenBucket returned %T, not *tokenBucket", tb)
	}
	tb.SetClock(clk.now)
	return tb, clk
}

// --- burst -------------------------------------------------------------

// TestTokenBucket_BurstThenRefuse: a fresh key gets exactly `burst`
// allowances and the next one is refused. Off by one here is the
// difference between a 5-attempt limit and a 6-attempt limit, which is
// the sort of thing that stays wrong forever because nobody counts.
func TestTokenBucket_BurstThenRefuse(t *testing.T) {
	ctx := context.Background()
	tb, _ := newTestBucket(t, 1, time.Second, 5)

	for i := range 5 {
		ok, retryAfter := tb.Allow(ctx, "k")
		if !ok {
			t.Fatalf("attempt %d of the burst was refused (retryAfter %v); "+
				"the bucket does not hold its stated capacity", i+1, retryAfter)
		}
		if retryAfter != 0 {
			t.Errorf("attempt %d allowed but reported retryAfter %v; "+
				"an allowed call has nothing to wait for", i+1, retryAfter)
		}
	}

	ok, retryAfter := tb.Allow(ctx, "k")
	if ok {
		t.Fatal("the 6th attempt was allowed against a burst of 5; the limiter does not limit")
	}
	if retryAfter <= 0 {
		t.Errorf("refused with retryAfter %v; a refusal that names no wait "+
			"trains clients to hot-loop on it", retryAfter)
	}
}

// TestTokenBucket_KeysAreIndependent: exhausting one key must not
// refuse another. A limiter that shared one bucket across keys would
// pass every single-key test above and lock out the whole service — and
// in a pooled process, one tenant's burst would lock out every other.
func TestTokenBucket_KeysAreIndependent(t *testing.T) {
	ctx := context.Background()
	tb, _ := newTestBucket(t, 1, time.Second, 2)

	for range 3 {
		tb.Allow(ctx, "tenant-a")
	}
	if ok, _ := tb.Allow(ctx, "tenant-a"); ok {
		t.Fatal("tenant-a was not exhausted; the rest of this test proves nothing")
	}

	if ok, _ := tb.Allow(ctx, "tenant-b"); !ok {
		t.Error("tenant-b was refused because tenant-a exhausted its budget; " +
			"one customer can deny service to every other")
	}
}

// --- refill ------------------------------------------------------------

// TestTokenBucket_RefillsOverTime walks the refill curve rather than
// asserting one point on it: drained, still drained just before the
// token is due, allowed just after, and refused again immediately after
// that (one token restored, not the whole bucket).
func TestTokenBucket_RefillsOverTime(t *testing.T) {
	ctx := context.Background()
	// 2 per second => one token every 500ms.
	tb, clk := newTestBucket(t, 2, time.Second, 2)

	tb.Allow(ctx, "k")
	tb.Allow(ctx, "k")
	ok, retryAfter := tb.Allow(ctx, "k")
	if ok {
		t.Fatal("the bucket was not drained")
	}
	if want := 500 * time.Millisecond; retryAfter > want+time.Millisecond {
		t.Errorf("retryAfter = %v, want about %v — the hint overstates the wait, "+
			"so a client that obeys it idles longer than it must", retryAfter, want)
	}

	clk.advance(499 * time.Millisecond)
	if ok, _ := tb.Allow(ctx, "k"); ok {
		t.Error("allowed 1ms before a whole token had accrued; the bucket rounds in " +
			"the attacker's favour")
	}

	clk.advance(2 * time.Millisecond) // now just past the 500ms mark
	if ok, _ := tb.Allow(ctx, "k"); !ok {
		t.Fatal("still refused after a full token accrued; the bucket never refills " +
			"and the first burst locks the key out permanently")
	}

	if ok, _ := tb.Allow(ctx, "k"); ok {
		t.Error("a second attempt was allowed immediately; the elapsed time " +
			"restored more than it earned")
	}
}

// TestTokenBucket_RefillCapsAtBurst: an idle key does not bank credit.
// Without the cap, a key untouched overnight arrives with tens of
// thousands of tokens and the limiter is decorative on exactly the
// account an attacker picked precisely because it is quiet.
func TestTokenBucket_RefillCapsAtBurst(t *testing.T) {
	ctx := context.Background()
	tb, clk := newTestBucket(t, 10, time.Second, 3)

	tb.Allow(ctx, "k")          // create the bucket
	clk.advance(24 * time.Hour) // idle for a day: 864,000 tokens' worth

	allowed := 0
	for range 100 {
		if ok, _ := tb.Allow(ctx, "k"); ok {
			allowed++
			continue
		}
		break
	}
	if allowed != 3 {
		t.Errorf("an idle key banked %d allowances against a burst of 3; "+
			"a quiet account is unlimited on its first move", allowed)
	}
}

// --- degenerate configuration -----------------------------------------

// TestTokenBucket_DegenerateConfigAllowsEverything pins the documented
// fail-open on a misconfigured limiter. Stated as a test because it is
// the one place this package deliberately does NOT fail closed, and an
// undocumented reversal would be a silent outage: rate 0 read as "zero
// allowed" locks every user out of the login form.
func TestTokenBucket_DegenerateConfigAllowsEverything(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name        string
		rate, burst int
		per         time.Duration
	}{
		{"zero rate", 0, 5, time.Second},
		{"zero burst", 5, 0, time.Second},
		{"zero period", 5, 5, 0},
		{"negative rate", -1, 5, time.Second},
		{"negative burst", 5, -1, time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tb := NewTokenBucket(tc.rate, tc.per, tc.burst)
			for i := range 50 {
				if ok, _ := tb.Allow(ctx, "k"); !ok {
					t.Fatalf("attempt %d refused by a degenerate limiter; "+
						"a misconfiguration locked every caller out", i+1)
				}
			}
		})
	}
}

// --- bounded memory ----------------------------------------------------

// TestTokenBucket_BoundsItsKeyMap: the keys are attacker-influenced, so
// an unbounded map is a memory-exhaustion vector — the same finding as
// the tenant registry cache in 7e-1.
func TestTokenBucket_BoundsItsKeyMap(t *testing.T) {
	ctx := context.Background()
	tb, ok := NewTokenBucket(1, time.Second, 1).(*tokenBucket)
	if !ok {
		t.Fatal("NewTokenBucket did not return *tokenBucket")
	}
	clk := newFakeClock()
	tb.SetClock(clk.now)

	for i := range maxThrottleKeys + 500 {
		tb.Allow(ctx, fmt.Sprintf("key-%d", i))
		// Advance so lastSeen is strictly ordered and eviction is
		// deterministic rather than map-iteration-dependent.
		clk.advance(time.Millisecond)
	}

	tb.mu.Lock()
	n := len(tb.buckets)
	tb.mu.Unlock()
	if n > maxThrottleKeys {
		t.Errorf("bucket map holds %d keys, cap is %d; attacker-chosen keys grow "+
			"the map without bound", n, maxThrottleKeys)
	}
}

// TestTokenBucket_EvictsTheOldest: at the cap, the LEAST recently seen
// key goes. Evicting the most recent instead would forget the active
// attacker and keep idle strangers, which is precisely backwards.
func TestTokenBucket_EvictsTheOldest(t *testing.T) {
	ctx := context.Background()
	tb, ok := NewTokenBucket(1, time.Hour, 1).(*tokenBucket)
	if !ok {
		t.Fatal("NewTokenBucket did not return *tokenBucket")
	}
	clk := newFakeClock()
	tb.SetClock(clk.now)

	tb.Allow(ctx, "oldest")
	clk.advance(time.Minute)
	for i := range maxThrottleKeys - 1 {
		tb.Allow(ctx, fmt.Sprintf("filler-%d", i))
		clk.advance(time.Millisecond)
	}
	// Keep "oldest" stale but re-touch a filler so it is not the victim.
	tb.Allow(ctx, "filler-0")
	clk.advance(time.Millisecond)

	tb.Allow(ctx, "the-straw") // forces one eviction

	tb.mu.Lock()
	_, oldestSurvived := tb.buckets["oldest"]
	_, touchedSurvived := tb.buckets["filler-0"]
	tb.mu.Unlock()

	if oldestSurvived {
		t.Error("the least-recently-seen key survived eviction")
	}
	if !touchedSurvived {
		t.Error("a recently touched key was evicted while a stale one survived; " +
			"the active caller is the one being forgotten")
	}
}

// --- concurrency -------------------------------------------------------

// TestTokenBucket_ConcurrentAllowIsExact: under -race, N goroutines
// hammering one key must yield exactly `burst` allowances. A limiter
// that read-modify-writes its token count outside the lock would hand
// out more under contention — which is exactly when it matters.
func TestTokenBucket_ConcurrentAllowIsExact(t *testing.T) {
	ctx := context.Background()
	const burst = 20
	tb, _ := newTestBucket(t, 1, time.Hour, burst) // refill too slow to interfere

	var mu sync.Mutex
	allowed := 0
	var wg sync.WaitGroup
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := tb.Allow(ctx, "hot"); ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowed != burst {
		t.Errorf("concurrent callers got %d allowances against a burst of %d; "+
			"the limiter leaks under contention", allowed, burst)
	}
}
