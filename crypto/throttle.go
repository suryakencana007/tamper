package crypto

import (
	"context"
	"math"
	"sync"
	"time"
)

// Throttle is the rate-limit port.
//
// It lives in crypto because both consumers need it and neither can
// import the other: identity throttles Login and the TOTP verifies,
// espresso throttles StartLogin and SCIM, and espresso imports identity.
// crypto is the package they already share.
//
// KEYS ARE CALLER-COMPOSED. tamper does not decide whether email, IP,
// tenant or some combination is the right dimension to limit on — that
// is deployment-dependent, and a framework that picked one would be
// wrong for half its users. A deployment behind a shared corporate NAT
// wants email; one facing the open internet wants IP; a pooled one
// usually wants the tenant in the key so one abusive customer cannot
// exhaust another's budget.
type Throttle interface {
	// Allow reports whether the action may proceed and, when it may not,
	// how long until it may.
	//
	// It MUST NOT depend on whether the thing named by key exists. A
	// limiter that only counts real accounts turns "you are rate
	// limited" into "that account exists", which is the enumeration
	// oracle the collapsed login errors exist to prevent.
	Allow(ctx context.Context, key string) (ok bool, retryAfter time.Duration)
}

// maxThrottleKeys bounds the in-process bucket map.
//
// The keys are caller-composed from request data, so they are
// attacker-influenced, and an unbounded map keyed on attacker input is a
// memory-exhaustion vector — the same finding as the tenant registry
// cache in 7e-1. At the cap an insert evicts the least-recently-touched
// bucket. Eviction rather than refusal, for the same reason: refusing to
// track past the cap would let an attacker fill it with junk and leave
// every real key unlimited.
//
// Evicting a bucket forgets its consumption, so an attacker who can
// force eviction gets a fresh budget. That is a real limitation of any
// bounded in-process limiter and is why a deployment that must not be
// evicted under load uses a shared store instead — see NewTokenBucket.
const maxThrottleKeys = 65536

// tokenBucket is the in-process default: classic token bucket, `burst`
// capacity, refilled at `rate` tokens per `per`.
type tokenBucket struct {
	mu      sync.Mutex
	buckets map[string]*bucketState

	// refillPerNano is tokens gained per nanosecond. Precomputed so the
	// hot path does no division.
	refillPerNano float64
	burst         float64

	now func() time.Time
}

type bucketState struct {
	tokens   float64
	lastSeen time.Time
}

var _ Throttle = (*tokenBucket)(nil)

// NewTokenBucket returns the in-process token-bucket Throttle: `rate`
// actions per `per`, allowing bursts up to `burst`.
//
// PER-REPLICA, NOT GLOBAL. This is process state. Behind N replicas the
// effective limit is N times what you configured, and a deployment that
// needs a real global limit backs Throttle with a shared store (Redis,
// the database) instead. Documented rather than hidden because a limiter
// that is quietly 4x looser than its configuration is worse than one you
// know is per-replica.
//
// Zero or negative rate/per/burst all yield a Throttle that allows
// everything, which is the compat shape — a misconfigured limiter must
// not lock every user out of a login form. It is also why nil is
// tolerated at the call sites: absent limiting and useless limiting have
// the same failure mode, and neither should take the service down.
func NewTokenBucket(rate int, per time.Duration, burst int) Throttle {
	tb := &tokenBucket{
		buckets: make(map[string]*bucketState),
		burst:   float64(burst),
		now:     time.Now,
	}
	if rate > 0 && per > 0 {
		tb.refillPerNano = float64(rate) / float64(per)
	}
	return tb
}

// SetClock swaps the clock. Test seam only — it lets a bucket's refill be
// exercised without sleeping, so the suite has no wall-clock dependence.
func (t *tokenBucket) SetClock(now func() time.Time) {
	if now == nil {
		return
	}
	t.mu.Lock()
	t.now = now
	t.mu.Unlock()
}

func (t *tokenBucket) Allow(_ context.Context, key string) (bool, time.Duration) {
	// A bucket with no refill rate or no capacity limits nothing.
	if t.refillPerNano <= 0 || t.burst <= 0 {
		return true, 0
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()

	b, ok := t.buckets[key]
	if !ok {
		t.evictIfFullLocked()
		b = &bucketState{tokens: t.burst, lastSeen: now}
		t.buckets[key] = b
	} else if elapsed := now.Sub(b.lastSeen); elapsed > 0 {
		b.tokens = math.Min(t.burst, b.tokens+float64(elapsed)*t.refillPerNano)
	}
	b.lastSeen = now

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	// Time until one whole token exists again.
	need := 1 - b.tokens
	return false, time.Duration(need / t.refillPerNano)
}

// evictIfFullLocked drops the least-recently-touched bucket when the map
// is at capacity. Caller holds mu.
func (t *tokenBucket) evictIfFullLocked() {
	if len(t.buckets) < maxThrottleKeys {
		return
	}
	var oldestKey string
	var oldest time.Time
	for k, b := range t.buckets {
		if oldest.IsZero() || b.lastSeen.Before(oldest) {
			oldestKey, oldest = k, b.lastSeen
		}
	}
	delete(t.buckets, oldestKey)
}
