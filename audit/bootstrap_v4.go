package audit

import (
	"context"
	"fmt"
	"time"
)

// The canonical_version=4 chain-segment anchor.
//
// WHY THIS IS GO AND NOT SQL. The anchor is an ordinary chain row and
// its prev_hash must be the REAL latest hash of the existing chain. The
// HashSize zero sentinel is correct only on an empty table; writing it
// onto a populated DB produces a row whose linkage check fails at the
// next boot, which is the migration breaking the very guarantee it is
// migrating. Migration 005 therefore adds columns only, and the anchor
// is emitted through Logger.Log — the one path that reads the latest
// hash under the write lock.
//
// WHY IT MUST LAND BEFORE THE FIRST v4 ROW. verifyRows selects the walk
// root from the most recent anchor and takes the ENCODER VERSION from
// it, overriding each row's own column. A v4 row sitting after a v3
// anchor is therefore re-hashed under the v3 encoder and reads as
// tamper. Emitting the anchor first is not tidiness; it is the
// difference between a clean boot and a chain that reports itself
// forged.

// HasChainRestartV4 reports whether the DB already carries a v4
// chain-restart anchor. The idempotency key for BootstrapChainV4 —
// subsequent boots see true and skip.
func (l *SQLiteLogger) HasChainRestartV4(ctx context.Context) (bool, error) {
	n, err := l.store.Queries.CountChainRestartV2(ctx, int64(CanonicalVersion4))
	if err != nil {
		return false, fmt.Errorf("audit: count v4 chain-restart rows: %w", err)
	}
	return n > 0, nil
}

// BootstrapChainV4 emits the single v4 chain-restart anchor, once.
//
// ONLY WHEN TENANCY IS CONFIGURED. A single-tenant deployment never
// calls this and never gains a v4 row, so its audit DB is byte-identical
// to what it was before this slice — invariant 1 satisfied by not
// participating rather than by careful equivalence. Guarded here rather
// than left to the caller because "remember not to call this" is the
// kind of instruction that survives exactly one refactor.
//
// Returns (false, nil) when the anchor already exists or tenancy is off.
// Call at boot, BEFORE any application event is logged.
func (l *SQLiteLogger) BootstrapChainV4(ctx context.Context, at time.Time, id string) (bool, error) {
	if l == nil || l.store == nil {
		return false, nil
	}
	if !l.opts.Tenancy {
		return false, nil
	}
	already, err := l.HasChainRestartV4(ctx)
	if err != nil {
		return false, err
	}
	if already {
		return false, nil
	}
	if id == "" {
		return false, fmt.Errorf("audit: BootstrapChainV4 requires an event id")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}

	// Emitted through Log so it picks up the real latest hash, the
	// monotonic-at bump and the v4 commitments like any other row. The
	// version is set EXPLICITLY rather than left to the Tenancy default,
	// so this reads correctly even if that default is ever changed.
	//
	// The anchor carries no tenant. It is a property of the chain, not
	// of any customer, and giving it one would put a chain-machinery row
	// inside a tenant's export.
	_, err = l.Log(ctx, Event{
		ID:               id,
		At:               at,
		Actor:            ActorSystem("audit"),
		Action:           ActionAuditChainRestart,
		ResourceType:     ResourceType("audit_chain"),
		ResourceID:       "v4",
		CanonicalVersion: CanonicalVersion4,
	})
	if err != nil {
		return false, fmt.Errorf("audit: emit v4 chain-restart anchor: %w", err)
	}
	return true, nil
}
