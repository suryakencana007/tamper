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
// WHAT THE ANCHOR IS FOR. It marks where the v4 segment begins and
// becomes Verify's walk root. It is NOT needed for a clean verify:
// Verify hashes each row under its own version, so a DB with v4 rows
// and no v4 anchor verifies clean.
//
// It has a cost, worth knowing before calling this on a DB with
// history: Verify starts at the newest anchor, so the rows before it
// leave Verify's walk. They stay covered by VerifyChainPostMigration.

// HasChainRestartV4 is the idempotency key for BootstrapChainV4.
//
// Despite its name it does not look for an anchor. It reports whether
// the DB holds ANY row at canonical_version=4 (CountChainRestartV2 is
// `SELECT COUNT(*) FROM events WHERE canonical_version = ?`). So it is
// true after the anchor is written, and equally true once one ordinary
// v4 row exists without an anchor.
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
// Optional: see the top of this file for what the anchor does and what
// it costs.
//
// Returns (false, nil) when tenancy is off or the DB already holds a v4
// row — any v4 row, not only an anchor (see HasChainRestartV4). So an
// application that wants the anchor must call this BEFORE its first v4
// event is logged; called later it writes nothing.
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
