package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/suryakencana007/tamper/audit/internal/sqlitestore"
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
// chain-restart ANCHOR: a row whose action is ActionAuditChainRestart
// and whose canonical_version is 4. The idempotency key for
// BootstrapChainV4 — subsequent boots see true and skip.
//
// AN ANCHOR, NOT "ANY v4 ROW" (TD-16). Until this change the check was
// CountChainRestartV2(4), and despite its name that query is
// `SELECT COUNT(*) FROM events WHERE canonical_version = ?` — it counts
// every row at the version, anchor or not. So one ordinary v4 row
// logged before the bootstrap ran made this report true with no anchor
// in the table, and BootstrapChainV4 returned (false, nil) on that boot
// and on every boot after it. On a DB that already carries an older
// (v3) anchor that is not a cosmetic gap: Verify takes its encoder from
// the newest anchor, re-hashed every v4 row as v3, and reported tamper
// on rows nobody had touched — and the one call that could repair it
// was the call that had just talked itself out of running. The mistake
// "the application logged before it bootstrapped" was converted from
// recoverable into permanent by the very guard meant to make the
// bootstrap safe to repeat.
//
// The question is therefore asked of the anchor itself: action AND
// version, through GetLatestChainRestartAtVersion — a query that was
// already generated for exactly this predicate, so the fix adds no SQL.
// A late bootstrap now emits; rows logged after it verify under v4.
//
// HONEST SCOPE. This makes the bootstrap REPAIRABLE, it does not make
// the order irrelevant. A v4 row written before the anchor stays where
// it is, between the older anchor and the late one: Verify roots its
// walk at the newest anchor and so no longer reads that row at all,
// while VerifyChainPostMigration and VerifyLegacy(4, "") — which hash
// it under its own version — still cover it and find it intact. "Call
// at boot, BEFORE any application event is logged" remains the
// contract.
//
// It also ties the answer to the anchor ROW surviving. PruneOlderThan
// deletes by age and the anchor is the oldest v4 row, so once retention
// removes it this reports false again and the next boot emits a fresh
// anchor — at most one per retention window, each linked into the chain
// through Log like any other row. The old count answered true for as
// long as any v4 row survived, which is exactly the property that made
// it wrong.
//
// HasChainRestartV2 and HasChainRestartV3 still count rows. They share
// the flaw, but other consumers' boot paths depend on what they answer
// today, so changing them is its own change rather than a rider on this
// one.
func (l *SQLiteLogger) HasChainRestartV4(ctx context.Context) (bool, error) {
	_, err := l.store.Queries.GetLatestChainRestartAtVersion(ctx, sqlitestore.GetLatestChainRestartAtVersionParams{
		Action:           string(ActionAuditChainRestart),
		CanonicalVersion: int64(CanonicalVersion4),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("audit: look up v4 chain-restart anchor: %w", err)
	}
	return true, nil
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
//
// "Already exists" means the anchor row, not any v4 row — see
// HasChainRestartV4. A call that arrives late, after ordinary v4 rows
// were logged, therefore still emits and returns true: that is the
// repair path for a boot sequence that got the order wrong, and it used
// to be silently refused.
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
