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

// HasChainRestartV4 reports whether the DB carries a v4 chain-restart
// ANCHOR: a row whose action is ActionAuditChainRestart and whose
// canonical_version is 4.
//
// AN ANCHOR, NOT "ANY v4 ROW" (TD-16). Until this change the check was
// CountChainRestartV2(4), and despite its name that query is
// `SELECT COUNT(*) FROM events WHERE canonical_version = ?` — it counts
// every row at the version, anchor or not. So one ordinary v4 row
// logged before the bootstrap ran made this report true with no anchor
// in the table. The answer is now asked of the anchor itself, action AND
// version, through GetLatestChainRestartAtVersion — a query that was
// already generated for exactly this predicate, so the fix adds no SQL.
//
// BootstrapChainV4 NO LONGER CALLS THIS. It used to be the bootstrap's
// idempotency key, and even answered truthfully it is the wrong key:
// "a v4 anchor exists somewhere" says nothing about whether it is the
// NEWEST anchor, which is the only one Verify reads, nor about whether a
// missing one should be written (see needsChainRestartV4). It stays
// exported as what its name says — a statement about the table, for
// callers and operators who want to ask it — and in particular:
//
//   - true does not mean the chain is correctly anchored (an older
//     anchor may have been written after the v4 one);
//   - false does not mean the bootstrap will emit (the anchor may have
//     been pruned, or never needed).
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

// needsChainRestartV4 is the whole of BootstrapChainV4's decision: does
// this DB need a v4 anchor written NOW. It is decided by the NEWEST
// chain-restart anchor, because that is the row Verify decides by:
// verifyRows roots its walk there and hashes every later row under that
// anchor's version, whatever each row's own column says.
//
// The decision used to be one question — "is there any v4 row?" — and it
// was wrong in the one case where being wrong is expensive (TD-16): a DB
// with an older anchor and a v4 row logged before the bootstrap ran.
// There Verify takes its encoder from the newest anchor (v3), re-hashes
// every v4 row as v3 and reports tamper on rows nobody touched, and the
// row count told the only call that could end it that its work was
// already done. A boot sequence that logged before it bootstrapped was
// converted from recoverable into permanent by the very guard meant to
// make the bootstrap safe to repeat.
//
// 1. THE NEWEST ANCHOR IS v4 → no. The idempotent case: every boot after
// the one that emitted.
//
// 2. THE NEWEST ANCHOR IS AT AN OLDER VERSION → yes, whatever v4 rows —
// or v4 anchors — are already there. That older anchor is what makes
// Verify hash v4 rows under the wrong encoder, so a newer v4 anchor is
// REQUIRED. Three DBs arrive here:
//
//   - the normal upgrade, where the anchor lands before the first v4
//     row;
//   - the late call on the damaged DB above — the branch the row count
//     used to refuse;
//   - a DB that HAS a v4 anchor with an older one written after it. An
//     application whose legacy boot bootstrap runs after this one emits
//     its v3 chain-restart row on top of the v4 anchor, and every v4 row
//     from then on reads as tamper. "Some v4 anchor exists → skip", the
//     natural reading of step 1, would leave that unrepaired forever;
//     which is why step 1 asks about the newest anchor and not about
//     HasChainRestartV4.
//
// 3. NO ANCHOR OF ANY VERSION → the old rule, unchanged: yes only while
// the DB holds no v4 row. That is the first Tenancy boot — a fresh DB,
// or one that only ever held unanchored older rows — and the anchor
// marks where the v4 segment begins, as it always has.
//
// With v4 rows present and no anchor anywhere, the answer is no, and
// this is deliberate rather than a leftover. It is the DB whose anchor
// retention has pruned (PruneOlderThan deletes by age and the anchor is
// the oldest v4 row), and the DB where ordinary v4 rows were logged
// without one ever being written. In both, Verify finds no anchor and
// falls back to walking EVERY surviving row under that row's own
// version — the widest coverage it has, and already clean. An anchor
// written now would repair nothing, there being no older anchor to
// override, and it would cost coverage: Verify roots at the newest
// anchor, so every row before the new one would drop out of its walk.
// After a prune that would happen again on the first boot of every
// retention window. Collapsing this branch into "no v4 anchor → emit" —
// the obvious simplification — is exactly that regression.
//
// A newest anchor at a version ABOVE 4 answers no as well. No such
// version exists today; if one ever does, a v4 anchor written after it
// would drag the segment back under the v4 encoder.
//
// HONEST SCOPE. This makes a late bootstrap REPAIRABLE, it does not make
// the order irrelevant. A v4 row written between an older anchor and the
// late v4 one stays where it is: Verify roots at the late anchor and no
// longer reads that row at all, while VerifyChainPostMigration and
// VerifyLegacy(4, "") — which hash it under its own version — still
// cover it and find it intact. "Call at boot, BEFORE any application
// event is logged" remains the contract.
//
// The reads here and the Log that follows are not one transaction, and
// neither were the single read and the Log before them: two replicas
// booting together can both answer yes. Unchanged by this function, and
// not made worse by it.
func (l *SQLiteLogger) needsChainRestartV4(ctx context.Context) (bool, error) {
	newest, err := l.store.Queries.GetLatestChainRestart(ctx, string(ActionAuditChainRestart))
	if err == nil {
		return int(newest.CanonicalVersion) < CanonicalVersion4, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("audit: look up latest chain-restart anchor: %w", err)
	}

	n, err := l.store.Queries.CountChainRestartV2(ctx, int64(CanonicalVersion4))
	if err != nil {
		return false, fmt.Errorf("audit: count v4 rows: %w", err)
	}
	return n == 0, nil
}

// BootstrapChainV4 emits the v4 chain-restart anchor when the chain
// needs one — on a correctly ordered boot sequence, exactly once.
//
// ONLY WHEN TENANCY IS CONFIGURED. A single-tenant deployment never
// calls this and never gains a v4 row, so its audit DB is byte-identical
// to what it was before this slice — invariant 1 satisfied by not
// participating rather than by careful equivalence. Guarded here rather
// than left to the caller because "remember not to call this" is the
// kind of instruction that survives exactly one refactor.
//
// Returns (false, nil) when tenancy is off or the DB does not need the
// anchor. Call at boot, BEFORE any application event is logged.
//
// "Does not need" is needsChainRestartV4's three-step decision, taken
// from the NEWEST chain-restart anchor rather than from a row count. In
// short: newest anchor is v4 → skip; newest anchor is OLDER → emit, even
// when the call arrives late and v4 rows were already logged, and even
// when an earlier v4 anchor sits behind that older one (the two repair
// paths; the first used to be silently refused); no anchor of any
// version → emit only while the DB holds no v4 row, so a pruned anchor
// is never replaced by one that would shrink what Verify walks.
//
// A (false, nil) therefore does NOT imply HasChainRestartV4 is true, and
// a repaired DB can carry more than one v4 anchor.
func (l *SQLiteLogger) BootstrapChainV4(ctx context.Context, at time.Time, id string) (bool, error) {
	if l == nil || l.store == nil {
		return false, nil
	}
	if !l.opts.Tenancy {
		return false, nil
	}
	needed, err := l.needsChainRestartV4(ctx)
	if err != nil {
		return false, err
	}
	if !needed {
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
