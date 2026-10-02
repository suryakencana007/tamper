package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TD-16 — the idempotency key of BootstrapChainV4.
//
// HasChainRestartV4 used to answer "is there a v4 anchor?" by counting
// every v4 row. One ordinary v4 row logged before the bootstrap was
// enough to make it say yes, and from then on the bootstrap refused to
// write the anchor it was the only way to write. These tests pin the
// question to the anchor row itself.
//
// Every test here that logs before bootstrapping is the mutation proof
// for the fix: restore the row-counting check and they fail, because
// the late bootstrap goes back to returning (false, nil).

// countV4Anchors counts the rows that ARE v4 anchors — action and
// version both. Written out against the DB rather than through
// HasChainRestartV4 so the assertions below do not ask the code under
// test to mark its own homework.
func countV4Anchors(t *testing.T, l *SQLiteLogger) int {
	t.Helper()
	var n int
	if err := l.store.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM events WHERE action = ? AND canonical_version = ?`,
		string(ActionAuditChainRestart), CanonicalVersion4).Scan(&n); err != nil {
		t.Fatalf("count v4 anchors: %v", err)
	}
	return n
}

func mustHaveChainRestartV4(t *testing.T, l *SQLiteLogger, want bool, when string) {
	t.Helper()
	got, err := l.HasChainRestartV4(context.Background())
	if err != nil {
		t.Fatalf("HasChainRestartV4 (%s): %v", when, err)
	}
	if got != want {
		t.Fatalf("HasChainRestartV4 (%s) = %v, want %v", when, got, want)
	}
}

// TestHasChainRestartV4_CountsAnchorsNotRows is the predicate on its
// own, through the three states that matter: nothing, ordinary v4 rows
// with no anchor, and the anchor.
//
// The middle state is the whole of TD-16. An empty DB and an anchored
// DB were answered correctly by the old row count too, which is why the
// flaw survived every test that bootstrapped first.
func TestHasChainRestartV4_CountsAnchorsNotRows(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

	mustHaveChainRestartV4(t, l, false, "empty DB")

	for i, id := range []string{"v4-a", "v4-b"} {
		got, err := l.Log(ctx, tenantEvent(id, base.Add(time.Duration(i)*time.Second), "acme"))
		if err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
		if got.CanonicalVersion != CanonicalVersion4 {
			t.Fatalf("row %s landed at v%d, want v4 — the fixture is not exercising "+
				"the case under test", id, got.CanonicalVersion)
		}
	}
	if n := countV4Anchors(t, l); n != 0 {
		t.Fatalf("fixture has %d v4 anchors before the bootstrap, want 0", n)
	}
	got, err := l.HasChainRestartV4(ctx)
	if err != nil {
		t.Fatalf("HasChainRestartV4 (ordinary v4 rows, no anchor): %v", err)
	}
	if got {
		t.Fatal("HasChainRestartV4 = true on a DB holding ordinary v4 rows and NO " +
			"anchor; it is counting rows at the version rather than anchors, and " +
			"BootstrapChainV4 will skip the anchor on every boot from here on")
	}

	emitted, err := l.BootstrapChainV4(ctx, base.Add(time.Minute), "v4-anchor")
	if err != nil || !emitted {
		t.Fatalf("BootstrapChainV4 = (%v, %v), want (true, nil)", emitted, err)
	}
	mustHaveChainRestartV4(t, l, true, "after the bootstrap")
}

// TestHasChainRestartV4_IgnoresAnchorsAtOtherVersions: the predicate is
// action AND version. A v3 chain-restart row is an anchor, but it is not
// the v4 one — and it is exactly the row an existing deployment already
// has when it first switches Tenancy on. Matching on the action alone
// would skip the bootstrap on every DB that needs it most.
func TestHasChainRestartV4_IgnoresAnchorsAtOtherVersions(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

	if _, err := l.Log(ctx, Event{
		ID:               "v3-anchor",
		At:               base,
		Actor:            ActorSystem("audit"),
		Action:           ActionAuditChainRestart,
		ResourceType:     ResourceType("audit_chain"),
		ResourceID:       "v3",
		CanonicalVersion: CanonicalVersion3,
	}); err != nil {
		t.Fatalf("emit v3 anchor: %v", err)
	}
	mustHaveChainRestartV4(t, l, false, "v3 anchor only")
}

// TestBootstrapChainV4_EmitsAfterAnOrdinaryV4Row is the repair path.
// The application logged first and bootstrapped second — the wrong
// order, and the one a boot sequence drifts into the moment somebody
// adds an audited step above the bootstrap call. The anchor must still
// be written, exactly once.
func TestBootstrapChainV4_EmitsAfterAnOrdinaryV4Row(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

	if _, err := l.Log(ctx, tenantEvent("early", base, "acme")); err != nil {
		t.Fatalf("Log early: %v", err)
	}

	emitted, err := l.BootstrapChainV4(ctx, base.Add(time.Second), "v4-anchor")
	if err != nil {
		t.Fatalf("late BootstrapChainV4: %v", err)
	}
	if !emitted {
		t.Fatal("BootstrapChainV4 returned (false, nil) on a DB with a v4 row and " +
			"NO v4 anchor; the ordinary row was mistaken for the anchor, and no " +
			"later boot can repair it")
	}
	mustHaveChainRestartV4(t, l, true, "after the late bootstrap")

	second, err := l.BootstrapChainV4(ctx, base.Add(time.Hour), "v4-anchor-2")
	if err != nil {
		t.Fatalf("second BootstrapChainV4: %v", err)
	}
	if second {
		t.Error("a second bootstrap emitted another v4 anchor; every restart would " +
			"add a chain segment")
	}
	if n := countV4Anchors(t, l); n != 1 {
		t.Errorf("v4 anchors = %d, want exactly 1", n)
	}

	// The anchor went through Log, so it is linked onto the row that was
	// already there rather than restarting from the zero sentinel.
	if _, err := verifyChainPostMigrationStore(ctx, l); err != nil {
		t.Errorf("the chain does not walk after a late bootstrap: %v", err)
	}
}

// TestBootstrapChainV4_LateOnAnAnchoredV3DB is the case that hurt
// (TestTD09_TenancyWithoutBootstrap case (d) in tech-debt-proofs.md):
// the DB an existing deployment actually has. Its boot emitted a v3
// chain-restart anchor long ago; Tenancy is switched on; one v4 row is
// logged before BootstrapChainV4 runs.
//
// From that row on, Verify reported tamper — it takes the encoder from
// the newest anchor (v3) and re-hashes the v4 row under it — and the
// bootstrap, seeing "a v4 row", declined to write the anchor that would
// have ended it. Nothing in the API could move the DB out of that
// state. Now the late bootstrap emits, and everything logged after it
// verifies.
func TestBootstrapChainV4_LateOnAnAnchoredV3DB(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

	// Boot 1 — tenancy OFF. The application's own bootstrap emits the v3
	// anchor, then an ordinary v3 row.
	opened, err := NewSQLiteLogger(dbPath, SQLiteLoggerOptions{})
	if err != nil {
		t.Fatalf("open (tenancy off): %v", err)
	}
	a3 := opened.(*SQLiteLogger)
	if _, err := a3.Log(ctx, Event{
		ID:               "v3-anchor",
		At:               base,
		Actor:            ActorSystem("audit"),
		Action:           ActionAuditChainRestart,
		ResourceType:     ResourceType("audit_chain"),
		ResourceID:       "v3",
		CanonicalVersion: CanonicalVersion3,
	}); err != nil {
		t.Fatalf("emit v3 anchor: %v", err)
	}
	if _, err := a3.Log(ctx, makeEvent("v3-row", base.Add(time.Second), Action("auth.login"))); err != nil {
		t.Fatalf("Log v3-row: %v", err)
	}
	if res, err := a3.Verify(ctx); err != nil || res.Tamper {
		t.Fatalf("the v3 DB does not verify before the switch: %+v, %v", res, err)
	}
	if err := a3.Close(); err != nil {
		t.Fatalf("close (tenancy off): %v", err)
	}

	// Boot 2 — the same file, Tenancy ON, and an event logged BEFORE the
	// bootstrap.
	reopened, err := NewSQLiteLogger(dbPath, SQLiteLoggerOptions{Tenancy: true})
	if err != nil {
		t.Fatalf("reopen (tenancy on): %v", err)
	}
	l := reopened.(*SQLiteLogger)
	t.Cleanup(func() { _ = l.Close() })

	between, err := l.Log(ctx, tenantEvent("v4-between", base.Add(2*time.Second), "acme"))
	if err != nil {
		t.Fatalf("Log v4-between: %v", err)
	}
	if between.CanonicalVersion != CanonicalVersion4 {
		t.Fatalf("v4-between landed at v%d, want v4", between.CanonicalVersion)
	}

	// The damage this test exists for, asserted so the test cannot pass on
	// a fixture that never reproduced it. Not a property worth having —
	// the reason the anchor has to land first (see bootstrap_v4.go). If
	// Verify ever stops overriding the row's own version this fails, and
	// the right response is to delete this block, not to restore the
	// override.
	damaged, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify (before the late bootstrap): %v", err)
	}
	if !damaged.Tamper || damaged.FirstBadIndex != 2 {
		t.Fatalf("Verify before the late bootstrap = %+v, want tamper at index 2 "+
			"(the v4 row re-hashed under the v3 anchor's encoder); the fixture "+
			"is not in the state TD-16 describes", damaged)
	}
	mustHaveChainRestartV4(t, l, false, "one ordinary v4 row behind a v3 anchor")

	// The repair.
	emitted, err := l.BootstrapChainV4(ctx, base.Add(3*time.Second), "v4-anchor")
	if err != nil {
		t.Fatalf("late BootstrapChainV4: %v", err)
	}
	if !emitted {
		t.Fatal("the late bootstrap emitted nothing; Verify reports tamper on this " +
			"DB and the only call that could end it has refused to run")
	}
	if n := countV4Anchors(t, l); n != 1 {
		t.Fatalf("v4 anchors = %d, want exactly 1", n)
	}
	for i, id := range []string{"v4-after-a", "v4-after-b"} {
		if _, err := l.Log(ctx, tenantEvent(id, base.Add(time.Duration(4+i)*time.Second), "acme")); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	// Verify roots at the newest anchor — now the v4 one — and walks it
	// plus the two rows after it under the v4 encoder.
	res, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify (after the late bootstrap): %v", err)
	}
	if res.Tamper {
		t.Fatalf("Verify still reports tamper after the late bootstrap: %+v", res)
	}
	if res.Total != 3 {
		t.Errorf("Verify walked %d rows, want 3 (the late anchor and the two rows "+
			"after it)", res.Total)
	}

	// THE ROW IN BETWEEN. v4-between sits after the v3 anchor and before
	// the late v4 one. The late anchor does not rewrite it and nothing
	// here tries to: it was hashed correctly under v4 when it was written
	// and its bytes have not moved.
	//
	// What changed is who reads it. Verify no longer does — the Total of
	// 3 above is the anchor and its two successors, and v4-between is
	// behind the walk root, like every row before any anchor. The two
	// walks that honour the row's own canonical_version still cover it,
	// and both find it intact:
	boot, err := verifyChainPostMigrationStore(ctx, l)
	if err != nil {
		t.Fatalf("VerifyChainPostMigration rejects the repaired chain: %v", err)
	}
	if boot.Count != 6 {
		t.Errorf("the boot guard walked %d rows, want all 6", boot.Count)
	}
	legacy, err := l.VerifyLegacy(ctx, CanonicalVersion4, "")
	if err != nil {
		t.Fatalf("VerifyLegacy(4): %v", err)
	}
	if legacy.Tamper {
		t.Errorf("VerifyLegacy(4) reports tamper on the v4 segment: %+v", legacy)
	}
	if legacy.Total != 4 {
		t.Errorf("VerifyLegacy(4) walked %d rows, want 4 (v4-between, the late "+
			"anchor and the two rows after it)", legacy.Total)
	}

	// And "still cover it" means an edit to it is still caught. Without
	// this the two clean results above would be equally consistent with a
	// row nobody reads at all.
	if _, err := l.store.DB.ExecContext(ctx,
		`UPDATE events SET tenant_id = 'globex' WHERE id = 'v4-between'`); err != nil {
		t.Fatalf("tamper update: %v", err)
	}
	if _, err := verifyChainPostMigrationStore(ctx, l); !IsChainMismatch(err) {
		t.Errorf("the boot guard did not catch an edit to the in-between row "+
			"(err = %v); a row logged before a late bootstrap has left every "+
			"per-row walk", err)
	}
	legacy, err = l.VerifyLegacy(ctx, CanonicalVersion4, "")
	if err != nil {
		t.Fatalf("VerifyLegacy(4) after the edit: %v", err)
	}
	if !legacy.Tamper || legacy.FirstBadIndex != 0 {
		t.Errorf("VerifyLegacy(4) after an edit to the in-between row = %+v, want "+
			"tamper at index 0", legacy)
	}
}

// TestBootstrapChainV4_ReanchorsAfterTheAnchorIsPruned records a
// consequence of keying on the anchor row rather than on any v4 row, so
// that it is a stated behaviour and not a surprise.
//
// PruneOlderThan deletes by age and the anchor is the oldest v4 row.
// Under the old row count the bootstrap stayed quiet for as long as any
// v4 row survived; now, once retention removes the anchor, the next boot
// emits a new one. That is at most one anchor per retention window, each
// linked into the chain through Log, and the chain must verify across
// it.
func TestBootstrapChainV4_ReanchorsAfterTheAnchorIsPruned(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

	if _, err := l.BootstrapChainV4(ctx, base, "v4-anchor"); err != nil {
		t.Fatalf("BootstrapChainV4: %v", err)
	}
	for i, id := range []string{"a", "b", "c"} {
		if _, err := l.Log(ctx, tenantEvent(id, base.Add(time.Duration(i+1)*time.Hour), "acme")); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	// Retention takes the anchor and row "a"; "b" and "c" survive.
	n, err := l.PruneOlderThan(ctx, base.Add(90*time.Minute))
	if err != nil {
		t.Fatalf("PruneOlderThan: %v", err)
	}
	if n != 2 {
		t.Fatalf("pruned %d rows, want 2 (the anchor and row a)", n)
	}
	mustHaveChainRestartV4(t, l, false, "anchor pruned, v4 rows surviving")

	emitted, err := l.BootstrapChainV4(ctx, base.Add(24*time.Hour), "v4-anchor-2")
	if err != nil {
		t.Fatalf("BootstrapChainV4 after the prune: %v", err)
	}
	if !emitted {
		t.Fatal("no anchor was emitted on a DB whose v4 anchor has been pruned")
	}
	if n := countV4Anchors(t, l); n != 1 {
		t.Errorf("v4 anchors = %d, want exactly 1", n)
	}
	if _, err := l.Log(ctx, tenantEvent("d", base.Add(25*time.Hour), "acme")); err != nil {
		t.Fatalf("Log d: %v", err)
	}

	if res, err := l.Verify(ctx); err != nil || res.Tamper {
		t.Errorf("Verify after re-anchoring = %+v, %v; want a clean walk", res, err)
	}
	if _, err := verifyChainPostMigrationStore(ctx, l); err != nil {
		t.Errorf("the boot guard rejects the re-anchored chain: %v", err)
	}
}
