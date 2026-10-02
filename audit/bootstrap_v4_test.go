package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TD-16 — when BootstrapChainV4 writes the v4 anchor.
//
// The decision used to be "is there any v4 row?". One ordinary v4 row
// logged before the bootstrap was enough to make it say the anchor was
// there, and from then on the bootstrap refused to write the anchor it
// was the only way to write. It is now taken from the NEWEST
// chain-restart anchor, in three steps (see needsChainRestartV4), and
// each test below holds one of them in place:
//
//   - newest anchor is v4 → skip
//     (TestV4_BootstrapIsIdempotentAndGated, and the closing calls of the
//     two repair tests here);
//   - newest anchor is older → emit
//     (TestBootstrapChainV4_LateOnAnAnchoredV3DB,
//     TestBootstrapChainV4_ReanchorsWhenAnOlderAnchorLandsAfterIt);
//   - no anchor at all → emit only while there is no v4 row
//     (TestBootstrapChainV4_SkipsOnAnUnanchoredDBWithV4Rows,
//     TestBootstrapChainV4_DoesNotReanchorAfterTheAnchorIsPruned).
//
// Each step has a tempting simplification, and each simplification turns
// one of these red: the old row count fails both repair tests; "some v4
// anchor exists → skip" fails the second of them; "no v4 anchor → emit"
// fails the two no-anchor tests.

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

// v3AnchorEvent is the chain-restart row an application's own (pre-v4)
// boot bootstrap emits: the reserved action at an explicit
// canonical_version=3.
func v3AnchorEvent(id string, at time.Time) Event {
	return Event{
		ID:               id,
		At:               at,
		Actor:            ActorSystem("audit"),
		Action:           ActionAuditChainRestart,
		ResourceType:     ResourceType("audit_chain"),
		ResourceID:       "v3",
		CanonicalVersion: CanonicalVersion3,
	}
}

// TestHasChainRestartV4_CountsAnchorsNotRows is the predicate on its
// own, through the three states that matter: nothing, ordinary v4 rows
// with no anchor, and the anchor.
//
// The middle state is where it used to lie. An empty DB and an anchored
// DB were answered correctly by the old row count too, which is why the
// flaw survived every test that bootstrapped first.
func TestHasChainRestartV4_CountsAnchorsNotRows(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

	t.Run("ordinary v4 rows are not an anchor", func(t *testing.T) {
		l := v4Logger(t)
		mustHaveChainRestartV4(t, l, false, "empty DB")

		for i, id := range []string{"v4-a", "v4-b"} {
			got, err := l.Log(ctx, tenantEvent(id, base.Add(time.Duration(i)*time.Second), "acme"))
			if err != nil {
				t.Fatalf("Log %s: %v", id, err)
			}
			if got.CanonicalVersion != CanonicalVersion4 {
				t.Fatalf("row %s landed at v%d, want v4 — the fixture is not "+
					"exercising the case under test", id, got.CanonicalVersion)
			}
		}
		got, err := l.HasChainRestartV4(ctx)
		if err != nil {
			t.Fatalf("HasChainRestartV4 (ordinary v4 rows, no anchor): %v", err)
		}
		if got {
			t.Fatal("HasChainRestartV4 = true on a DB holding ordinary v4 rows and " +
				"NO anchor; it is counting rows at the version rather than anchors")
		}
	})

	t.Run("the anchor is", func(t *testing.T) {
		l := v4Logger(t)
		emitted, err := l.BootstrapChainV4(ctx, base, "v4-anchor")
		if err != nil || !emitted {
			t.Fatalf("BootstrapChainV4 on a fresh DB = (%v, %v), want (true, nil)", emitted, err)
		}
		mustHaveChainRestartV4(t, l, true, "after the bootstrap")
	})
}

// TestHasChainRestartV4_IgnoresAnchorsAtOtherVersions: the predicate is
// action AND version. A v3 chain-restart row is an anchor, but it is not
// the v4 one — and it is exactly the row an existing deployment already
// has when it first switches Tenancy on.
func TestHasChainRestartV4_IgnoresAnchorsAtOtherVersions(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

	if _, err := l.Log(ctx, v3AnchorEvent("v3-anchor", base)); err != nil {
		t.Fatalf("emit v3 anchor: %v", err)
	}
	mustHaveChainRestartV4(t, l, false, "v3 anchor only")
}

// TestBootstrapChainV4_SkipsOnAnUnanchoredDBWithV4Rows is step 3 with a
// v4 row present: no anchor of any version, and the application logged
// before it bootstrapped.
//
// Nothing is broken on this DB. With no anchor, Verify walks every row
// under that row's own version and is clean. An anchor written late
// would not repair anything — there is no older anchor's encoder to
// override — and would move Verify's walk root past the rows already
// logged. So the bootstrap leaves it alone, which is also what it did
// before TD-16; HasChainRestartV4 is honestly false here, and "no v4
// anchor" on its own must not be read as "write one".
func TestBootstrapChainV4_SkipsOnAnUnanchoredDBWithV4Rows(t *testing.T) {
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
	if emitted {
		t.Error("BootstrapChainV4 emitted an anchor onto a DB with v4 rows and no " +
			"anchor of any version; Verify already walks every row there, and the " +
			"new walk root hides the rows logged before it")
	}
	if n := countV4Anchors(t, l); n != 0 {
		t.Errorf("v4 anchors = %d, want 0", n)
	}
	mustHaveChainRestartV4(t, l, false, "after the skipped bootstrap")

	if _, err := l.Log(ctx, tenantEvent("later", base.Add(2*time.Second), "acme")); err != nil {
		t.Fatalf("Log later: %v", err)
	}
	res, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Tamper {
		t.Errorf("Verify reports tamper on an unanchored v4 chain: %+v", res)
	}
	if res.Total != 2 {
		t.Errorf("Verify walked %d rows, want 2 — every row on the DB, the early "+
			"one included", res.Total)
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
	if _, err := a3.Log(ctx, v3AnchorEvent("v3-anchor", base)); err != nil {
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
	mustHaveChainRestartV4(t, l, true, "after the late bootstrap")
	for i, id := range []string{"v4-after-a", "v4-after-b"} {
		if _, err := l.Log(ctx, tenantEvent(id, base.Add(time.Duration(4+i)*time.Second), "acme")); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	// And it is a repair, not a habit: the next boot finds the newest
	// anchor at v4 and writes nothing.
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
	// walks that hash each row under its own canonical_version still
	// cover it, and both find it intact:
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

// TestBootstrapChainV4_ReanchorsWhenAnOlderAnchorLandsAfterIt is why
// step 1 reads the NEWEST anchor instead of asking HasChainRestartV4.
//
// The bootstraps ran in the wrong order: the v4 anchor went in first,
// and an application's legacy boot bootstrap — which knows nothing about
// v4 — then emitted its v3 chain-restart row on top of it. The newest
// anchor is now v3, so Verify re-hashes every later v4 row as v3 and
// reports tamper. A v4 anchor exists the whole time; "a v4 anchor exists
// → skip" would look at this DB on every boot and decide it was done.
func TestBootstrapChainV4_ReanchorsWhenAnOlderAnchorLandsAfterIt(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

	first, err := l.BootstrapChainV4(ctx, base, "v4-anchor")
	if err != nil || !first {
		t.Fatalf("first bootstrap = (%v, %v), want (true, nil)", first, err)
	}
	if _, err := l.Log(ctx, v3AnchorEvent("v3-anchor", base.Add(time.Second))); err != nil {
		t.Fatalf("emit v3 anchor: %v", err)
	}
	row, err := l.Log(ctx, tenantEvent("v4-row", base.Add(2*time.Second), "acme"))
	if err != nil {
		t.Fatalf("Log v4-row: %v", err)
	}
	if row.CanonicalVersion != CanonicalVersion4 {
		t.Fatalf("v4-row landed at v%d, want v4", row.CanonicalVersion)
	}

	// The damage, asserted for the same reason as in the test above: the
	// walk is rooted at the v3 anchor (index 0) and the v4 row behind it
	// (index 1) is hashed under v3.
	damaged, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify (before the repair): %v", err)
	}
	if !damaged.Tamper || damaged.FirstBadIndex != 1 {
		t.Fatalf("Verify before the repair = %+v, want tamper at index 1 (the v4 "+
			"row re-hashed under the later v3 anchor's encoder); the fixture is "+
			"not in the state this test describes", damaged)
	}
	// A v4 anchor IS on the table. That is the whole trap.
	mustHaveChainRestartV4(t, l, true, "v4 anchor behind a newer v3 anchor")

	second, err := l.BootstrapChainV4(ctx, base.Add(3*time.Second), "v4-anchor-2")
	if err != nil {
		t.Fatalf("second BootstrapChainV4: %v", err)
	}
	if !second {
		t.Fatal("the bootstrap skipped because a v4 anchor exists, though a v3 " +
			"anchor was written after it; Verify reports tamper on every v4 row " +
			"from here on and no later boot will repair it")
	}
	for i, id := range []string{"v4-after-a", "v4-after-b"} {
		if _, err := l.Log(ctx, tenantEvent(id, base.Add(time.Duration(4+i)*time.Second), "acme")); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	res, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify (after the repair): %v", err)
	}
	if res.Tamper {
		t.Fatalf("Verify still reports tamper after the repair: %+v", res)
	}
	if res.Total != 3 {
		t.Errorf("Verify walked %d rows, want 3 (the second v4 anchor and the two "+
			"rows after it)", res.Total)
	}
	if _, err := verifyChainPostMigrationStore(ctx, l); err != nil {
		t.Errorf("the boot guard rejects the repaired chain: %v", err)
	}

	third, err := l.BootstrapChainV4(ctx, base.Add(time.Hour), "v4-anchor-3")
	if err != nil {
		t.Fatalf("third BootstrapChainV4: %v", err)
	}
	if third {
		t.Error("a third bootstrap emitted again with the newest anchor already " +
			"at v4; every restart would add a chain segment")
	}
	if n := countV4Anchors(t, l); n != 2 {
		t.Errorf("v4 anchors = %d, want 2 (the original and the repair)", n)
	}
}

// TestBootstrapChainV4_DoesNotReanchorAfterTheAnchorIsPruned is step 3
// on the DB retention produces. PruneOlderThan deletes by age and the
// anchor is the oldest v4 row, so sooner or later it goes — and with it
// the last anchor of any version.
//
// That is not a chain in need of an anchor. With none left, Verify walks
// EVERY surviving row under that row's own version, which is the widest
// coverage it has. A fresh anchor on the next boot would move the walk
// root to "now" and drop every surviving row before it out of Verify,
// once per retention window: tamper detection given away to restore a
// row nothing was missing.
func TestBootstrapChainV4_DoesNotReanchorAfterTheAnchorIsPruned(t *testing.T) {
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
	// The predicate stays truthful: there is no v4 anchor any more. It is
	// the bootstrap that must not act on that alone.
	mustHaveChainRestartV4(t, l, false, "anchor pruned, v4 rows surviving")

	emitted, err := l.BootstrapChainV4(ctx, base.Add(24*time.Hour), "v4-anchor-2")
	if err != nil {
		t.Fatalf("BootstrapChainV4 after the prune: %v", err)
	}
	if emitted {
		t.Error("the bootstrap re-anchored a chain whose anchor was pruned; the new " +
			"walk root hides every surviving row before it from Verify, and it " +
			"will do so again each retention window")
	}
	if n := countV4Anchors(t, l); n != 0 {
		t.Errorf("v4 anchors = %d, want 0 — a new anchor row appeared", n)
	}
	if _, err := l.Log(ctx, tenantEvent("d", base.Add(25*time.Hour), "acme")); err != nil {
		t.Fatalf("Log d: %v", err)
	}

	res, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify after the prune: %v", err)
	}
	if res.Tamper {
		t.Errorf("Verify reports tamper on the pruned chain: %+v", res)
	}
	if res.Total != 3 {
		t.Errorf("Verify walked %d rows, want 3 — every surviving row (b, c, d)", res.Total)
	}
	if _, err := verifyChainPostMigrationStore(ctx, l); err != nil {
		t.Errorf("the boot guard rejects the pruned chain: %v", err)
	}
}
