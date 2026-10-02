package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// Verify hashes each row under its OWN canonical_version.
//
// These tests exist because Verify used to do something else on the
// anchored path — it took the newest chain-restart anchor's version and
// applied it to every later row — and every one of the chains below
// read as TAMPER although no row had been touched. Each test builds a
// chain that mixes versions behind one anchor, in an order a real
// deployment can produce, and asserts two things: the untouched chain
// verifies clean, and a real edit is still caught.

// openAt opens the audit DB at path with tenancy on or off. Reopening
// one path with different options is the whole point of these tests: it
// is how a deployment changes its mind between boots, and how two
// replicas on different configs share one DB.
func openAt(t *testing.T, path string, tenancy bool) *SQLiteLogger {
	t.Helper()
	l, err := NewSQLiteLogger(path, SQLiteLoggerOptions{Tenancy: tenancy})
	if err != nil {
		t.Fatalf("NewSQLiteLogger(tenancy=%v): %v", tenancy, err)
	}
	sl, ok := l.(*SQLiteLogger)
	if !ok {
		t.Fatalf("NewSQLiteLogger returned %T", l)
	}
	return sl
}

// mustLog appends one ordinary event and returns it as stored.
func mustLog(t *testing.T, l *SQLiteLogger, id string, at time.Time) Event {
	t.Helper()
	e, err := l.Log(context.Background(), tenantEvent(id, at, "acme"))
	if err != nil {
		t.Fatalf("Log(%s): %v", id, err)
	}
	return e
}

// mustAnchor appends a chain-restart anchor at the given version, the
// way an application's boot bootstrap does.
func mustAnchor(t *testing.T, l *SQLiteLogger, id string, at time.Time, version int) {
	t.Helper()
	if _, err := l.Log(context.Background(), Event{
		ID:               id,
		At:               at,
		Actor:            ActorSystem("audit"),
		Action:           ActionAuditChainRestart,
		ResourceType:     ResourceType("audit_chain"),
		ResourceID:       "restart",
		CanonicalVersion: version,
	}); err != nil {
		t.Fatalf("emit v%d anchor %s: %v", version, id, err)
	}
}

// requireClean asserts Verify walked `total` rows and found no tamper,
// and that the boot guard agrees. The total matters as much as the
// verdict: a walk that quietly covered fewer rows would also be "clean".
func requireClean(t *testing.T, l *SQLiteLogger, total int64, what string) {
	t.Helper()
	ctx := context.Background()
	got, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("%s: Verify: %v", what, err)
	}
	if got.Tamper {
		t.Fatalf("%s: Verify reports TAMPER at index %d of %d on a chain nobody touched — "+
			"a row was hashed under a version other than its own", what, got.FirstBadIndex, got.Total)
	}
	if got.Total != total {
		t.Fatalf("%s: Verify walked %d rows, want %d", what, got.Total, total)
	}
	if _, err := VerifyChainPostMigration(ctx, l); err != nil {
		t.Fatalf("%s: boot guard: %v", what, err)
	}
}

// requireTamperAt asserts Verify reports tamper at exactly `index`.
func requireTamperAt(t *testing.T, l *SQLiteLogger, index int64, what string) {
	t.Helper()
	got, err := l.Verify(context.Background())
	if err != nil {
		t.Fatalf("%s: Verify: %v", what, err)
	}
	if !got.Tamper {
		t.Fatalf("%s: Verify is clean (total=%d); the edit went unnoticed", what, got.Total)
	}
	if got.FirstBadIndex != index {
		t.Fatalf("%s: tamper at index %d, want %d", what, got.FirstBadIndex, index)
	}
}

// exec runs one statement straight against the audit DB — the attacker's
// (or the careless operator's) path, bypassing Log.
func exec(t *testing.T, l *SQLiteLogger, query string, args ...any) {
	t.Helper()
	res, err := SQLiteAuditDBForTest(l).ExecContext(context.Background(), query, args...)
	if err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("exec %q touched %d rows, want 1", query, n)
	}
}

// anchoredV3ThenV4 builds the chain TD-16 was reported on: a v3 anchor
// and a v3 row from a deployment before tenancy, then — tenancy switched
// on and NO v4 anchor written — a v4 row.
//
//	0 v3-anchor (v3)   1 v3-row (v3)   2 v4-row (v4)
func anchoredV3ThenV4(t *testing.T) *SQLiteLogger {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	base := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	v3 := openAt(t, path, false)
	mustAnchor(t, v3, "v3-anchor", base, CanonicalVersion3)
	if got := mustLog(t, v3, "v3-row", base.Add(time.Second)); got.CanonicalVersion != CanonicalVersion3 {
		t.Fatalf("fixture: v3-row stored at version %d", got.CanonicalVersion)
	}
	if err := v3.Close(); err != nil {
		t.Fatalf("close v3 logger: %v", err)
	}

	v4 := openAt(t, path, true)
	t.Cleanup(func() { _ = v4.Close() })
	if got := mustLog(t, v4, "v4-row", base.Add(2*time.Second)); got.CanonicalVersion != CanonicalVersion4 {
		t.Fatalf("fixture: v4-row stored at version %d", got.CanonicalVersion)
	}
	return v4
}

// A v4 row behind a v3 anchor, with no v4 anchor anywhere. This is the
// boot sequence that logged before it bootstrapped; under the old
// override it read as tamper at index 2 and nothing could repair it.
func TestVerify_V4RowBehindAnOlderAnchorIsClean(t *testing.T) {
	l := anchoredV3ThenV4(t)
	requireClean(t, l, 3, "v3 anchor, v3 row, v4 row, no v4 anchor")
}

// The same chain must still CATCH an edit. Per-row dispatch is only
// worth having if it does not turn the walk into one that accepts
// anything; each of these is a change to a stored row that Log never
// made.
func TestVerify_StillDetectsEditsInAMixedVersionSegment(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
		args  []any
		index int64
	}{
		{"content of the v4 row", `UPDATE events SET resource_id = 'forged' WHERE id = ?`, []any{"v4-row"}, 2},
		{"content of the v3 row", `UPDATE events SET resource_id = 'forged' WHERE id = ?`, []any{"v3-row"}, 1},
		// The tenant is inside the v4 payload. Moving a row to another
		// customer must break its hash — the reason v4 exists.
		{"tenant of the v4 row", `UPDATE events SET tenant_id = 'globex' WHERE id = ?`, []any{"v4-row"}, 2},
		// The version column itself. A row relabelled to another version
		// is hashed with an encoder it was not written with, so the walk
		// catches the relabel: the column is an input to the check, not a
		// way around it.
		{"v4 row relabelled as v3", `UPDATE events SET canonical_version = 3 WHERE id = ?`, []any{"v4-row"}, 2},
		{"v3 row relabelled as v4", `UPDATE events SET canonical_version = 4 WHERE id = ?`, []any{"v3-row"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := anchoredV3ThenV4(t)
			requireClean(t, l, 3, "before the edit")
			exec(t, l, tc.query, tc.args...)
			requireTamperAt(t, l, tc.index, tc.name)
		})
	}
}

// A v3 row behind a v4 anchor: a rolling deploy, where one replica
// already runs with tenancy and another still writes v3 into the same
// DB, or a deployment that turned tenancy on, off, and on again. The old
// override hashed the v3 row as v4 and reported tamper for good — the
// newest anchor was already v4, so no bootstrap would ever run again.
func TestVerify_V3RowBehindAV4AnchorIsClean(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	base := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	on := openAt(t, path, true)
	if emitted, err := on.BootstrapChainV4(ctx, base, "v4-anchor"); err != nil || !emitted {
		t.Fatalf("BootstrapChainV4: emitted=%v err=%v", emitted, err)
	}
	mustLog(t, on, "v4-first", base.Add(time.Second))
	if err := on.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	off := openAt(t, path, false) // the replica on the old config
	if got := mustLog(t, off, "v3-between", base.Add(2*time.Second)); got.CanonicalVersion != CanonicalVersion3 {
		t.Fatalf("fixture: v3-between stored at version %d", got.CanonicalVersion)
	}
	if err := off.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	again := openAt(t, path, true)
	t.Cleanup(func() { _ = again.Close() })
	mustLog(t, again, "v4-second", base.Add(3*time.Second))

	//	0 v4-anchor (v4)  1 v4-first (v4)  2 v3-between (v3)  3 v4-second (v4)
	requireClean(t, again, 4, "v4 anchor, v4 row, v3 row, v4 row")

	exec(t, again, `UPDATE events SET resource_id = 'forged' WHERE id = ?`, "v3-between")
	requireTamperAt(t, again, 2, "edit to the v3 row behind the v4 anchor")
}

// An older anchor written AFTER the v4 one — an application whose legacy
// boot bootstrap runs after tenancy was switched on. The newest anchor
// is then v3 and every later row is v4; the override read all of them as
// tamper until the next boot wrote a repair anchor.
func TestVerify_OlderAnchorAfterTheV4AnchorIsClean(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	base := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	l := openAt(t, path, true)
	t.Cleanup(func() { _ = l.Close() })
	if emitted, err := l.BootstrapChainV4(ctx, base, "v4-anchor"); err != nil || !emitted {
		t.Fatalf("BootstrapChainV4: emitted=%v err=%v", emitted, err)
	}
	mustAnchor(t, l, "v3-anchor-late", base.Add(time.Second), CanonicalVersion3)
	mustLog(t, l, "v4-after-1", base.Add(2*time.Second))
	mustLog(t, l, "v4-after-2", base.Add(3*time.Second))

	// The walk roots at the newest anchor, which is the late v3 one.
	//	0 v3-anchor-late (v3)  1 v4-after-1 (v4)  2 v4-after-2 (v4)
	requireClean(t, l, 3, "v4 anchor, late v3 anchor, two v4 rows")

	exec(t, l, `UPDATE events SET tenant_id = 'globex' WHERE id = ?`, "v4-after-2")
	requireTamperAt(t, l, 2, "tenant edit behind the late v3 anchor")
}

// The limit Verify's doc comment names, pinned so that nobody reads a
// clean result as more than it is.
//
// Before per-row dispatch, a v3 row behind a v4 anchor read as tamper —
// a false alarm, but also the only thing that pointed at a row whose
// tenant is not in its hash. That signal is gone, by design: Verify
// reports edits, not rows it would have preferred at another version.
// What remains true is what was always true of a v3 row: its tenant
// can be rewritten and its hash does not notice. A v4 row in the same
// chain is protected, which the last assertion shows.
//
// If this test starts failing because the tenant edit IS caught, the
// limit has been closed: update Verify's doc comment and delete this.
func TestVerify_KnownLimit_V3RowTenantIsNotHashed(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	base := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	on := openAt(t, path, true)
	if emitted, err := on.BootstrapChainV4(ctx, base, "v4-anchor"); err != nil || !emitted {
		t.Fatalf("BootstrapChainV4: emitted=%v err=%v", emitted, err)
	}
	mustLog(t, on, "v4-row", base.Add(time.Second))
	if err := on.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	off := openAt(t, path, false)
	t.Cleanup(func() { _ = off.Close() })
	mustLog(t, off, "v3-row", base.Add(2*time.Second))
	requireClean(t, off, 3, "v4 anchor, v4 row, v3 row")

	exec(t, off, `UPDATE events SET tenant_id = 'globex' WHERE id = ?`, "v3-row")
	requireClean(t, off, 3, "after moving the v3 row to another tenant")

	exec(t, off, `UPDATE events SET tenant_id = 'globex' WHERE id = ?`, "v4-row")
	requireTamperAt(t, off, 1, "moving the v4 row to another tenant")
}
