package audit

import (
	"context"
	"encoding/hex"
	"testing"
	"time"
)

// TestMigrateLegacyV2Hashes_UsersWalkScenario reproduces the v1.5 Step
// 81 walk scenario: 6 v=2 rows in (at,id) order matching what the
// user's dump showed — 5 fixture rows at April 2026 + 1 bootstrap row
// at May 2026. Goal: verify the migration produces a clean chain that
// VerifyLegacy(2) walks cleanly.
func TestMigrateLegacyV2Hashes_UsersWalkScenario(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Seed in INSERTION order (not at-order): bootstrap first (like
	// v1.2 boot), then fixture rows (like v1.3 walk Step 66).
	fixtureAt := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	bootstrapAt := time.Date(2026, 5, 19, 15, 55, 57, 699202473, time.UTC)

	bootstrap := Event{
		ID:               "3fe6a66d-3445-48b1-8abe-c41a34935be1",
		At:               bootstrapAt,
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainRestart,
		ResourceType:     "system",
		CanonicalVersion: CanonicalVersion2,
	}
	v2Restart := Event{
		ID:               "v2-restart",
		At:               fixtureAt,
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainRestart,
		ResourceType:     "system",
		CanonicalVersion: CanonicalVersion2,
	}
	evt002 := Event{
		ID:               "evt-002",
		At:               fixtureAt.Add(1 * time.Minute),
		Actor:            Actor{Type: ActorTypeUser, Name: "alice"},
		Action:           "auth.login",
		ResourceType:     "",
		CanonicalVersion: CanonicalVersion2,
	}
	evt003 := Event{
		ID:               "evt-003",
		At:               fixtureAt.Add(2 * time.Minute),
		Actor:            Actor{Type: ActorTypeUser, Name: "alice"},
		Action:           "app.create",
		ResourceType:     "",
		CanonicalVersion: CanonicalVersion2,
	}
	evt004 := Event{
		ID:               "evt-004",
		At:               fixtureAt.Add(3 * time.Minute),
		Actor:            Actor{Type: ActorTypeServiceAccount, Name: "scim-provisioner"},
		Action:           "group.create",
		ResourceType:     "",
		CanonicalVersion: CanonicalVersion2,
	}
	evt005 := Event{
		ID:               "evt-005",
		At:               fixtureAt.Add(4 * time.Minute),
		Actor:            Actor{Type: ActorTypeUser, Name: "alice"},
		Action:           "deployment.create",
		ResourceType:     ResourceDeployment,
		CanonicalVersion: CanonicalVersion2,
	}

	// Seed each row via Logger.Log — mimics how the v1.3 fixture loader
	// inserted these rows. Each Log() call grabs latestHash() so the
	// rows chain in insertion order, not in (at,id) order.
	for i, e := range []Event{bootstrap, v2Restart, evt002, evt003, evt004, evt005} {
		if _, err := l.Log(ctx, e); err != nil {
			t.Fatalf("seed row %d (id=%s): %v", i, e.ID, err)
		}
	}

	// Run the migration.
	result, err := l.MigrateLegacyV2Hashes(ctx)
	if err != nil {
		t.Fatalf("MigrateLegacyV2Hashes: %v", err)
	}
	t.Logf("RowsScanned=%d RowsUpdated=%d", result.RowsScanned, result.RowsUpdated)
	if result.RowsScanned != 6 {
		t.Errorf("RowsScanned = %d, want 6", result.RowsScanned)
	}

	// Dump rows in (at,id) order.
	rows, err := l.store.Queries.ListEventsByCanonicalVersion(ctx, int64(CanonicalVersion2))
	if err != nil {
		t.Fatalf("ListEventsByCanonicalVersion: %v", err)
	}
	for i, r := range rows {
		t.Logf("[%d] id=%-40s at=%s prev=%s hash=%s",
			i, r.ID, r.At.Format(time.RFC3339Nano),
			hex.EncodeToString(r.PrevHash)[:16],
			hex.EncodeToString(r.Hash)[:16])
	}

	// Verify post-migration.
	res, err := l.VerifyLegacy(ctx, CanonicalVersion2, "")
	if err != nil {
		t.Fatalf("VerifyLegacy post-migration: %v", err)
	}
	if res.Tamper {
		t.Errorf("VerifyLegacy reports tamper at index %d after migration (Total=%d)",
			res.FirstBadIndex, res.Total)
	}
	if res.Total != 6 {
		t.Errorf("Total = %d, want 6", res.Total)
	}
}
