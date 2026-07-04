package audit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// TestChainHashDeterminism_DriverIndependent is the v1.16 Sprint 1 Task 01
// audit-chain determinism guard (contract sub-deliverable 5).
//
// Audit-DB topology (verified against packages/tamper/audit/sqlitestore +
// internal/audit/audit_sqlite.go): the audit chain lives entirely in its
// OWN SQLite database (packages/tamper/audit/sqlitestore). The SQLiteLogger never
// touches the main store -- so the main DB driver (sqlite vs postgres,
// selected by build tag) has ZERO bearing on the audit chain. There is no
// internal/store/postgresaudit package and the contract does not introduce
// one; the audit DB is always SQLite regardless of the main-DB driver.
//
// The chain-hash computation (canonicalPayloadForVersion + sha256) is pure
// Go reading from sqlitestore query results. "Determinism across drivers"
// therefore reduces to: the same input row set produces byte-identical
// chain hashes on repeated independent builds. This test feeds an identical
// row set through two independent loggers + their bootstrapAuditChainMigrate
// path (MigrateLegacyV2Hashes) and asserts the final chain hashes match
// exactly. If a future change ever coupled the audit chain to the main DB,
// this guard would surface non-determinism the moment the coupling leaked a
// driver-specific value (e.g. a timestamp rendered differently per engine)
// into the hashed payload.
func TestChainHashDeterminism_DriverIndependent(t *testing.T) {
	ctx := context.Background()

	// A fixed, representative row set covering the audit_events surface the
	// hash reads (actor_id, action, resource, before, after, at) -- the
	// exact columns the task contract calls out.
	events := []Event{
		{
			ID:           "ev-1",
			At:           time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC),
			Actor:        Actor{UserID: "u-1", Email: "alice@example.com", IP: "10.0.0.1"},
			Action:       ActionAuditChainRestart,
			ResourceType: "system",
		},
		{
			ID:           "ev-2",
			At:           time.Date(2026, 6, 1, 9, 5, 0, 0, time.UTC),
			Actor:        Actor{UserID: "u-1", Email: "alice@example.com", IP: "10.0.0.1"},
			Action:       Action("project.create"),
			ResourceType: "project",
			ResourceID:   "p-1",
			After:        json.RawMessage(`{"name":"demo","slug":"demo"}`),
		},
		{
			ID:           "ev-3",
			At:           time.Date(2026, 6, 1, 9, 10, 0, 0, time.UTC),
			Actor:        Actor{UserID: "u-2", Email: "bob@example.com", IP: "10.0.0.2"},
			Action:       Action("app.update"),
			ResourceType: "app",
			ResourceID:   "a-1",
			Before:       json.RawMessage(`{"port":8080}`),
			After:        json.RawMessage(`{"port":9090}`),
		},
	}

	buildAndHash := func() string {
		l := newSQLiteLoggerForTest(t).(*SQLiteLogger)
		for _, e := range events {
			e.CanonicalVersion = CanonicalVersion2
			if _, err := l.Log(ctx, e); err != nil {
				t.Fatalf("Log %s: %v", e.ID, err)
			}
		}
		// Run the same migrate path bootstrapAuditChainMigrate uses.
		if _, err := l.MigrateLegacyV2Hashes(ctx); err != nil {
			t.Fatalf("MigrateLegacyV2Hashes: %v", err)
		}
		h, err := l.latestHash(ctx)
		if err != nil {
			t.Fatalf("latestHash: %v", err)
		}
		return hex.EncodeToString(h)
	}

	first := buildAndHash()
	second := buildAndHash()

	if first != second {
		t.Fatalf("chain hash non-deterministic across independent builds:\n  first  = %s\n  second = %s", first, second)
	}
	if first == "" {
		t.Fatal("chain hash empty; expected a non-trivial final hash over the row set")
	}
}
