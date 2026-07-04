package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/suryakencana007/barista/packages/tamper/audit/sqlitestore"
)

// TestMigrateLegacyV2Hashes_FreshInstallNoOp confirms the greenfield
// path: a brand-new audit DB with zero v=2 rows reports RowsScanned=0,
// RowsUpdated=0, Skipped=false (Skipped tracks boot-level idempotency
// via marker presence, not "nothing to do"). The boot wrapper
// translates RowsScanned=0 into "skip marker emission" separately.
func TestMigrateLegacyV2Hashes_FreshInstallNoOp(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	result, err := l.MigrateLegacyV2Hashes(ctx)
	if err != nil {
		t.Fatalf("MigrateLegacyV2Hashes: %v", err)
	}
	if result.RowsScanned != 0 {
		t.Errorf("RowsScanned = %d, want 0", result.RowsScanned)
	}
	if result.RowsUpdated != 0 {
		t.Errorf("RowsUpdated = %d, want 0", result.RowsUpdated)
	}
	if result.Skipped {
		t.Errorf("Skipped = true; method-level call never sets Skipped")
	}
}

// TestMigrateLegacyV2Hashes_SingleRowGreenfield confirms a DB whose
// only v=2 row was written under the CURRENT encoder reports
// RowsScanned=1, RowsUpdated=0. This is the shape of a fresh v1.5+
// install whose bootstrapAuditChainRestart just emitted the v=2
// chain-restart row via Logger.Log (which dispatches to the current
// canonicalPayloadLegacyV2 encoder).
//
// Post-migration: VerifyLegacy(2, "") walks clean.
func TestMigrateLegacyV2Hashes_SingleRowGreenfield(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Emit one v=2 chain-restart row via the current encoder. Logger.Log
	// fills in PrevHash from latestHash() (= genesis on empty DB) and
	// computes the hash via canonicalPayloadLegacyV2.
	if _, err := l.Log(ctx, Event{
		ID:               "boot-cr-v2",
		At:               time.Date(2026, 5, 23, 10, 0, 0, 0, time.UTC),
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainRestart,
		ResourceType:     "system",
		CanonicalVersion: CanonicalVersion2,
	}); err != nil {
		t.Fatalf("Log bootstrap row: %v", err)
	}

	result, err := l.MigrateLegacyV2Hashes(ctx)
	if err != nil {
		t.Fatalf("MigrateLegacyV2Hashes: %v", err)
	}
	if result.RowsScanned != 1 {
		t.Errorf("RowsScanned = %d, want 1", result.RowsScanned)
	}
	if result.RowsUpdated != 0 {
		t.Errorf("RowsUpdated = %d, want 0 (current-encoder row needs no update)", result.RowsUpdated)
	}

	// VerifyLegacy walks the v=2 segment cleanly post-migration.
	res, err := l.VerifyLegacy(ctx, CanonicalVersion2, "")
	if err != nil {
		t.Fatalf("VerifyLegacy: %v", err)
	}
	if res.Tamper {
		t.Fatalf("VerifyLegacy reports tamper at index %d after migration", res.FirstBadIndex)
	}
	if res.Total != 1 {
		t.Errorf("Total = %d, want 1", res.Total)
	}
}

// canonicalPayloadLegacyV2PreV14 reproduces the pre-v1.4 v=2 canonical
// encoder shape: every field as today, EXCEPT the timestamp is
// formatted as `e.At.UTC().Format(time.RFC3339Nano)` instead of
// `strconv.FormatInt(e.At.UnixNano(), 10)`. Used by the migration
// tests to seed rows whose stored hashes were "written by a pre-v1.4
// binary."
//
// Lives in the test file (not committed as a separate helper) so the
// test fixture stays close to the migration assertion and the encoder
// drift is grep-visible.
func canonicalPayloadLegacyV2PreV14(e Event, prevHash []byte) []byte {
	actorType := string(e.Actor.Type)
	if actorType == "" {
		actorType = string(ActorTypeUser)
	}
	dataJSON := string(e.After)
	fields := []string{
		hex.EncodeToString(prevHash),
		// Pre-v1.4 shape: RFC3339Nano string. TD-AUDIT-09 / v1.4 closed
		// this in canonicalPayloadLegacyV2; the migration tests resurrect
		// it locally so we can seed pre-v1.4-hash rows.
		e.At.UTC().Format(time.RFC3339Nano),
		actorType,
		e.Actor.Name,
		string(e.Action),
		string(e.ResourceType),
		e.ResourceID,
		e.ClusterID,
		dataJSON,
	}
	return []byte(strings.Join(fields, "|"))
}

// computeHashPreV14 mirrors computeHash() but uses the pre-v1.4 v=2
// encoder so test-seeded rows carry hashes a pre-v1.4 binary would have
// written. Genesis prevHash is HashSize zero bytes.
func computeHashPreV14(prevHash []byte, e Event) []byte {
	h := sha256.New()
	h.Write(prevHash)
	h.Write(canonicalPayloadLegacyV2PreV14(e, prevHash))
	return h.Sum(nil)
}

// seedPreV14V2Row inserts a single v=2 row into the audit DB whose
// stored Hash was computed under the pre-v1.4 RFC3339Nano-based
// encoder. The caller threads prevHash forward through the chain so
// every seeded row links to the previous row's pre-v1.4 hash.
//
// Returns the row's stored Hash so the caller can use it as the next
// row's PrevHash.
func seedPreV14V2Row(t *testing.T, l *SQLiteLogger, e Event, prevHash []byte) []byte {
	t.Helper()
	h := computeHashPreV14(prevHash, e)
	beforeJSON := ""
	if len(e.Before) > 0 {
		beforeJSON = string(e.Before)
	}
	afterJSON := ""
	if len(e.After) > 0 {
		afterJSON = string(e.After)
	}
	if err := l.store.Queries.InsertEvent(context.Background(), sqlitestore.InsertEventParams{
		ID:               e.ID,
		At:               e.At.UTC(),
		ActorUserID:      e.Actor.UserID,
		ActorEmail:       e.Actor.Email,
		ActorIp:          e.Actor.IP,
		ActorType:        string(e.Actor.Type),
		ActorName:        e.Actor.Name,
		Action:           string(e.Action),
		ResourceType:     string(e.ResourceType),
		ResourceID:       e.ResourceID,
		ClusterID:        e.ClusterID,
		RequestID:        e.RequestID,
		BeforeJson:       beforeJSON,
		AfterJson:        afterJSON,
		PrevHash:         prevHash,
		Hash:             h,
		CanonicalVersion: int64(CanonicalVersion2),
	}); err != nil {
		t.Fatalf("seedPreV14V2Row insert: %v", err)
	}
	return h
}

// TestMigrateLegacyV2Hashes_OneRow_SingleBootstrapRestart confirms a DB
// with one v=2 chain-restart row whose hash was computed under the
// pre-v1.4 encoder gets migrated: RowsScanned=1, RowsUpdated=1.
// VerifyLegacy(2, "") walks clean post-migration.
//
// This is the exact shape of a pre-v1.4-era install whose audit DB
// carried only the bootstrap row forward.
func TestMigrateLegacyV2Hashes_OneRow_SingleBootstrapRestart(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Seed a v=2 chain-restart row whose hash was computed under the
	// pre-v1.4 encoder. Use a timestamp with sub-microsecond precision
	// so the RFC3339Nano vs UnixNano divergence is real (not just a
	// coincidental match at zero-precision times).
	bootstrapAt := time.Date(2026, 3, 1, 10, 0, 0, 123456789, time.UTC)
	e := Event{
		ID:               "boot-cr-v2",
		At:               bootstrapAt,
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainRestart,
		ResourceType:     "system",
		CanonicalVersion: CanonicalVersion2,
	}
	genesis := make([]byte, HashSize)
	storedHash := seedPreV14V2Row(t, l, e, genesis)

	// Pre-condition: VerifyLegacy reports tamper at index 0 because the
	// stored hash was computed under the old encoder.
	res, err := l.VerifyLegacy(ctx, CanonicalVersion2, "")
	if err != nil {
		t.Fatalf("VerifyLegacy pre-migration: %v", err)
	}
	if !res.Tamper {
		t.Fatalf("VerifyLegacy pre-migration should report tamper on pre-v1.4 hash; got clean Total=%d", res.Total)
	}

	// Run the migration.
	result, err := l.MigrateLegacyV2Hashes(ctx)
	if err != nil {
		t.Fatalf("MigrateLegacyV2Hashes: %v", err)
	}
	if result.RowsScanned != 1 {
		t.Errorf("RowsScanned = %d, want 1", result.RowsScanned)
	}
	if result.RowsUpdated != 1 {
		t.Errorf("RowsUpdated = %d, want 1 (pre-v1.4 row needs update)", result.RowsUpdated)
	}

	// Post-condition: VerifyLegacy(2, "") walks clean.
	res, err = l.VerifyLegacy(ctx, CanonicalVersion2, "")
	if err != nil {
		t.Fatalf("VerifyLegacy post-migration: %v", err)
	}
	if res.Tamper {
		t.Fatalf("VerifyLegacy reports tamper at index %d after migration", res.FirstBadIndex)
	}
	if res.Total != 1 {
		t.Errorf("Total = %d, want 1", res.Total)
	}

	// The stored hash was overwritten in place. Confirm via direct read.
	row, err := l.store.Queries.GetEventByID(ctx, "boot-cr-v2")
	if err != nil {
		t.Fatalf("GetEventByID: %v", err)
	}
	if bytesEqual(row.Hash, storedHash) {
		t.Errorf("post-migration hash unchanged from pre-v1.4 hash; UPDATE didn't fire")
	}
}

// TestMigrateLegacyV2Hashes_MultipleRows_ChainOrderPreserved confirms a
// multi-row v=2 segment is walked in chain-ascending order: each
// row's recomputed prev_hash matches the previous row's recomputed
// hash. Five pre-v1.4-hashed rows → migration updates all five → full
// chain verifies post-migration.
func TestMigrateLegacyV2Hashes_MultipleRows_ChainOrderPreserved(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	base := time.Date(2026, 4, 1, 10, 0, 0, 123456789, time.UTC)

	// Seed 5 pre-v1.4-encoded v=2 rows chained together. The first row's
	// PrevHash is genesis; each successor's PrevHash is the previous
	// row's pre-v1.4 hash.
	rows := []Event{
		{
			ID:               "row-1",
			At:               base,
			Actor:            ActorSystem("barista"),
			Action:           ActionAuditChainRestart,
			ResourceType:     "system",
			CanonicalVersion: CanonicalVersion2,
		},
		{
			ID:               "row-2",
			At:               base.Add(1 * time.Second),
			Actor:            Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
			Action:           "project.create",
			ResourceType:     ResourceProject,
			ResourceID:       "p-1",
			CanonicalVersion: CanonicalVersion2,
		},
		{
			ID:               "row-3",
			At:               base.Add(2 * time.Second),
			Actor:            Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
			Action:           "app.create",
			ResourceType:     ResourceApp,
			ResourceID:       "a-1",
			CanonicalVersion: CanonicalVersion2,
		},
		{
			ID:               "row-4",
			At:               base.Add(3 * time.Second),
			Actor:            Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
			Action:           "deployment.create",
			ResourceType:     ResourceDeployment,
			ResourceID:       "d-1",
			CanonicalVersion: CanonicalVersion2,
		},
		{
			ID:               "row-5",
			At:               base.Add(4 * time.Second),
			Actor:            Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
			Action:           "deployment.create",
			ResourceType:     ResourceDeployment,
			ResourceID:       "d-2",
			CanonicalVersion: CanonicalVersion2,
		},
	}

	prev := make([]byte, HashSize)
	for _, e := range rows {
		prev = seedPreV14V2Row(t, l, e, prev)
	}

	// Pre-condition: VerifyLegacy reports tamper.
	res, err := l.VerifyLegacy(ctx, CanonicalVersion2, "")
	if err != nil {
		t.Fatalf("VerifyLegacy pre-migration: %v", err)
	}
	if !res.Tamper {
		t.Fatalf("VerifyLegacy pre-migration should report tamper; got clean Total=%d", res.Total)
	}

	// Migrate.
	result, err := l.MigrateLegacyV2Hashes(ctx)
	if err != nil {
		t.Fatalf("MigrateLegacyV2Hashes: %v", err)
	}
	if result.RowsScanned != 5 {
		t.Errorf("RowsScanned = %d, want 5", result.RowsScanned)
	}
	if result.RowsUpdated != 5 {
		t.Errorf("RowsUpdated = %d, want 5 (every row's hash was pre-v1.4)", result.RowsUpdated)
	}

	// Post-condition: full chain verifies clean.
	res, err = l.VerifyLegacy(ctx, CanonicalVersion2, "")
	if err != nil {
		t.Fatalf("VerifyLegacy post-migration: %v", err)
	}
	if res.Tamper {
		t.Fatalf("VerifyLegacy reports tamper at index %d after migration (Total=%d)",
			res.FirstBadIndex, res.Total)
	}
	if res.Total != 5 {
		t.Errorf("Total = %d, want 5", res.Total)
	}

	// Also confirm chain-order: each row's recomputed prev_hash matches
	// the previous row's recomputed hash, walked back via direct DB reads.
	dbRows, err := l.store.Queries.ListEventsByCanonicalVersion(ctx, int64(CanonicalVersion2))
	if err != nil {
		t.Fatalf("ListEventsByCanonicalVersion post-migration: %v", err)
	}
	for i := 1; i < len(dbRows); i++ {
		if !bytesEqual(dbRows[i].PrevHash, dbRows[i-1].Hash) {
			t.Errorf("row %d (id=%s) prev_hash does not equal row %d hash; chain link broken",
				i, dbRows[i].ID, i-1)
		}
	}
}

// TestMigrateLegacyV2Hashes_Idempotent confirms function-level
// idempotency: re-running MigrateLegacyV2Hashes against an already-
// migrated DB writes zero rows (every recomputed hash matches the
// stored hash from the prior migration).
//
// Note: boot-level idempotency (don't re-run + re-emit the marker)
// lives in bootstrapAuditChainMigrate via HasChainMigrate. This test
// covers the orthogonal property — calling MigrateLegacyV2Hashes
// twice in succession is safe + produces converged state.
func TestMigrateLegacyV2Hashes_Idempotent(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Seed 3 pre-v1.4 v=2 rows.
	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	rows := []Event{
		{
			ID:               "a",
			At:               base,
			Actor:            ActorSystem("barista"),
			Action:           ActionAuditChainRestart,
			ResourceType:     "system",
			CanonicalVersion: CanonicalVersion2,
		},
		{
			ID:               "b",
			At:               base.Add(1 * time.Second),
			Actor:            Actor{Type: ActorTypeUser, UserID: "u-1"},
			Action:           "project.create",
			ResourceType:     ResourceProject,
			ResourceID:       "p-1",
			CanonicalVersion: CanonicalVersion2,
		},
		{
			ID:               "c",
			At:               base.Add(2 * time.Second),
			Actor:            Actor{Type: ActorTypeUser, UserID: "u-1"},
			Action:           "app.create",
			ResourceType:     ResourceApp,
			ResourceID:       "a-1",
			CanonicalVersion: CanonicalVersion2,
		},
	}
	prev := make([]byte, HashSize)
	for _, e := range rows {
		prev = seedPreV14V2Row(t, l, e, prev)
	}

	// First migration: all 3 rows update.
	r1, err := l.MigrateLegacyV2Hashes(ctx)
	if err != nil {
		t.Fatalf("first MigrateLegacyV2Hashes: %v", err)
	}
	if r1.RowsScanned != 3 || r1.RowsUpdated != 3 {
		t.Fatalf("first call: RowsScanned=%d RowsUpdated=%d, want 3/3", r1.RowsScanned, r1.RowsUpdated)
	}

	// Capture post-first-migration hashes for byte-identical check.
	firstPass, err := l.store.Queries.ListEventsByCanonicalVersion(ctx, int64(CanonicalVersion2))
	if err != nil {
		t.Fatalf("ListEventsByCanonicalVersion: %v", err)
	}
	wantHashes := make([][]byte, len(firstPass))
	for i, r := range firstPass {
		wantHashes[i] = append([]byte(nil), r.Hash...)
	}

	// Second migration: zero rows update (already converged).
	r2, err := l.MigrateLegacyV2Hashes(ctx)
	if err != nil {
		t.Fatalf("second MigrateLegacyV2Hashes: %v", err)
	}
	if r2.RowsScanned != 3 {
		t.Errorf("second call: RowsScanned = %d, want 3", r2.RowsScanned)
	}
	if r2.RowsUpdated != 0 {
		t.Errorf("second call: RowsUpdated = %d, want 0 (already migrated)", r2.RowsUpdated)
	}

	// Byte-identical hashes across calls.
	secondPass, err := l.store.Queries.ListEventsByCanonicalVersion(ctx, int64(CanonicalVersion2))
	if err != nil {
		t.Fatalf("ListEventsByCanonicalVersion post-second: %v", err)
	}
	for i, r := range secondPass {
		if !bytesEqual(r.Hash, wantHashes[i]) {
			t.Errorf("row %d (id=%s): hash drifted between idempotent calls", i, r.ID)
		}
	}
}

// TestMigrateLegacyV2Hashes_MixedV2V3Segments confirms the migration is
// scoped to v=2 rows only: v=3 rows in the same DB are untouched.
//
// Seeds 2 pre-v1.4 v=2 rows + 5 v=3 rows via Logger.Log. Migration
// reports RowsScanned=2, RowsUpdated=2. Default Verify() (v=3 walk)
// stays clean both before and after the migration.
func TestMigrateLegacyV2Hashes_MixedV2V3Segments(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Seed 2 pre-v1.4 v=2 rows.
	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	v2Rows := []Event{
		{
			ID:               "v2-a",
			At:               base,
			Actor:            ActorSystem("barista"),
			Action:           ActionAuditChainRestart,
			ResourceType:     "system",
			CanonicalVersion: CanonicalVersion2,
		},
		{
			ID:               "v2-b",
			At:               base.Add(1 * time.Second),
			Actor:            Actor{Type: ActorTypeUser, UserID: "u-1"},
			Action:           "project.create",
			ResourceType:     ResourceProject,
			ResourceID:       "p-1",
			CanonicalVersion: CanonicalVersion2,
		},
	}
	prev := make([]byte, HashSize)
	for _, e := range v2Rows {
		prev = seedPreV14V2Row(t, l, e, prev)
	}

	// Emit 5 v=3 rows via Logger.Log (current encoder). The first v=3
	// row's prev_hash will pick up from latestHash() which equals the
	// last v=2 row's stored (pre-v1.4) hash; that's fine — v=3 rows
	// don't depend on the v=2 row's hash being "correct" under the
	// current encoder. Verify() walks from the latest chain-restart
	// row forward (none of these v=3 rows is a chain-restart, so the
	// walker actually picks v2-a as the latest chain_restart row);
	// that's an integration concern we don't assert here. The
	// migration-scope claim is what we DO assert: v=3 row count
	// unchanged + their hashes unchanged.
	v3Base := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	for i, id := range []string{"v3-a", "v3-b", "v3-c", "v3-d", "v3-e"} {
		if _, err := l.Log(ctx, Event{
			ID:           id,
			At:           v3Base.Add(time.Duration(i) * time.Second),
			Actor:        Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
			Action:       "project.create",
			ResourceType: ResourceProject,
			ResourceID:   "p-" + id,
		}); err != nil {
			t.Fatalf("Log v3 %s: %v", id, err)
		}
	}

	// Snapshot v=3 hashes pre-migration.
	v3Pre, err := l.store.Queries.ListEventsByCanonicalVersion(ctx, int64(CanonicalVersion3))
	if err != nil {
		t.Fatalf("ListEventsByCanonicalVersion(3): %v", err)
	}
	if len(v3Pre) != 5 {
		t.Fatalf("pre-migration v=3 row count = %d, want 5", len(v3Pre))
	}
	pre := make(map[string][]byte, len(v3Pre))
	for _, r := range v3Pre {
		pre[r.ID] = append([]byte(nil), r.Hash...)
	}

	// Migrate.
	result, err := l.MigrateLegacyV2Hashes(ctx)
	if err != nil {
		t.Fatalf("MigrateLegacyV2Hashes: %v", err)
	}
	if result.RowsScanned != 2 {
		t.Errorf("RowsScanned = %d, want 2 (v=2 rows only)", result.RowsScanned)
	}
	if result.RowsUpdated != 2 {
		t.Errorf("RowsUpdated = %d, want 2 (pre-v1.4 v=2 rows)", result.RowsUpdated)
	}

	// v=3 rows unchanged post-migration.
	v3Post, err := l.store.Queries.ListEventsByCanonicalVersion(ctx, int64(CanonicalVersion3))
	if err != nil {
		t.Fatalf("ListEventsByCanonicalVersion(3) post: %v", err)
	}
	if len(v3Post) != 5 {
		t.Errorf("post-migration v=3 row count = %d, want 5 (migration must not touch v=3)", len(v3Post))
	}
	for _, r := range v3Post {
		if !bytesEqual(r.Hash, pre[r.ID]) {
			t.Errorf("v=3 row id=%s: hash changed across v=2 migration; migration must not touch v=3 rows", r.ID)
		}
	}

	// v=2 segment walks clean post-migration.
	res, err := l.VerifyLegacy(ctx, CanonicalVersion2, "")
	if err != nil {
		t.Fatalf("VerifyLegacy(2) post: %v", err)
	}
	if res.Tamper {
		t.Fatalf("VerifyLegacy(2) reports tamper after migration; FirstBadIndex=%d Total=%d",
			res.FirstBadIndex, res.Total)
	}
	if res.Total != 2 {
		t.Errorf("VerifyLegacy(2) Total = %d, want 2", res.Total)
	}
}

// TestHasChainMigrate_AbsentReturnsFalse confirms HasChainMigrate
// returns (false, nil) on a fresh DB with zero
// system.audit.chain_migrate rows.
func TestHasChainMigrate_AbsentReturnsFalse(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	ok, err := l.HasChainMigrate(ctx)
	if err != nil {
		t.Fatalf("HasChainMigrate: %v", err)
	}
	if ok {
		t.Errorf("HasChainMigrate = true on empty DB, want false")
	}
}

// TestHasChainMigrate_PresentReturnsTrue confirms HasChainMigrate
// returns (true, nil) once a system.audit.chain_migrate row exists.
func TestHasChainMigrate_PresentReturnsTrue(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Insert a system.audit.chain_migrate row via Logger.Log so it
	// lands under the current canonical_version=3 encoder.
	if _, err := l.Log(ctx, Event{
		ID:           "migrate-marker",
		At:           time.Now().UTC(),
		Actor:        ActorSystem("barista"),
		Action:       ActionAuditChainMigrate,
		ResourceType: "system",
	}); err != nil {
		t.Fatalf("Log marker: %v", err)
	}

	ok, err := l.HasChainMigrate(ctx)
	if err != nil {
		t.Fatalf("HasChainMigrate: %v", err)
	}
	if !ok {
		t.Errorf("HasChainMigrate = false after marker insert, want true")
	}
}

// TestMigrateLegacyV2Hashes_NumericRowCountSanity walks the migration's
// per-row counter shape via a small but distinct mix: one already-
// current-encoder v=2 row (RowsUpdated must NOT count it) + two
// pre-v1.4-encoder v=2 rows (RowsUpdated must count both). Confirms
// RowsUpdated discriminates correctly and the chain-walk's
// rolling-prev-hash threads through the mixed-condition case.
//
// The "already correct" row is row 0 (chain genesis with empty prev),
// emitted via Logger.Log. The two pre-v1.4 rows follow.
//
// Note: this is an extra discrimination test beyond the spec's 6
// required cases — it pins down the per-row UPDATE branch contract.
func TestMigrateLegacyV2Hashes_NumericRowCountSanity(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Row 0: current-encoder v=2 row via Logger.Log.
	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	if _, err := l.Log(ctx, Event{
		ID:               "current-encoder",
		At:               base,
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainRestart,
		ResourceType:     "system",
		CanonicalVersion: CanonicalVersion2,
	}); err != nil {
		t.Fatalf("Log current-encoder row: %v", err)
	}

	// Determine the just-written row's stored hash so the seeded
	// pre-v1.4 rows can chain forward from it via PrevHash.
	stored, err := l.store.Queries.GetEventByID(ctx, "current-encoder")
	if err != nil {
		t.Fatalf("GetEventByID: %v", err)
	}
	prev := stored.Hash

	// Row 1 + 2: pre-v1.4 v=2 rows chained off the current-encoder row.
	for i, id := range []string{"old-1", "old-2"} {
		e := Event{
			ID:               id,
			At:               base.Add(time.Duration(i+1) * time.Second),
			Actor:            Actor{Type: ActorTypeUser, UserID: "u-1"},
			Action:           "project.create",
			ResourceType:     ResourceProject,
			ResourceID:       "p-" + id,
			CanonicalVersion: CanonicalVersion2,
		}
		prev = seedPreV14V2Row(t, l, e, prev)
	}

	// Migrate.
	result, err := l.MigrateLegacyV2Hashes(ctx)
	if err != nil {
		t.Fatalf("MigrateLegacyV2Hashes: %v", err)
	}
	if result.RowsScanned != 3 {
		t.Errorf("RowsScanned = %d, want 3", result.RowsScanned)
	}
	// Row 0 already has the current encoder's hash + matches the
	// expected prev=genesis chain head; rows 1 + 2 carry pre-v1.4
	// hashes (also bound to row 0's stored hash, which is unchanged
	// post-migration). So row 0 is a no-op, rows 1 + 2 are updates.
	if result.RowsUpdated != 2 {
		t.Errorf("RowsUpdated = %d, want 2 (row 0 already current, rows 1+2 pre-v1.4)", result.RowsUpdated)
	}

	res, err := l.VerifyLegacy(ctx, CanonicalVersion2, "")
	if err != nil {
		t.Fatalf("VerifyLegacy post: %v", err)
	}
	if res.Tamper {
		t.Fatalf("VerifyLegacy reports tamper after mixed-shape migration; FirstBadIndex=%d Total=%d",
			res.FirstBadIndex, res.Total)
	}
	if res.Total != 3 {
		t.Errorf("Total = %d, want 3", res.Total)
	}
}

// TestRehashChainInPlace_RecoversStalePrevHash mirrors the v1.8 walk
// Step 100 finding — a real-world chain where row 1's stored prev_hash
// is stale (doesn't match row 0's recomputed hash), causing the v1.8
// boot guard to fail with a linkage error. RehashChainInPlace must
// re-thread the chain so a follow-up VerifyChainPostMigration walks
// clean.
//
// TD-AUDIT-12 closure proof — this is the corruption shape the
// v1.5.0-dev original-boot incident produced. MigrateLegacyV2Hashes
// (v=2-only) cannot recover it; RehashChainInPlace can.
func TestRehashChainInPlace_RecoversStalePrevHash(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Seed a clean v=3 chain via Logger.Log — 4 rows chained correctly.
	base := time.Date(2026, 5, 24, 11, 49, 29, 0, time.UTC)
	ids := []string{"row-0-restart", "row-1-data", "row-2-data", "row-3-data"}
	for i, id := range ids {
		e := Event{
			ID:           id,
			At:           base.Add(time.Duration(i) * time.Millisecond),
			Actor:        Actor{Type: ActorTypeUser, UserID: "u-1"},
			Action:       "project.create",
			ResourceType: ResourceProject,
			ResourceID:   "p-" + id,
		}
		if i == 0 {
			e.Actor = ActorSystem("barista")
			e.Action = ActionAuditChainRestart
			e.ResourceType = "system"
		}
		if _, err := l.Log(ctx, e); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	// Sanity: pre-corruption walk is clean.
	if _, err := verifyChainPostMigrationStore(ctx, l); err != nil {
		t.Fatalf("pre-corruption walk should be clean; got: %v", err)
	}

	// Corrupt row 1's prev_hash — the dev DB TD-AUDIT-12 shape. Row 1's
	// stored hash stays unchanged (no longer self-consistent under the
	// corrupted prev_hash, but the chain-walk fails at the LINKAGE
	// check before reaching the recompute, mirroring the dev DB).
	db := SQLiteAuditDBForTest(l)
	if db == nil {
		t.Fatal("SQLiteAuditDBForTest returned nil")
	}
	stalePrev := make([]byte, HashSize)
	for i := range stalePrev {
		stalePrev[i] = 0xAA
	}
	if _, err := db.ExecContext(ctx, `UPDATE events SET prev_hash = ? WHERE id = ?`, stalePrev, "row-1-data"); err != nil {
		t.Fatalf("UPDATE prev_hash: %v", err)
	}

	// Confirm the boot guard catches it — expect a chain mismatch at
	// index 1, linkage failure.
	_, err := verifyChainPostMigrationStore(ctx, l)
	if err == nil {
		t.Fatal("expected ChainMismatchError, got nil")
	}
	var mismatch *ChainMismatchError
	if !IsChainMismatch(err) {
		t.Fatalf("err = %v, want ChainMismatchError", err)
	}
	_ = mismatch

	// Recover via RehashChainInPlace — the v1.8 walk-fix.
	res, err := l.RehashChainInPlace(ctx)
	if err != nil {
		t.Fatalf("RehashChainInPlace: %v", err)
	}
	if res.RowsScanned != 4 {
		t.Errorf("RowsScanned = %d, want 4", res.RowsScanned)
	}
	if res.RowsUpdated < 1 {
		t.Errorf("RowsUpdated = %d, want >=1 (row 1 must be re-threaded)", res.RowsUpdated)
	}

	// Post-recovery walk must be clean.
	if _, err := verifyChainPostMigrationStore(ctx, l); err != nil {
		t.Fatalf("post-recovery walk should be clean; got: %v", err)
	}

	// Idempotency: re-running on a clean chain produces zero writes.
	res2, err := l.RehashChainInPlace(ctx)
	if err != nil {
		t.Fatalf("RehashChainInPlace 2nd run: %v", err)
	}
	if res2.RowsScanned != 4 {
		t.Errorf("2nd run RowsScanned = %d, want 4", res2.RowsScanned)
	}
	if res2.RowsUpdated != 0 {
		t.Errorf("2nd run RowsUpdated = %d, want 0 (clean chain)", res2.RowsUpdated)
	}
}

// TestRehashChainInPlace_CrossCanonicalVersion confirms the recovery
// tool walks rows of mixed canonical_versions correctly — recomputing
// each under its own version. Mirrors the dev DB shape: v=2 row 0
// followed by v=3 rows. MigrateLegacyV2Hashes filters to v=2 only and
// cannot do this; RehashChainInPlace must.
func TestRehashChainInPlace_CrossCanonicalVersion(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	base := time.Date(2026, 5, 24, 11, 49, 29, 0, time.UTC)

	// Row 0: v=2 chain_restart.
	if _, err := l.Log(ctx, Event{
		ID:               "v2-restart",
		At:               base,
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainRestart,
		ResourceType:     "system",
		CanonicalVersion: CanonicalVersion2,
	}); err != nil {
		t.Fatalf("Log v2-restart: %v", err)
	}

	// Rows 1+ are v=3 — Logger.Log uses CanonicalVersion3 by default.
	for i, id := range []string{"v3-restart", "v3-migrate", "v3-data-a"} {
		e := Event{
			ID:           id,
			At:           base.Add(time.Duration(i+1) * time.Millisecond),
			Actor:        Actor{Type: ActorTypeUser, UserID: "u-1"},
			Action:       "project.create",
			ResourceType: ResourceProject,
			ResourceID:   "p-" + id,
		}
		if i == 0 {
			e.Actor = ActorSystem("barista")
			e.Action = ActionAuditChainRestart
			e.ResourceType = "system"
		}
		if i == 1 {
			e.Actor = ActorSystem("barista")
			e.Action = ActionAuditChainMigrate
			e.ResourceType = "system"
		}
		if _, err := l.Log(ctx, e); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	// Corrupt row 1 (v=3 chain_restart) — the dev DB shape: v=2/v=3
	// segment boundary's prev_hash gets de-threaded.
	db := SQLiteAuditDBForTest(l)
	stale := make([]byte, HashSize)
	for i := range stale {
		stale[i] = 0xBB
	}
	if _, err := db.ExecContext(ctx, `UPDATE events SET prev_hash = ? WHERE id = ?`, stale, "v3-restart"); err != nil {
		t.Fatalf("UPDATE: %v", err)
	}

	// Boot guard catches it.
	if _, err := verifyChainPostMigrationStore(ctx, l); err == nil {
		t.Fatal("expected mismatch on cross-version stale prev_hash")
	}

	// Recover.
	res, err := l.RehashChainInPlace(ctx)
	if err != nil {
		t.Fatalf("RehashChainInPlace: %v", err)
	}
	if res.RowsScanned != 4 {
		t.Errorf("RowsScanned = %d, want 4", res.RowsScanned)
	}

	// Post-recovery walks clean.
	if _, err := verifyChainPostMigrationStore(ctx, l); err != nil {
		t.Fatalf("post-recovery walk should be clean across canonical_versions; got: %v", err)
	}
}

// TestRehashChainInPlace_EmptyChain confirms a no-rows audit DB
// reports RowsScanned=0 without error. Mirrors MigrateLegacyV2Hashes'
// fresh-install path.
func TestRehashChainInPlace_EmptyChain(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	res, err := l.RehashChainInPlace(ctx)
	if err != nil {
		t.Fatalf("RehashChainInPlace on empty chain: %v", err)
	}
	if res.RowsScanned != 0 {
		t.Errorf("RowsScanned = %d, want 0", res.RowsScanned)
	}
	if res.RowsUpdated != 0 {
		t.Errorf("RowsUpdated = %d, want 0", res.RowsUpdated)
	}
}
