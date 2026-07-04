package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestVerifyLegacy_WalksEntireSegment seeds the v1.0-chain.json fixture
// (5 rows at v=2) via Logger.Log + emits 3 additional v=2 rows via
// Logger.Log afterward, then calls VerifyLegacy(ctx, 2, "") and asserts
// every row gets walked regardless of where the rows sit in time.
//
// This is the TD-AUDIT-10 closure proof: pre-v1.4 VerifyLegacy rooted
// the walk at the latest chain-restart row, so additional v=2 rows
// emitted after a chain-restart elsewhere could be unreachable. v1.4
// walks the entire v=N segment.
func TestVerifyLegacy_WalksEntireSegment(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Seed the 5-row fixture via Logger.Log so the inserted chain links
	// forward through latestHash + the v=2 encoder.
	rows := loadV10ChainFixture(t)
	for _, r := range rows {
		e := fixtureRowToEvent(t, r)
		e.PrevHash = nil
		e.Hash = nil
		if _, err := l.Log(ctx, e); err != nil {
			t.Fatalf("Log fixture %s: %v", r.ID, err)
		}
	}

	// 3 additional v=2 rows after the fixture, simulating operator
	// activity post-fixture-load.
	base := time.Date(2026, 4, 1, 11, 0, 0, 0, time.UTC)
	for i, id := range []string{"extra-a", "extra-b", "extra-c"} {
		if _, err := l.Log(ctx, Event{
			ID:               id,
			At:               base.Add(time.Duration(i) * time.Second),
			Actor:            Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
			Action:           "project.create",
			ResourceType:     ResourceProject,
			ResourceID:       "p-" + id,
			CanonicalVersion: CanonicalVersion2,
		}); err != nil {
			t.Fatalf("Log extra %s: %v", id, err)
		}
	}

	res, err := l.VerifyLegacy(ctx, CanonicalVersion2, "")
	if err != nil {
		t.Fatalf("VerifyLegacy(2, \"\"): %v", err)
	}
	if res.Tamper {
		t.Fatalf("expected clean chain across the entire v=2 segment; got Tamper at index %d (Total=%d)",
			res.FirstBadIndex, res.Total)
	}
	if got, want := res.Total, int64(len(rows)+3); got != want {
		t.Errorf("Total = %d, want %d (fixture rows + extras)", got, want)
	}
}

// TestVerifyLegacy_LoadedFixtureBeforeBootstrap reproduces the v1.3
// DoD walk Step 66 scenario: bootstrap chain-restart row is the
// segment genesis (inserted at a timestamp older than the fixture
// rows), then the v1.0-chain.json fixture loads via Logger.Log so the
// fixture rows link forward from bootstrap's hash. v1.4's
// walk-entire-segment shape covers both the bootstrap row + every
// fixture row in one pass.
//
// Pre-v1.4, the walker rooted at the latest chain-restart row at v=2
// (= the bootstrap row's position in time). When the fixture rows
// were chronologically older than bootstrap, they fell behind the
// walker's starting point and were unreachable. This caused the v1.3
// walk Step 66 finding: `VerifyLegacy(2)` reported Total=1 instead of
// Total=1+5 on a freshly-fixture-loaded DB.
func TestVerifyLegacy_LoadedFixtureBeforeBootstrap(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Step 1: insert the bootstrap chain-restart row at March 2026 - a
	// timestamp older than every fixture row (which are dated April
	// 2026). Logger.Log picks PrevHash from latestHash() (= genesis
	// because the DB is empty), so the bootstrap row anchors the
	// segment.
	bootstrapAt := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	if _, err := l.Log(ctx, Event{
		ID:               "boot-cr-v2",
		At:               bootstrapAt,
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainRestart,
		ResourceType:     "system",
		CanonicalVersion: CanonicalVersion2,
	}); err != nil {
		t.Fatalf("Log bootstrap row: %v", err)
	}

	// Step 2: load fixture rows via Logger.Log. Each Log call picks
	// PrevHash from latestHash() - the first fixture row links to
	// bootstrap, every subsequent fixture row links to the previous.
	// Hashes are recomputed under the v=2 encoder, so the fixture's
	// committed PrevHash + Hash columns are ignored (intentional - the
	// chain is internally re-stamped against THIS DB's running tail).
	rows := loadV10ChainFixture(t)
	for _, r := range rows {
		e := fixtureRowToEvent(t, r)
		e.PrevHash = nil
		e.Hash = nil
		if _, err := l.Log(ctx, e); err != nil {
			t.Fatalf("Log fixture %s: %v", r.ID, err)
		}
	}

	res, err := l.VerifyLegacy(ctx, CanonicalVersion2, "")
	if err != nil {
		t.Fatalf("VerifyLegacy(2, \"\"): %v", err)
	}
	if res.Tamper {
		t.Fatalf("expected clean chain across bootstrap + fixture; got Tamper at index %d (Total=%d)",
			res.FirstBadIndex, res.Total)
	}
	// Walker visits bootstrap first (March) then fixture rows in
	// April order; the chain links forward through the entire segment.
	if got, want := res.Total, int64(len(rows)+1); got != want {
		t.Errorf("Total = %d, want %d (bootstrap + fixture rows)", got, want)
	}
}

// TestVerifyLegacy_EmptySegment confirms a DB with zero rows at the
// requested canonical_version returns a clean (Total=0, Tamper=false)
// result, NOT a tamper claim. Operators interpret this as "nothing to
// walk at this version on this DB."
func TestVerifyLegacy_EmptySegment(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	res, err := l.VerifyLegacy(ctx, CanonicalVersion2, "")
	if err != nil {
		t.Fatalf("VerifyLegacy on empty DB: %v", err)
	}
	if res.Tamper {
		t.Fatalf("empty DB should not report tamper; got FirstBadIndex=%d", res.FirstBadIndex)
	}
	if res.Total != 0 {
		t.Errorf("Total = %d, want 0", res.Total)
	}
}

// TestVerifyLegacy_OnlyV3Rows confirms a DB with v=3 rows but zero v=2
// rows returns a clean empty result when VerifyLegacy(2) is called. The
// v=2 segment is empty even though the DB has v=3 rows.
func TestVerifyLegacy_OnlyV3Rows(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	base := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	for i, id := range []string{"v3-a", "v3-b", "v3-c"} {
		if _, err := l.Log(ctx, Event{
			ID:           id,
			At:           base.Add(time.Duration(i) * time.Second),
			Actor:        Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
			Action:       "project.create",
			ResourceType: ResourceProject,
			ResourceID:   "p-" + id,
		}); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	res, err := l.VerifyLegacy(ctx, CanonicalVersion2, "")
	if err != nil {
		t.Fatalf("VerifyLegacy(2) on v=3-only DB: %v", err)
	}
	if res.Tamper {
		t.Fatalf("v=3-only DB should not report tamper for VerifyLegacy(2); got FirstBadIndex=%d", res.FirstBadIndex)
	}
	if res.Total != 0 {
		t.Errorf("Total = %d, want 0 (no v=2 rows present)", res.Total)
	}
}

// TestVerifyLegacy_DetectsTamperInOldestRow seeds 3 v=2 rows then
// corrupts the OLDEST row's `action` column. VerifyLegacy(2) must
// report Tamper=true, FirstBadIndex=0 — confirming the walker starts
// from the oldest row, not from the latest chain-restart marker (the
// v1.4 walk-entire-segment behavior).
func TestVerifyLegacy_DetectsTamperInOldestRow(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	for i, id := range []string{"v2-oldest", "v2-mid", "v2-newest"} {
		if _, err := l.Log(ctx, Event{
			ID:               id,
			At:               base.Add(time.Duration(i) * time.Second),
			Actor:            Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
			Action:           "project.create",
			ResourceType:     ResourceProject,
			ResourceID:       "p-" + id,
			CanonicalVersion: CanonicalVersion2,
		}); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	// Corrupt the OLDEST row's action — if the walker rooted somewhere
	// later in time (the v1.3 bug shape), this tamper would be missed.
	if _, err := l.store.DB.ExecContext(ctx,
		"UPDATE events SET action = ? WHERE id = ?",
		"project.delete-tamper", "v2-oldest"); err != nil {
		t.Fatalf("tamper inject: %v", err)
	}

	res, err := l.VerifyLegacy(ctx, CanonicalVersion2, "")
	if err != nil {
		t.Fatalf("VerifyLegacy(2): %v", err)
	}
	if !res.Tamper {
		t.Fatalf("VerifyLegacy(2) failed to detect tamper in the oldest v=2 row")
	}
	if got, want := res.FirstBadIndex, int64(0); got != want {
		t.Errorf("FirstBadIndex = %d, want %d (oldest row)", got, want)
	}
}

// TestVerifyLegacy_FromID_NarrowsWindow seeds 5 v=2 rows + calls
// VerifyLegacy(ctx, 2, rows[2].ID). The chain-restart-rooted query
// shape returns the anchor row + every later row, so the walk covers
// 3 rows (rows[2], rows[3], rows[4]) cleanly.
func TestVerifyLegacy_FromID_NarrowsWindow(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	ids := []string{"a", "b", "c", "d", "e"}
	for i, id := range ids {
		if _, err := l.Log(ctx, Event{
			ID:               id,
			At:               base.Add(time.Duration(i) * time.Second),
			Actor:            Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
			Action:           "project.create",
			ResourceType:     ResourceProject,
			ResourceID:       "p-" + id,
			CanonicalVersion: CanonicalVersion2,
		}); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	res, err := l.VerifyLegacy(ctx, CanonicalVersion2, "c")
	if err != nil {
		t.Fatalf("VerifyLegacy(2, c): %v", err)
	}
	if res.Tamper {
		t.Fatalf("expected clean chain from row c forward; got Tamper at index %d", res.FirstBadIndex)
	}
	if got, want := res.Total, int64(3); got != want {
		t.Errorf("Total = %d, want %d (rows c, d, e)", got, want)
	}
}

// TestVerifyLegacy_FromID_NotFound asserts the walker fails loud when
// the supplied --from-id row doesn't exist. CLI maps this to exit 1.
func TestVerifyLegacy_FromID_NotFound(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// 3 v=2 rows so the segment isn't empty (separate from the
	// not-found error path).
	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	for i, id := range []string{"a", "b", "c"} {
		if _, err := l.Log(ctx, Event{
			ID:               id,
			At:               base.Add(time.Duration(i) * time.Second),
			Actor:            Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
			Action:           "project.create",
			ResourceType:     ResourceProject,
			ResourceID:       "p-" + id,
			CanonicalVersion: CanonicalVersion2,
		}); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	_, err := l.VerifyLegacy(ctx, CanonicalVersion2, "no-such-id")
	if err == nil {
		t.Fatalf("VerifyLegacy(2, no-such-id) should error on unknown id")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error %q should mention 'not found'", err.Error())
	}
}

// TestVerifyLegacy_FromID_RejectsWrongVersion seeds 1 v=2 row + 1 v=3
// row. Calling VerifyLegacy(2, <v3-row-id>) returns an error indicating
// the version mismatch — operators don't accidentally walk a v=3 row's
// downstream under the v=2 encoder.
func TestVerifyLegacy_FromID_RejectsWrongVersion(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	if _, err := l.Log(ctx, Event{
		ID:               "v2-row",
		At:               base,
		Actor:            Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
		Action:           "project.create",
		ResourceType:     ResourceProject,
		ResourceID:       "p-v2",
		CanonicalVersion: CanonicalVersion2,
	}); err != nil {
		t.Fatalf("Log v2 row: %v", err)
	}
	if _, err := l.Log(ctx, Event{
		ID:           "v3-row",
		At:           base.Add(time.Second),
		Actor:        Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
		Action:       "project.create",
		ResourceType: ResourceProject,
		ResourceID:   "p-v3",
		// CanonicalVersion default = 3.
	}); err != nil {
		t.Fatalf("Log v3 row: %v", err)
	}

	_, err := l.VerifyLegacy(ctx, CanonicalVersion2, "v3-row")
	if err == nil {
		t.Fatalf("VerifyLegacy(2, v3-row) should error on canonical_version mismatch")
	}
	if !strings.Contains(err.Error(), "canonical_version=3") {
		t.Errorf("error %q should mention 'canonical_version=3'", err.Error())
	}
	if !strings.Contains(err.Error(), "want 2") {
		t.Errorf("error %q should mention 'want 2'", err.Error())
	}
}

// TestBootstrapChainRestartRow_VerifiesUnderNewEncoder drives the
// production bootstrap shape end-to-end: emit a v=2 row via
// Logger.Log({CanonicalVersion: 2, ...}) at `time.Now()` precision,
// then walk via VerifyLegacy(ctx, 2, ""). The v1.4 UnixNano-encoded
// payload survives SQLite TEXT round-trip so the row's stored Hash
// recomputes cleanly under canonicalPayloadLegacyV2 — the property
// the v1.3 walk Step 63 symptom was about (TD-AUDIT-09 closure).
func TestBootstrapChainRestartRow_VerifiesUnderNewEncoder(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// time.Now() has nanosecond precision — exactly the property that
	// broke under the pre-v1.4 RFC3339Nano encoder.
	if _, err := l.Log(ctx, Event{
		ID:               "boot-cr-v2",
		At:               time.Now().UTC(),
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainRestart,
		ResourceType:     "system",
		CanonicalVersion: CanonicalVersion2,
	}); err != nil {
		t.Fatalf("Log bootstrap row: %v", err)
	}

	res, err := l.VerifyLegacy(ctx, CanonicalVersion2, "")
	if err != nil {
		t.Fatalf("VerifyLegacy(2, \"\"): %v", err)
	}
	if res.Tamper {
		t.Fatalf("v1.4 encoder should produce a clean chain for the bootstrap row; got Tamper at index %d", res.FirstBadIndex)
	}
	if got, want := res.Total, int64(1); got != want {
		t.Errorf("Total = %d, want %d", got, want)
	}
}

// TestV10ChainFixture_RoundTripsThroughLoggerLog_NewEncoder is the
// v1.4-shaped regen guard: load every fixture row via Logger.Log,
// VerifyLegacy(2, "") walks them cleanly + the fixture's stored hashes
// recompute exactly under the new encoder. If anyone regenerates the
// fixture by accident without running `go run
// ./internal/audit/testdata/gen` after an encoder change, this fires.
func TestV10ChainFixture_RoundTripsThroughLoggerLog_NewEncoder(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	raw, err := os.ReadFile(filepath.Join("testdata", "v1.0-chain.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var rows []v10ChainFixtureRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	// Replay through Logger.Log so PrevHash + Hash are recomputed
	// against this DB's chain — but verify the fixture's STORED hash
	// matches the canonicalPayloadLegacyV2 recomputation too. The
	// fixture's prev_hash + hash chain is internally consistent under
	// the v1.4 encoder; if either drifted (or the regen step was
	// skipped), this fires.
	prev := make([]byte, HashSize)
	for i, r := range rows {
		e := fixtureRowToEvent(t, r)

		// Inline chain recomputation against the fixture's stored
		// occurred_at + the rolling prev pointer.
		payload := canonicalPayloadLegacyV2(e, prev)
		// Recompute using the same sha256 shape walkChain uses.
		want := sha256Sum(prev, payload)
		wantHex := hex.EncodeToString(want)
		if r.Hash != wantHex {
			t.Errorf("row %d (id=%s): committed hash %s; new encoder produces %s — fixture is stale",
				i, r.ID, r.Hash, wantHex)
		}
		prev = want

		// Replay via Logger.Log to also exercise the production
		// emission path. PrevHash + Hash get re-stamped against this
		// DB's chain (which is empty before the first Log) so they
		// match the fixture rows step-by-step.
		e.PrevHash = nil
		e.Hash = nil
		if _, err := l.Log(ctx, e); err != nil {
			t.Fatalf("Log fixture row %s: %v", r.ID, err)
		}
	}

	res, err := l.VerifyLegacy(ctx, CanonicalVersion2, "")
	if err != nil {
		t.Fatalf("VerifyLegacy: %v", err)
	}
	if res.Tamper {
		t.Fatalf("post-Log VerifyLegacy reports tamper at index %d", res.FirstBadIndex)
	}
	if got, want := res.Total, int64(len(rows)); got != want {
		t.Errorf("Total = %d, want %d", got, want)
	}
}

// TestCanonicalPayloadForVersion_StillDispatches is the sanity check
// that the v1.4 encoder swap didn't break the dispatcher's case
// statement. Both v=2 and v=3 paths must still route to their
// respective encoders without error.
func TestCanonicalPayloadForVersion_StillDispatches(t *testing.T) {
	at := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	e := Event{
		ID:           "evt-dispatch",
		At:           at,
		Actor:        Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
		Action:       "project.create",
		ResourceType: ResourceProject,
		ResourceID:   "p-dispatch",
	}
	prev := make([]byte, HashSize)

	v2Payload, err := canonicalPayloadForVersion(e, prev, CanonicalVersion2)
	if err != nil {
		t.Fatalf("canonicalPayloadForVersion(v=2): %v", err)
	}
	if !strings.Contains(string(v2Payload), "|") {
		t.Errorf("v2 dispatch should produce pipe-separated bytes; got %q", v2Payload)
	}

	v3Payload, err := canonicalPayloadForVersion(e, prev, CanonicalVersion3)
	if err != nil {
		t.Fatalf("canonicalPayloadForVersion(v=3): %v", err)
	}
	// v3 is length-prefixed binary; it should NOT contain pipe bytes
	// in any predictable position. The two encodings MUST differ.
	if string(v2Payload) == string(v3Payload) {
		t.Errorf("v2 and v3 dispatch produced identical bytes — dispatcher broken")
	}

	// Unknown version still errors (already covered by other tests,
	// pinned here for the dispatcher contract).
	if _, err := canonicalPayloadForVersion(e, prev, 99); err == nil {
		t.Errorf("canonicalPayloadForVersion(99) should error on unknown version")
	}
}

// sha256Sum is a tiny helper for the fixture round-trip test —
// keeps the assertion body single-statement.
func sha256Sum(prev, payload []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(payload)
	return h.Sum(nil)
}
