package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/suryakencana007/barista/packages/tamper/audit/sqlitestore"
)

// v10ChainFixtureRow mirrors the JSON shape committed at
// internal/audit/testdata/v1.0-chain.json. The fields use the v1.0 wire
// shape — `occurred_at` (not `at`), `target_type` / `target_id` (not
// `resource_type` / `resource_id`), `data_json` for the After snapshot.
// Audit.Event uses the modern field names; loadV10ChainFixture maps
// between them so the fixture stays authoritative for the v1.0 shape.
type v10ChainFixtureRow struct {
	ID         string `json:"id"`
	OccurredAt string `json:"occurred_at"`
	Actor      struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"actor"`
	Action           string `json:"action"`
	TargetType       string `json:"target_type"`
	TargetID         string `json:"target_id"`
	ClusterID        string `json:"cluster_id"`
	DataJSON         string `json:"data_json"`
	PrevHash         string `json:"prev_hash"`
	Hash             string `json:"hash"`
	CanonicalVersion int    `json:"canonical_version"`
}

// loadV10ChainFixture parses the committed v1.0 chain JSON. Surfaces as
// fixture rows + the parsed `audit.Event` slice (mapped to the modern
// field names) + the hex hash strings so tests can assert the exact
// stored Hash bytes round-trip through canonicalPayloadLegacyV2 +
// sha256.
func loadV10ChainFixture(t *testing.T) []v10ChainFixtureRow {
	t.Helper()
	path := filepath.Join("testdata", "v1.0-chain.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var rows []v10ChainFixtureRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(rows) == 0 {
		t.Fatalf("fixture %s is empty", path)
	}
	return rows
}

// fixtureRowToEvent maps a v1.0 wire-shape fixture row into an
// audit.Event suitable for canonicalPayloadLegacyV2. The After slot
// carries data_json (v1.0 stored the post-state in data_json); Before
// stays nil (v1.0 didn't have a Before snapshot in the canonical
// payload).
func fixtureRowToEvent(t *testing.T, r v10ChainFixtureRow) Event {
	t.Helper()
	at, err := time.Parse(time.RFC3339Nano, r.OccurredAt)
	if err != nil {
		t.Fatalf("parse occurred_at %q: %v", r.OccurredAt, err)
	}
	prevHashBytes, err := hex.DecodeString(r.PrevHash)
	if err != nil {
		t.Fatalf("decode prev_hash %q: %v", r.PrevHash, err)
	}
	hashBytes, err := hex.DecodeString(r.Hash)
	if err != nil {
		t.Fatalf("decode hash %q: %v", r.Hash, err)
	}
	e := Event{
		ID:               r.ID,
		At:               at,
		Actor:            Actor{Type: ActorType(r.Actor.Type), Name: r.Actor.Name},
		Action:           Action(r.Action),
		ResourceType:     ResourceType(r.TargetType),
		ResourceID:       r.TargetID,
		ClusterID:        r.ClusterID,
		PrevHash:         prevHashBytes,
		Hash:             hashBytes,
		CanonicalVersion: r.CanonicalVersion,
	}
	if r.DataJSON != "" {
		e.After = json.RawMessage(r.DataJSON)
	}
	return e
}

// TestCanonicalPayloadLegacyV2_FixtureRoundTrip asserts every row in
// the committed v1.0 chain fixture round-trips through
// canonicalPayloadLegacyV2 + sha256 to produce the stored Hash. If any
// future change to the v2 canonical shape drifts, this fires loudly.
func TestCanonicalPayloadLegacyV2_FixtureRoundTrip(t *testing.T) {
	rows := loadV10ChainFixture(t)
	for i, r := range rows {
		e := fixtureRowToEvent(t, r)
		payload := canonicalPayloadLegacyV2(e, e.PrevHash)
		h := sha256.New()
		h.Write(e.PrevHash)
		h.Write(payload)
		got := h.Sum(nil)
		want := e.Hash
		if !bytesEqual(got, want) {
			t.Errorf("row %d (id=%s): computed hash %x, stored hash %x — v2 canonical shape drifted",
				i, e.ID, got, want)
		}
	}
}

// TestCanonicalPayloadLegacyV2_FieldOrder pins the exact byte sequence
// the v2 encoder produces for a hand-built event. If the encoder's
// field order or formatting ever drifts (e.g., someone re-enables
// RFC3339Nano formatting, or reorders the fields), this fires before
// the fixture-based round-trip test does — gives a clearer error
// message ("encoding shape changed") than ("stored hash mismatches").
//
// v1.4 — TD-AUDIT-09: the timestamp field is now base-10 int64 string
// of `at.UnixNano()` (literal "1775386800000000000" for the test's
// 2026-04-01 10:00:00 UTC). Pre-v1.4 used `at.UTC().Format(RFC3339Nano)`
// which lost SQLite TEXT round-trip precision.
func TestCanonicalPayloadLegacyV2_FieldOrder(t *testing.T) {
	at := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	e := Event{
		ID:               "evt-001",
		At:               at,
		Actor:            Actor{Type: ActorTypeUser, Name: "alice"},
		Action:           "auth.login",
		ResourceType:     "user",
		ResourceID:       "user-alice",
		ClusterID:        "",
		CanonicalVersion: CanonicalVersion2,
	}
	prev := make([]byte, HashSize) // genesis
	got := string(canonicalPayloadLegacyV2(e, prev))
	want := strings.Join([]string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		strconv.FormatInt(at.UnixNano(), 10),
		"user",
		"alice",
		"auth.login",
		"user",
		"user-alice",
		"",
		"",
	}, "|")
	if got != want {
		t.Errorf("v2 canonical bytes drift:\n got:  %q\n want: %q", got, want)
	}
}

// TestCanonicalPayloadLegacyV2_UnixNanoEncoding is the v1.4 TD-AUDIT-09
// closure proof: the legacy v2 encoder embeds the timestamp as a
// base-10 int64 string of `e.At.UnixNano()`, NOT as a
// `time.RFC3339Nano` text representation. The two encodings differ for
// timestamps with sub-microsecond precision (the precision that survives
// SQLite TEXT round-trip in `time.RFC3339Nano` form is microseconds,
// not nanoseconds), so a row written with `time.Now()` and read back
// from the DB at higher precision would hash differently under
// pre-v1.4's encoder vs the v1.4 encoder.
func TestCanonicalPayloadLegacyV2_UnixNanoEncoding(t *testing.T) {
	// Pick a timestamp with sub-microsecond precision that would have
	// drifted under the pre-v1.4 encoder. UnixNano is precision-stable.
	at := time.Date(2026, 4, 1, 10, 0, 0, 123456789, time.UTC)
	e := Event{
		ID:               "evt-precision",
		At:               at,
		Actor:            Actor{Type: ActorTypeUser, Name: "alice"},
		Action:           "auth.login",
		ResourceType:     "user",
		ResourceID:       "user-alice",
		CanonicalVersion: CanonicalVersion2,
	}
	prev := make([]byte, HashSize)
	got := string(canonicalPayloadLegacyV2(e, prev))

	// The encoder must embed the UnixNano int64 literal.
	wantNanos := strconv.FormatInt(at.UnixNano(), 10)
	if !strings.Contains(got, wantNanos) {
		t.Errorf("v2 encoder should embed UnixNano %q; got %q", wantNanos, got)
	}
	// The encoder must NOT embed the RFC3339Nano string — that's the
	// pre-v1.4 shape; we're explicitly asserting it doesn't leak back
	// in via some future "fix" to make the timestamp human-readable.
	rfc := at.UTC().Format(time.RFC3339Nano)
	if strings.Contains(got, rfc) {
		t.Errorf("v2 encoder must not embed RFC3339Nano %q; got %q", rfc, got)
	}
}

// seedV10FixtureIntoStore inserts every row in the fixture into a
// fresh SQLite audit DB via direct SQL writes (Logger.Log writes v3
// rows, which is not what we want for fixture replay). Returns the
// SQLiteLogger ready for Verify / VerifyLegacy calls.
func seedV10FixtureIntoStore(t *testing.T) *SQLiteLogger {
	t.Helper()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)
	rows := loadV10ChainFixture(t)
	for _, r := range rows {
		e := fixtureRowToEvent(t, r)
		if err := insertEventDirect(t, l, e); err != nil {
			t.Fatalf("insert fixture %s: %v", r.ID, err)
		}
	}
	return l
}

// insertEventDirect bypasses Logger.Log so a test can insert rows at
// arbitrary canonical_versions with pre-computed PrevHash + Hash. Used
// by the v1.0 fixture replay + the tamper tests.
func insertEventDirect(t *testing.T, l *SQLiteLogger, e Event) error {
	t.Helper()
	beforeJSON := ""
	if len(e.Before) > 0 {
		beforeJSON = string(e.Before)
	}
	afterJSON := ""
	if len(e.After) > 0 {
		afterJSON = string(e.After)
	}
	return l.store.Queries.InsertEvent(context.Background(), sqlitestore.InsertEventParams{
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
		PrevHash:         e.PrevHash,
		Hash:             e.Hash,
		CanonicalVersion: int64(e.CanonicalVersion),
	})
}

// TestV10Chain_RoundTripsThroughLoggerLog asserts the bootstrap write
// path — Logger.Log(Event{CanonicalVersion: 2, ...}) — produces a
// chain that VerifyLegacy(2) walks cleanly end-to-end (TD-AUDIT-08
// closure).
//
// Context: the v1.2 walk Step 59.2 surfaced "tamper detected at index
// 0" when `barista audit verify --legacy --canonical-version=2` was
// run against a fresh-v1.2-install. The diagnosis: existing fixture
// tests used insertEventDirect, bypassing the bootstrap Log path
// (cmd/barista/main.go::insertChainRestartIfMissing uses Logger.Log
// to emit the genesis row). This test closes the integration gap by
// replaying the v1.0-chain.json fixture through Logger.Log under
// CanonicalVersion: 2 and asserting VerifyLegacy(2) reports a clean
// chain across all fixture rows.
//
// Code reading at v1.3 scope time confirmed Logger.Log already
// honors e.CanonicalVersion (audit_sqlite.go:140-143 dispatches to
// computeHash with the explicit version). This test is the regression
// guard — if a future change accidentally re-introduces a default-to-v3
// bug in the Log dispatch, the v=2 row's hash will not match what
// canonicalPayloadLegacyV2 produces and VerifyLegacy(2) will fire
// tamper at index 0.
//
// Note: this test does NOT assert hash equality to the fixture's
// committed hash. The fixture's hash was computed at row-creation
// time with the fixture's exact prev_hash and timestamp. The Log
// path picks PrevHash from latestHash() at Log time (zero bytes for
// the first row, the prior row's Hash thereafter), which matches the
// fixture's chained shape because we replay rows in order on a fresh
// DB. The fixture's stored Hash isn't re-asserted here — it's the
// chain INTEGRITY (PrevHash linkage + recomputed hash equality with
// the row's own stored Hash) that VerifyLegacy enforces, which is
// the property the v1.2 walk Step 59.2 symptom was about.
func TestV10Chain_RoundTripsThroughLoggerLog(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	fixture := loadV10ChainFixture(t)
	for _, r := range fixture {
		e := fixtureRowToEvent(t, r)
		// Clear the fixture-supplied PrevHash + Hash bytes so
		// Logger.Log fills them in from the running chain. Keep
		// CanonicalVersion=2 (the bootstrap row's version); Logger.Log
		// must dispatch to canonicalPayloadLegacyV2 via computeHash.
		e.PrevHash = nil
		e.Hash = nil
		if _, err := l.Log(ctx, e); err != nil {
			t.Fatalf("Log row %s: %v", e.ID, err)
		}
	}

	res, err := l.VerifyLegacy(ctx, CanonicalVersion2, "")
	if err != nil {
		t.Fatalf("VerifyLegacy: %v", err)
	}
	if res.Tamper {
		t.Fatalf("expected chain valid; got Tamper=true at index %d", res.FirstBadIndex)
	}
	if got, want := res.Total, int64(len(fixture)); got != want {
		t.Fatalf("expected %d rows verified; got %d", want, got)
	}
}

// TestWalkChain_AllV2 confirms the v1.2 task 04 closure for pure-v2
// chain segments: replay the committed v1.0 chain fixture into a fresh
// DB, run Verify with explicit canonicalVersion=2 → clean walk of all
// 5 fixture rows.
func TestWalkChain_AllV2(t *testing.T) {
	l := seedV10FixtureIntoStore(t)
	rows := loadV10ChainFixture(t)
	res := walkChain(toStoreRows(t, l, len(rows)), CanonicalVersion2)
	if res.Tamper {
		t.Fatalf("walkChain reported tamper at index %d on pure-v2 fixture", res.FirstBadIndex)
	}
	if got, want := res.Total, int64(len(rows)); got != want {
		t.Errorf("Total = %d, want %d", got, want)
	}
}

// TestWalkChain_AllV3 confirms the v1.1+ shape continues to walk
// cleanly. Three v3 events emitted via Logger.Log, then walkChain
// with canonicalVersion=3.
func TestWalkChain_AllV3(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)
	base := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	for i, id := range []string{"v3-a", "v3-b", "v3-c"} {
		_, err := l.Log(ctx, Event{
			ID:           id,
			At:           base.Add(time.Duration(i) * time.Second),
			Actor:        Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
			Action:       "project.create",
			ResourceType: ResourceProject,
			ResourceID:   "p-" + id,
		})
		if err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}
	res := walkChain(toStoreRows(t, l, 3), CanonicalVersion3)
	if res.Tamper {
		t.Fatalf("walkChain reported tamper at index %d on pure-v3 chain", res.FirstBadIndex)
	}
	if got, want := res.Total, int64(3); got != want {
		t.Errorf("Total = %d, want %d", got, want)
	}
}

// TestWalkChain_MixedV2V3 confirms the per-row dispatch — a mixed-
// version chain with v2 fixture rows followed by a v3 chain-restart
// row + v3 successors walks cleanly under per-row encoder dispatch
// (canonicalVersion=0 passed to walkChain).
func TestWalkChain_MixedV2V3(t *testing.T) {
	ctx := context.Background()
	l := seedV10FixtureIntoStore(t)

	// After the 5 v2 fixture rows, splice a v3 chain-restart row + 3
	// v3 successors. The v3 chain-restart row's PrevHash links to the
	// last v2 fixture row's Hash so the linkage check survives the
	// segment join.
	rows := loadV10ChainFixture(t)
	lastV2Hash, err := hex.DecodeString(rows[len(rows)-1].Hash)
	if err != nil {
		t.Fatalf("decode last v2 hash: %v", err)
	}
	v3Base := time.Date(2026, 4, 2, 10, 0, 0, 0, time.UTC)
	v3Restart := Event{
		ID:               "v3-restart",
		At:               v3Base,
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainRestart,
		ResourceType:     "system",
		PrevHash:         lastV2Hash,
		CanonicalVersion: CanonicalVersion3,
	}
	v3Restart.Hash = computeHash(v3Restart.PrevHash, v3Restart, CanonicalVersion3)
	if err := insertEventDirect(t, l, v3Restart); err != nil {
		t.Fatalf("insert v3 restart: %v", err)
	}
	// 3 v3 successors via Logger.Log (which picks up the latest hash
	// and links forward).
	for i, id := range []string{"v3-a", "v3-b", "v3-c"} {
		_, err := l.Log(ctx, Event{
			ID:           id,
			At:           v3Base.Add(time.Duration(i+1) * time.Second),
			Actor:        Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
			Action:       "project.create",
			ResourceType: ResourceProject,
			ResourceID:   "p-" + id,
		})
		if err != nil {
			t.Fatalf("Log v3 %s: %v", id, err)
		}
	}

	// walkChain with canonicalVersion=0 → per-row dispatch.
	totalRows := len(rows) + 1 + 3 // 5 v2 + 1 v3 restart + 3 v3 successors
	res := walkChain(toStoreRows(t, l, totalRows), 0)
	if res.Tamper {
		t.Fatalf("walkChain reported tamper at index %d on mixed v2→v3 chain (Total=%d)",
			res.FirstBadIndex, res.Total)
	}
	if got, want := res.Total, int64(totalRows); got != want {
		t.Errorf("Total = %d, want %d", got, want)
	}
}

// TestWalkChain_V2RowTamper confirms tamper detection inside the v2
// segment. Flip one byte in the stored hash of the second fixture
// row, then re-verify — should fire at index 1.
func TestWalkChain_V2RowTamper(t *testing.T) {
	ctx := context.Background()
	l := seedV10FixtureIntoStore(t)
	rows := loadV10ChainFixture(t)
	// Tamper: corrupt the stored action on row index 1 (evt-002).
	if _, err := l.store.DB.ExecContext(ctx,
		"UPDATE events SET action = ? WHERE id = ?",
		"app.delete-tamper", rows[1].ID); err != nil {
		t.Fatalf("tamper inject: %v", err)
	}
	res := walkChain(toStoreRows(t, l, len(rows)), CanonicalVersion2)
	if !res.Tamper {
		t.Fatalf("walkChain failed to detect v2 tamper")
	}
	if got, want := res.FirstBadIndex, int64(1); got != want {
		t.Errorf("FirstBadIndex = %d, want %d", got, want)
	}
}

// TestWalkChain_V3RowTamper confirms tamper detection inside the v3
// segment. Emit three v3 rows via Log, then corrupt event "b" — should
// fire at index 1.
func TestWalkChain_V3RowTamper(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)
	base := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	for i, id := range []string{"a", "b", "c"} {
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
	if _, err := l.store.DB.ExecContext(ctx,
		"UPDATE events SET action = ? WHERE id = ?",
		"project.delete-tamper", "b"); err != nil {
		t.Fatalf("tamper inject: %v", err)
	}
	res := walkChain(toStoreRows(t, l, 3), CanonicalVersion3)
	if !res.Tamper {
		t.Fatalf("walkChain failed to detect v3 tamper")
	}
	if got, want := res.FirstBadIndex, int64(1); got != want {
		t.Errorf("FirstBadIndex = %d, want %d", got, want)
	}
}

// TestWalkChain_UnknownVersion_FailsLoud confirms a row with an
// unknown canonical_version (here 99 — neither 1, 2, nor 3) reports
// tamper at that row's index when walkChain is run with per-row
// dispatch.
func TestWalkChain_UnknownVersion_FailsLoud(t *testing.T) {
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)
	// Single row at canonical_version=99 — clearly anomalous. Hash
	// bytes are arbitrary because we expect the encoder to error
	// before the hash gets re-checked.
	e := Event{
		ID:               "future-row",
		At:               time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC),
		Actor:            Actor{Type: ActorTypeUser, UserID: "u-1"},
		Action:           "project.create",
		PrevHash:         make([]byte, HashSize),
		Hash:             make([]byte, HashSize),
		CanonicalVersion: 99,
	}
	if err := insertEventDirect(t, l, e); err != nil {
		t.Fatalf("insert future row: %v", err)
	}
	res := walkChain(toStoreRows(t, l, 1), 0)
	if !res.Tamper {
		t.Fatalf("walkChain should have failed loud on canonical_version=99")
	}
	if got, want := res.FirstBadIndex, int64(0); got != want {
		t.Errorf("FirstBadIndex = %d, want %d", got, want)
	}
}

// TestWalkChain_V1RowInTheWild_FailsLoud confirms a row stored at
// canonical_version=1 fires tamper. The v1.0 bootstrap migration was
// supposed to promote every v1 row to v2 — finding one in the wild
// means either the migration didn't run on this DB or someone hand-
// edited the column.
func TestWalkChain_V1RowInTheWild_FailsLoud(t *testing.T) {
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)
	e := Event{
		ID:               "v1-anomalous",
		At:               time.Date(2025, 12, 1, 10, 0, 0, 0, time.UTC),
		Actor:            Actor{Type: ActorTypeUser, UserID: "u-old"},
		Action:           "project.create",
		PrevHash:         make([]byte, HashSize),
		Hash:             make([]byte, HashSize),
		CanonicalVersion: CanonicalVersion1,
	}
	if err := insertEventDirect(t, l, e); err != nil {
		t.Fatalf("insert v1 row: %v", err)
	}
	res := walkChain(toStoreRows(t, l, 1), 0)
	if !res.Tamper {
		t.Fatalf("walkChain should have failed loud on canonical_version=1")
	}
	if got, want := res.FirstBadIndex, int64(0); got != want {
		t.Errorf("FirstBadIndex = %d, want %d", got, want)
	}
}

// toStoreRows reads the n most-recent events from the audit DB back
// in chain-ascending order for walkChain to chew on. Used by the
// walkChain tests so we read the rows back through the SQLite layer
// rather than constructing them inline (catches any byte-encoding
// drift between InsertEvent + the SELECT path).
func toStoreRows(t *testing.T, l *SQLiteLogger, n int) []sqlitestore.Event {
	t.Helper()
	rows, err := l.store.Queries.ListEventsForVerify(context.Background())
	if err != nil {
		t.Fatalf("ListEventsForVerify: %v", err)
	}
	if len(rows) < n {
		t.Fatalf("ListEventsForVerify returned %d rows, want at least %d", len(rows), n)
	}
	return rows
}
