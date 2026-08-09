package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"github.com/suryakencana007/tamper/tenant"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newSQLiteLoggerForTest opens a fresh audit DB inside t.TempDir().
// Cleanup is automatic via t.Cleanup; callers don't have to defer
// Close.
func newSQLiteLoggerForTest(t *testing.T) Logger {
	t.Helper()
	return newSQLiteLoggerForTestWithOpts(t, SQLiteLoggerOptions{})
}

// newSQLiteLoggerForTestWithOpts is the variant that lets a test
// thread an EmailLookup (or any future option) into the logger.
func newSQLiteLoggerForTestWithOpts(t *testing.T, opts SQLiteLoggerOptions) Logger {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	l, err := NewSQLiteLogger(dbPath, opts)
	if err != nil {
		t.Fatalf("NewSQLiteLogger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// makeEvent fills in the caller-provided fields (ID/At/Action) and
// leaves the optional ones empty. Used as a fixture builder so each
// test reads as a single Log call rather than 12 lines of struct
// init.
func makeEvent(id string, at time.Time, action Action) Event {
	return Event{
		ID:           id,
		At:           at,
		Actor:        Actor{UserID: "u-1", Email: "alice@example.com", IP: "10.0.0.1"},
		Action:       action,
		ResourceType: ResourceProject,
		ResourceID:   "p-" + id,
		RequestID:    "req-" + id,
	}
}

func TestSQLiteLogger_LogAndList_NewestFirst(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t)

	base := time.Date(2026, 5, 8, 10, 0, 0, 0, time.UTC)
	for i, id := range []string{"a", "b", "c"} {
		_, err := l.Log(ctx, makeEvent(id, base.Add(time.Duration(i)*time.Second), "project.create"))
		if err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	page, err := l.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got, want := len(page.Events), 3; got != want {
		t.Fatalf("len(events) = %d, want %d", got, want)
	}
	// Newest first: c, b, a.
	wantIDs := []string{"c", "b", "a"}
	for i, e := range page.Events {
		if e.ID != wantIDs[i] {
			t.Errorf("events[%d].ID = %q, want %q", i, e.ID, wantIDs[i])
		}
	}
}

func TestSQLiteLogger_HashChain_FirstEventGenesisPrev(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t)

	first, err := l.Log(ctx, makeEvent("a", time.Now(), "project.create"))
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if got, want := len(first.PrevHash), HashSize; got != want {
		t.Fatalf("PrevHash len = %d, want %d", got, want)
	}
	for i, b := range first.PrevHash {
		if b != 0 {
			t.Fatalf("PrevHash[%d] = %x, want 0 (genesis)", i, b)
		}
	}
	if got, want := len(first.Hash), HashSize; got != want {
		t.Fatalf("Hash len = %d, want %d", got, want)
	}
}

func TestSQLiteLogger_HashChain_SecondEventLinksPrev(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t)

	a, err := l.Log(ctx, makeEvent("a", time.Now(), "project.create"))
	if err != nil {
		t.Fatalf("Log a: %v", err)
	}
	b, err := l.Log(ctx, makeEvent("b", time.Now(), "project.delete"))
	if err != nil {
		t.Fatalf("Log b: %v", err)
	}
	if !bytesEqual(b.PrevHash, a.Hash) {
		t.Fatalf("b.PrevHash != a.Hash")
	}
	if bytesEqual(b.Hash, a.Hash) {
		t.Fatalf("b.Hash == a.Hash — chain didn't move forward")
	}
}

func TestSQLiteLogger_Verify_CleanChain(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t)

	for i, id := range []string{"a", "b", "c", "d", "e"} {
		_, err := l.Log(ctx, makeEvent(id, time.Now().Add(time.Duration(i)*time.Millisecond), "project.create"))
		if err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	res, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Tamper {
		t.Fatalf("Verify reports tamper at index %d on a clean chain", res.FirstBadIndex)
	}
	if got, want := res.Total, int64(5); got != want {
		t.Errorf("Total = %d, want %d", got, want)
	}
}

func TestSQLiteLogger_Verify_DetectsHashTamper(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t)

	for i, id := range []string{"a", "b", "c"} {
		_, err := l.Log(ctx, makeEvent(id, time.Now().Add(time.Duration(i)*time.Millisecond), "project.create"))
		if err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	// Reach inside the SQLiteLogger's store and corrupt event "b"
	// (index 1). Direct DB write — simulates an attacker who
	// got file-system access to audit.db and rewrote bytes.
	sl, ok := l.(*SQLiteLogger)
	if !ok {
		t.Fatalf("expected *SQLiteLogger, got %T", l)
	}
	if _, err := sl.store.DB.ExecContext(ctx,
		"UPDATE events SET action = ? WHERE id = ?", "project.delete-cover-up", "b"); err != nil {
		t.Fatalf("tamper inject: %v", err)
	}

	res, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Tamper {
		t.Fatalf("Verify did not detect tamper")
	}
	// Chain is in chronological (asc) order during Verify; "b" is
	// index 1.
	if got, want := res.FirstBadIndex, int64(1); got != want {
		t.Errorf("FirstBadIndex = %d, want %d", got, want)
	}
}

func TestSQLiteLogger_Verify_DetectsLinkTamper(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t)

	for i, id := range []string{"a", "b", "c"} {
		_, err := l.Log(ctx, makeEvent(id, time.Now().Add(time.Duration(i)*time.Millisecond), "project.create"))
		if err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	// Cut the chain by zeroing event "b"'s prev_hash. Verify should
	// report tamper at index 1 (the broken link).
	sl, ok := l.(*SQLiteLogger)
	if !ok {
		t.Fatalf("expected *SQLiteLogger, got %T", l)
	}
	zeros := make([]byte, HashSize)
	if _, err := sl.store.DB.ExecContext(ctx,
		"UPDATE events SET prev_hash = ? WHERE id = ?", zeros, "b"); err != nil {
		t.Fatalf("link tamper inject: %v", err)
	}

	res, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Tamper || res.FirstBadIndex != 1 {
		t.Fatalf("Verify = %+v, want Tamper=true FirstBadIndex=1", res)
	}
}

func TestSQLiteLogger_Verify_EmptyChain(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t)

	res, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Tamper || res.Total != 0 {
		t.Fatalf("empty Verify = %+v, want Total=0 Tamper=false", res)
	}
}

func TestSQLiteLogger_PruneOlderThan(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t)

	// 5 events spaced 1 day apart, oldest first.
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, id := range []string{"a", "b", "c", "d", "e"} {
		_, err := l.Log(ctx, makeEvent(id, base.AddDate(0, 0, i), "project.create"))
		if err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	cutoff := base.AddDate(0, 0, 3) // keep last 2 (d, e)
	n, err := l.PruneOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("PruneOlderThan: %v", err)
	}
	if got, want := n, int64(3); got != want {
		t.Errorf("pruned = %d, want %d", got, want)
	}

	// The surviving suffix (d, e) must still verify cleanly even
	// though their PrevHash points at the now-deleted predecessor.
	res, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify post-prune: %v", err)
	}
	if res.Tamper {
		t.Fatalf("Verify reports tamper post-prune at index %d (Total=%d)", res.FirstBadIndex, res.Total)
	}
	if got, want := res.Total, int64(2); got != want {
		t.Errorf("Total post-prune = %d, want %d", got, want)
	}
}

func TestSQLiteLogger_List_FilterByActor(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t)

	now := time.Now()
	// 2 events for u-1, 1 event for u-2.
	bob := Actor{UserID: "u-2", Email: "bob@example.com"}
	for i, id := range []string{"a", "b", "c"} {
		e := makeEvent(id, now.Add(time.Duration(i)*time.Millisecond), "project.create")
		if id == "c" {
			e.Actor = bob
		}
		if _, err := l.Log(ctx, e); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	// Filter to u-1 → expect a, b only.
	page, err := l.List(ctx, Filter{ActorUserID: "u-1"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got, want := len(page.Events), 2; got != want {
		t.Fatalf("len = %d, want %d", got, want)
	}
}

func TestSQLiteLogger_List_FilterByResource(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t)

	now := time.Now()
	for i, id := range []string{"a", "b", "c"} {
		e := makeEvent(id, now.Add(time.Duration(i)*time.Millisecond), "project.create")
		// Force a specific resource on event "b".
		if id == "b" {
			e.ResourceType = ResourceCluster
			e.ResourceID = "cluster-prod"
		}
		if _, err := l.Log(ctx, e); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	page, err := l.List(ctx, Filter{ResourceType: ResourceCluster, ResourceID: "cluster-prod"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got, want := len(page.Events), 1; got != want {
		t.Fatalf("len = %d, want %d", got, want)
	}
	if page.Events[0].ID != "b" {
		t.Errorf("matched event = %s, want b", page.Events[0].ID)
	}
}

func TestSQLiteLogger_List_CursorPagination(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t)

	now := time.Now()
	for i := 0; i < 5; i++ {
		_, err := l.Log(ctx, makeEvent(string(rune('a'+i)), now.Add(time.Duration(i)*time.Millisecond), "project.create"))
		if err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}

	// Page size 2 → expect 3 pages: [e,d] [c,b] [a].
	page1, err := l.List(ctx, Filter{Limit: 2})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Events) != 2 || page1.NextCursor == "" {
		t.Fatalf("page1 = %+v, want 2 events + non-empty NextCursor", page1)
	}

	page2, err := l.List(ctx, Filter{Limit: 2, Cursor: page1.NextCursor})
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Events) != 2 {
		t.Fatalf("page2 events = %d, want 2", len(page2.Events))
	}

	page3, err := l.List(ctx, Filter{Limit: 2, Cursor: page2.NextCursor})
	if err != nil {
		t.Fatalf("page3: %v", err)
	}
	if len(page3.Events) != 1 || page3.NextCursor != "" {
		t.Fatalf("page3 = %+v, want 1 event + empty NextCursor", page3)
	}
}

func TestNoopLogger_AlwaysSilent(t *testing.T) {
	ctx := context.Background()
	l := NewNoopLogger()

	in := makeEvent("x", time.Now(), "test")
	out, err := l.Log(ctx, in)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if out.ID != in.ID {
		t.Errorf("Log echoed wrong event: %+v", out)
	}

	page, err := l.List(ctx, Filter{})
	if err != nil || len(page.Events) != 0 {
		t.Errorf("List = %+v, %v", page, err)
	}

	res, err := l.Verify(ctx)
	if err != nil || res.Total != 0 || res.Tamper {
		t.Errorf("Verify = %+v, %v", res, err)
	}

	n, err := l.PruneOlderThan(ctx, time.Now())
	if err != nil || n != 0 {
		t.Errorf("PruneOlderThan = %d, %v", n, err)
	}

	if err := l.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestNewSQLiteLogger_EmptyPath_Errors(t *testing.T) {
	if _, err := NewSQLiteLogger("", SQLiteLoggerOptions{}); err == nil {
		t.Fatal("expected error on empty dbPath")
	}
}

func TestEvent_BeforeAfterRoundTrip(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t)

	type project struct {
		Name string `json:"name"`
	}
	beforeBlob, _ := json.Marshal(project{Name: "old"})
	afterBlob, _ := json.Marshal(project{Name: "new"})

	in := makeEvent("a", time.Now(), "project.update")
	in.Before = beforeBlob
	in.After = afterBlob
	if _, err := l.Log(ctx, in); err != nil {
		t.Fatalf("Log: %v", err)
	}

	page, err := l.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Events) != 1 {
		t.Fatalf("len = %d, want 1", len(page.Events))
	}
	got := page.Events[0]
	if string(got.Before) != string(beforeBlob) {
		t.Errorf("Before = %q, want %q", got.Before, beforeBlob)
	}
	if string(got.After) != string(afterBlob) {
		t.Errorf("After = %q, want %q", got.After, afterBlob)
	}
}

// Sanity check — ensures sql.ErrNoRows doesn't leak through latestHash
// when callers use the package directly (as the audit middleware will
// in the next session). Empty DB → genesis prev_hash, not error.
func TestSQLiteLogger_LatestHash_EmptyDB(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)
	prev, err := l.latestHash(ctx)
	if err != nil {
		if !errIsNoRows(err) {
			t.Fatalf("latestHash on empty DB: %v", err)
		}
	}
	if got, want := len(prev), HashSize; got != want {
		t.Fatalf("len = %d, want %d", got, want)
	}
	for i, b := range prev {
		if b != 0 {
			t.Fatalf("prev[%d] = %x, want 0", i, b)
		}
	}
}

// errIsNoRows is the test-only sql.ErrNoRows recognise without
// pulling sql into the package's main surface.
func errIsNoRows(err error) bool {
	return err == sql.ErrNoRows
}

// TestActorFromContext_DefaultsToUser confirms the default-actor
// invariant: contexts that lack an explicit override resolve to
// ActorTypeUser. Every v0.6+ emission site that didn't set Type
// explicitly carries forward unchanged because of this.
func TestActorFromContext_DefaultsToUser(t *testing.T) {
	ctx := context.Background()
	got := ActorFromContext(ctx)
	if got.Type != ActorTypeUser {
		t.Errorf("default Actor.Type = %q, want %q", got.Type, ActorTypeUser)
	}
}

// TestWithActor_RoundTrip confirms WithActor + ActorFromContext are
// inverses for the three actor types.
func TestWithActor_RoundTrip(t *testing.T) {
	cases := []Actor{
		{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com", IP: "10.0.0.1"},
		ActorService("sa-1", "scim-provisioner", tenant.Single),
		ActorSystem("retention"),
	}
	for _, want := range cases {
		ctx := WithActor(context.Background(), want)
		got := ActorFromContext(ctx)
		if got != want {
			t.Errorf("round-trip mismatch:\n want %+v\n  got %+v", want, got)
		}
	}
}

// TestSQLiteLogger_HasChainRestartV2 confirms the boot path's idempotent
// check. Empty DB → false; after emitting the chain-restart row → true.
func TestSQLiteLogger_HasChainRestartV2(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	ok, err := l.HasChainRestartV2(ctx)
	if err != nil {
		t.Fatalf("HasChainRestartV2 (empty): %v", err)
	}
	if ok {
		t.Fatal("HasChainRestartV2 should be false on empty DB")
	}

	// Insert a v2 row at the canonical_version=2 shape.
	_, err = l.Log(ctx, Event{
		ID:               "chain-restart-1",
		At:               time.Now().UTC(),
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainRestart,
		ResourceType:     "system",
		CanonicalVersion: CanonicalVersion2,
	})
	if err != nil {
		t.Fatalf("Log: %v", err)
	}

	ok, err = l.HasChainRestartV2(ctx)
	if err != nil {
		t.Fatalf("HasChainRestartV2 (post-insert): %v", err)
	}
	if !ok {
		t.Fatal("HasChainRestartV2 should be true after v2 row inserted")
	}
}

// TestSQLiteLogger_Verify_WalksFromChainRestart confirms the v1.0
// Verify path: when a chain-restart row exists, walk only from that
// row forward — v0.9 rows in the table are skipped (they're a
// different canonical-shape segment that doesn't link forward into
// the v1.0 segment).
func TestSQLiteLogger_Verify_WalksFromChainRestart(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	base := time.Date(2026, 5, 15, 10, 0, 0, 0, time.UTC)

	// First: insert two v1-shape rows (pre-restart) via direct DB write.
	// Logger.Log rejects CanonicalVersion=1 emissions since v1.2 task
	// 04 (TD-AUDIT-05 closure) — the v1.0 bootstrap migration was
	// supposed to promote every v1 row to v2; v1 rows can only land
	// in the table via direct insert (an anomalous state we test the
	// verifier handles gracefully). The hashes here are intentionally
	// garbage — Verify's chain-restart-rooted walk excludes pre-restart
	// rows, so their hashes never get re-checked.
	for i, id := range []string{"v09-a", "v09-b"} {
		_, err := l.store.DB.ExecContext(ctx,
			`INSERT INTO events (
				id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name,
				action, resource_type, resource_id, cluster_id, request_id,
				before_json, after_json, prev_hash, hash, canonical_version
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, base.Add(time.Duration(i)*time.Second), "u-1", "alice@example.com",
			"", string(ActorTypeUser), "", "project.create", string(ResourceProject),
			"p-"+id, "", "", "", "",
			make([]byte, HashSize), make([]byte, HashSize), int64(CanonicalVersion1),
		)
		if err != nil {
			t.Fatalf("insert v0.9 fixture %s: %v", id, err)
		}
	}

	// Now the chain-restart row, v1.0 shape.
	restartAt := base.Add(10 * time.Second)
	if _, err := l.Log(ctx, Event{
		ID:               "v10-restart",
		At:               restartAt,
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainRestart,
		ResourceType:     "system",
		CanonicalVersion: CanonicalVersion2,
	}); err != nil {
		t.Fatalf("Log restart: %v", err)
	}

	// Three more v1.0 events.
	for i, id := range []string{"v10-a", "v10-b", "v10-c"} {
		e := Event{
			ID:               id,
			At:               restartAt.Add(time.Duration(i+1) * time.Second),
			Actor:            Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
			Action:           "project.create",
			ResourceType:     ResourceProject,
			ResourceID:       "p-" + id,
			CanonicalVersion: CanonicalVersion2,
		}
		if _, err := l.Log(ctx, e); err != nil {
			t.Fatalf("Log v1.0 %s: %v", id, err)
		}
	}

	res, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Tamper {
		t.Fatalf("Verify reported tamper at index %d on a contiguous v1.0 segment", res.FirstBadIndex)
	}
	// Total should be 4: the chain-restart + 3 subsequent v1.0
	// events. The 2 v0.9 rows are excluded.
	if got, want := res.Total, int64(4); got != want {
		t.Errorf("Verify.Total = %d, want %d (chain-restart + 3 v1.0 rows)", got, want)
	}
}

// TestActorService_NameField confirms TD-AUDIT-03 closure: the SA
// name lands in Actor.Name, not Actor.Email.
func TestActorService_NameField(t *testing.T) {
	a := ActorService("sa-123", "scim-provisioner", tenant.Single)
	if a.Type != ActorTypeServiceAccount {
		t.Errorf("Type = %q, want %q", a.Type, ActorTypeServiceAccount)
	}
	if a.UserID != "sa-123" {
		t.Errorf("UserID = %q, want %q", a.UserID, "sa-123")
	}
	if a.Name != "scim-provisioner" {
		t.Errorf("Name = %q, want %q", a.Name, "scim-provisioner")
	}
	if a.Email != "" {
		t.Errorf("Email = %q, want empty (name should land in Name, not Email)", a.Email)
	}
}

// TestActorSystem_NameField confirms TD-AUDIT-03 closure for system
// actors: the subsystem name lands in Actor.Name, not Actor.Email.
func TestActorSystem_NameField(t *testing.T) {
	a := ActorSystem("retention")
	if a.Type != ActorTypeSystem {
		t.Errorf("Type = %q, want %q", a.Type, ActorTypeSystem)
	}
	if a.UserID != "system" {
		t.Errorf("UserID = %q, want %q", a.UserID, "system")
	}
	if a.Name != "retention" {
		t.Errorf("Name = %q, want %q", a.Name, "retention")
	}
	if a.Email != "" {
		t.Errorf("Email = %q, want empty (name should land in Name, not Email)", a.Email)
	}
}

// TestEventCanonical_v3 confirms the v1.1 canonical payload includes
// actor.name bytes. Two events differing only in Actor.Name MUST
// produce different canonical payloads under v3.
func TestEventCanonical_v3(t *testing.T) {
	at := time.Date(2026, 5, 15, 10, 0, 0, 0, time.UTC)
	mk := func(name string) Event {
		return Event{
			ID:               "evt-1",
			At:               at,
			Actor:            Actor{Type: ActorTypeSystem, UserID: "system", Name: name},
			Action:           ActionAuditChainRestart,
			ResourceType:     "system",
			CanonicalVersion: CanonicalVersion3,
		}
	}
	a := canonicalPayload(mk("barista"))
	b := canonicalPayload(mk("retention"))
	if string(a) == string(b) {
		t.Fatal("v3 canonical payloads should differ when Actor.Name differs")
	}
	// The shorter Name ("barista") payload must be strictly smaller
	// (or different length) than the longer ("retention") — confirms
	// the name bytes are actually being length-prefixed in.
	if len(a) == len(b) {
		t.Errorf("v3 canonical payloads differ only by Name but have equal length (%d) — name bytes not included?", len(a))
	}
}

// TestEventCanonical_v2_legacy confirms the v1.0 (canonical_version=2)
// canonical payload is the pipe-separated shape reproduced by
// canonicalPayloadLegacyV2 (closes TD-AUDIT-05 in v1.2 task 04;
// v1.4 — TD-AUDIT-09 — switched the timestamp field to UnixNano()).
// The encoding is `hex(prev_hash) | int64(at.UnixNano()) | actor.type
// | actor.name | action | resource_type | resource_id | cluster_id |
// data_json` — pipe-separated, free-text fields not length-prefixed.
//
// Two properties asserted:
//
//  1. Different Actor.Name → different bytes. The v2 shape includes
//     actor.name; the original v1.0 binary that wrote these rows
//     placed the SA / system actor's human-readable name in this
//     position. The collision class on '|' is accepted as historical
//     fact (motivated v=3's length-prefixed switch).
//  2. Output is NOT length-prefixed — contains literal '|' bytes and
//     the timestamp is a base-10 int64 string. Distinguishes v2 from
//     v3 at a glance.
func TestEventCanonical_v2_legacy(t *testing.T) {
	at := time.Date(2026, 5, 15, 10, 0, 0, 0, time.UTC)
	mk := func(name string) Event {
		return Event{
			ID:               "evt-1",
			At:               at,
			Actor:            Actor{Type: ActorTypeSystem, UserID: "system", Name: name},
			Action:           ActionAuditChainRestart,
			ResourceType:     "system",
			CanonicalVersion: CanonicalVersion2,
		}
	}
	a := canonicalPayload(mk("barista"))
	b := canonicalPayload(mk("retention"))
	if string(a) == string(b) {
		t.Fatal("v2 canonical payloads should differ when Actor.Name differs (name IS part of v1.0's pipe-separated shape)")
	}
	// Output must contain literal '|' bytes — the v2 shape is
	// pipe-separated, not length-prefixed. This is the property that
	// distinguishes v2 from v3 visually + bytes-wise.
	if !strings.Contains(string(a), "|") {
		t.Fatal("v2 canonical payload should contain literal '|' bytes (pipe-separated encoding)")
	}
	// Output must contain the UnixNano int64-string-formatted timestamp
	// (v1.4 — TD-AUDIT-09 closure; pre-v1.4 used RFC3339Nano).
	wantNanos := strconv.FormatInt(at.UnixNano(), 10)
	if !strings.Contains(string(a), wantNanos) {
		t.Fatalf("v2 canonical payload should embed UnixNano timestamp %q", wantNanos)
	}
	// Output must NOT contain the RFC3339Nano-formatted timestamp —
	// the v1.4 encoder swap is load-bearing.
	rfc := at.UTC().Format(time.RFC3339Nano)
	if strings.Contains(string(a), rfc) {
		t.Fatalf("v2 canonical payload should not embed RFC3339Nano timestamp %q (pre-v1.4 encoding)", rfc)
	}
}

// TestSQLiteLogger_EmailLookup_Enriches confirms TD-AUDIT-04
// closure: a user-type emission with empty Email but non-empty
// UserID gets enriched at Log time when the logger is constructed
// with an EmailLookup option.
func TestSQLiteLogger_EmailLookup_Enriches(t *testing.T) {
	ctx := context.Background()
	lookups := map[string]string{
		"u-1": "alice@example.com",
		"u-2": "bob@example.com",
	}
	l := newSQLiteLoggerForTestWithOpts(t, SQLiteLoggerOptions{
		EmailLookup: func(_ context.Context, userID string) (string, bool) {
			email, ok := lookups[userID]
			return email, ok
		},
	})

	// User actor with empty Email + non-empty UserID. Logger must
	// enrich at emit time.
	in := Event{
		ID:           "evt-enrich-1",
		At:           time.Now().UTC(),
		Actor:        Actor{Type: ActorTypeUser, UserID: "u-1"},
		Action:       "project.create",
		ResourceType: ResourceProject,
		ResourceID:   "p-1",
	}
	if _, err := l.Log(ctx, in); err != nil {
		t.Fatalf("Log: %v", err)
	}

	page, err := l.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Events) == 0 {
		t.Fatal("expected 1 event, got 0")
	}
	got := page.Events[0]
	if got.Actor.Email != "alice@example.com" {
		t.Errorf("Email = %q, want %q (EmailLookup should have populated it)", got.Actor.Email, "alice@example.com")
	}
}

// TestSQLiteLogger_EmailLookup_NoOp confirms the negative cases:
//   - User actor with pre-populated Email is left alone (no lookup
//     wasted on a row that already has an email).
//   - System actor never triggers lookup (no email semantically).
//   - Service-account actor never triggers lookup (no email
//     semantically).
//   - Lookup returning (_, false) leaves Email empty (best-effort).
func TestSQLiteLogger_EmailLookup_NoOp(t *testing.T) {
	ctx := context.Background()
	lookupCalls := 0
	l := newSQLiteLoggerForTestWithOpts(t, SQLiteLoggerOptions{
		EmailLookup: func(_ context.Context, userID string) (string, bool) {
			lookupCalls++
			if userID == "u-existing" {
				// Should not be invoked for u-existing because Email
				// is already populated. If we get here, the guard is
				// broken.
				return "wrong@example.com", true
			}
			return "", false
		},
	})

	cases := []struct {
		name        string
		actor       Actor
		wantEmail   string
		wantLookups int
	}{
		{
			name:        "user with email — no lookup",
			actor:       Actor{Type: ActorTypeUser, UserID: "u-existing", Email: "right@example.com"},
			wantEmail:   "right@example.com",
			wantLookups: 0,
		},
		{
			name:        "system actor — no lookup",
			actor:       ActorSystem("retention"),
			wantEmail:   "",
			wantLookups: 0,
		},
		{
			name:        "service_account actor — no lookup",
			actor:       ActorService("sa-1", "scim-provisioner", tenant.Single),
			wantEmail:   "",
			wantLookups: 0,
		},
		{
			name:        "user, lookup returns (_, false) — empty email",
			actor:       Actor{Type: ActorTypeUser, UserID: "u-unknown"},
			wantEmail:   "",
			wantLookups: 1,
		},
	}

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lookupCalls = 0
			id := "evt-noop-" + string(rune('a'+i))
			_, err := l.Log(ctx, Event{
				ID:           id,
				At:           time.Now().UTC().Add(time.Duration(i) * time.Millisecond),
				Actor:        c.actor,
				Action:       "project.create",
				ResourceType: ResourceProject,
				ResourceID:   "p-" + id,
			})
			if err != nil {
				t.Fatalf("Log: %v", err)
			}
			if lookupCalls != c.wantLookups {
				t.Errorf("lookupCalls = %d, want %d", lookupCalls, c.wantLookups)
			}
			page, err := l.List(ctx, Filter{Limit: 1})
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(page.Events) == 0 {
				t.Fatal("expected at least 1 event")
			}
			if got := page.Events[0].Actor.Email; got != c.wantEmail {
				t.Errorf("Actor.Email = %q, want %q", got, c.wantEmail)
			}
		})
	}
}

// TestHasChainRestartV3 confirms the boot-path idempotent check.
// Empty DB → false; after emitting a v3 row → true.
func TestHasChainRestartV3(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	ok, err := l.HasChainRestartV3(ctx)
	if err != nil {
		t.Fatalf("HasChainRestartV3 (empty): %v", err)
	}
	if ok {
		t.Fatal("HasChainRestartV3 should be false on empty DB")
	}

	// Insert a v2 row first — HasChainRestartV3 must still be false.
	if _, err := l.Log(ctx, Event{
		ID:               "chain-restart-v2",
		At:               time.Now().UTC(),
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainRestart,
		ResourceType:     "system",
		CanonicalVersion: CanonicalVersion2,
	}); err != nil {
		t.Fatalf("Log v2 restart: %v", err)
	}

	ok, err = l.HasChainRestartV3(ctx)
	if err != nil {
		t.Fatalf("HasChainRestartV3 (after v2): %v", err)
	}
	if ok {
		t.Fatal("HasChainRestartV3 should still be false when only v2 row present")
	}

	// Now insert a v3 row.
	if _, err := l.Log(ctx, Event{
		ID:               "chain-restart-v3",
		At:               time.Now().UTC().Add(time.Second),
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainRestart,
		ResourceType:     "system",
		CanonicalVersion: CanonicalVersion3,
	}); err != nil {
		t.Fatalf("Log v3 restart: %v", err)
	}

	ok, err = l.HasChainRestartV3(ctx)
	if err != nil {
		t.Fatalf("HasChainRestartV3 (post-insert): %v", err)
	}
	if !ok {
		t.Fatal("HasChainRestartV3 should be true after v3 row inserted")
	}
}

// TestVerify_DefaultsToLatestChainStart confirms the v1.1 Verify
// default: walk from v3 row when present, v2 row when v3 absent,
// row 0 when no restart marker exists at all.
func TestVerify_DefaultsToLatestChainStart(t *testing.T) {
	ctx := context.Background()

	// Case 1: no restart marker → walks from row 0 under per-row
	// canonical_version. With three default-v3 events, verify must
	// report Total=3.
	t.Run("no_restart_marker", func(t *testing.T) {
		l := newSQLiteLoggerForTest(t)
		for i, id := range []string{"a", "b", "c"} {
			if _, err := l.Log(ctx, makeEvent(id, time.Now().Add(time.Duration(i)*time.Millisecond), "project.create")); err != nil {
				t.Fatalf("Log %s: %v", id, err)
			}
		}
		res, err := l.Verify(ctx)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if res.Tamper {
			t.Fatalf("Verify reported tamper at index %d on a fresh v1.1 segment", res.FirstBadIndex)
		}
		if got, want := res.Total, int64(3); got != want {
			t.Errorf("Total = %d, want %d", got, want)
		}
	})

	// Case 2: v2 restart marker only → Verify walks from v2 row +
	// re-hashes successors under v2 shape.
	t.Run("v2_only", func(t *testing.T) {
		l := newSQLiteLoggerForTest(t)
		base := time.Date(2026, 5, 15, 10, 0, 0, 0, time.UTC)
		// v2 chain-restart row.
		if _, err := l.Log(ctx, Event{
			ID:               "v2-restart",
			At:               base,
			Actor:            ActorSystem("barista"),
			Action:           ActionAuditChainRestart,
			ResourceType:     "system",
			CanonicalVersion: CanonicalVersion2,
		}); err != nil {
			t.Fatalf("Log v2 restart: %v", err)
		}
		// Two v2 successors.
		for i, id := range []string{"v2-a", "v2-b"} {
			if _, err := l.Log(ctx, Event{
				ID:               id,
				At:               base.Add(time.Duration(i+1) * time.Second),
				Actor:            Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
				Action:           "project.create",
				ResourceType:     ResourceProject,
				ResourceID:       "p-" + id,
				CanonicalVersion: CanonicalVersion2,
			}); err != nil {
				t.Fatalf("Log %s: %v", id, err)
			}
		}
		res, err := l.Verify(ctx)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if res.Tamper {
			t.Fatalf("Verify reported tamper at index %d on v2-only segment", res.FirstBadIndex)
		}
		if got, want := res.Total, int64(3); got != want {
			t.Errorf("Total = %d, want %d (restart + 2 v2 events)", got, want)
		}
	})

	// Case 3: both v2 + v3 restart markers → Verify walks from the
	// MORE-RECENT (v3) row.
	t.Run("v2_then_v3", func(t *testing.T) {
		l := newSQLiteLoggerForTest(t)
		base := time.Date(2026, 5, 15, 10, 0, 0, 0, time.UTC)
		// v2 restart + 2 v2 successors.
		if _, err := l.Log(ctx, Event{
			ID:               "v2-restart",
			At:               base,
			Actor:            ActorSystem("barista"),
			Action:           ActionAuditChainRestart,
			ResourceType:     "system",
			CanonicalVersion: CanonicalVersion2,
		}); err != nil {
			t.Fatalf("Log v2 restart: %v", err)
		}
		for i, id := range []string{"v2-a", "v2-b"} {
			if _, err := l.Log(ctx, Event{
				ID:               id,
				At:               base.Add(time.Duration(i+1) * time.Second),
				Actor:            Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
				Action:           "project.create",
				ResourceType:     ResourceProject,
				ResourceID:       "p-" + id,
				CanonicalVersion: CanonicalVersion2,
			}); err != nil {
				t.Fatalf("Log %s: %v", id, err)
			}
		}
		// v3 restart + 3 v3 successors.
		restartV3At := base.Add(10 * time.Second)
		if _, err := l.Log(ctx, Event{
			ID:               "v3-restart",
			At:               restartV3At,
			Actor:            ActorSystem("barista"),
			Action:           ActionAuditChainRestart,
			ResourceType:     "system",
			CanonicalVersion: CanonicalVersion3,
		}); err != nil {
			t.Fatalf("Log v3 restart: %v", err)
		}
		for i, id := range []string{"v3-a", "v3-b", "v3-c"} {
			if _, err := l.Log(ctx, Event{
				ID:           id,
				At:           restartV3At.Add(time.Duration(i+1) * time.Second),
				Actor:        Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
				Action:       "project.create",
				ResourceType: ResourceProject,
				ResourceID:   "p-" + id,
				// CanonicalVersion left zero — default to v3.
			}); err != nil {
				t.Fatalf("Log %s: %v", id, err)
			}
		}
		res, err := l.Verify(ctx)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if res.Tamper {
			t.Fatalf("Verify reported tamper at index %d on v3 segment", res.FirstBadIndex)
		}
		// Total = v3 restart + 3 v3 successors = 4. v2 rows excluded.
		if got, want := res.Total, int64(4); got != want {
			t.Errorf("Total = %d, want %d (v3 restart + 3 v3 successors)", got, want)
		}

		// Legacy walk under v2 should also work and report 3 rows
		// (v2 restart + 2 v2 successors).
		sl := l.(*SQLiteLogger)
		legacy, err := sl.VerifyLegacy(ctx, CanonicalVersion2, "")
		if err != nil {
			t.Fatalf("VerifyLegacy v2: %v", err)
		}
		if legacy.Tamper {
			t.Fatalf("VerifyLegacy v2 reported tamper at index %d", legacy.FirstBadIndex)
		}
		if got, want := legacy.Total, int64(3); got != want {
			t.Errorf("VerifyLegacy v2 Total = %d, want %d (v2 restart + 2 v2 successors)", got, want)
		}
	})
}

// TestLog_HonorsCanonicalVersion_V2 asserts Logger.Log respects an
// explicit CanonicalVersion: 2 by hashing the row under
// canonicalPayloadLegacyV2 (v1.0 pipe-separated shape) — NOT under
// canonicalPayloadV3.
//
// Regression guard for TD-AUDIT-08. The v1.2 walk Step 59.2 surfaced
// a "tamper at index 0" symptom on `audit verify --legacy
// --canonical-version=2` against the bootstrap chain-restart row. Code
// reading at v1.3 scope time showed Logger.Log already honors
// e.CanonicalVersion via computeHash dispatch (audit_sqlite.go line
// 140-143); this test makes the round-trip property load-bearing so a
// future regression that re-introduces a default-to-v3 bug surfaces
// here rather than at walk time.
func TestLog_HonorsCanonicalVersion_V2(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	in := Event{
		ID:               "v2-row",
		At:               time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC),
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainRestart,
		ResourceType:     "system",
		CanonicalVersion: CanonicalVersion2,
	}
	out, err := l.Log(ctx, in)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}

	// Recompute the expected hash under canonicalPayloadLegacyV2 with
	// the genesis prev (32 zero bytes). The result must equal the
	// stored Hash.
	genesisPrev := make([]byte, HashSize)
	wantPayload := canonicalPayloadLegacyV2(out, genesisPrev)
	hh := sha256.New()
	hh.Write(genesisPrev)
	hh.Write(wantPayload)
	want := hh.Sum(nil)
	if !bytesEqual(out.Hash, want) {
		t.Errorf("stored Hash mismatches canonicalPayloadLegacyV2 round-trip\n got:  %x\n want: %x", out.Hash, want)
	}

	// Cross-check: the v3 encoder must produce a DIFFERENT hash for
	// the same event (since v2 + v3 encode actor.name + actor.type
	// differently). If they match, the dispatch is broken (Log is
	// always using v3).
	v3Payload := canonicalPayloadV3(out, genesisPrev)
	v3h := sha256.New()
	v3h.Write(genesisPrev)
	v3h.Write(v3Payload)
	v3Hash := v3h.Sum(nil)
	if bytesEqual(out.Hash, v3Hash) {
		t.Errorf("stored Hash matches v3 encoder shape — Log did not honor CanonicalVersion=2")
	}
}

// TestLog_HonorsCanonicalVersion_V3 asserts Logger.Log under an
// explicit CanonicalVersion: 3 hashes the row under
// canonicalPayloadV3 (v1.1+ length-prefixed shape). Complements
// TestLog_HonorsCanonicalVersion_V2 — together they exercise both
// branches of the canonicalPayloadForVersion dispatch table.
func TestLog_HonorsCanonicalVersion_V3(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	in := Event{
		ID:               "v3-row",
		At:               time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC),
		Actor:            Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
		Action:           "project.create",
		ResourceType:     ResourceProject,
		ResourceID:       "p-v3",
		CanonicalVersion: CanonicalVersion3,
	}
	out, err := l.Log(ctx, in)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}

	genesisPrev := make([]byte, HashSize)
	wantPayload := canonicalPayloadV3(out, genesisPrev)
	hh := sha256.New()
	hh.Write(genesisPrev)
	hh.Write(wantPayload)
	want := hh.Sum(nil)
	if !bytesEqual(out.Hash, want) {
		t.Errorf("stored Hash mismatches canonicalPayloadV3 round-trip\n got:  %x\n want: %x", out.Hash, want)
	}
}

// TestLog_DefaultsToV3WhenUnset asserts Logger.Log promotes
// CanonicalVersion=0 to CanonicalVersion3 at emit time + persists the
// row at canonical_version=3. v0.6+ emission sites that built Event
// literals without setting CanonicalVersion explicitly rely on this
// default — the test pins it.
func TestLog_DefaultsToV3WhenUnset(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	in := Event{
		ID:           "default-v3",
		At:           time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC),
		Actor:        Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
		Action:       "project.create",
		ResourceType: ResourceProject,
		ResourceID:   "p-default",
		// CanonicalVersion intentionally unset (= 0).
	}
	out, err := l.Log(ctx, in)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if got, want := out.CanonicalVersion, CanonicalVersion3; got != want {
		t.Errorf("CanonicalVersion = %d, want %d (Log should default 0 → 3)", got, want)
	}

	// Stored column must read back as 3 too (defensive — confirms the
	// default is persisted, not just stamped on the in-memory Event).
	page, err := l.List(ctx, Filter{Limit: 1})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Events) != 1 {
		t.Fatalf("List returned %d events, want 1", len(page.Events))
	}
	if got, want := page.Events[0].CanonicalVersion, CanonicalVersion3; got != want {
		t.Errorf("persisted canonical_version = %d, want %d", got, want)
	}

	// Hash must match canonicalPayloadV3.
	genesisPrev := make([]byte, HashSize)
	wantPayload := canonicalPayloadV3(out, genesisPrev)
	hh := sha256.New()
	hh.Write(genesisPrev)
	hh.Write(wantPayload)
	want := hh.Sum(nil)
	if !bytesEqual(out.Hash, want) {
		t.Errorf("default-v3 row Hash mismatches canonicalPayloadV3\n got:  %x\n want: %x", out.Hash, want)
	}
}

// insertChainRestartForTest mirrors the shape of
// cmd/barista/main.go::insertChainRestartIfMissing — emits a system-
// actor `system.audit.chain_restart` row via Logger.Log under the
// requested CanonicalVersion. Lives in the audit-package tests so the
// integration round-trip is asserted without pulling cmd/barista into
// the test surface (which would create a circular dependency).
//
// The production helper at cmd/barista/main.go has additional
// idempotency + uuid generation + logging — that helper is still the
// authoritative call site at boot. This is the test-side proxy: same
// Event shape (Actor.System("barista"), Action=ActionAuditChainRestart,
// ResourceType="system", CanonicalVersion=N), so any future change in
// either the helper or the integration shape stays linked.
func insertChainRestartForTest(t *testing.T, l Logger, version int) {
	t.Helper()
	ctx := context.Background()
	if _, err := l.Log(ctx, Event{
		ID:               "chain-restart-v" + string(rune('0'+version)),
		At:               time.Now().UTC(),
		Actor:            ActorSystem("barista"),
		Action:           ActionAuditChainRestart,
		ResourceType:     "system",
		CanonicalVersion: version,
	}); err != nil {
		t.Fatalf("insert chain-restart v%d: %v", version, err)
	}
}

// TestBootstrapChainRestart_VerifyLegacyClean drives the bootstrap
// chain-restart insertion path end-to-end against a fresh audit DB
// + asserts both VerifyLegacy(CanonicalVersion2) and Verify (default)
// walk cleanly afterwards. Direct integration test for TD-AUDIT-08
// closure — the v1.2 walk Step 59.2 symptom ("tamper at index 0" on
// `--legacy --canonical-version=2`) is the property under test here.
//
// Mirrors cmd/barista/main.go::bootstrapAuditChainRestart: a v=2 row
// is inserted via Logger.Log first, then a v=3 row. Verify (default)
// walks from the latest restart marker (v3); VerifyLegacy(2) walks
// from the v2 restart row forward — both must report a clean chain.
func TestBootstrapChainRestart_VerifyLegacyClean(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t).(*SQLiteLogger)

	// Emit both chain-restart rows in the same order cmd/barista's
	// bootstrap does: v=2 first, then v=3. The v=3 row's PrevHash
	// links to the v=2 row's Hash via Log's latestHash path.
	insertChainRestartForTest(t, l, CanonicalVersion2)
	insertChainRestartForTest(t, l, CanonicalVersion3)

	// Legacy walk under v=2 — the symptom the v1.2 walk Step 59.2 hit.
	// Must return a clean chain with the single v=2 row (the v=3 row
	// is at a different canonical_version and never appears in the
	// v=2 segment query).
	legacy, err := l.VerifyLegacy(ctx, CanonicalVersion2, "")
	if err != nil {
		t.Fatalf("VerifyLegacy(2): %v", err)
	}
	if legacy.Tamper {
		t.Fatalf("VerifyLegacy(2) reported tamper at index %d on a clean bootstrap chain", legacy.FirstBadIndex)
	}
	if got, want := legacy.Total, int64(1); got != want {
		t.Errorf("VerifyLegacy(2).Total = %d, want %d (v=2 chain-restart row only)", got, want)
	}

	// Default Verify path — must walk from the v=3 restart row
	// forward and report a clean chain (the v3 segment contains only
	// the v=3 restart row at this point).
	def, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if def.Tamper {
		t.Fatalf("Verify reported tamper at index %d on a clean v3 chain", def.FirstBadIndex)
	}
	if got, want := def.Total, int64(1); got != want {
		t.Errorf("Verify.Total = %d, want %d (v=3 chain-restart row only)", got, want)
	}
}

// TestEvent_ClusterID_Roundtrip confirms v1.1 task 04: writing an
// event with ClusterID=X persists the value and reads it back through
// both List + ListScoped. Belongs alongside the canonical-shape tests
// because cluster_id is the new wire field, but it's NOT part of the
// canonical-payload hash so this test asserts ONLY the
// persistence-round-trip property, not anything chain-related.
func TestEvent_ClusterID_Roundtrip(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t)

	base := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	in := Event{
		ID:           "evt-cluster-rt",
		At:           base,
		Actor:        Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
		Action:       "app.create",
		ResourceType: ResourceApp,
		ResourceID:   "app-1",
		ClusterID:    "cluster-A",
	}
	if _, err := l.Log(ctx, in); err != nil {
		t.Fatalf("Log: %v", err)
	}

	// List path: ClusterID round-trips on the unscoped read.
	page, err := l.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Events) != 1 {
		t.Fatalf("List events = %d, want 1", len(page.Events))
	}
	if got := page.Events[0].ClusterID; got != "cluster-A" {
		t.Errorf("List Events[0].ClusterID = %q, want %q", got, "cluster-A")
	}

	// ListScoped path: passing cluster-A as a reachable cluster returns
	// the event. The non-cluster-scoped branch of the WHERE clause
	// (cluster_id = '') is unreachable here since we only inserted one
	// row.
	page, err = l.ListScoped(ctx, []string{"cluster-A"}, Filter{})
	if err != nil {
		t.Fatalf("ListScoped: %v", err)
	}
	if len(page.Events) != 1 {
		t.Fatalf("ListScoped events = %d, want 1", len(page.Events))
	}
	if got := page.Events[0].ClusterID; got != "cluster-A" {
		t.Errorf("ListScoped Events[0].ClusterID = %q, want %q", got, "cluster-A")
	}
}

// TestListScoped_FilterCorrectness asserts the v1.1 task 04 scope
// filter semantics across the four (admin, deployer-on-A, viewer-on-B,
// no-acls) caller cases. Each case feeds a different reachable
// cluster set into ListScoped against the SAME fixture event stream
// and asserts the right subset comes back.
//
// Note: the system-cluster-admin case is the HANDLER's dispatch
// concern (it skips ListScoped and calls List). At the logger layer,
// "admin sees everything" means "passing every cluster id to
// ListScoped returns every cluster-scoped row plus every empty-scope
// row" — that's the upper-bound assertion here.
func TestListScoped_FilterCorrectness(t *testing.T) {
	ctx := context.Background()
	l := newSQLiteLoggerForTest(t)

	base := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)

	// Fixture: 6 events.
	//   - 2 non-cluster-scoped (auth.login, auth.register; empty
	//     ClusterID).
	//   - 2 on cluster-A (app.create, deployment.create).
	//   - 2 on cluster-B (app.create, deployment.create).
	type evt struct {
		id        string
		action    Action
		clusterID string
	}
	fixture := []evt{
		{"e1", "auth.login", ""},
		{"e2", "app.create", "cluster-A"},
		{"e3", "auth.register", ""},
		{"e4", "deployment.create", "cluster-A"},
		{"e5", "app.create", "cluster-B"},
		{"e6", "deployment.create", "cluster-B"},
	}
	for i, f := range fixture {
		_, err := l.Log(ctx, Event{
			ID:           f.id,
			At:           base.Add(time.Duration(i) * time.Second),
			Actor:        Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com"},
			Action:       f.action,
			ResourceType: ResourceApp,
			ResourceID:   "x",
			ClusterID:    f.clusterID,
		})
		if err != nil {
			t.Fatalf("Log %s: %v", f.id, err)
		}
	}

	// Build a quick lookup of expected IDs per case.
	containsID := func(events []Event, id string) bool {
		for _, e := range events {
			if e.ID == id {
				return true
			}
		}
		return false
	}

	cases := []struct {
		name        string
		clusterIDs  []string
		expectedIDs []string
	}{
		// "Admin" at this layer = caller reaches via all cluster IDs.
		// Returns every row (4 cluster-scoped + 2 non-cluster-scoped).
		{
			name:        "all_reachable",
			clusterIDs:  []string{"cluster-A", "cluster-B"},
			expectedIDs: []string{"e1", "e2", "e3", "e4", "e5", "e6"},
		},
		// Deployer-on-A sees A's events + non-cluster-scoped, not B.
		{
			name:        "deployer_on_A",
			clusterIDs:  []string{"cluster-A"},
			expectedIDs: []string{"e1", "e2", "e3", "e4"},
		},
		// Viewer-on-B sees B's events + non-cluster-scoped, not A.
		{
			name:        "viewer_on_B",
			clusterIDs:  []string{"cluster-B"},
			expectedIDs: []string{"e1", "e3", "e5", "e6"},
		},
		// No ACL grants → only non-cluster-scoped rows.
		{
			name:        "no_acls",
			clusterIDs:  []string{},
			expectedIDs: []string{"e1", "e3"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			page, err := l.ListScoped(ctx, c.clusterIDs, Filter{})
			if err != nil {
				t.Fatalf("ListScoped: %v", err)
			}
			if got, want := len(page.Events), len(c.expectedIDs); got != want {
				t.Fatalf("ListScoped returned %d events, want %d (events: %+v)", got, want, page.Events)
			}
			for _, want := range c.expectedIDs {
				if !containsID(page.Events, want) {
					t.Errorf("expected event %q in scoped result, missing", want)
				}
			}
		})
	}
}

// TestIsReservedAction pins the reserved-namespace guard consumers use to
// keep untrusted input from minting a chain-anchor action (which would
// truncate Verify's walk root — see IsReservedAction's doc).
func TestIsReservedAction(t *testing.T) {
	reserved := []Action{
		ActionAuditChainRestart,
		ActionAuditChainMigrate,
		"system.audit.chain_restart", // the exact truncation-attack string
		"system.audit.anything",      // whole namespace is fenced
		Action(ReservedActionPrefix), // the bare prefix
	}
	for _, a := range reserved {
		if !IsReservedAction(a) {
			t.Errorf("IsReservedAction(%q) = false, want true", a)
		}
	}
	ordinary := []Action{
		"project.create", "auth.login", "cluster.member.grant",
		"system.audit", // no trailing dot — not in the namespace
		"", "system", "audit.system.chain_restart",
	}
	for _, a := range ordinary {
		if IsReservedAction(a) {
			t.Errorf("IsReservedAction(%q) = true, want false", a)
		}
	}
}
