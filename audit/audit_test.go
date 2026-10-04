package audit

import (
	"context"
	"encoding/json"
	"github.com/suryakencana007/tamper/tenant"
	"path/filepath"
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
