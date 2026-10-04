package audit

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every row is canonical_version=4. These tests pin the three places
// that make it so: what Log writes, what Log refuses, and what
// NewSQLiteLogger refuses to open.

// singleTenantEvent is an event exactly as a single-tenant deployment
// emits one: PII present, TenantID never set anywhere.
func singleTenantEvent(id string, at time.Time) Event {
	return Event{
		ID: id,
		At: at,
		Actor: Actor{
			Type:  ActorTypeUser,
			Email: "alice@example.com",
			Name:  "Alice",
			IP:    "203.0.113.7",
		},
		Action:       "auth.login",
		ResourceType: "user",
	}
}

// eventByID reads one stored event back through List.
func eventByID(t *testing.T, l Logger, id string) Event {
	t.Helper()
	page, err := l.List(context.Background(), Filter{Limit: 100})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, e := range page.Events {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("event %q not found", id)
	return Event{}
}

// A logger built with default options writes v4, salts the row and
// commits to its PII — with no tenant anywhere on the event.
func TestLog_WritesV4ByDefault(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)

	got, err := l.Log(ctx, singleTenantEvent("a", time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if got.CanonicalVersion != CanonicalVersion4 {
		t.Fatalf("CanonicalVersion = %d, want %d", got.CanonicalVersion, CanonicalVersion4)
	}
	if got.TenantID != "" || got.Actor.TenantID != "" {
		t.Fatalf("a single-tenant event grew a tenant: event=%q actor=%q", got.TenantID, got.Actor.TenantID)
	}
	if len(got.RowSalt) != RowSaltSize || IsRedacted(got.RowSalt) {
		t.Fatalf("RowSalt = %x, want %d fresh random bytes", got.RowSalt, RowSaltSize)
	}
	if len(got.Commitments.ActorEmail) != CommitmentSize {
		t.Fatalf("no commitment to the actor email: %x", got.Commitments.ActorEmail)
	}
	if stored := eventByID(t, l, "a"); stored.CanonicalVersion != CanonicalVersion4 {
		t.Fatalf("stored canonical_version = %d, want %d", stored.CanonicalVersion, CanonicalVersion4)
	}
}

// An explicit CanonicalVersion4 is accepted; every other explicit
// version is refused and writes nothing.
func TestLog_RefusesEveryVersionButV4(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC)

	explicit := singleTenantEvent("explicit-v4", base)
	explicit.CanonicalVersion = CanonicalVersion4
	if _, err := l.Log(ctx, explicit); err != nil {
		t.Fatalf("explicit CanonicalVersion4 was refused: %v", err)
	}

	for _, version := range []int{1, 2, 3, 5, -1} {
		e := singleTenantEvent("refused", base.Add(time.Second))
		e.CanonicalVersion = version
		_, err := l.Log(ctx, e)
		if err == nil {
			t.Fatalf("Log accepted canonical_version=%d; such a row has no encoder and "+
				"would read as tamper on every verify", version)
		}
		if !strings.Contains(err.Error(), "canonical_version=4") {
			t.Errorf("version %d: the error should say which version is written, got %q", version, err)
		}
	}

	page, err := l.List(ctx, Filter{Limit: 100})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Events) != 1 || page.Events[0].ID != "explicit-v4" {
		t.Fatalf("a refused event left a row behind: %+v", page.Events)
	}
	if vr, err := l.Verify(ctx); err != nil || vr.Tamper || vr.Total != 1 {
		t.Fatalf("Verify after refusals = %+v err=%v, want 1 clean row", vr, err)
	}
}

// A DB that holds a row at another version is refused at open, with an
// error that says what the problem is and what to do.
func TestNewSQLiteLogger_RefusesPreV4Rows(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "audit.db")

	first, err := NewSQLiteLogger(dbPath, SQLiteLoggerOptions{})
	if err != nil {
		t.Fatalf("NewSQLiteLogger: %v", err)
	}
	sl := first.(*SQLiteLogger)
	if _, err := sl.Log(ctx, singleTenantEvent("v4-row", time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC))); err != nil {
		t.Fatalf("Log: %v", err)
	}
	// Log would never write this row, so it is inserted directly: a row
	// left behind by a version of the package that still wrote v3.
	old := singleTenantEvent("v3-row", time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC))
	old.CanonicalVersion = 3
	old.PrevHash = make([]byte, HashSize)
	old.Hash = make([]byte, HashSize)
	if err := InsertEventDirectForTest(ctx, sl, old); err != nil {
		t.Fatalf("seed pre-v4 row: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := NewSQLiteLogger(dbPath, SQLiteLoggerOptions{})
	if err == nil {
		_ = reopened.Close()
		t.Fatal("NewSQLiteLogger opened a DB that holds a canonical_version=3 row")
	}
	// Both causes are named, and the file is never called disposable: a
	// relabelled row is tampering, and the error cannot tell which it is.
	for _, want := range []string{"canonical_version=3", dbPath, "Keep the file", "new audit DB", "altered"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should contain %q, got %q", want, err)
		}
	}
}

// seedDirect inserts a row Log would never write, at the given version.
func seedDirect(t *testing.T, l *SQLiteLogger, id string, version int, at time.Time) {
	t.Helper()
	e := singleTenantEvent(id, at)
	e.CanonicalVersion = version
	e.PrevHash = make([]byte, HashSize)
	e.Hash = make([]byte, HashSize)
	if err := InsertEventDirectForTest(context.Background(), l, e); err != nil {
		t.Fatalf("seed %s at v%d: %v", id, version, err)
	}
}

// reopenErr closes l and returns the error from opening the same file.
func reopenErr(t *testing.T, l *SQLiteLogger, dbPath string) error {
	t.Helper()
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := NewSQLiteLogger(dbPath, SQLiteLoggerOptions{})
	if err == nil {
		_ = reopened.Close()
	}
	return err
}

// The refusal says how many rows there are at each version, lowest
// first. The count is the part that tells an operator what they are
// looking at: one stray row in a v4 file is a row that was changed; a
// file of older rows is an old file.
func TestNewSQLiteLogger_RefusalCountsRowsPerVersion(t *testing.T) {
	base := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		seed map[string]int // id -> version, besides three v4 rows
		want string
	}{
		{"one stray row", map[string]int{"x": 3}, "1 at canonical_version=3"},
		{"several versions, lowest first", map[string]int{"a": 3, "b": 2, "c": 3, "d": 2, "e": 2},
			"3 at canonical_version=2, 2 at canonical_version=3"},
		{"a version above 4", map[string]int{"x": 5}, "1 at canonical_version=5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "audit.db")
			first, err := NewSQLiteLogger(dbPath, SQLiteLoggerOptions{})
			if err != nil {
				t.Fatalf("NewSQLiteLogger: %v", err)
			}
			sl := first.(*SQLiteLogger)
			for i, id := range []string{"v4-1", "v4-2", "v4-3"} {
				if _, err := sl.Log(context.Background(), singleTenantEvent(id, base.Add(time.Duration(i)*time.Hour))); err != nil {
					t.Fatalf("Log: %v", err)
				}
			}
			n := 0
			for id, version := range tc.seed {
				n++
				seedDirect(t, sl, id, version, base.Add(-time.Duration(n)*time.Hour))
			}

			err = reopenErr(t, sl, dbPath)
			if err == nil {
				t.Fatal("NewSQLiteLogger opened a DB that holds rows at another version")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal should say %q, got %q", tc.want, err)
			}
			if !strings.Contains(err.Error(), "Keep the file") {
				t.Errorf("the refusal should say to keep the file, got %q", err)
			}
		})
	}
}

// A canonical_version that is not an integer cannot be read at all.
// The file is still refused, and still not called disposable.
func TestNewSQLiteLogger_RefusesUnreadableVersion(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	first, err := NewSQLiteLogger(dbPath, SQLiteLoggerOptions{})
	if err != nil {
		t.Fatalf("NewSQLiteLogger: %v", err)
	}
	sl := first.(*SQLiteLogger)
	if _, err := sl.Log(context.Background(), singleTenantEvent("a", time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC))); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if _, err := SQLiteAuditDBForTest(sl).ExecContext(context.Background(),
		`UPDATE events SET canonical_version = 'x' WHERE id = 'a'`); err != nil {
		t.Fatalf("UPDATE: %v", err)
	}

	err = reopenErr(t, sl, dbPath)
	if err == nil {
		t.Fatal("NewSQLiteLogger opened a DB whose row has a non-integer canonical_version")
	}
	for _, want := range []string{"Keep the file", "altered", dbPath} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should contain %q, got %q", want, err)
		}
	}
}

// The version column is an input to both verify walks. A row relabelled
// to another version while the logger is open is reported at that row.
func TestVerify_RelabelledVersionIsTamper(t *testing.T) {
	ctx := context.Background()
	l := seedChain(t, "a", "b", "c")

	if vr, err := l.Verify(ctx); err != nil || vr.Tamper || vr.Total != 3 {
		t.Fatalf("Verify before the relabel = %+v err=%v", vr, err)
	}
	if _, err := SQLiteAuditDBForTest(l).ExecContext(ctx,
		`UPDATE events SET canonical_version = 3 WHERE id = 'b'`); err != nil {
		t.Fatalf("UPDATE: %v", err)
	}

	vr, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !vr.Tamper || vr.FirstBadIndex != 1 {
		t.Fatalf("Verify = %+v, want tamper at index 1 — the relabelled row", vr)
	}
	_, err = VerifyChainPostMigration(ctx, l)
	mismatch := requireMismatch(t, err, 1, "b")
	if !strings.Contains(mismatch.Reason, "unknown canonical_version=3") {
		t.Errorf("Reason = %q, want it to name the unknown version", mismatch.Reason)
	}
}

// Redaction needs no option. On a single-tenant deployment the PII is
// erased, and both verify walks stay clean afterwards.
func TestRedaction_SingleTenantShape(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC)

	for i, id := range []string{"a", "b"} {
		if _, err := l.Log(ctx, singleTenantEvent(id, base.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	redacted, err := l.RedactEvent(ctx, "b")
	if err != nil {
		t.Fatalf("RedactEvent: %v", err)
	}
	if !redacted {
		t.Fatal("RedactEvent reported (false, nil) on a row Log just wrote")
	}
	if missing, err := l.RedactEvent(ctx, "no-such-row"); err != nil || missing {
		t.Fatalf("RedactEvent(absent row) = %v, %v; want false, nil", missing, err)
	}

	e := eventByID(t, l, "b")
	if e.Actor.Email != "" || e.Actor.Name != "" || e.Actor.IP != "" {
		t.Fatalf("redacted row still carries PII: email=%q name=%q ip=%q",
			e.Actor.Email, e.Actor.Name, e.Actor.IP)
	}
	if untouched := eventByID(t, l, "a"); untouched.Actor.Email == "" {
		t.Fatal("redacting b also erased a")
	}

	if vr, err := l.Verify(ctx); err != nil || vr.Tamper || vr.Total != 2 {
		t.Fatalf("Verify after redaction = %+v err=%v, want 2 clean rows", vr, err)
	}
	if _, err := VerifyChainPostMigration(ctx, l); err != nil {
		t.Fatalf("boot guard after redaction: %v", err)
	}
}

// Log never trusts a salt or commitments that arrive on the event. An
// event read back from List and logged again, with its PII changed,
// must be stored with commitments to the PII it holds NOW.
func TestLog_ReplacesSuppliedSaltAndCommitments(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC)

	if _, err := l.Log(ctx, singleTenantEvent("a", base)); err != nil {
		t.Fatalf("Log: %v", err)
	}
	stale := eventByID(t, l, "a") // carries a's RowSalt and Commitments
	oldSalt := append([]byte(nil), stale.RowSalt...)
	stale.ID = "b"
	stale.At = base.Add(time.Second)
	stale.Actor.Email = "mallory@example.com" // PII no longer matches the commitments

	if _, err := l.Log(ctx, stale); err != nil {
		t.Fatalf("Log of a re-used event: %v", err)
	}
	got := eventByID(t, l, "b")
	if string(got.RowSalt) == string(oldSalt) {
		t.Error("Log kept the salt that arrived on the event")
	}
	if checked, err := VerifyCommitments(got); !checked || err != nil {
		t.Fatalf("VerifyCommitments = %v, %v on a row Log just wrote; the commitments "+
			"were not computed from the row's own PII", checked, err)
	}

	// An all-zero salt would mark a row holding plaintext as redacted.
	zero := singleTenantEvent("c", base.Add(2*time.Second))
	zero.RowSalt = make([]byte, RowSaltSize)
	if _, err := l.Log(ctx, zero); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if got := eventByID(t, l, "c"); IsRedacted(got.RowSalt) {
		t.Error("Log stored the all-zero salt it was handed; the row reads as redacted while holding PII")
	}
	if vr, err := l.Verify(ctx); err != nil || vr.Tamper || vr.Total != 3 {
		t.Fatalf("Verify = %+v err=%v, want 3 clean rows", vr, err)
	}
}

// The email filled in by EmailLookup is part of what the row commits to.
func TestLog_CommitsToTheEnrichedEmail(t *testing.T) {
	ctx := context.Background()
	l, err := NewSQLiteLogger(filepath.Join(t.TempDir(), "audit.db"), SQLiteLoggerOptions{
		EmailLookup: func(context.Context, string) (string, bool) { return "alice@example.com", true },
	})
	if err != nil {
		t.Fatalf("NewSQLiteLogger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if _, err := l.Log(ctx, Event{
		ID: "a", At: time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC),
		Actor: Actor{Type: ActorTypeUser, UserID: "u-1"}, Action: "auth.login",
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	got := eventByID(t, l, "a")
	if got.Actor.Email != "alice@example.com" {
		t.Fatalf("email was not enriched: %q", got.Actor.Email)
	}
	if checked, err := VerifyCommitments(got); !checked || err != nil {
		t.Fatalf("VerifyCommitments = %v, %v; the commitment was taken before the enrichment", checked, err)
	}
}

// A failed lookup is an error, not "no such row". An erasure sweep that
// is told (false, nil) records the PII as gone.
func TestRedactEvent_FailedLookupIsAnError(t *testing.T) {
	l := v4Logger(t)
	if _, err := l.Log(context.Background(), singleTenantEvent("a", time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC))); err != nil {
		t.Fatalf("Log: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	redacted, err := l.RedactEvent(ctx, "a")
	if err == nil {
		t.Fatalf("RedactEvent on a cancelled context returned (%v, nil); the row exists and still holds its PII", redacted)
	}
	if redacted {
		t.Error("RedactEvent reported true alongside an error")
	}
	if e := eventByID(t, l, "a"); e.Actor.Email == "" {
		t.Error("the row was redacted although the call failed")
	}
}

// ListScoped builds its own SELECT. The events it returns must carry
// what List's do: the tenant, the salt and the commitments.
func TestListScoped_ReturnsTenantSaltAndCommitments(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	e := tenantEvent("a", time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC), "acme")
	e.Actor.TenantID = "vendor"
	e.ClusterID = "c-1"
	if _, err := l.Log(ctx, e); err != nil {
		t.Fatalf("Log: %v", err)
	}
	want := eventByID(t, l, "a")

	for name, clusters := range map[string][]string{"with clusters": {"c-1"}, "no clusters": nil} {
		t.Run(name, func(t *testing.T) {
			if clusters == nil {
				// The no-cluster path only returns unscoped rows.
				if _, err := SQLiteAuditDBForTest(l).ExecContext(ctx, `UPDATE events SET cluster_id = '' WHERE id = 'a'`); err != nil {
					t.Fatalf("UPDATE: %v", err)
				}
			}
			page, err := l.ListScoped(ctx, clusters, Filter{Limit: 10})
			if err != nil {
				t.Fatalf("ListScoped: %v", err)
			}
			if len(page.Events) != 1 {
				t.Fatalf("ListScoped returned %d events, want 1", len(page.Events))
			}
			got := page.Events[0]
			if got.TenantID != "acme" || got.Actor.TenantID != "vendor" {
				t.Errorf("tenant fields = %q / %q, want acme / vendor", got.TenantID, got.Actor.TenantID)
			}
			if string(got.RowSalt) != string(want.RowSalt) {
				t.Errorf("RowSalt = %x, want %x", got.RowSalt, want.RowSalt)
			}
			if checked, err := VerifyCommitments(got); !checked || err != nil {
				t.Errorf("VerifyCommitments = %v, %v on an event from ListScoped; it came back "+
					"without its salt or commitments", checked, err)
			}
		})
	}
}
