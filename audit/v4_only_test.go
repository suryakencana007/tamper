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
	for _, want := range []string{"canonical_version=3", "fresh audit DB", dbPath} {
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
