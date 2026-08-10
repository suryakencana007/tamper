package audit

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This file closes #25's two halves: the blessed single-tenant erasure
// path is pinned as a regression guard, and the trap that used to plant a
// delayed forgery alarm now fails loudly at write time.

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

// TestRedaction_SingleTenantShape pins the path #25 verified by hand and
// the option docs now bless: Tenancy: true on a deployment with NO
// tenants. Every event carries an empty TenantID, the v4 anchor lands at
// boot, redaction erases the PII, and BOTH verify walks stay clean. If
// this ever breaks, the erasure recipe the documentation sells to
// single-tenant operators is broken with it.
func TestRedaction_SingleTenantShape(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t) // Tenancy: true — the switch, not a tenant in sight
	base := time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC)

	emitted, err := l.BootstrapChainV4(ctx, base, "v4-anchor")
	if err != nil {
		t.Fatalf("BootstrapChainV4: %v", err)
	}
	if !emitted {
		t.Fatal("the v4 anchor was not emitted on a fresh Tenancy: true logger")
	}

	for i, id := range []string{"a", "b"} {
		got, err := l.Log(ctx, singleTenantEvent(id, base.Add(time.Duration(i+1)*time.Second)))
		if err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
		if got.CanonicalVersion != CanonicalVersion4 {
			t.Fatalf("event %s landed at v%d, want v4 — the single-tenant shape "+
				"is not reaching the redactable encoder", id, got.CanonicalVersion)
		}
		if got.TenantID != "" {
			t.Fatalf("event %s grew a tenant %q from nowhere", id, got.TenantID)
		}
	}

	redacted, err := l.RedactEvent(ctx, "b")
	if err != nil {
		t.Fatalf("RedactEvent: %v", err)
	}
	if !redacted {
		t.Fatal("RedactEvent reported (false, nil) on a live v4 row — the exact " +
			"silent failure #25 describes, now on the documented path")
	}

	rows, err := l.ListByCanonicalVersion(ctx, CanonicalVersion4)
	if err != nil {
		t.Fatalf("ListByCanonicalVersion: %v", err)
	}
	for _, e := range rows {
		if e.ID != "b" {
			continue
		}
		if e.Actor.Email != "" || e.Actor.Name != "" || e.Actor.IP != "" {
			t.Fatalf("redacted row still carries PII: email=%q name=%q ip=%q",
				e.Actor.Email, e.Actor.Name, e.Actor.IP)
		}
	}

	// Both verify walks must agree the chain is intact — the divergence
	// between them is exactly what the write-time guard exists to prevent.
	if res, err := l.Verify(ctx); err != nil {
		t.Fatalf("Verify after single-tenant redaction: %v (result %+v)", err, res)
	}
	if _, err := verifyChainPostMigrationStore(ctx, l); err != nil {
		t.Fatalf("boot-guard walk after single-tenant redaction: %v", err)
	}
}

// TestLog_ExplicitV4WithoutTenancyIsRejected is the loud trap. Before
// #25's fix this wrote a row that verified at boot and read as FORGED
// under Verify's anchor-driven walk — a false tamper report on a database
// nobody touched, firing long after the mistake and far from it. Now the
// mistake errors at the only moment it is cheap: the write.
func TestLog_ExplicitV4WithoutTenancyIsRejected(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	lg, err := NewSQLiteLogger(dbPath, SQLiteLoggerOptions{}) // Tenancy: false
	if err != nil {
		t.Fatalf("NewSQLiteLogger: %v", err)
	}
	t.Cleanup(func() { _ = lg.(*SQLiteLogger).Close() })
	l := lg.(*SQLiteLogger)
	base := time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC)

	e := singleTenantEvent("forced", base)
	e.CanonicalVersion = CanonicalVersion4
	_, err = l.Log(ctx, e)
	if err == nil {
		t.Fatal("Log accepted an explicit v4 event on a Tenancy: false logger — " +
			"this row would read as tamper under Verify once anything checks it")
	}
	if !strings.Contains(err.Error(), "Tenancy") {
		t.Errorf("the rejection does not name the misconfiguration: %v", err)
	}

	// Nothing may have been written — a rejected event must leave no row.
	rows, err := l.ListByCanonicalVersion(ctx, CanonicalVersion4)
	if err != nil {
		t.Fatalf("ListByCanonicalVersion: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("the rejected event left %d v4 row(s) behind", len(rows))
	}

	// The guard is narrow on purpose: explicit v2/v3 stays legal on a
	// default logger — that is the fixture-replay path consumers rely on.
	e3 := singleTenantEvent("legacy", base.Add(time.Second))
	e3.CanonicalVersion = CanonicalVersion3
	if _, err := l.Log(ctx, e3); err != nil {
		t.Fatalf("explicit v3 on a default logger must stay legal, got: %v", err)
	}
}
