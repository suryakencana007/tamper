package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/audit"
)

// Phase 20's reason to exist, as tests. The rule: a non-genesis baseline is legitimate only when a
// checkpoint IN the chain names it — so pruning by policy and excising rows by hand finally produce
// different verdicts. The second case is the one the feature exists for.
//
// The hand-excision uses DeleteEventByID rather than raw SQL on purpose: that is the API an operator
// (or an attacker with database access) actually has, so the test attacks the door that exists.
func TestAnchor_PruneIsCleanAndExcisingIsTamper(t *testing.T) {
	t.Run("prune by policy verifies clean, and says it was pruned", func(t *testing.T) {
		ctx, l, cutoff := seededChain(t)
		if _, err := l.PruneOlderThan(ctx, cutoff); err != nil {
			t.Fatalf("prune: %v", err)
		}
		res, err := l.Verify(ctx)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if res.Tamper {
			t.Fatalf("a legitimate prune reported TAMPER at index %d — a guard that refuses real "+
				"compaction gets bypassed rather than fixed", res.FirstBadIndex)
		}
		if !res.Pruned || res.AnchoredAt == "" {
			t.Errorf("VerifyResult = %+v, want Pruned=true with AnchoredAt", res)
		}
	})

	t.Run("removing a prefix by hand is TAMPER", func(t *testing.T) {
		ctx, l, _ := seededChain(t)
		// The seeded ids, spelled as the seed spells them: the first version of this test deleted
		// "a" and "b", which no row has, so nothing was removed and the assertion below "passed" a
		// clean chain with Total=4. A delete of a missing id is not an error — worth knowing when a
		// test asserts that something is gone.
		for _, id := range []string{"e-a", "e-b"} {
			if err := l.DeleteEventByID(ctx, id); err != nil {
				t.Fatalf("delete %s: %v", id, err)
			}
		}
		res, err := l.Verify(ctx)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !res.Tamper {
			t.Fatalf("a prefix removed with no anchor verified CLEAN (%+v) — this is the whole "+
				"feature: before Phase 20 this and a real prune were indistinguishable", res)
		}
		if res.FirstBadIndex != 0 {
			t.Errorf("FirstBadIndex = %d, want 0 — the gap is at the start of the chain", res.FirstBadIndex)
		}
	})

	t.Run("deleting the checkpoint is TAMPER", func(t *testing.T) {
		ctx, l, cutoff := seededChain(t)
		if _, err := l.PruneOlderThan(ctx, cutoff); err != nil {
			t.Fatalf("prune: %v", err)
		}
		id := checkpointID(t, ctx, l)
		if err := l.DeleteEventByID(ctx, id); err != nil {
			t.Fatalf("delete checkpoint: %v", err)
		}
		res, err := l.Verify(ctx)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !res.Tamper {
			t.Error("the checkpoint was deleted and the chain still verified clean — an anchor that " +
				"can be removed is not an anchor")
		}
	})

	t.Run("an unpruned chain is unchanged", func(t *testing.T) {
		ctx, l, _ := seededChain(t)
		res, err := l.Verify(ctx)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if res.Tamper || res.Pruned || res.AnchoredAt != "" {
			t.Errorf("VerifyResult = %+v, want clean and unpruned — this slice is additive", res)
		}
	})
}

var seedBase = time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

func seededChain(t *testing.T) (context.Context, audit.Logger, time.Time) {
	t.Helper()
	ctx := context.Background()
	l, err := audit.NewSQLiteLogger(t.TempDir()+"/audit.db", audit.SQLiteLoggerOptions{})
	if err != nil {
		t.Fatalf("NewSQLiteLogger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	for i, a := range []string{"a", "b", "c", "d"} {
		if _, err := l.Log(ctx, audit.Event{
			ID:           "e-" + a,
			At:           seedBase.Add(time.Duration(i) * time.Second),
			Action:       audit.Action(a),
			ResourceType: "test",
			Actor:        audit.ActorSystem("t"),
		}); err != nil {
			t.Fatalf("log %s: %v", a, err)
		}
	}
	return ctx, l, seedBase.Add(2 * time.Second) // strictly older than: removes a and b
}

func checkpointID(t *testing.T, ctx context.Context, l audit.Logger) string {
	t.Helper()
	page, err := l.List(ctx, audit.Filter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, e := range page.Events {
		if e.Action == audit.ActionChainPruned {
			return e.ID
		}
	}
	t.Fatal("no checkpoint in the chain after a prune — the anchor was never written")
	return ""
}
