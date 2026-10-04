package sqlitestore

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// The open-time check must be served by the partial index, or it is a
// scan of the whole events table on every process start. This pins the
// pairing: the query's WHERE has to keep implying the index's predicate.
// Changing the literal 4 to a bound parameter, or renaming the index,
// fails here.
func TestCountEventsNotAtV4_UsesThePartialIndex(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	rows, err := store.DB.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+countEventsNotAtV4)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var plan []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("scan plan row: %v", err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("plan rows: %v", err)
	}

	joined := strings.Join(plan, " | ")
	if !strings.Contains(joined, "idx_events_not_v4") {
		t.Fatalf("the check does not use idx_events_not_v4; it scans the table on every open.\nplan: %s", joined)
	}
	if strings.Contains(joined, "SCAN events") && !strings.Contains(joined, "USING") {
		t.Fatalf("the plan scans the events table: %s", joined)
	}
}
