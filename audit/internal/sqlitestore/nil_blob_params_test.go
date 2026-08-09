package sqlitestore_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/audit/internal/sqlitestore"
)

// TestInsertEventParams_BareStructLiteral is the regression guard for the
// defect Barista's CI found on 2026-08-09.
//
// Migration 005 added six BLOB NOT NULL columns. Their DEFAULT can never
// fire, because sqlc names every column in the INSERT. So before
// sqltypes.Blob existed, a caller that built InsertEventParams as a plain
// struct literal — the only way to build it, and the only thing a caller
// written before v4 could possibly do — sent six explicit NULLs and got
// `NOT NULL constraint failed: events.row_salt`.
//
// The test is deliberately written as an OUTSIDE caller (package
// sqlitestore_test, importing the package by path) and deliberately sets
// only the pre-v4 fields. Adding the v4 fields here would restore the very
// workaround this exists to make unnecessary, and the test would pass while
// guarding nothing.
func TestInsertEventParams_BareStructLiteral(t *testing.T) {
	t.Parallel()

	store, err := sqlitestore.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()

	// Exactly the shape of a pre-v4 consumer: every field it knew about,
	// and not one field it could not have known about.
	err = store.Queries.InsertEvent(ctx, sqlitestore.InsertEventParams{
		ID:               "bare-literal",
		At:               time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC),
		ActorUserID:      "u1",
		ActorEmail:       "a@example.com",
		ActorIp:          "127.0.0.1",
		ActorType:        "user",
		ActorName:        "A",
		Action:           "auth.login",
		ResourceType:     "system",
		ResourceID:       "",
		ClusterID:        "",
		RequestID:        "",
		BeforeJson:       "",
		AfterJson:        "",
		PrevHash:         make([]byte, 32),
		Hash:             make([]byte, 32),
		CanonicalVersion: 3,
	})
	if err != nil {
		t.Fatalf("insert with a bare pre-v4 struct literal must succeed, got: %v", err)
	}

	// The nil Blobs must have landed as empty, not NULL — otherwise the
	// NOT NULL columns would hold something a later read cannot trust.
	rows, err := store.Queries.ListEventsForVerify(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	r := rows[0]
	for _, c := range []struct {
		name string
		got  []byte
	}{
		{"row_salt", r.RowSalt},
		{"c_actor_email", r.CActorEmail},
		{"c_actor_name", r.CActorName},
		{"c_actor_ip", r.CActorIp},
		{"c_before", r.CBefore},
		{"c_after", r.CAfter},
	} {
		if c.got == nil {
			t.Errorf("%s read back as nil; want empty, non-NULL", c.name)
		}
		if len(c.got) != 0 {
			t.Errorf("%s = %x, want empty", c.name, c.got)
		}
	}
}
