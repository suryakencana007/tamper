package tenant

import (
	"context"
	"errors"
	"sync"
	"testing"
)

var ctxT = context.Background()

func mustCreate(t *testing.T, m *MemStore, d Descriptor) {
	t.Helper()
	if err := m.Create(ctxT, d); err != nil {
		t.Fatalf("Create(%+v): %v", d, err)
	}
}

func TestCreate_RejectsWhatItCannotStore(t *testing.T) {
	m := NewMemStore()
	cases := []struct {
		name string
		d    Descriptor
		want error
	}{
		{"empty id is the single tenant", Descriptor{ID: "", Slug: "x", Status: StatusActive}, ErrSingleTenant},
		{"unknown status", Descriptor{ID: "acme", Slug: "x", Status: Status("held")}, ErrInvalidDescriptor},
		{"zero status", Descriptor{ID: "acme", Slug: "x"}, ErrInvalidDescriptor},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := m.Create(ctxT, tc.d); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			// A refusal writes nothing.
			if got, err := m.List(ctxT); err != nil || len(got) != 0 {
				t.Fatalf("table after a refusal = %v, %v; want empty", got, err)
			}
		})
	}
}

func TestCreate_ConflictIsRefusedNotOverwrite(t *testing.T) {
	m := NewMemStore()
	mustCreate(t, m, Descriptor{ID: "acme", Slug: "acme", Status: StatusActive})
	if err := m.SetStatus(ctxT, New("acme"), StatusSuspended); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	// Same id, different slug: refused, and the suspended status survives.
	err := m.Create(ctxT, Descriptor{ID: "acme", Slug: "other", Status: StatusActive})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate id: err = %v, want ErrConflict", err)
	}
	d, err := m.ByID(ctxT, "acme")
	if err != nil || d.Status != StatusSuspended {
		t.Fatalf("after a refused duplicate: %+v, %v; want the suspended row untouched", d, err)
	}

	// Same slug, new id: refused.
	err = m.Create(ctxT, Descriptor{ID: "globex", Slug: "acme", Status: StatusActive})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate slug: err = %v, want ErrConflict", err)
	}
	if _, err := m.ByID(ctxT, "globex"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the refused tenant was created anyway: %v", err)
	}
}

func TestCreate_EmptySlugDoesNotCollide(t *testing.T) {
	m := NewMemStore()
	mustCreate(t, m, Descriptor{ID: "a", Status: StatusActive})
	mustCreate(t, m, Descriptor{ID: "b", Status: StatusActive})
	if got, _ := m.List(ctxT); len(got) != 2 {
		t.Fatalf("tenants = %d, want 2 (an empty slug is not a shared handle)", len(got))
	}
}

func TestCreate_StoresParentIDAsGiven(t *testing.T) {
	m := NewMemStore()
	mustCreate(t, m, Descriptor{ID: "org-1", Slug: "org-1", ParentID: "tg-acme", Status: StatusActive})
	d, err := m.ByID(ctxT, "org-1")
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if d.ParentID != "tg-acme" {
		t.Fatalf("ParentID = %q, want it stored verbatim", d.ParentID)
	}
}

func TestList_IsOrderedByID(t *testing.T) {
	m := NewMemStore()
	for _, id := range []string{"c", "a", "b"} {
		mustCreate(t, m, Descriptor{ID: id, Slug: id, Status: StatusActive})
	}
	got, err := m.List(ctxT)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for i, want := range []string{"a", "b", "c"} {
		if got[i].ID != want {
			t.Fatalf("List[%d] = %q, want %q", i, got[i].ID, want)
		}
	}
}

func TestSetStatus_Refusals(t *testing.T) {
	m := NewMemStore()
	mustCreate(t, m, Descriptor{ID: "acme", Slug: "acme", Status: StatusActive})

	cases := []struct {
		name   string
		id     ID
		status Status
		want   error
	}{
		{"unset id", ID{}, StatusSuspended, ErrInvalidDescriptor},
		{"single tenant", Single, StatusSuspended, ErrSingleTenant},
		{"unknown status", New("acme"), Status("held"), ErrInvalidDescriptor},
		{"unknown tenant", New("nope"), StatusSuspended, ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := m.SetStatus(ctxT, tc.id, tc.status); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			d, err := m.ByID(ctxT, "acme")
			if err != nil || d.Status != StatusActive {
				t.Fatalf("after a refusal: %+v, %v; want acme still active", d, err)
			}
		})
	}
}

func TestSetStatus_IsIdempotentAndSurvivesTheRoundTrip(t *testing.T) {
	m := NewMemStore()
	mustCreate(t, m, Descriptor{ID: "acme", Slug: "acme", Status: StatusActive})
	for i := 0; i < 2; i++ {
		if err := m.SetStatus(ctxT, New("acme"), StatusSuspended); err != nil {
			t.Fatalf("SetStatus #%d: %v", i+1, err)
		}
	}
	d, err := m.ByID(ctxT, "acme")
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if d.Status != StatusSuspended {
		t.Fatalf("status = %q, want %q (Store returns the row uninterpreted)", d.Status, StatusSuspended)
	}
	if d.Slug != "acme" {
		t.Fatalf("slug = %q, want it preserved by a status change", d.Slug)
	}
}

// List on an empty store is an empty SLICE, not nil: a console ranges over it.
func TestList_EmptyStoreIsNonNil(t *testing.T) {
	got, err := NewMemStore().List(ctxT)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got == nil {
		t.Fatal("List returned nil; want an empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("List = %v, want empty", got)
	}
}

// The write port shares the store's mutex; this bites under -race only.
func TestAdminStore_ConcurrentAccess(t *testing.T) {
	m := NewMemStore()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(3)
		id := "t-" + string(rune('a'+i))
		go func() { defer wg.Done(); _ = m.Create(ctxT, Descriptor{ID: id, Slug: id, Status: StatusActive}) }()
		go func() { defer wg.Done(); _ = m.SetStatus(ctxT, New(id), StatusSuspended) }()
		go func() { defer wg.Done(); _, _ = m.List(ctxT) }()
	}
	wg.Wait()

	got, err := m.List(ctxT)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 8 {
		t.Fatalf("tenants = %d, want 8", len(got))
	}
}
