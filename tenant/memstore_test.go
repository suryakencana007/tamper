package tenant

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func acme() Descriptor {
	return Descriptor{ID: "t-acme", Slug: "acme", Status: StatusActive}
}

func TestMemStore_ByIDRoundTrip(t *testing.T) {
	s := NewMemStore()
	s.Seed(acme())

	got, err := s.ByID(context.Background(), "t-acme")
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got != acme() {
		t.Errorf("ByID = %+v, want %+v", got, acme())
	}
}

func TestMemStore_BySlugRoundTrip(t *testing.T) {
	s := NewMemStore()
	s.Seed(acme())

	got, err := s.BySlug(context.Background(), "acme")
	if err != nil {
		t.Fatalf("BySlug: %v", err)
	}
	if got != acme() {
		t.Errorf("BySlug = %+v, want %+v", got, acme())
	}
}

func TestMemStore_ByIDNotFound(t *testing.T) {
	s := NewMemStore()
	s.Seed(acme())

	got, err := s.ByID(context.Background(), "t-globex")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ByID(miss) err = %v, want ErrNotFound", err)
	}
	if got != (Descriptor{}) {
		t.Errorf("ByID(miss) returned %+v, want the zero Descriptor", got)
	}
}

func TestMemStore_BySlugNotFound(t *testing.T) {
	s := NewMemStore()
	s.Seed(acme())

	got, err := s.BySlug(context.Background(), "globex")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("BySlug(miss) err = %v, want ErrNotFound", err)
	}
	if got != (Descriptor{}) {
		t.Errorf("BySlug(miss) returned %+v, want the zero Descriptor", got)
	}
}

// TestMemStore_SlugAndIDNamespacesAreSeparate: a slug must not resolve
// through ByID, nor an id through BySlug. Conflating them would let a
// caller address a tenant by the wrong handle.
func TestMemStore_SlugAndIDNamespacesAreSeparate(t *testing.T) {
	s := NewMemStore()
	s.Seed(acme())

	if _, err := s.ByID(context.Background(), "acme"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ByID(slug) err = %v, want ErrNotFound", err)
	}
	if _, err := s.BySlug(context.Background(), "t-acme"); !errors.Is(err, ErrNotFound) {
		t.Errorf("BySlug(id) err = %v, want ErrNotFound", err)
	}
}

// TestMemStore_EmptyKeyNeverResolves pins the deny-by-default rule
// (§6.2) against the input most likely to arrive by accident: a zero
// value that slipped through an unpopulated field. A seeded zero-value
// row must not turn "" into a wildcard.
func TestMemStore_EmptyKeyNeverResolves(t *testing.T) {
	s := NewMemStore()
	s.Seed(Descriptor{}) // the accident: a tenant with no id and no slug
	s.Seed(acme())

	if _, err := s.ByID(context.Background(), ""); !errors.Is(err, ErrNotFound) {
		t.Errorf(`ByID("") err = %v, want ErrNotFound`, err)
	}
	if _, err := s.BySlug(context.Background(), ""); !errors.Is(err, ErrNotFound) {
		t.Errorf(`BySlug("") err = %v, want ErrNotFound`, err)
	}
}

// TestMemStore_SuspendedRoundTripsUninterpreted pins that the Store
// hands back the row as stored. Collapsing suspended onto not-found is
// the CALLER's decision, made at the wire (§6.3) — a Store that decided
// it here would deny the admin surfaces that exist to un-suspend.
func TestMemStore_SuspendedRoundTripsUninterpreted(t *testing.T) {
	s := NewMemStore()
	susp := Descriptor{ID: "t-globex", Slug: "globex", Status: StatusSuspended}
	s.Seed(susp)

	got, err := s.ByID(context.Background(), "t-globex")
	if err != nil {
		t.Fatalf("ByID(suspended) err = %v, want nil", err)
	}
	if got.Status != StatusSuspended {
		t.Errorf("Status = %q, want %q", got.Status, StatusSuspended)
	}
}

// TestMemStore_SeedReplacesStaleSlugMapping: re-seeding with a changed
// slug must retire the old handle, or BySlug keeps resolving a name the
// tenant gave up — and a name a DIFFERENT tenant may since have taken.
func TestMemStore_SeedReplacesStaleSlugMapping(t *testing.T) {
	s := NewMemStore()
	s.Seed(acme())
	s.Seed(Descriptor{ID: "t-acme", Slug: "acme-corp", Status: StatusActive})

	if _, err := s.BySlug(context.Background(), "acme"); !errors.Is(err, ErrNotFound) {
		t.Errorf("stale slug still resolves: err = %v, want ErrNotFound", err)
	}
	got, err := s.BySlug(context.Background(), "acme-corp")
	if err != nil {
		t.Fatalf("BySlug(new slug): %v", err)
	}
	if got.ID != "t-acme" {
		t.Errorf("ID = %q, want %q", got.ID, "t-acme")
	}
}

// TestMemStore_SeedDoesNotOrphanAnotherTenantsSlug: Seed is
// last-writer-wins on a slug (identity.MemStore is the same on an
// email), so a tenant's old slug may already belong to someone else by
// the time it renames away. Retiring it unconditionally would make that
// OTHER tenant unreachable by its own handle — a lookup silently
// missing a row that exists, which is the worst shape a test double can
// take: it fails a later slice's test for a reason that is not in that
// slice.
func TestMemStore_SeedDoesNotOrphanAnotherTenantsSlug(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()

	s.Seed(Descriptor{ID: "t-a", Slug: "acme", Status: StatusActive})
	s.Seed(Descriptor{ID: "t-b", Slug: "acme", Status: StatusActive})  // t-b takes the slug
	s.Seed(Descriptor{ID: "t-a", Slug: "alpha", Status: StatusActive}) // t-a renames away

	got, err := s.BySlug(ctx, "acme")
	if err != nil {
		t.Fatalf(`BySlug("acme") = %v; t-b's live mapping was orphaned by t-a's rename`, err)
	}
	if got.ID != "t-b" {
		t.Errorf(`BySlug("acme").ID = %q, want %q`, got.ID, "t-b")
	}
	// t-a's new handle still resolves to t-a.
	if g, err := s.BySlug(ctx, "alpha"); err != nil || g.ID != "t-a" {
		t.Errorf(`BySlug("alpha") = (%+v, %v), want t-a`, g, err)
	}
}

// TestMemStore_ParentIDCarriedNotResolved: ParentID is reserved. The
// store carries it verbatim and resolves NOTHING through it — no
// inheritance, no fallback to the parent on a child miss.
func TestMemStore_ParentIDCarriedNotResolved(t *testing.T) {
	s := NewMemStore()
	s.Seed(Descriptor{ID: "t-parent", Slug: "parent", Status: StatusActive})
	child := Descriptor{ID: "t-child", Slug: "child", ParentID: "t-parent", Status: StatusActive}
	s.Seed(child)

	got, err := s.ByID(context.Background(), "t-child")
	if err != nil {
		t.Fatalf("ByID(child): %v", err)
	}
	if got.ParentID != "t-parent" {
		t.Errorf("ParentID = %q, want %q", got.ParentID, "t-parent")
	}
	// A miss on an unknown id must NOT walk up to any parent.
	if _, err := s.ByID(context.Background(), "t-unknown"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown id err = %v, want ErrNotFound", err)
	}
}

// TestMemStore_ConcurrentAccess exercises the mutex. It only bites
// under -race; without the detector it is a smoke test.
func TestMemStore_ConcurrentAccess(t *testing.T) {
	s := NewMemStore()
	s.Seed(acme())
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(3)
		go func() { defer wg.Done(); s.Seed(Descriptor{ID: "t-" + string(rune('a'+i)), Slug: string(rune('a' + i))}) }()
		go func() { defer wg.Done(); _, _ = s.ByID(ctx, "t-acme") }()
		go func() { defer wg.Done(); _, _ = s.BySlug(ctx, "acme") }()
	}
	wg.Wait()

	if _, err := s.ByID(ctx, "t-acme"); err != nil {
		t.Fatalf("ByID after concurrent access: %v", err)
	}
}
