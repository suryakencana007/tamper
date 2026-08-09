package tenant

import (
	"context"
	"fmt"
	"sync"
)

// MemStore is an in-memory Store — the reference implementation and
// test double. Map lookups; fine for tests, examples and small embedded
// uses, not a production store.
//
// It implements Store and nothing else. In particular it does NOT
// implement Resolver — see the note on that interface.
type MemStore struct {
	mu       sync.RWMutex
	byID     map[string]Descriptor
	slugToID map[string]string
}

var _ Store = (*MemStore)(nil)

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{
		byID:     make(map[string]Descriptor),
		slugToID: make(map[string]string),
	}
}

// Seed inserts or replaces a fully-specified tenant (tests, examples).
// The Descriptor is stored verbatim — Status included, uninterpreted.
//
// Re-seeding a tenant whose Slug changed retires its OLD slug mapping,
// so BySlug never resolves a handle the tenant no longer has.
//
// The retirement is ownership-checked. Seed is last-writer-wins on a
// slug, the way identity.MemStore is on an email, so a slug this tenant
// once held may since have been claimed by another one — that mapping
// belongs to the claimant now and is left alone. Deleting it
// unconditionally would make a THIRD tenant unreachable by its own slug
// as a side effect of renaming this one.
func (m *MemStore) Seed(d Descriptor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if prev, ok := m.byID[d.ID]; ok && prev.Slug != d.Slug && m.slugToID[prev.Slug] == d.ID {
		delete(m.slugToID, prev.Slug)
	}
	m.byID[d.ID] = d
	m.slugToID[d.Slug] = d.ID
}

// ByID implements Store.
//
// The Descriptor comes back as stored: Status is NOT interpreted here,
// so a suspended tenant round-trips with StatusSuspended and the caller
// decides what that means (see ErrSuspended).
func (m *MemStore) ByID(_ context.Context, id string) (Descriptor, error) {
	// An empty key never resolves — absent, empty and mismatched all
	// mean deny (sketch §6.2). "" is a legal tenant id meaning the
	// single-tenant deployment, which is exactly the deployment with no
	// tenant row to find; letting it hit a seeded zero-value row would
	// hand a wildcard to the one input most likely to arrive by
	// accident.
	if id == "" {
		return Descriptor{}, fmt.Errorf("%w: tenant %q", ErrNotFound, id)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.byID[id]
	if !ok {
		return Descriptor{}, fmt.Errorf("%w: tenant %s", ErrNotFound, id)
	}
	return d, nil
}

// BySlug implements Store. Same empty-key deny and same
// non-interpretation of Status as ByID.
func (m *MemStore) BySlug(_ context.Context, slug string) (Descriptor, error) {
	if slug == "" {
		return Descriptor{}, fmt.Errorf("%w: tenant slug %q", ErrNotFound, slug)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.slugToID[slug]
	if !ok {
		return Descriptor{}, fmt.Errorf("%w: tenant slug %s", ErrNotFound, slug)
	}
	return m.byID[id], nil
}
