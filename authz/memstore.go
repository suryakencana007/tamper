package authz

import (
	"context"
	"sync"
)

// MemStore is an in-memory BindingStore — the reference implementation and
// the natural test double. Linear scans over a slice: fine for tests and
// small embedded deployments, not intended for large binding sets (that is
// what an application's SQL-backed store is for).
type MemStore struct {
	mu       sync.RWMutex
	bindings []Binding
}

var _ BindingStore = (*MemStore)(nil)

// NewMemStore returns a store pre-seeded with bindings.
func NewMemStore(bindings ...Binding) *MemStore {
	m := &MemStore{}
	for _, b := range bindings {
		m.Grant(b)
	}
	return m
}

// Grant adds a binding. Exact duplicates are ignored (idempotent).
func (m *MemStore) Grant(b Binding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.bindings {
		if existing == b {
			return
		}
	}
	m.bindings = append(m.bindings, b)
}

// Revoke removes every binding exactly equal to b.
func (m *MemStore) Revoke(b Binding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.bindings[:0]
	for _, existing := range m.bindings {
		if existing != b {
			kept = append(kept, existing)
		}
	}
	m.bindings = kept
}

// BindingsFor implements BindingStore (exact subject + resource match).
func (m *MemStore) BindingsFor(_ context.Context, sub Subject, res Resource) ([]Binding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Binding
	for _, b := range m.bindings {
		if b.Subject == sub && b.Resource == res {
			out = append(out, b)
		}
	}
	return out, nil
}

// BindingsForSubject implements BindingStore (concrete resources only).
func (m *MemStore) BindingsForSubject(_ context.Context, sub Subject, resourceType string) ([]Binding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Binding
	for _, b := range m.bindings {
		if b.Subject == sub && b.Resource.Type == resourceType && b.Resource.ID != "" {
			out = append(out, b)
		}
	}
	return out, nil
}

// BindingsOnResource implements BindingStore (exact resource match).
func (m *MemStore) BindingsOnResource(_ context.Context, res Resource) ([]Binding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Binding
	for _, b := range m.bindings {
		if b.Resource == res {
			out = append(out, b)
		}
	}
	return out, nil
}
