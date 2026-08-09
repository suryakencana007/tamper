package oidc

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/suryakencana007/tamper/tenant"
)

// MemProviderStore is an in-memory ProviderStore for tests and
// examples. Not for production — nothing persists.
type MemProviderStore struct {
	mu   sync.Mutex
	recs map[string]ProviderRecord
}

var _ ProviderStore = (*MemProviderStore)(nil)

// NewMemProviderStore returns an empty in-memory store.
func NewMemProviderStore() *MemProviderStore {
	return &MemProviderStore{recs: make(map[string]ProviderRecord)}
}

func (s *MemProviderStore) InsertProvider(_ context.Context, rec ProviderRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.recs[rec.ID]; ok {
		return ErrProviderExists
	}
	s.recs[rec.ID] = rec
	return nil
}

func (s *MemProviderStore) GetProvider(_ context.Context, id string) (ProviderRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recs[id]
	if !ok {
		return ProviderRecord{}, ErrProviderNotFound
	}
	return rec, nil
}

func (s *MemProviderStore) ListProviders(_ context.Context) ([]ProviderRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sortedLocked(func(ProviderRecord) bool { return true }), nil
}

func (s *MemProviderStore) ListEnabledProviders(_ context.Context, tenantID tenant.ID) ([]ProviderRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sortedLocked(func(r ProviderRecord) bool { return r.Enabled }), nil
}

func (s *MemProviderStore) UpdateProvider(_ context.Context, rec ProviderRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.recs[rec.ID]
	if !ok {
		return ErrProviderNotFound
	}
	rec.CreatedAt = existing.CreatedAt
	s.recs[rec.ID] = rec
	return nil
}

func (s *MemProviderStore) UpdateProviderSealedSecret(_ context.Context, id string, sealed []byte, updatedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recs[id]
	if !ok {
		return ErrProviderNotFound
	}
	rec.SealedClientSecret = sealed
	rec.UpdatedAt = updatedAt
	s.recs[id] = rec
	return nil
}

func (s *MemProviderStore) DeleteProvider(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.recs, id)
	return nil
}

// sortedLocked returns matching records sorted by display name
// ascending (the ProviderStore ordering contract), id as tiebreak.
func (s *MemProviderStore) sortedLocked(match func(ProviderRecord) bool) []ProviderRecord {
	out := make([]ProviderRecord, 0, len(s.recs))
	for _, r := range s.recs {
		if match(r) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DisplayName != out[j].DisplayName {
			return out[i].DisplayName < out[j].DisplayName
		}
		return out[i].ID < out[j].ID
	})
	return out
}
