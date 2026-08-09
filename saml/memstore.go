package saml

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

func (s *MemProviderStore) UpdateProviderSealedKey(_ context.Context, id string, sealed []byte, updatedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recs[id]
	if !ok {
		return ErrProviderNotFound
	}
	rec.SealedSigningKey = sealed
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

// MemAssertionReplayStore is a process-local AssertionReplayStore for
// tests and single-replica deployments.
//
// SINGLE PROCESS ONLY. With N replicas an attacker gets up to N
// acceptances of a captured IdP-initiated assertion — one per replica,
// because each holds its own map. Any multi-replica deployment that runs
// AllowIDPInitiated=true MUST supply a shared store instead; tamper cannot
// detect that this one was handed to more than one process.
type MemAssertionReplayStore struct {
	mu   sync.Mutex
	seen map[string]time.Time // key -> expiresAt
	now  func() time.Time
}

var _ AssertionReplayStore = (*MemAssertionReplayStore)(nil)

// NewMemAssertionReplayStore returns an empty in-memory ledger.
func NewMemAssertionReplayStore() *MemAssertionReplayStore {
	return &MemAssertionReplayStore{seen: make(map[string]time.Time), now: time.Now}
}

// SetClock swaps the clock seam. Test-seam only.
func (s *MemAssertionReplayStore) SetClock(now func() time.Time) {
	if now == nil {
		return
	}
	s.mu.Lock()
	s.now = now
	s.mu.Unlock()
}

// ConsumeAssertion records key under one lock acquisition — the
// compare-and-set is the same critical section as the read, so concurrent
// callers cannot both observe "fresh". An expired prior entry for the same
// key is treated as absent (the assertion's own window has closed, so a
// row that outlived it is meaningless). An opportunistic O(n) sweep of
// expired rows runs inline, so there is no goroutine, ticker, or Close to
// manage.
func (s *MemAssertionReplayStore) ConsumeAssertion(_ context.Context, key string, expiresAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	// Inline sweep — cheap for the small, short-TTL working set a SAML ACS
	// produces, and it keeps the map bounded without background machinery.
	for k, exp := range s.seen {
		if !exp.After(now) {
			delete(s.seen, k)
		}
	}
	if exp, ok := s.seen[key]; ok && exp.After(now) {
		return false, nil // still-live prior entry — replay
	}
	s.seen[key] = expiresAt
	return true, nil
}
