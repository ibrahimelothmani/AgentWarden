// Package store persists Incidents for the dashboard. The in-memory
// implementation is intentionally simple and swappable: Store is an
// interface specifically so a Postgres- or SQLite-backed implementation
// can replace it without touching the pipeline or API layers.
package store

import (
	"sort"
	"sync"

	"github.com/agentwarden/agentwarden/pkg/types"
)

// Store persists and retrieves Incidents.
type Store interface {
	Save(types.Incident) error
	List(limit int) ([]types.Incident, error)
	Get(id string) (types.Incident, bool, error)
}

// MemoryStore is a thread-safe, in-process Store. Data does not survive a
// restart — see docs/ARCHITECTURE.md for the planned Postgres-backed
// implementation.
type MemoryStore struct {
	mu        sync.RWMutex
	incidents map[string]types.Incident
	order     []string // insertion order, newest last
}

// NewMemoryStore builds an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		incidents: make(map[string]types.Incident),
	}
}

// Save records an incident, overwriting any prior entry with the same ID.
func (s *MemoryStore) Save(incident types.Incident) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.incidents[incident.ID]; !exists {
		s.order = append(s.order, incident.ID)
	}
	s.incidents[incident.ID] = incident
	return nil
}

// List returns up to limit incidents, most recent first. limit <= 0 means
// "no limit".
func (s *MemoryStore) List(limit int) ([]types.Incident, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]types.Incident, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.incidents[id])
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})

	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Get retrieves a single incident by ID.
func (s *MemoryStore) Get(id string) (types.Incident, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inc, ok := s.incidents[id]
	return inc, ok, nil
}
