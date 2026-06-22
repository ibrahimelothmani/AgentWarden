package store

import (
	"testing"
	"time"

	"github.com/agentwarden/agentwarden/pkg/types"
)

func TestMemoryStore_SaveAndGet(t *testing.T) {
	s := NewMemoryStore()
	inc := types.Incident{ID: "abc123", AgentID: "dev-agent-01", Verdict: types.VerdictApproved, CreatedAt: time.Now()}

	if err := s.Save(inc); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, ok, err := s.Get("abc123")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected incident to be found")
	}
	if got.AgentID != "dev-agent-01" {
		t.Errorf("AgentID = %q, want dev-agent-01", got.AgentID)
	}
}

func TestMemoryStore_Get_MissingReturnsFalse(t *testing.T) {
	s := NewMemoryStore()
	_, ok, err := s.Get("nope")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for missing incident")
	}
}

func TestMemoryStore_List_OrderedNewestFirst(t *testing.T) {
	s := NewMemoryStore()
	base := time.Now()
	s.Save(types.Incident{ID: "1", CreatedAt: base.Add(1 * time.Minute)})
	s.Save(types.Incident{ID: "2", CreatedAt: base.Add(3 * time.Minute)})
	s.Save(types.Incident{ID: "3", CreatedAt: base.Add(2 * time.Minute)})

	got, err := s.List(0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3", len(got))
	}
	wantOrder := []string{"2", "3", "1"}
	for i, id := range wantOrder {
		if got[i].ID != id {
			t.Errorf("position %d: got ID %q, want %q", i, got[i].ID, id)
		}
	}
}

func TestMemoryStore_List_RespectsLimit(t *testing.T) {
	s := NewMemoryStore()
	for i := 0; i < 5; i++ {
		s.Save(types.Incident{ID: string(rune('a' + i)), CreatedAt: time.Now()})
	}
	got, err := s.List(2)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("len(got) = %d, want 2", len(got))
	}
}
