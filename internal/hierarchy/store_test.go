package hierarchy

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := NewStore(db)
	if err := s.EnsureTables(); err != nil {
		t.Fatalf("ensure tables: %v", err)
	}
	return s
}

func TestGetWorkspaceIDForTopic(t *testing.T) {
	s := newTestStore(t)
	ws, err := s.CreateWorkspace("ws1", "")
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	proj, err := s.CreateProject(ws.ID, "proj1", "")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	topic, err := s.CreateTopic(proj.ID, "topic1", "", "claude")
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}

	got, err := s.GetWorkspaceIDForTopic(topic.ID)
	if err != nil {
		t.Fatalf("GetWorkspaceIDForTopic: %v", err)
	}
	if got != ws.ID {
		t.Fatalf("workspace id=%d, want %d", got, ws.ID)
	}
}

func TestGetWorkspaceIDForTopicNotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetWorkspaceIDForTopic(9999); err == nil {
		t.Fatal("expected error for nonexistent topic, got nil")
	}
}

func TestCreateStoryForSessionLinksImmediately(t *testing.T) {
	s := newTestStore(t)
	ws, _ := s.CreateWorkspace("ws1", "")
	proj, _ := s.CreateProject(ws.ID, "proj1", "")
	topic, _ := s.CreateTopic(proj.ID, "topic1", "", "claude")

	story, err := s.CreateStoryForSession(topic.ID, "My Story", "session-key-1")
	if err != nil {
		t.Fatalf("CreateStoryForSession: %v", err)
	}
	if story.TopicID != topic.ID || story.Name != "My Story" {
		t.Fatalf("story mismatch: %+v", story)
	}

	found, err := s.FindStoryBySessionKey("session-key-1")
	if err != nil {
		t.Fatalf("FindStoryBySessionKey: %v", err)
	}
	if found.ID != story.ID {
		t.Fatalf("found story id=%d, want %d", found.ID, story.ID)
	}
}
