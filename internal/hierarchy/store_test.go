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
	// Create story_runs table needed for StoryHasRuns/BindAgent tests.
	// This table is owned by the registry package but hierarchy depends on it.
	db.Exec(`CREATE TABLE IF NOT EXISTS story_runs (
		id               INTEGER PRIMARY KEY AUTOINCREMENT,
		story_id         INTEGER NOT NULL,
		agent_profile_id INTEGER NOT NULL,
		runtime_id       INTEGER NOT NULL,
		provider         TEXT NOT NULL,
		session_key      TEXT NOT NULL DEFAULT '',
		agent_session_id TEXT NOT NULL DEFAULT '',
		exec_id          TEXT NOT NULL DEFAULT '',
		prompt           TEXT NOT NULL,
		effective_prompt TEXT NOT NULL,
		permission_mode  TEXT NOT NULL DEFAULT '',
		cwd              TEXT NOT NULL DEFAULT '',
		session_title    TEXT NOT NULL DEFAULT '',
		status           TEXT NOT NULL DEFAULT 'queued',
		error            TEXT NOT NULL DEFAULT '',
		created_by       INTEGER NOT NULL,
		created_at       INTEGER NOT NULL,
		started_at       INTEGER NOT NULL DEFAULT 0,
		finished_at      INTEGER NOT NULL DEFAULT 0
	)`)
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

func TestTopicOrchestrationNoteRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ws, _ := s.CreateWorkspace("ws1", "")
	proj, _ := s.CreateProject(ws.ID, "proj1", "")
	topic, _ := s.CreateTopic(proj.ID, "topic1", "", "claude")

	// Initially empty
	got, err := s.GetTopic(topic.ID)
	if err != nil {
		t.Fatalf("GetTopic: %v", err)
	}
	if got.OrchestrationNote != "" {
		t.Errorf("expected empty orchestration_note, got %q", got.OrchestrationNote)
	}

	// Update and verify
	if err := s.UpdateTopicOrchestrationNote(topic.ID, "Step 1 → Step 2 → Step 3"); err != nil {
		t.Fatalf("UpdateTopicOrchestrationNote: %v", err)
	}
	got2, err := s.GetTopic(topic.ID)
	if err != nil {
		t.Fatalf("GetTopic after update: %v", err)
	}
	if got2.OrchestrationNote != "Step 1 → Step 2 → Step 3" {
		t.Errorf("expected orchestration_note, got %q", got2.OrchestrationNote)
	}
}

func TestStoryAgentFieldsRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ws, _ := s.CreateWorkspace("ws1", "")
	proj, _ := s.CreateProject(ws.ID, "proj1", "")
	topic, _ := s.CreateTopic(proj.ID, "topic1", "", "claude")
	story, _ := s.CreateStory(topic.ID, "Test Story", "")

	// Initially no agent
	got, err := s.GetStory(story.ID)
	if err != nil {
		t.Fatalf("GetStory: %v", err)
	}
	if got.AgentProfileID != nil {
		t.Error("expected nil agent_profile_id")
	}
	if got.LatestRunID != nil {
		t.Error("expected nil latest_run_id")
	}

	// Bind agent
	agentID := int64(42)
	if err := s.BindAgentToStory(story.ID, agentID); err != nil {
		t.Fatalf("BindAgentToStory: %v", err)
	}
	got2, err := s.GetStory(story.ID)
	if err != nil {
		t.Fatalf("GetStory after bind: %v", err)
	}
	if got2.AgentProfileID == nil || *got2.AgentProfileID != 42 {
		t.Errorf("expected agent_profile_id 42, got %v", got2.AgentProfileID)
	}

	// Update run summary
	if err := s.UpdateStoryRunSummary(story.ID, 1, "sess-key-1", "running"); err != nil {
		t.Fatalf("UpdateStoryRunSummary: %v", err)
	}
	got3, err := s.GetStory(story.ID)
	if err != nil {
		t.Fatalf("GetStory after summary: %v", err)
	}
	if got3.LatestRunID == nil || *got3.LatestRunID != 1 {
		t.Errorf("expected latest_run_id 1, got %v", got3.LatestRunID)
	}
	if got3.LatestSessionKey != "sess-key-1" {
		t.Errorf("expected latest_session_key sess-key-1, got %s", got3.LatestSessionKey)
	}
	if got3.Status != "running" {
		t.Errorf("expected status running, got %s", got3.Status)
	}
}

func TestBindAgentLocksAfterFirstRun(t *testing.T) {
	s := newTestStore(t)
	ws, _ := s.CreateWorkspace("ws1", "")
	proj, _ := s.CreateProject(ws.ID, "proj1", "")
	topic, _ := s.CreateTopic(proj.ID, "topic1", "", "claude")
	story, _ := s.CreateStory(topic.ID, "Test Story", "")

	// First bind should succeed
	if err := s.BindAgentToStory(story.ID, 10); err != nil {
		t.Fatalf("first bind: %v", err)
	}

	// Change to different agent before any runs should succeed
	if err := s.BindAgentToStory(story.ID, 20); err != nil {
		t.Fatalf("rebind before runs: %v", err)
	}

	// Simulate a run by directly inserting into story_runs
	s.db.Exec(`INSERT INTO story_runs (story_id, agent_profile_id, runtime_id, provider, prompt, effective_prompt, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		story.ID, 20, 1, "claude", "test", "test", 1, 1)

	// Now try to change agent — should fail with ErrStoryAgentLocked
	err := s.BindAgentToStory(story.ID, 30)
	if err != ErrStoryAgentLocked {
		t.Errorf("expected ErrStoryAgentLocked, got %v", err)
	}

	// Re-binding same agent should still succeed
	if err := s.BindAgentToStory(story.ID, 20); err != nil {
		t.Errorf("rebind same agent should succeed, got %v", err)
	}
}

func TestStoryHasRuns(t *testing.T) {
	s := newTestStore(t)
	ws, _ := s.CreateWorkspace("ws1", "")
	proj, _ := s.CreateProject(ws.ID, "proj1", "")
	topic, _ := s.CreateTopic(proj.ID, "topic1", "", "claude")
	story, _ := s.CreateStory(topic.ID, "Test Story", "")

	has, err := s.StoryHasRuns(story.ID)
	if err != nil {
		t.Fatalf("StoryHasRuns: %v", err)
	}
	if has {
		t.Error("new story should not have runs")
	}

	// Insert a run
	s.db.Exec(`INSERT INTO story_runs (story_id, agent_profile_id, runtime_id, provider, prompt, effective_prompt, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		story.ID, 1, 1, "claude", "test", "test", 1, 1)

	has2, err := s.StoryHasRuns(story.ID)
	if err != nil {
		t.Fatalf("StoryHasRuns after insert: %v", err)
	}
	if !has2 {
		t.Error("story with runs should have runs")
	}
}

func TestGetWorkspaceIDForStory(t *testing.T) {
	s := newTestStore(t)
	ws, _ := s.CreateWorkspace("ws1", "")
	proj, _ := s.CreateProject(ws.ID, "proj1", "")
	topic, _ := s.CreateTopic(proj.ID, "topic1", "", "claude")
	story, _ := s.CreateStory(topic.ID, "Test Story", "")

	got, err := s.GetWorkspaceIDForStory(story.ID)
	if err != nil {
		t.Fatalf("GetWorkspaceIDForStory: %v", err)
	}
	if got != ws.ID {
		t.Errorf("expected workspace %d, got %d", ws.ID, got)
	}
}

func TestGetWorkspaceIDForStoryNotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetWorkspaceIDForStory(9999); err == nil {
		t.Fatal("expected error for nonexistent story")
	}
}
