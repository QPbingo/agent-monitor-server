package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heybox/agent-monitor-hook/sdk"
	"github.com/heybox/agent-monitor-server/internal/auth"
	"github.com/heybox/agent-monitor-server/internal/hierarchy"
)

func makePayload(fields map[string]interface{}) json.RawMessage {
	b, _ := json.Marshal(fields)
	return b
}

func jsonContains(payload json.RawMessage, needle string) bool {
	return strings.Contains(string(payload), needle)
}

func TestBuildTurn_UserPrompt(t *testing.T) {
	s := &Session{}
	ev := &HookEvent{
		Event:       "UserPromptSubmit",
		AgentType:   "claude",
		TimestampMs: 1000,
		Payload:     makePayload(map[string]interface{}{"prompt": "hello world"}),
	}
	s.applyEvent(ev, getHandler(ev.AgentType))

	if len(s.Turns) != 1 {
		t.Fatalf("expected 1 turn, got %d", len(s.Turns))
	}
	turn := s.Turns[0]
	if turn.TurnIdx != 0 {
		t.Errorf("expected turn_idx 0, got %d", turn.TurnIdx)
	}
	if turn.UserInput != "hello world" {
		t.Errorf("expected user_input 'hello world', got %q", turn.UserInput)
	}
	if turn.UserTS != 1000 {
		t.Errorf("expected user_ts 1000, got %d", turn.UserTS)
	}
}

func TestBuildTurn_AssistantText(t *testing.T) {
	s := &Session{}
	s.Turns = append(s.Turns, Turn{TurnIdx: 0, UserInput: "test", UserTS: 1000, Entries: []TurnEntry{}})
	ev := &HookEvent{
		Event:       "AssistantText",
		AgentType:   "opencode",
		TimestampMs: 2000,
		Payload:     makePayload(map[string]interface{}{"text": "I need to think about this"}),
	}
	s.applyEvent(ev, getHandler(ev.AgentType))
	if len(s.Turns[0].Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(s.Turns[0].Entries))
	}
	e := s.Turns[0].Entries[0]
	if e.Event != "AssistantText" {
		t.Errorf("expected event AssistantText, got %q", e.Event)
	}
	if string(e.Payload) == "" {
		t.Error("expected non-empty payload")
	}
}

func TestBuildTurn_ReasoningPart(t *testing.T) {
	s := &Session{}
	s.Turns = append(s.Turns, Turn{TurnIdx: 0, UserInput: "test", UserTS: 1000, Entries: []TurnEntry{}})
	ev := &HookEvent{
		Event:       "ReasoningPart",
		TimestampMs: 2000,
		Payload:     makePayload(map[string]interface{}{"text": "reasoning content"}),
	}
	s.applyEvent(ev, getHandler(ev.AgentType))
	e := s.Turns[0].Entries[0]
	if e.Event != "ReasoningPart" {
		t.Errorf("expected event ReasoningPart, got %q", e.Event)
	}
	if len(e.Payload) == 0 {
		t.Error("expected non-empty payload")
	}
}

func TestBuildTurn_ToolCallSingle(t *testing.T) {
	s := &Session{}
	s.Turns = append(s.Turns, Turn{TurnIdx: 0, UserInput: "test", UserTS: 1000, Entries: []TurnEntry{}})

	pre := &HookEvent{
		Event: "PreToolUse", TimestampMs: 2000,
		Payload: makePayload(map[string]interface{}{"tool_name": "Read", "tool_input": map[string]interface{}{"filePath": "/foo.go"}}),
	}
	s.applyEvent(pre, &ClaudeCodeHandler{})
	post := &HookEvent{
		Event: "PostToolUse", TimestampMs: 3000,
		Payload: makePayload(map[string]interface{}{"tool_name": "Read", "tool_output": "file content"}),
	}
	s.applyEvent(post, &ClaudeCodeHandler{})

	entry := s.Turns[0].Entries[0]
	if len(entry.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(entry.Tools))
	}
	if entry.Tools[0].Name != "Read" || entry.Tools[0].Status != "completed" {
		t.Errorf("tool mismatch: %+v", entry.Tools[0])
	}
	if entry.Tools[0].Output != "file content" {
		t.Errorf("expected output, got %q", entry.Tools[0].Output)
	}
}

func TestBuildTurn_PostToolPayloadPreservedAsOwnEntry(t *testing.T) {
	s := &Session{}
	s.Turns = append(s.Turns, Turn{TurnIdx: 0, UserInput: "test", UserTS: 1000, Entries: []TurnEntry{}})

	s.applyEvent(&HookEvent{
		Event: "PreToolUse", TimestampMs: 2000,
		Payload: makePayload(map[string]interface{}{"tool_name": "Read", "tool_input": map[string]interface{}{"filePath": "/foo.go"}}),
	}, &ClaudeCodeHandler{})
	s.applyEvent(&HookEvent{
		Event: "PostToolUse", TimestampMs: 3000,
		Payload: makePayload(map[string]interface{}{
			"tool_name":   "Read",
			"tool_output": "file content",
			"metadata":    map[string]interface{}{"bytes": 12},
		}),
	}, &ClaudeCodeHandler{})

	if len(s.Turns[0].Entries) != 2 {
		t.Fatalf("expected pre tool group plus post payload entry, got %d entries", len(s.Turns[0].Entries))
	}
	post := s.Turns[0].Entries[1]
	if post.Event != "PostToolUse" {
		t.Fatalf("post entry event=%s, want PostToolUse", post.Event)
	}
	if !json.Valid(post.Payload) || !json.Valid(s.Turns[0].Entries[0].Payload) {
		t.Fatalf("expected valid raw payloads, got pre=%q post=%q", s.Turns[0].Entries[0].Payload, post.Payload)
	}
	if !jsonContains(post.Payload, `"metadata"`) {
		t.Fatalf("post payload missing metadata: %s", post.Payload)
	}
}

func TestBuildTurn_ToolCallMultipleSameGroup(t *testing.T) {
	s := &Session{}
	s.Turns = append(s.Turns, Turn{TurnIdx: 0, UserInput: "test", UserTS: 1000, Entries: []TurnEntry{}})
	s.applyEvent(&HookEvent{Event: "PreToolUse", TimestampMs: 2000, Payload: makePayload(map[string]interface{}{"tool_name": "Read", "tool_input": map[string]interface{}{"filePath": "/a.go"}})}, &ClaudeCodeHandler{})
	s.applyEvent(&HookEvent{Event: "PostToolUse", TimestampMs: 2500, Payload: makePayload(map[string]interface{}{"tool_name": "Read", "tool_output": "a"})}, &ClaudeCodeHandler{})
	s.applyEvent(&HookEvent{Event: "PreToolUse", TimestampMs: 2600, Payload: makePayload(map[string]interface{}{"tool_name": "Write", "tool_input": map[string]interface{}{"filePath": "/b.go"}})}, &ClaudeCodeHandler{})
	s.applyEvent(&HookEvent{Event: "PostToolUse", TimestampMs: 3000, Payload: makePayload(map[string]interface{}{"tool_name": "Write", "tool_output": "b"})}, &ClaudeCodeHandler{})

	entry := s.Turns[0].Entries[0]
	if len(entry.Tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(entry.Tools))
	}
	if entry.Tools[0].Name != "Read" || entry.Tools[1].Name != "Write" {
		t.Errorf("tool names mismatch")
	}
}

func TestCapGrowthDoesNotDropSessionHistoryOrOutput(t *testing.T) {
	s := &Session{}
	for i := 0; i < 501; i++ {
		s.Turns = append(s.Turns, Turn{TurnIdx: i, UserInput: "prompt"})
	}
	s.AgentOutput = string(make([]byte, 100001))

	s.capGrowth()

	if len(s.Turns) != 501 {
		t.Fatalf("turns were trimmed to %d, want 501", len(s.Turns))
	}
	if len(s.AgentOutput) != 100001 {
		t.Fatalf("agent output was trimmed to %d bytes, want 100001", len(s.AgentOutput))
	}
}

func TestHandleEventToolCompletionDeltaIncludesTurns(t *testing.T) {
	var deltas []*Delta
	sm := NewSessionManager(nil, "u1", "d1")
	sm.SetNotify(func(eventType string, data interface{}) {
		if eventType == "delta" {
			deltas = append(deltas, data.(*Delta))
		}
	})

	sm.HandleEvent(&HookEvent{Event: "UserPromptSubmit", AgentType: "claude", SessionID: "sid1", TimestampMs: 1000, Payload: makePayload(map[string]interface{}{"prompt": "read"})})
	sm.HandleEvent(&HookEvent{Event: "PreToolUse", AgentType: "claude", SessionID: "sid1", TimestampMs: 2000, Payload: makePayload(map[string]interface{}{"tool_name": "Read", "tool_input": map[string]interface{}{"filePath": "/a.go"}})})
	sm.HandleEvent(&HookEvent{Event: "PostToolUse", AgentType: "claude", SessionID: "sid1", TimestampMs: 3000, Payload: makePayload(map[string]interface{}{"tool_name": "Read", "tool_output": "content"})})

	if len(deltas) == 0 {
		t.Fatal("expected deltas")
	}
	last := deltas[len(deltas)-1]
	if _, ok := last.Changes["turns"]; !ok {
		t.Fatalf("last delta changes=%v, want turns", last.Changes)
	}
}

func TestBuildTurn_ToolFailure(t *testing.T) {
	s := &Session{}
	s.Turns = append(s.Turns, Turn{TurnIdx: 0, UserInput: "test", UserTS: 1000, Entries: []TurnEntry{}})
	s.applyEvent(&HookEvent{Event: "PreToolUse", TimestampMs: 2000, Payload: makePayload(map[string]interface{}{"tool_name": "Bash", "tool_input": map[string]interface{}{"command": "rm -rf /"}})}, &ClaudeCodeHandler{})
	s.applyEvent(&HookEvent{Event: "PostToolUseFailure", TimestampMs: 2500, Payload: makePayload(map[string]interface{}{"tool_name": "Bash", "reason": "blocked"})}, &ClaudeCodeHandler{})

	if len(s.Turns[0].Entries) != 2 {
		t.Fatalf("expected tool group plus failure payload entry, got %d", len(s.Turns[0].Entries))
	}
	tc := s.Turns[0].Entries[0].Tools[0]
	if tc.Status != "error" || tc.Output != "blocked" {
		t.Errorf("expected error tool, got status=%s output=%s", tc.Status, tc.Output)
	}
	if s.Turns[0].Entries[1].Event != "PostToolUseFailure" {
		t.Fatalf("expected failure payload entry, got %s", s.Turns[0].Entries[1].Event)
	}
}

func TestBuildTurn_FullTurnFlow(t *testing.T) {
	s := &Session{}
	s.applyEvent(&HookEvent{Event: "UserPromptSubmit", TimestampMs: 1000, Payload: makePayload(map[string]interface{}{"prompt": "sort"})}, &ClaudeCodeHandler{})
	s.applyEvent(&HookEvent{Event: "ReasoningPart", TimestampMs: 1500, Payload: makePayload(map[string]interface{}{"text": "I should use quicksort"})}, &ClaudeCodeHandler{})
	s.applyEvent(&HookEvent{Event: "PreToolUse", TimestampMs: 2000, Payload: makePayload(map[string]interface{}{"tool_name": "Read", "tool_input": map[string]interface{}{"filePath": "/main.go"}})}, &ClaudeCodeHandler{})
	s.applyEvent(&HookEvent{Event: "PostToolUse", TimestampMs: 2500, Payload: makePayload(map[string]interface{}{"tool_name": "Read", "tool_output": "pkg main"})}, &ClaudeCodeHandler{})
	s.applyEvent(&HookEvent{Event: "AssistantText", TimestampMs: 3500, Payload: makePayload(map[string]interface{}{"text": "I wrote sort to /main.go"})}, &ClaudeCodeHandler{})

	if len(s.Turns) != 1 {
		t.Fatalf("expected 1 turn, got %d", len(s.Turns))
	}
	turn := s.Turns[0]
	if len(turn.Entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(turn.Entries))
	}
	if turn.Entries[0].Event != "ReasoningPart" {
		t.Errorf("expected ReasoningPart, got %s", turn.Entries[0].Event)
	}
	if len(turn.Entries[1].Tools) != 1 {
		t.Errorf("expected 1 tool in entry 1")
	}
	if turn.Entries[2].Event != "PostToolUse" {
		t.Errorf("expected PostToolUse, got %s", turn.Entries[2].Event)
	}
	if turn.Entries[3].Event != "AssistantText" {
		t.Errorf("expected AssistantText, got %s", turn.Entries[3].Event)
	}
}

func TestBuildTurn_MultipleTurns(t *testing.T) {
	s := &Session{}
	s.applyEvent(&HookEvent{Event: "UserPromptSubmit", TimestampMs: 1000, Payload: makePayload(map[string]interface{}{"prompt": "first"})}, &ClaudeCodeHandler{})
	s.applyEvent(&HookEvent{Event: "AssistantText", TimestampMs: 1500, Payload: makePayload(map[string]interface{}{"text": "first response"})}, &ClaudeCodeHandler{})
	s.applyEvent(&HookEvent{Event: "UserPromptSubmit", TimestampMs: 2000, Payload: makePayload(map[string]interface{}{"prompt": "second"})}, &ClaudeCodeHandler{})
	s.applyEvent(&HookEvent{Event: "AssistantText", TimestampMs: 2500, Payload: makePayload(map[string]interface{}{"text": "second response"})}, &ClaudeCodeHandler{})

	if len(s.Turns) != 2 {
		t.Fatalf("expected 2 turns, got %d", len(s.Turns))
	}
}

func TestBuildTurn_GenericInfoEvents(t *testing.T) {
	s := &Session{}
	s.Turns = append(s.Turns, Turn{TurnIdx: 0, UserInput: "test", UserTS: 1000, Entries: []TurnEntry{}})
	// Any non-structural event should create a generic entry
	s.applyEvent(&HookEvent{Event: "ConfigChange", TimestampMs: 2000, Payload: makePayload(map[string]interface{}{"source": "user_settings"})}, &ClaudeCodeHandler{})
	s.applyEvent(&HookEvent{Event: "FileEdited", TimestampMs: 3000, Payload: makePayload(map[string]interface{}{"filePath": "/test.go"})}, &ClaudeCodeHandler{})
	s.applyEvent(&HookEvent{Event: "PermissionAsked", TimestampMs: 4000, Payload: makePayload(map[string]interface{}{"tool_name": "Bash", "message": "allow?"})}, &ClaudeCodeHandler{})

	if len(s.Turns[0].Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(s.Turns[0].Entries))
	}
	// Each entry preserves its native event name
	if s.Turns[0].Entries[0].Event != "ConfigChange" {
		t.Errorf("expected ConfigChange, got %s", s.Turns[0].Entries[0].Event)
	}
	if s.Turns[0].Entries[1].Event != "FileEdited" {
		t.Errorf("expected FileEdited, got %s", s.Turns[0].Entries[1].Event)
	}
	if s.Turns[0].Entries[2].Event != "PermissionAsked" {
		t.Errorf("expected PermissionAsked, got %s", s.Turns[0].Entries[2].Event)
	}
}

func TestBuildTurn_WebInputActive(t *testing.T) {
	s := &Session{webInputActive: true}
	s.Turns = append(s.Turns, Turn{TurnIdx: 0, UserInput: "web input", UserTS: 1000, Entries: []TurnEntry{}})
	s.applyEvent(&HookEvent{Event: "UserPromptSubmit", TimestampMs: 2000, Payload: makePayload(map[string]interface{}{"prompt": "duplicate"})}, &ClaudeCodeHandler{})
	// Should NOT create a new turn
	if len(s.Turns) != 1 {
		t.Fatalf("expected 1 turn, got %d", len(s.Turns))
	}
	if s.webInputActive {
		t.Error("expected webInputActive to be cleared")
	}
}

func TestSessionEndAddsResult(t *testing.T) {
	sm := &SessionManager{
		sessions: make(map[string]*Session), userID: "u1", deviceID: "d1",
	}
	key := ComputeSessionKey("u1", "d1", "opencode", "sid1")
	s := &Session{
		UserID: "u1", DeviceID: "d1", AgentType: "opencode",
		AgentSessionID: "sid1", SessionKey: key,
		Turns: []Turn{{TurnIdx: 0, UserInput: "test", UserTS: 1000, Entries: []TurnEntry{}}},
	}
	sm.sessions[key] = s
	ev := &HookEvent{Event: "Stop", AgentType: "opencode", SessionID: "sid1", TimestampMs: 5000,
		Payload: makePayload(map[string]interface{}{"model_output": "final"})}
	sm.HandleEvent(ev)

	turn := s.Turns[0]
	if len(turn.Entries) == 0 || turn.Entries[len(turn.Entries)-1].Event != "Stop" {
		t.Errorf("expected Stop entry, got %d entries", len(turn.Entries))
	}
}

func TestClaudeMessageDisplayDeltasAppendModelOutput(t *testing.T) {
	s := &Session{AgentOutput: "[12:00:00] PostToolUse Bash -> tool output"}
	s.applyEvent(&HookEvent{Event: "MessageDisplay", AgentType: "claude", TimestampMs: 2000, Payload: makePayload(map[string]interface{}{"index": 0, "delta": "final ", "final": false})}, &ClaudeCodeHandler{})
	s.applyEvent(&HookEvent{Event: "MessageDisplay", AgentType: "claude", TimestampMs: 2100, Payload: makePayload(map[string]interface{}{"index": 1, "delta": "answer", "final": true})}, &ClaudeCodeHandler{})

	want := "[12:00:00] PostToolUse Bash -> tool output\nfinal answer"
	if s.AgentOutput != want {
		t.Fatalf("AgentOutput=%q, want %q", s.AgentOutput, want)
	}
}

func TestClaudeStopAddsLastAssistantMessageFallback(t *testing.T) {
	s := &Session{AgentOutput: "[12:00:00] PostToolUse Bash -> tool output"}
	s.applyEvent(&HookEvent{Event: "Stop", AgentType: "claude", TimestampMs: 3000, Payload: makePayload(map[string]interface{}{"last_assistant_message": "canonical final answer"})}, &ClaudeCodeHandler{})

	want := "[12:00:00] PostToolUse Bash -> tool output\ncanonical final answer"
	if s.AgentOutput != want {
		t.Fatalf("AgentOutput=%q, want %q", s.AgentOutput, want)
	}
}

func TestComputeDelta_Turns(t *testing.T) {
	sm := &SessionManager{}
	old := &Session{Turns: []Turn{{TurnIdx: 0, UserInput: "a", Entries: []TurnEntry{}}}}
	new := &Session{Turns: []Turn{{TurnIdx: 0, UserInput: "a", Entries: []TurnEntry{{Event: "AssistantText", TS: 100}}}}}
	delta := sm.computeDelta(old, new)
	if delta == nil {
		t.Fatal("expected delta")
	}
	if _, ok := delta.Changes["turns"]; !ok {
		t.Error("expected turns in delta")
	}
}

func TestExtractStringField(t *testing.T) {
	p := makePayload(map[string]interface{}{"foo": "bar"})
	if v := extractStringField(p, "foo"); v != "bar" {
		t.Errorf("expected bar, got %q", v)
	}
}

func TestExtractToolInput(t *testing.T) {
	h := &ClaudeCodeHandler{}
	p := makePayload(map[string]interface{}{"tool_input": map[string]interface{}{"command": "ls"}})
	if v := h.ExtractToolInput(p); v != "ls" {
		t.Errorf("expected ls, got %q", v)
	}
}

func TestExtractToolOutput(t *testing.T) {
	h := &ClaudeCodeHandler{}
	p := makePayload(map[string]interface{}{"tool_output": "done"})
	if v := h.ExtractToolOutput(p); v != "done" {
		t.Errorf("expected done, got %q", v)
	}
}

func TestStoreTurnsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	sess := &Session{
		UserID: "u1", DeviceID: "d1", AgentType: "opencode",
		AgentSessionID: "sid1", SessionKey: "key1",
		Status: StatusActive, StartTimeMs: 1000,
		Turns: []Turn{{
			TurnIdx: 0, UserInput: "hello", UserTS: 1000,
			Entries: []TurnEntry{
				{Event: "ReasoningPart", TS: 1100, Payload: json.RawMessage(`{"text":"thinking..."}`)},
				{Event: "PreToolUse", Tools: []ToolCall{{Name: "Read", Input: "/f.go", Output: "c", Status: "completed", StartTS: 1200, EndTS: 1300}}, StartTS: 1200, Payload: json.RawMessage(`{"tool_name":"Read"}`)},
				{Event: "AssistantText", TS: 1400, Payload: json.RawMessage(`{"text":"response"}`)},
			},
		}},
	}
	if err := store.Upsert(sess); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	sessions, err := store.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	loaded := sessions[0]
	if len(loaded.Turns) != 1 {
		t.Fatalf("expected 1 turn, got %d", len(loaded.Turns))
	}
	if len(loaded.Turns[0].Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(loaded.Turns[0].Entries))
	}
	if loaded.Turns[0].Entries[0].Event != "ReasoningPart" {
		t.Errorf("expected ReasoningPart, got %s", loaded.Turns[0].Entries[0].Event)
	}
	if loaded.Turns[0].Entries[1].Tools[0].Name != "Read" {
		t.Errorf("expected tool Read, got %s", loaded.Turns[0].Entries[1].Tools[0].Name)
	}
	if loaded.Turns[0].Entries[2].Event != "AssistantText" {
		t.Errorf("expected AssistantText, got %s", loaded.Turns[0].Entries[2].Event)
	}
}

func newSDKSessionManagerFixture(t *testing.T) (*SessionManager, *Store, int64) {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	db, err := store.DB()
	if err != nil {
		t.Fatalf("DB: %v", err)
	}
	authStore := auth.NewStore(db)
	if err := authStore.EnsureTables(); err != nil {
		t.Fatalf("auth tables: %v", err)
	}
	hierStore := hierarchy.NewStore(db)
	if err := hierStore.EnsureTables(); err != nil {
		t.Fatalf("hier tables: %v", err)
	}
	user, err := authStore.Register("sdk-user", "pw")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	ws, err := hierStore.CreateWorkspace("sdk-ws", "")
	if err != nil {
		t.Fatalf("create ws: %v", err)
	}
	hierStore.SetPermission(user.ID, "workspace", ws.ID, hierarchy.LevelWorkspaceAdmin, user.ID)
	mgr := NewSessionManager(store, "local", "device-1")
	mgr.SetHierarchyStore(hierStore)
	return mgr, store, ws.ID
}

func TestRegisterSDKSessionCreatesMonitoredSession(t *testing.T) {
	mgr, _, wsID := newSDKSessionManagerFixture(t)
	sdkSess := &sdk.Session{ID: "sdk-sid", AgentType: sdk.AgentClaude, Title: "SDK title", CWD: "/tmp/sdk", CreatedAt: time.Now()}

	monitored, err := mgr.RegisterSDKSession("claude", sdkSess, wsID, 0, "")
	if err != nil {
		t.Fatalf("RegisterSDKSession: %v", err)
	}

	if monitored.Source != "sdk" {
		t.Fatalf("Source=%q, want sdk", monitored.Source)
	}
	if monitored.AgentSessionID != "sdk-sid" || monitored.SessionTitle != "SDK title" || monitored.CWD != "/tmp/sdk" {
		t.Fatalf("monitored session mismatch: %+v", monitored)
	}
	if monitored.StoryID == nil {
		t.Fatalf("expected SDK session to be linked to a story")
	}
	if got := mgr.GetSession(monitored.SessionKey); got == nil {
		t.Fatalf("registered session missing from manager")
	}
}

func TestRegisterSDKSessionWithExplicitTopicCreatesStoryUnderThatTopic(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	db, err := store.DB()
	if err != nil {
		t.Fatalf("DB: %v", err)
	}
	hierStore := hierarchy.NewStore(db)
	if err := hierStore.EnsureTables(); err != nil {
		t.Fatalf("hier tables: %v", err)
	}
	ws, err := hierStore.CreateWorkspace("ws1", "")
	if err != nil {
		t.Fatalf("create ws: %v", err)
	}
	proj, err := hierStore.CreateProject(ws.ID, "proj1", "")
	if err != nil {
		t.Fatalf("create proj: %v", err)
	}
	topic, err := hierStore.CreateTopic(proj.ID, "topic1", "", "claude")
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}

	mgr := NewSessionManager(store, "local", "device-1")
	mgr.SetHierarchyStore(hierStore)

	sdkSess := &sdk.Session{ID: "sdk-sid-2", AgentType: sdk.AgentClaude, CreatedAt: time.Now()}
	monitored, err := mgr.RegisterSDKSession("claude", sdkSess, ws.ID, topic.ID, "My Explicit Story")
	if err != nil {
		t.Fatalf("RegisterSDKSession: %v", err)
	}
	if monitored.StoryID == nil {
		t.Fatalf("expected a story to be linked")
	}
	story, err := hierStore.GetStory(*monitored.StoryID)
	if err != nil {
		t.Fatalf("GetStory: %v", err)
	}
	if story.TopicID != topic.ID {
		t.Fatalf("story topic_id=%d, want %d (explicit topic)", story.TopicID, topic.ID)
	}
	if story.Name != "My Explicit Story" {
		t.Fatalf("story name=%q, want %q", story.Name, "My Explicit Story")
	}
}

func TestRecordSDKPromptDoesNotCreatePendingInput(t *testing.T) {
	mgr, _, wsID := newSDKSessionManagerFixture(t)
	monitored, err := mgr.RegisterSDKSession("claude", &sdk.Session{ID: "sdk-sid", AgentType: sdk.AgentClaude, CreatedAt: time.Now()}, wsID, 0, "")
	if err != nil {
		t.Fatalf("RegisterSDKSession: %v", err)
	}

	if !mgr.RecordSDKPrompt(monitored.SessionKey, "hello sdk") {
		t.Fatalf("RecordSDKPrompt returned false")
	}

	got := mgr.GetSession(monitored.SessionKey)
	if got == nil || got.UserInput != "hello sdk" || got.Status != StatusActive || got.TurnCount != 1 || len(got.Turns) != 1 {
		t.Fatalf("recorded SDK prompt session mismatch: %+v", got)
	}
	if pending := mgr.GetPendingInput(monitored.SessionKey); pending != "" {
		t.Fatalf("pending input=%q, want empty for sdk session", pending)
	}
}

func TestRecordSDKMessageEmitsLiveOutputDelta(t *testing.T) {
	mgr, _, wsID := newSDKSessionManagerFixture(t)
	monitored, err := mgr.RegisterSDKSession("claude", &sdk.Session{ID: "sdk-sid", AgentType: sdk.AgentClaude, CreatedAt: time.Now()}, wsID, 0, "")
	if err != nil {
		t.Fatalf("RegisterSDKSession: %v", err)
	}
	mgr.RecordSDKPrompt(monitored.SessionKey, "hello sdk")
	var gotDelta *Delta
	mgr.SetNotify(func(eventType string, data interface{}) {
		if eventType == "delta" {
			gotDelta, _ = data.(*Delta)
		}
	})

	if !mgr.RecordSDKMessage(monitored.SessionKey, sdk.Message{Type: sdk.MessageTypeText, Content: "stream chunk", Timestamp: time.Now()}) {
		t.Fatalf("RecordSDKMessage returned false")
	}

	if gotDelta == nil {
		t.Fatalf("expected delta")
	}
	if gotDelta.Changes["agent_output"] != "stream chunk" {
		t.Fatalf("agent_output delta=%v, want stream chunk", gotDelta.Changes["agent_output"])
	}
	if _, ok := gotDelta.Changes["turns"]; !ok {
		t.Fatalf("expected turns in delta changes: %#v", gotDelta.Changes)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
