package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heybox/agent-monitor-server/internal/session"
)

type recordingHandler struct {
	events []*session.HookEvent
}

func (h *recordingHandler) HandleEvent(event *session.HookEvent) {
	h.events = append(h.events, event)
}

func TestEventWatcherProcessesLargeSingleLineEvent(t *testing.T) {
	dir := t.TempDir()
	handler := &recordingHandler{}
	ew, err := NewEventWatcher(dir, "tok", handler)
	if err != nil {
		t.Fatalf("NewEventWatcher: %v", err)
	}
	ew.lastPos = 0

	payload := map[string]interface{}{"text": strings.Repeat("x", 2*1024*1024+1)}
	line, err := json.Marshal(session.HookEvent{
		Event:       "AssistantText",
		AgentType:   "claude",
		SessionID:   "sid",
		DaemonToken: "tok",
		TimestampMs: 1000,
		Payload:     mustRawJSON(t, payload),
	})
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), append(line, '\n'), 0600); err != nil {
		t.Fatalf("write events: %v", err)
	}

	ew.handleNewLines()

	if len(handler.events) != 1 {
		t.Fatalf("processed %d events, want 1", len(handler.events))
	}
}

func mustRawJSON(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal raw: %v", err)
	}
	return b
}
