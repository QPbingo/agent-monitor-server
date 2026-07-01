package session

import "encoding/json"

// EventClass is the semantic classification of an event for turn building.
type EventClass int

const (
	ClassOther EventClass = iota
	ClassUserPrompt
	ClassPreTool
	ClassPostTool
	ClassPostToolFailure
)

// AgentHandler provides agent-specific event processing logic.
type AgentHandler interface {
	ClassifyEvent(event *HookEvent, sess *Session) EventClass
	ExtractToolName(payload json.RawMessage) string
	ExtractToolInput(payload json.RawMessage) string
	ExtractToolOutput(payload json.RawMessage) string
	ExtractUserPromptText(event *HookEvent) string
	IsTerminalEvent(event string) bool
	LifecycleStatus(event string) (Status, bool)
	OnEvent(sess *Session, event *HookEvent)
}

// ── Handler dispatch ──

var handlers = map[string]AgentHandler{
	"claude":   &ClaudeCodeHandler{},
	"codex":    &CodexHandler{},
	"opencode": &OpenCodeHandler{},
}

func getHandler(agentType string) AgentHandler {
	h, ok := handlers[agentType]
	if !ok {
		return &ClaudeCodeHandler{}
	}
	return h
}

// ── Shared helpers ──

func parsePartPayload(payload json.RawMessage) (partType, status, role string) {
	if len(payload) == 0 {
		return
	}
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return
	}
	if r, ok := data["_role"].(string); ok {
		role = r
	}
	part, _ := data["part"].(map[string]interface{})
	if part == nil {
		return
	}
	partType, _ = part["type"].(string)
	if state, ok := part["state"].(map[string]interface{}); ok {
		status, _ = state["status"].(string)
	}
	return
}

func firstStringInMap(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	for _, v := range m {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
