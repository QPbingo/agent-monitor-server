package session

import "encoding/json"

type CodexHandler struct{}

func (h *CodexHandler) ClassifyEvent(event *HookEvent, _ *Session) EventClass {
	switch event.Event {
	case "UserPromptSubmit":
		return ClassUserPrompt
	case "PreToolUse":
		return ClassPreTool
	case "PostToolUse":
		return ClassPostTool
	case "PostToolUseFailure":
		return ClassPostToolFailure
	}
	return ClassOther
}

func (h *CodexHandler) ExtractToolName(payload json.RawMessage) string {
	return extractStringField(payload, "tool_name", "tool", "toolName")
}

func (h *CodexHandler) ExtractToolInput(payload json.RawMessage) string {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return ""
	}
	if input, ok := data["tool_input"].(map[string]interface{}); ok {
		if v := firstStringInMap(input, "command", "filePath", "file_path"); v != "" {
			return v
		}
	}
	if input, ok := data["input"].(map[string]interface{}); ok {
		if v := firstStringInMap(input, "command", "filePath", "file_path"); v != "" {
			return v
		}
	}
	return ""
}

func (h *CodexHandler) ExtractToolOutput(payload json.RawMessage) string {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return ""
	}
	if out, ok := data["tool_output"].(string); ok && out != "" {
		return out
	}
	if out, ok := data["output"].(string); ok && out != "" {
		return out
	}
	if out, ok := data["result"].(string); ok && out != "" {
		return out
	}
	if state, ok := data["state"].(map[string]interface{}); ok {
		if out, ok := state["output"].(string); ok && out != "" {
			return out
		}
	}
	return ""
}

func (h *CodexHandler) ExtractUserPromptText(event *HookEvent) string {
	return extractStringField(event.Payload, "prompt", "user_input", "text", "message")
}

func (h *CodexHandler) IsTerminalEvent(event string) bool {
	switch event {
	case "Stop", "session_end", "SessionEnd", "SessionClose", "SessionDeleted":
		return true
	}
	return false
}

func (h *CodexHandler) LifecycleStatus(event string) (Status, bool) {
	switch event {
	case "SessionStart", "session_start":
		return StatusActive, true
	case "Stop", "session_end":
		return StatusStopped, true
	case "SessionError", "StopFailure", "session_error", "stop_failure":
		return StatusError, true
	case "SessionEnd", "SessionClose", "SessionDeleted", "session_close", "session_deleted":
		return StatusStopped, true
	}
	return "", false
}

func (h *CodexHandler) OnEvent(sess *Session, event *HookEvent) {
	switch event.Event {
	case "PreToolUse", "PostToolUse":
		sess.extractToolInfo(event.Payload)
		sess.appendAgentOutput(event.Payload)
	case "AssistantText", "ReasoningPart":
		sess.extractModelOutput(event.Payload)
	case "VcsBranchUpdated":
		sess.extractBranchInfo(event.Payload)
	}
}
