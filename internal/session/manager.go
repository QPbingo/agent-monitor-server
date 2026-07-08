package session

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/heybox/agent-monitor-hook/sdk"
	"github.com/heybox/agent-monitor-server/internal/hierarchy"
	"github.com/heybox/agent-monitor-server/internal/scanner"
)

type NotifyFunc func(eventType string, data interface{})

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	store    *Store
	notify   NotifyFunc

	userID        string
	deviceID      string
	pendingInputs map[string]string
	hierStore     *hierarchy.Store
	hierNotify    NotifyFunc // callback for hierarchy updates
}

func NewSessionManager(store *Store, userID, deviceID string) *SessionManager {
	return &SessionManager{
		sessions:      make(map[string]*Session),
		store:         store,
		userID:        userID,
		deviceID:      deviceID,
		pendingInputs: make(map[string]string),
	}
}

func (sm *SessionManager) SetNotify(fn NotifyFunc)              { sm.notify = fn }
func (sm *SessionManager) SetHierarchyStore(h *hierarchy.Store) { sm.hierStore = h }
func (sm *SessionManager) SetHierarchyNotify(fn NotifyFunc)     { sm.hierNotify = fn }
func (sm *SessionManager) UserID() string                       { return sm.userID }
func (sm *SessionManager) DeviceID() string                     { return sm.deviceID }

func (sm *SessionManager) RegisterSDKSession(agentType string, sdkSess *sdk.Session, workspaceID int64, topicID int64, storyName string) (*Session, error) {
	if sdkSess == nil {
		return nil, nil
	}
	now := time.Now().UnixMilli()
	createdAt := now
	if !sdkSess.CreatedAt.IsZero() {
		createdAt = sdkSess.CreatedAt.UnixMilli()
	}
	key := ComputeSessionKey(sm.userID, sm.deviceID, agentType, sdkSess.ID)

	sm.mu.Lock()
	sess, exists := sm.sessions[key]
	if !exists {
		sess = &Session{UserID: sm.userID, DeviceID: sm.deviceID, AgentType: agentType, AgentSessionID: sdkSess.ID, SessionKey: key, Status: StatusIdle, StartTimeMs: createdAt, Source: "sdk"}
		sm.sessions[key] = sess
	}
	sess.Source = "sdk"
	sess.AgentType = agentType
	sess.AgentSessionID = sdkSess.ID
	sess.CWD = sdkSess.CWD
	if sdkSess.Title != "" {
		sess.SessionTitle = sdkSess.Title
	}
	if sess.SessionTitle == "" {
		sess.SessionTitle = sdkSess.ID
	}
	if sess.StartTimeMs == 0 {
		sess.StartTimeMs = createdAt
	}
	sess.LastEventTimeMs = now
	sess.LastEventType = "SDKSessionCreated"
	sess.LastHookEvent = "SDKSessionCreated"
	sess.lastHookTime = now
	sm.mu.Unlock()

	if sm.hierStore != nil {
		var story *hierarchy.Story
		var err error
		if topicID != 0 {
			name := storyName
			if name == "" {
				name = sess.SessionTitle
			}
			story, err = sm.hierStore.CreateStoryForSession(topicID, name, key)
		} else {
			story, err = sm.hierStore.FindOrCreateAgentSessionStory(workspaceID, agentType, key, sess.SessionTitle)
		}
		if err != nil {
			return nil, err
		}
		sm.mu.Lock()
		sess.StoryID = &story.ID
		sm.mu.Unlock()
	}

	if sm.store != nil {
		if err := sm.store.Upsert(sess); err != nil {
			log.Printf("[session] upsert sdk session: %v", err)
		}
	}
	if sm.hierNotify != nil && sm.hierStore != nil {
		if tree, err := sm.hierStore.GetFullHierarchy(); err == nil {
			sm.hierNotify("hierarchy_updated", tree)
		}
	}
	if sm.notify != nil {
		clone := *sess
		clone.Payload = nil
		if exists {
			sm.notify("delta", &Delta{SessionKey: key, Changes: map[string]interface{}{"source": clone.Source, "session_title": clone.SessionTitle, "cwd": clone.CWD, "story_id": clone.StoryID}, TimestampMs: now})
		} else {
			sm.notify("session_added", &clone)
		}
	}
	clone := *sess
	return &clone, nil
}

func (sm *SessionManager) RecordSDKPrompt(key string, text string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sess, ok := sm.sessions[key]
	if !ok || sess.Source != "sdk" {
		return false
	}
	old := cloneSession(sess)
	sess.TurnCount++
	sess.UserInput = text
	sess.Status = StatusActive
	sess.LastEventTimeMs = time.Now().UnixMilli()
	sess.LastEventType = "SDKPrompt"
	sess.LastHookEvent = "SDKPrompt"
	sess.lastHookTime = sess.LastEventTimeMs
	sess.Turns = append(sess.Turns, Turn{TurnIdx: len(sess.Turns), UserInput: text, UserTS: sess.LastEventTimeMs, Entries: []TurnEntry{}})
	if sm.store != nil {
		if err := sm.store.Upsert(sess); err != nil {
			log.Printf("[session] upsert sdk prompt: %v", err)
		}
	}
	if sm.notify != nil {
		if delta := sm.computeDelta(&old, sess); delta != nil {
			sm.notify("delta", delta)
		}
	}
	return true
}

func (sm *SessionManager) RecordSDKMessage(key string, msg sdk.Message) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sess, ok := sm.sessions[key]
	if !ok || sess.Source != "sdk" {
		return false
	}
	old := cloneSession(sess)
	sess.LastEventTimeMs = time.Now().UnixMilli()
	sess.LastEventType = "SDKMessage"
	sess.LastHookEvent = "SDKMessage"
	sess.lastHookTime = sess.LastEventTimeMs
	if msg.Content != "" {
		if sess.AgentOutput != "" {
			sess.AgentOutput += "\n"
		}
		sess.AgentOutput += msg.Content
	}
	if len(sess.Turns) > 0 {
		sess.recordSDKToolCallOrGenericEntry(len(sess.Turns)-1, msg)
	}
	if sm.store != nil {
		if err := sm.store.Upsert(sess); err != nil {
			log.Printf("[session] upsert sdk message: %v", err)
		}
	}
	if sm.notify != nil {
		if delta := sm.computeDelta(&old, sess); delta != nil {
			sm.notify("delta", delta)
		}
	}
	return true
}

// recordSDKToolCallOrGenericEntry appends msg to the given turn, either as a
// structured ToolCall — grouped the same way hook-driven PreToolUse/
// PostToolUse events are (see addToolRunning/completeTool below) — or as a
// generic SDKMessage entry for anything else. This is what lets SDK-driven
// sessions render tool calls in the timeline the same way hook-driven
// sessions already do.
//
// Known limitation: ClaudeSDK never emits a MessageTypeToolResult (Claude
// Code's stream-json returns tool results as "user" messages, which
// ClaudeSDK.parseMessage currently classifies as MessageTypeSystem and
// ignores) — so a Claude tool call recorded here shows status "running"
// indefinitely. Accepted gap: diff review reads git state directly and does
// not depend on tool_result data (see plan Task 7 for the full rationale).
func (s *Session) recordSDKToolCallOrGenericEntry(turnIdx int, msg sdk.Message) {
	turn := &s.Turns[turnIdx]
	ts := s.LastEventTimeMs
	switch msg.Type {
	case sdk.MessageTypeToolUse:
		tc := ToolCall{Name: msg.ToolName, Input: msg.ToolInput, Status: "running", StartTS: ts}
		var group *TurnEntry
		for i := len(turn.Entries) - 1; i >= 0; i-- {
			if len(turn.Entries[i].Tools) > 0 {
				group = &turn.Entries[i]
				break
			}
		}
		if group == nil {
			turn.Entries = append(turn.Entries, TurnEntry{Event: "SDKToolUse", Tools: []ToolCall{tc}, StartTS: ts})
		} else {
			group.Tools = append(group.Tools, tc)
		}
	case sdk.MessageTypeToolResult:
		for i := len(turn.Entries) - 1; i >= 0; i-- {
			entry := &turn.Entries[i]
			for j := len(entry.Tools) - 1; j >= 0; j-- {
				tc := &entry.Tools[j]
				if tc.Status == "running" {
					tc.Status = "completed"
					tc.Output = msg.Content
					tc.EndTS = ts
					return
				}
			}
		}
		turn.Entries = append(turn.Entries, TurnEntry{Event: "SDKMessage", TS: ts, Payload: msg.RawJSON})
	default:
		turn.Entries = append(turn.Entries, TurnEntry{Event: "SDKMessage", TS: ts, Payload: msg.RawJSON})
	}
}

func (sm *SessionManager) MarkSDKSessionIdle(key string) {
	sm.setSDKSessionStatus(key, StatusIdle, "SDKComplete", "")
}
func (sm *SessionManager) MarkSDKSessionStopped(key string) {
	sm.setSDKSessionStatus(key, StatusStopped, "SDKCancelled", "")
}
func (sm *SessionManager) MarkSDKSessionError(key string, errText string) {
	sm.setSDKSessionStatus(key, StatusError, "SDKError", errText)
}

func (sm *SessionManager) setSDKSessionStatus(key string, status Status, event string, output string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sess, ok := sm.sessions[key]
	if !ok || sess.Source != "sdk" {
		return
	}
	old := cloneSession(sess)
	sess.Status = status
	sess.LastEventTimeMs = time.Now().UnixMilli()
	sess.LastEventType = event
	sess.LastHookEvent = event
	sess.lastHookTime = sess.LastEventTimeMs
	if output != "" {
		sess.AgentOutput = output
	}
	if sm.store != nil {
		if err := sm.store.Upsert(sess); err != nil {
			log.Printf("[session] upsert sdk status: %v", err)
		}
	}
	if sm.notify != nil {
		if delta := sm.computeDelta(&old, sess); delta != nil {
			sm.notify("delta", delta)
		}
	}
}

func (sm *SessionManager) LoadFromStore() {
	sessions, err := sm.store.LoadAll()
	if err != nil {
		log.Printf("[session] load from store: %v", err)
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for _, s := range sessions {
		if _, exists := sm.sessions[s.SessionKey]; !exists {
			sm.sessions[s.SessionKey] = s
		}
	}
	// Reconcile story links for sessions loaded from store that may not
	// have been auto-assigned to hierarchy stories.
	for _, s := range sm.sessions {
		if s.StoryID == nil && s.AgentType != "" && s.AgentSessionID != "" && sm.hierStore != nil {
			title := s.SessionTitle
			if title == "" {
				title = s.AgentSessionID
			}
			story, err := sm.hierStore.FindOrCreateInspirationStory(s.AgentType, s.SessionKey, title)
			if err != nil {
				log.Printf("[session] reconcile story link for %s: %v", s.SessionKey, err)
			} else {
				s.StoryID = &story.ID
				if sm.store != nil {
					sm.store.Upsert(s)
				}
			}
		}
	}
	log.Printf("[session] loaded %d sessions from store", len(sessions))
}

func (sm *SessionManager) HandleEvent(event *HookEvent) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	handler := getHandler(event.AgentType)
	key := ComputeSessionKey(sm.userID, sm.deviceID, event.AgentType, event.SessionID)
	sess, exists := sm.sessions[key]

	if !exists {
		if handler.IsTerminalEvent(event.Event) {
			return
		}
		sess = &Session{
			UserID:         sm.userID,
			DeviceID:       sm.deviceID,
			AgentType:      event.AgentType,
			AgentSessionID: event.SessionID,
			SessionKey:     key,
			Status:         StatusActive,
			StartTimeMs:    event.TimestampMs,
			Payload:        event.Payload,
		}
		sm.sessions[key] = sess
		sess.applyEvent(event, handler)

		// Auto-assign to inspiration project
		if sm.hierStore != nil {
			title := sess.SessionTitle
			if title == "" {
				title = sess.AgentSessionID
			}
			story, err := sm.hierStore.FindOrCreateInspirationStory(event.AgentType, key, title)
			if err != nil {
				log.Printf("[session] auto-assign story: %v", err)
			} else {
				sess.StoryID = &story.ID
				if sm.hierNotify != nil {
					if tree, err := sm.hierStore.GetFullHierarchy(); err == nil {
						sm.hierNotify("hierarchy_updated", tree)
					}
				}
			}
		}

		if sm.store != nil {
			if err := sm.store.Upsert(sess); err != nil {
				log.Printf("[session] upsert new session: %v", err)
			}
		}
		if sm.notify != nil {
			clone := *sess
			clone.Payload = nil
			sm.notify("session_added", &clone)
		}
		return
	}

	old := cloneSession(sess)

	// Update status from lifecycle events, then apply side effects.
	if status, ok := handler.LifecycleStatus(event.Event); ok {
		sess.Status = status
	}
	if event.Event == "SessionStart" || event.Event == "session_start" || event.Event == "session.created" {
		sess.StartTimeMs = event.TimestampMs
	}

	sess.applyEvent(event, handler)
	// Cap unbounded growth of turns and agent output.
	sess.capGrowth()
	if sm.store != nil {
		if err := sm.store.Upsert(sess); err != nil {
			log.Printf("[session] upsert session: %v", err)
		}
	}

	if sm.notify != nil {
		delta := sm.computeDelta(&old, sess)
		if delta != nil {
			sm.notify("delta", delta)
		}
	}
}

func (s *Session) applyEvent(event *HookEvent, handler AgentHandler) {
	s.LastEventTimeMs = event.TimestampMs
	s.LastEventType = event.Event
	s.LastHookEvent = event.Event
	s.CWD = event.CWD
	s.PID = event.PID
	s.lastHookTime = event.TimestampMs
	s.Payload = event.Payload

	s.buildTurnEntry(event, handler)
	handler.OnEvent(s, event)

	// Promote to active unless already in a terminal state.
	if s.Status != StatusError && s.Status != StatusStopped && s.Status != StatusDisappeared {
		s.Status = StatusActive
	}
}

func (s *Session) buildTurnEntry(event *HookEvent, handler AgentHandler) {
	cls := handler.ClassifyEvent(event, s)
	switch cls {
	case ClassUserPrompt:
		if s.webInputActive {
			s.webInputActive = false
			return
		}
		input := handler.ExtractUserPromptText(event)
		s.TurnCount++
		s.UserInput = input
		if s.SessionTitle == "" && input != "" {
			s.SessionTitle = input
		}
		s.Turns = append(s.Turns, Turn{
			TurnIdx:   len(s.Turns),
			UserInput: input,
			UserTS:    event.TimestampMs,
			Entries:   []TurnEntry{},
		})

	case ClassPreTool:
		s.addToolRunning(event, handler)

	case ClassPostTool:
		s.completeTool(event, handler)
		s.addEventEntry(event)

	case ClassPostToolFailure:
		s.failTool(event, handler)
		s.addEventEntry(event)

	default:
		if s.webInputActive {
			s.webInputActive = false
		}
		s.addEventEntry(event)
	}
}

func (s *Session) addEventEntry(event *HookEvent) {
	s.ensureTurn()
	turn := s.ensureTurn()
	turn.Entries = append(turn.Entries, TurnEntry{
		Event:   event.Event,
		TS:      event.TimestampMs,
		Payload: event.Payload,
	})
}

func (s *Session) addToolRunning(event *HookEvent, handler AgentHandler) {
	toolName := handler.ExtractToolName(event.Payload)
	toolInput := handler.ExtractToolInput(event.Payload)
	if toolName == "" {
		return
	}
	s.ensureTurn()
	turn := s.ensureTurn()
	tc := ToolCall{Name: toolName, Input: toolInput, Status: "running", StartTS: event.TimestampMs}
	var group *TurnEntry
	for i := len(turn.Entries) - 1; i >= 0; i-- {
		if len(turn.Entries[i].Tools) > 0 {
			group = &turn.Entries[i]
			break
		}
	}
	if group == nil {
		turn.Entries = append(turn.Entries, TurnEntry{
			Event:   event.Event,
			Payload: event.Payload,
			Tools:   []ToolCall{tc},
			StartTS: event.TimestampMs,
		})
	} else {
		group.Tools = append(group.Tools, tc)
	}
}

func (s *Session) completeTool(event *HookEvent, handler AgentHandler) {
	toolName := handler.ExtractToolName(event.Payload)
	toolOutput := handler.ExtractToolOutput(event.Payload)
	status := extractStringField(event.Payload, "status")
	if status == "" {
		status = "completed"
	}
	if len(s.Turns) == 0 {
		return
	}
	turn := &s.Turns[len(s.Turns)-1]
	for i := len(turn.Entries) - 1; i >= 0; i-- {
		entry := &turn.Entries[i]
		for j := len(entry.Tools) - 1; j >= 0; j-- {
			tc := &entry.Tools[j]
			if tc.Status == "running" && (toolName == "" || tc.Name == toolName) {
				tc.Status = status
				tc.Output = toolOutput
				tc.EndTS = event.TimestampMs
				return
			}
		}
	}
}

func (s *Session) failTool(event *HookEvent, handler AgentHandler) {
	toolName := handler.ExtractToolName(event.Payload)
	toolOutput := handler.ExtractToolOutput(event.Payload)
	reason := extractStringField(event.Payload, "reason", "error", "message")
	s.ensureTurn()
	turn := s.ensureTurn()
	// Match first running tool when toolName is empty, consistent with completeTool.
	for i := len(turn.Entries) - 1; i >= 0; i-- {
		entry := &turn.Entries[i]
		for j := len(entry.Tools) - 1; j >= 0; j-- {
			tc := &entry.Tools[j]
			if tc.Status == "running" && tc.Name == toolName {
				tc.Status = "error"
				if toolOutput != "" {
					tc.Output = toolOutput
				} else {
					tc.Output = reason
				}
				tc.EndTS = event.TimestampMs
				return
			}
		}
	}
	turn.Entries = append(turn.Entries, TurnEntry{
		Event: event.Event,
		Tools: []ToolCall{{Name: toolName, Status: "error", Output: firstNonEmpty(reason, toolOutput), StartTS: event.TimestampMs, EndTS: event.TimestampMs}},
	})
}

func (s *Session) ensureTurn() *Turn {
	if len(s.Turns) == 0 {
		s.Turns = append(s.Turns, Turn{TurnIdx: 0, UserTS: 0, Entries: []TurnEntry{}})
	}
	return &s.Turns[len(s.Turns)-1]
}

func extractStringField(payload json.RawMessage, keys ...string) string {
	if len(payload) == 0 {
		return ""
	}
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return ""
	}
	for _, k := range keys {
		if v, ok := data[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func (s *Session) extractUserInput(payload json.RawMessage) {
	if len(payload) == 0 {
		return
	}
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return
	}
	for _, k := range []string{"prompt", "user_input", "text", "message"} {
		if v, ok := data[k].(string); ok && v != "" {
			s.UserInput = v
			return
		}
	}
}

func (s *Session) appendAgentOutput(payload json.RawMessage) {
	if len(payload) == 0 {
		return
	}
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return
	}
	toolName, _ := data["tool_name"].(string)
	if toolName == "" {
		toolName, _ = data["tool"].(string)
	}
	output, _ := data["tool_output"].(string)
	if output == "" {
		output, _ = data["output"].(string)
	}
	if output == "" {
		if toolInput, ok := data["tool_input"].(map[string]interface{}); ok {
			if cmd, ok := toolInput["command"].(string); ok {
				output = cmd
			} else if fp, ok := toolInput["filePath"].(string); ok {
				output = fp
			} else if fp, ok := toolInput["file_path"].(string); ok {
				output = fp
			} else if fp, ok := toolInput["path"].(string); ok {
				output = fp
			} else {
				keys := make([]string, 0, len(toolInput))
				for k := range toolInput {
					keys = append(keys, k)
				}
				if len(keys) > 0 {
					output = "(" + keys[0] + "...)"
				}
			}
		}
	}
	line := ""
	if toolName != "" {
		line = "[" + toolName + "]"
	}
	if output != "" {
		if line != "" {
			line += " "
		}
		line += output
	}
	if line == "" {
		return
	}
	ts := time.Now().Format("15:04:05")
	if s.AgentOutput != "" {
		s.AgentOutput += "\n"
	}
	s.AgentOutput += "[" + ts + "] "
	if s.LastHookEvent != "" {
		s.AgentOutput += s.LastHookEvent + " "
	}
	if toolName != "" {
		s.AgentOutput += toolName
	}
	if output != "" {
		s.AgentOutput += " → " + output
	}
}

func (s *Session) extractModelOutput(payload json.RawMessage) {
	if len(payload) == 0 {
		return
	}
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return
	}
	// Standard top-level keys (Claude, Codex, legacy).
	for _, k := range []string{"last_assistant_message", "model_output", "output", "text", "response"} {
		if v, ok := data[k].(string); ok && v != "" {
			if s.AgentOutput != "" {
				s.AgentOutput += "\n"
			}
			s.AgentOutput += "[model] " + v
			return
		}
	}
	// OpenCode: text is nested inside part.text.
	if part, ok := data["part"].(map[string]interface{}); ok {
		if text, ok := part["text"].(string); ok && text != "" {
			if s.AgentOutput != "" {
				s.AgentOutput += "\n"
			}
			s.AgentOutput += "[model] " + text
		}
	}
}

func (s *Session) extractBranchInfo(payload json.RawMessage) {
	if len(payload) == 0 {
		return
	}
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return
	}
	if branch, ok := data["branch"].(string); ok && branch != "" {
		s.GitBranch = branch
	}
}

// storeMessageRole extracts the role from an OpenCode message.updated event
// and stores it on the session. Subsequent message.part.updated text events
// use this role to decide whether the text is user input or model output,
// without depending on the plugin.js _role hack.
func (s *Session) storeMessageRole(payload json.RawMessage) {
	if len(payload) == 0 {
		return
	}
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return
	}
	info, ok := data["info"].(map[string]interface{})
	if !ok {
		return
	}
	role, _ := info["role"].(string)
	if role != "" {
		s.lastMessageRole = role
	}
}

// extractSessionTitle pulls the human-readable title from a session.updated
// event payload. OpenCode computes this server-side (e.g. "前后端分离数据交互…")
// and pushes it in `info.title`. We only overwrite the session title when
// OpenCode actually provides a non-empty value; the user-prompt-derived title
// set by buildTurnEntry is left alone when info.title is empty.
//
// Preference: OpenCode's info.title wins over a stale title because OpenCode
// updates it as the conversation evolves (initial user message → refined
// summary), so always overwriting is the right call here.
func (s *Session) extractSessionTitle(payload json.RawMessage) {
	if len(payload) == 0 {
		return
	}
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return
	}
	info, ok := data["info"].(map[string]interface{})
	if !ok {
		return
	}
	title, _ := info["title"].(string)
	if title != "" {
		s.SessionTitle = title
	}
}

func (s *Session) extractToolInfo(payload json.RawMessage) {
	if len(payload) == 0 {
		return
	}
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return
	}
	if tool, ok := data["tool"].(string); ok {
		s.LastCommand = tool
	} else if tool, ok := data["tool_name"].(string); ok {
		s.LastCommand = tool
	} else if tool, ok := data["command"].(string); ok {
		s.LastCommand = tool
	}
	if input, ok := data["input"].(map[string]interface{}); ok {
		if fp, ok := input["filePath"].(string); ok {
			s.LastFile = fp
		} else if fp, ok := input["file_path"].(string); ok {
			s.LastFile = fp
		} else if fp, ok := input["path"].(string); ok {
			s.LastFile = fp
		}
	}
	if file, ok := data["filePath"].(string); ok {
		s.LastFile = file
	} else if file, ok := data["file"].(string); ok {
		s.LastFile = file
	}
}

func (sm *SessionManager) HandleWebInput(key string, text string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sess, ok := sm.sessions[key]
	if !ok {
		return false
	}
	old := cloneSession(sess)
	sess.TurnCount++
	sess.UserInput = text
	sess.LastEventTimeMs = time.Now().UnixMilli()
	sess.LastEventType = "WebInput"
	sess.LastHookEvent = "WebInput"
	sess.lastHookTime = time.Now().UnixMilli()
	sess.Turns = append(sess.Turns, Turn{
		TurnIdx:   len(sess.Turns),
		UserInput: text,
		UserTS:    sess.LastEventTimeMs,
		Entries:   []TurnEntry{},
	})
	sess.webInputActive = true
	sm.pendingInputs[key] = text
	if sm.store != nil {
		if err := sm.store.Upsert(sess); err != nil {
			log.Printf("[session] upsert web input: %v", err)
		}
	}
	if sm.notify != nil {
		delta := sm.computeDelta(&old, sess)
		if delta != nil {
			sm.notify("delta", delta)
		}
	}
	return true
}

func (sm *SessionManager) GetPendingInput(key string) string {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	text := sm.pendingInputs[key]
	delete(sm.pendingInputs, key)
	return text
}

func (sm *SessionManager) HandlePidUpdate(key string, info *scanner.ProcessInfo) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sess, ok := sm.sessions[key]
	if !ok {
		return
	}
	changed := false
	if sess.PID != int(info.PID) {
		sess.PID = int(info.PID)
		changed = true
	}
	if sess.CWD != info.CWD && info.CWD != "" {
		sess.CWD = info.CWD
		changed = true
	}
	if diff := abs(sess.CPUPercent - info.CPUPercent); diff > 0.1 {
		sess.CPUPercent = info.CPUPercent
		changed = true
	}
	if diff := abs(sess.MemoryMB - info.MemoryMB); diff > 0.5 {
		sess.MemoryMB = info.MemoryMB
		changed = true
	}
	if info.CreateTimeMs > 0 {
		sess.ProcessCreateTimeMs = info.CreateTimeMs
	}
	if info.Name != "" && sess.Terminal != info.Name {
		sess.Terminal = info.Name
		changed = true
	}
	if sess.Status == StatusDisappeared {
		sess.Status = StatusActive
		sess.lastHookTime = time.Now().UnixMilli()
		changed = true
		// Use Upsert to also persist the status change, not just process fields.
		if sm.store != nil {
			if err := sm.store.Upsert(sess); err != nil {
				log.Printf("[session] upsert resurrect: %v", err)
			}
		}
	}
	if !changed {
		return
	}
	if sm.store != nil && sess.Status != StatusActive {
		if err := sm.store.UpdateProcessFields(sess); err != nil {
			log.Printf("[session] update process fields: %v", err)
		}
	}
	if sm.notify != nil {
		sm.notify("delta", &Delta{
			SessionKey: key,
			Changes: map[string]interface{}{
				"pid": sess.PID, "cwd": sess.CWD,
				"cpu_percent": sess.CPUPercent, "memory_mb": sess.MemoryMB,
			},
			TimestampMs: time.Now().UnixMilli(),
		})
	}
}

func (sm *SessionManager) MarkDisappeared(key string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sess, ok := sm.sessions[key]
	if !ok || sess.Status == StatusStopped || sess.Status == StatusDisappeared {
		return
	}
	sess.Status = StatusDisappeared
	if sm.store != nil {
		if err := sm.store.Upsert(sess); err != nil {
			log.Printf("[session] mark disappeared: %v", err)
		}
	}
	if sm.notify != nil {
		sm.notify("delta", &Delta{
			SessionKey:  key,
			Changes:     map[string]interface{}{"status": string(StatusDisappeared)},
			TimestampMs: time.Now().UnixMilli(),
		})
	}
}

func (sm *SessionManager) CheckIdleSessions() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	now := time.Now().UnixMilli()
	idleThreshold := int64(5 * 60 * 1000)
	for key, sess := range sm.sessions {
		if sess.Status != StatusActive && sess.Status != StatusIdle {
			continue
		}
		if sess.lastHookTime == 0 {
			continue
		}
		if now-sess.lastHookTime > idleThreshold {
			if sess.Status != StatusIdle {
				sess.Status = StatusIdle
				if sm.store != nil {
					if err := sm.store.Upsert(sess); err != nil {
						log.Printf("[session] upsert idle: %v", err)
					}
				}
				if sm.notify != nil {
					sm.notify("delta", &Delta{
						SessionKey:  key,
						Changes:     map[string]interface{}{"status": string(StatusIdle)},
						TimestampMs: now,
					})
				}
			}
		}
	}
}

func (sm *SessionManager) GetSessions() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make([]*Session, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		clone := *s
		result = append(result, &clone)
	}
	return result
}

func (sm *SessionManager) GetSession(key string) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.sessions[key]
	if !ok {
		return nil
	}
	clone := *s
	return &clone
}

func (sm *SessionManager) GetKnownPIDs() map[int]scanner.SessionPIDInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make(map[int]scanner.SessionPIDInfo)
	for _, sess := range sm.sessions {
		if sess.PID > 0 {
			result[sess.PID] = scanner.SessionPIDInfo{
				SessionKey: sess.SessionKey, PID: sess.PID,
				AgentType: sess.AgentType, CWD: sess.CWD,
			}
		}
	}
	return result
}

func (sm *SessionManager) GetSnapshot() *Snapshot {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sessions := make([]*Session, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		clone := *s
		clone.Payload = nil
		sessions = append(sessions, &clone)
	}
	return &Snapshot{Sessions: sessions, GenTimeMs: time.Now().UnixMilli()}
}

func (sm *SessionManager) GetSessionsForRecovery() map[string]*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make(map[string]*Session, len(sm.sessions))
	for k, v := range sm.sessions {
		result[k] = v
	}
	return result
}

func (sm *SessionManager) HasSession(key string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	_, ok := sm.sessions[key]
	return ok
}

func (sm *SessionManager) AddRecoveredSession(sess *Session) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	key := sess.SessionKey
	if _, exists := sm.sessions[key]; exists {
		return
	}
	sm.sessions[key] = sess
	if sm.store != nil {
		if err := sm.store.Upsert(sess); err != nil {
			log.Printf("[session] upsert recovered session: %v", err)
		}
	}
}

func (sm *SessionManager) BindPIDToSession(key string, info *scanner.ProcessInfo) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sess, ok := sm.sessions[key]
	if !ok {
		return
	}
	sess.PID = int(info.PID)
	sess.Terminal = info.Name
	sess.CWD = info.CWD
	sess.CPUPercent = info.CPUPercent
	sess.MemoryMB = info.MemoryMB
	sess.ProcessCreateTimeMs = info.CreateTimeMs
	sess.Status = StatusActive
	sess.lastHookTime = time.Now().UnixMilli()
	if sm.store != nil {
		if err := sm.store.Upsert(sess); err != nil {
			log.Printf("[session] bind pid: %v", err)
		}
	}
}

func (sm *SessionManager) computeDelta(old, new *Session) *Delta {
	changes := make(map[string]interface{})
	if old.PID != new.PID {
		changes["pid"] = new.PID
	}
	if old.CWD != new.CWD {
		changes["cwd"] = new.CWD
	}
	if old.Status != new.Status {
		changes["status"] = string(new.Status)
	}
	if old.LastEventTimeMs != new.LastEventTimeMs {
		changes["last_event_time_ms"] = new.LastEventTimeMs
	}
	if old.LastEventType != new.LastEventType {
		changes["last_event_type"] = new.LastEventType
	}
	if old.LastFile != new.LastFile {
		changes["last_file"] = new.LastFile
	}
	if old.LastCommand != new.LastCommand {
		changes["last_command"] = new.LastCommand
	}
	if old.TurnCount != new.TurnCount {
		changes["turn_count"] = new.TurnCount
	}
	if old.Terminal != new.Terminal {
		changes["terminal"] = new.Terminal
	}
	if old.ProcessCreateTimeMs != new.ProcessCreateTimeMs {
		changes["process_create_time_ms"] = new.ProcessCreateTimeMs
	}
	if old.GitBranch != new.GitBranch {
		changes["git_branch"] = new.GitBranch
	}
	if old.UserInput != new.UserInput {
		changes["user_input"] = new.UserInput
	}
	if old.AgentOutput != new.AgentOutput {
		changes["agent_output"] = new.AgentOutput
	}
	if old.SessionTitle != new.SessionTitle {
		changes["session_title"] = new.SessionTitle
	}
	if old.LastHookEvent != new.LastHookEvent {
		changes["last_hook_event"] = new.LastHookEvent
	}
	if !turnsEqual(old.Turns, new.Turns) {
		changes["turns"] = new.Turns
	}
	if len(changes) == 0 {
		return nil
	}
	return &Delta{SessionKey: new.SessionKey, Changes: changes, TimestampMs: time.Now().UnixMilli()}
}

func turnsEqual(a, b []Turn) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].TurnIdx != b[i].TurnIdx || a[i].UserInput != b[i].UserInput || a[i].UserTS != b[i].UserTS {
			return false
		}
		if len(a[i].Entries) != len(b[i].Entries) {
			return false
		}
		for j := range a[i].Entries {
			ea, eb := a[i].Entries[j], b[i].Entries[j]
			if ea.Event != eb.Event || ea.TS != eb.TS || ea.StartTS != eb.StartTS {
				return false
			}
			if len(ea.Tools) != len(eb.Tools) {
				return false
			}
			for k := range ea.Tools {
				ta, tb := ea.Tools[k], eb.Tools[k]
				if ta.Name != tb.Name || ta.Input != tb.Input || ta.Output != tb.Output || ta.Status != tb.Status || ta.StartTS != tb.StartTS || ta.EndTS != tb.EndTS {
					return false
				}
			}
		}
	}
	return true
}

func cloneSession(s *Session) Session {
	clone := *s
	clone.Turns = cloneTurns(s.Turns)
	return clone
}

func cloneTurns(turns []Turn) []Turn {
	if turns == nil {
		return nil
	}
	cloned := make([]Turn, len(turns))
	for i, turn := range turns {
		cloned[i] = turn
		if turn.Entries != nil {
			cloned[i].Entries = make([]TurnEntry, len(turn.Entries))
			for j, entry := range turn.Entries {
				cloned[i].Entries[j] = entry
				if entry.Payload != nil {
					cloned[i].Entries[j].Payload = append([]byte(nil), entry.Payload...)
				}
				if entry.Tools != nil {
					cloned[i].Entries[j].Tools = append([]ToolCall(nil), entry.Tools...)
				}
			}
		}
	}
	return cloned
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func (s *Session) capGrowth() {
	// Intentionally no-op: this monitor treats complete model output and raw
	// event history as primary data, so pruning here would be data loss.
}
