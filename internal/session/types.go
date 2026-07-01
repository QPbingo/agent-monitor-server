package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type Status string

const (
	StatusActive      Status = "active"
	StatusIdle        Status = "idle"
	StatusStopped     Status = "stopped"
	StatusUnknown     Status = "unknown"
	StatusDisappeared Status = "disappeared"
	StatusError       Status = "error"
)

type HookEvent struct {
	Event       string          `json:"event"`
	AgentType   string          `json:"agent_type"`
	SessionID   string          `json:"session_id"`
	DaemonToken string          `json:"daemon_token"`
	PID         int             `json:"pid"`
	CWD         string          `json:"cwd"`
	TimestampMs int64           `json:"timestamp_ms"`
	Payload     json.RawMessage `json:"payload"`
}

func ComputeSessionKey(userID, deviceID, agentType, agentSessionID string) string {
	data := fmt.Sprintf("%s|%s|%s|%s", userID, deviceID, agentType, agentSessionID)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

type Session struct {
	UserID         string `json:"user_id"`
	DeviceID       string `json:"device_id"`
	AgentType      string `json:"agent_type"`
	AgentSessionID string `json:"agent_session_id"`
	SessionKey     string `json:"session_key"`

	PID        int     `json:"pid"`
	Terminal   string  `json:"terminal"`
	CWD        string  `json:"cwd"`
	MemoryMB   float64 `json:"memory_mb"`
	CPUPercent float64 `json:"cpu_percent"`

	Status          Status          `json:"status"`
	StartTimeMs     int64           `json:"start_time_ms"`
	LastEventTimeMs int64           `json:"last_event_time_ms"`
	LastEventType   string          `json:"last_event_type"`
	LastFile        string          `json:"last_file"`
	LastCommand     string          `json:"last_command"`
	TurnCount       int             `json:"turn_count"`
	GitBranch       string          `json:"git_branch"`
	UserInput       string          `json:"user_input"`
	AgentOutput     string          `json:"agent_output"`
	SessionTitle    string          `json:"session_title"`
	LastHookEvent   string          `json:"last_hook_event"`
	Turns           []Turn          `json:"turns"`
	StoryID         *int64          `json:"story_id,omitempty"`
	Source          string          `json:"source,omitempty"`
	Payload         json.RawMessage `json:"payload,omitempty"`

	ProcessCreateTimeMs int64 `json:"process_create_time_ms,omitempty"`

	lastHookTime   int64
	dbID           int64
	webInputActive bool
	// OpenCode: tracks the role ("user" / "assistant") of the most recent
	// message.updated event, so subsequent message.part.updated events can
	// be classified correctly without relying on the plugin.js _role hack.
	lastMessageRole string
}

type Turn struct {
	TurnIdx   int         `json:"turn_idx"`
	UserInput string      `json:"user_input"`
	UserTS    int64       `json:"user_ts"`
	Entries   []TurnEntry `json:"entries"`
}

type TurnEntry struct {
	Event   string          `json:"event"`
	TS      int64           `json:"ts"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Tools   []ToolCall      `json:"tools,omitempty"`
	StartTS int64           `json:"start_ts,omitempty"`
}

type ToolCall struct {
	Name    string `json:"name"`
	Input   string `json:"input"`
	Output  string `json:"output"`
	Status  string `json:"status"`
	StartTS int64  `json:"start_ts"`
	EndTS   int64  `json:"end_ts,omitempty"`
}

type Delta struct {
	SessionKey  string                 `json:"session_key"`
	Changes     map[string]interface{} `json:"changes"`
	TimestampMs int64                  `json:"timestamp_ms"`
}

type Snapshot struct {
	Sessions  []*Session `json:"sessions"`
	GenTimeMs int64      `json:"gen_time_ms"`
}

type RecoveryCandidate struct {
	AgentType      string `json:"agent_type"`
	AgentSessionID string `json:"agent_session_id"`
	CWDHash        string `json:"cwd_hash"`
	StartTimeMs    int64  `json:"start_time_ms"`
	LastEventType  string `json:"last_event_type"`
	LastFile       string `json:"last_file"`
	LastCommand    string `json:"last_command"`
	TurnCount      int    `json:"turn_count"`
	GitBranch      string `json:"git_branch"`
	Terminal       string `json:"terminal"`
	PID            int    `json:"pid"`
	CWD            string `json:"cwd"`
	TranscriptPath string `json:"transcript_path"`
}
