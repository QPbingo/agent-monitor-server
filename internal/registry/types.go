package registry

// ── Provider ──

type Provider string

const (
	ProviderClaude   Provider = "claude"
	ProviderCodex    Provider = "codex"
	ProviderOpenCode Provider = "opencode"
)

// ── Auth Status ──

type AuthStatus string

const (
	AuthUnknown        AuthStatus = "unknown"
	AuthAuthenticated  AuthStatus = "authenticated"
	AuthUnauthenticated AuthStatus = "unauthenticated"
)

// ── Profile Status ──

type ProfileStatus string

const (
	ProfileActive   ProfileStatus = "active"
	ProfileDisabled ProfileStatus = "disabled"
)

// ── Run Status ──

type RunStatus string

const (
	RunQueued    RunStatus = "queued"
	RunRunning   RunStatus = "running"
	RunCompleted RunStatus = "completed"
	RunFailed    RunStatus = "failed"
	RunCancelled RunStatus = "cancelled"
)

// ── Runtime ──

type Runtime struct {
	ID                   int64  `json:"id"`
	UserID               string `json:"user_id"`
	DeviceID             string `json:"device_id"`
	Name                 string `json:"name"`
	Hostname             string `json:"hostname"`
	DefaultWorkspaceRoot string `json:"default_workspace_root"`
	LastSeenAt           int64  `json:"last_seen_at"`
	CreatedAt            int64  `json:"created_at"`
	UpdatedAt            int64  `json:"updated_at"`
}

// ── Capability ──

type Capability struct {
	ID            int64      `json:"id"`
	RuntimeID     int64      `json:"runtime_id"`
	Provider      Provider   `json:"provider"`
	BinaryPath    string     `json:"binary_path"`
	Version       string     `json:"version"`
	Available     bool       `json:"available"`
	AuthStatus    AuthStatus `json:"auth_status"`
	AuthMessage   string     `json:"auth_message"`
	HookInstalled bool       `json:"hook_installed"`
	HookStatus    string     `json:"hook_status"`
	LastScannedAt int64      `json:"last_scanned_at"`
	CreatedAt     int64      `json:"created_at"`
	UpdatedAt     int64      `json:"updated_at"`
}

// ── AgentProfile ──

type AgentProfile struct {
	ID             int64         `json:"id"`
	UserID         string        `json:"user_id"`
	WorkspaceID    int64         `json:"workspace_id"`
	RuntimeID      int64         `json:"runtime_id"`
	Provider       Provider      `json:"provider"`
	Name           string        `json:"name"`
	Description    string        `json:"description"`
	DefaultCwd     string        `json:"default_cwd"`
	Model          string        `json:"model"`
	PermissionMode string        `json:"permission_mode"`
	SystemPrompt   string        `json:"system_prompt"`
	Status         ProfileStatus `json:"status"`
	CreatedBy      int64         `json:"created_by"`
	CreatedAt      int64         `json:"created_at"`
	UpdatedAt      int64         `json:"updated_at"`
}

// ProfileInput is used for both create and update. On update, zero-value fields
// are left unchanged (the caller sets only fields they want to change).
type ProfileInput struct {
	UserID         string   `json:"user_id,omitempty"`
	WorkspaceID    int64    `json:"workspace_id,omitempty"`
	RuntimeID      int64    `json:"runtime_id,omitempty"`
	Provider       Provider `json:"provider,omitempty"`
	Name           string   `json:"name,omitempty"`
	Description    string   `json:"description,omitempty"`
	DefaultCwd     string   `json:"default_cwd,omitempty"`
	Model          string   `json:"model,omitempty"`
	PermissionMode string   `json:"permission_mode,omitempty"`
	SystemPrompt   string   `json:"system_prompt,omitempty"`
	CreatedBy      int64    `json:"created_by,omitempty"`
}

// ── StoryRun ──

type StoryRun struct {
	ID              int64     `json:"id"`
	StoryID         int64     `json:"story_id"`
	AgentProfileID  int64     `json:"agent_profile_id"`
	RuntimeID       int64     `json:"runtime_id"`
	Provider        Provider  `json:"provider"`
	SessionKey      string    `json:"session_key"`
	AgentSessionID  string    `json:"agent_session_id"`
	ExecID          string    `json:"exec_id"`
	Prompt          string    `json:"prompt"`
	EffectivePrompt string    `json:"effective_prompt"`
	PermissionMode  string    `json:"permission_mode"`
	Cwd             string    `json:"cwd"`
	SessionTitle    string    `json:"session_title"`
	Status          RunStatus `json:"status"`
	Error           string    `json:"error"`
	CreatedBy       int64     `json:"created_by"`
	CreatedAt       int64     `json:"created_at"`
	StartedAt       int64     `json:"started_at"`
	FinishedAt      int64     `json:"finished_at"`
}

type StoryRunInput struct {
	StoryID         int64    `json:"story_id"`
	AgentProfileID  int64    `json:"agent_profile_id"`
	RuntimeID       int64    `json:"runtime_id"`
	Provider        Provider `json:"provider"`
	SessionKey      string   `json:"session_key,omitempty"`
	AgentSessionID  string   `json:"agent_session_id,omitempty"`
	ExecID          string   `json:"exec_id,omitempty"`
	Prompt          string   `json:"prompt"`
	EffectivePrompt string   `json:"effective_prompt"`
	PermissionMode  string   `json:"permission_mode,omitempty"`
	Cwd             string   `json:"cwd,omitempty"`
	SessionTitle    string   `json:"session_title,omitempty"`
	CreatedBy       int64    `json:"created_by"`
}
