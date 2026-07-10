package hierarchy

type Workspace struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
}

type Project struct {
	ID          int64  `json:"id"`
	WorkspaceID int64  `json:"workspace_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
}

type Topic struct {
	ID                int64  `json:"id"`
	ProjectID         int64  `json:"project_id"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	AgentType         string `json:"agent_type,omitempty"`
	OrchestrationNote string `json:"orchestration_note,omitempty"`
	Status            string `json:"status"`
	CreatedAt         int64  `json:"created_at"`
	UpdatedAt         int64  `json:"updated_at"`
}

type Story struct {
	ID                int64  `json:"id"`
	TopicID           int64  `json:"topic_id"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	SessionKey        string `json:"session_key,omitempty"`
	AgentProfileID    *int64 `json:"agent_profile_id,omitempty"`
	LatestRunID       *int64 `json:"latest_run_id,omitempty"`
	LatestRunStatus   string `json:"latest_run_status,omitempty"`
	LatestSessionKey  string `json:"latest_session_key,omitempty"`
	Status            string `json:"status"`
	CreatedAt         int64  `json:"created_at"`
	UpdatedAt         int64  `json:"updated_at"`
}

type HierarchyTree struct {
	Workspaces []WorkspaceNode `json:"workspaces"`
}

type WorkspaceNode struct {
	Workspace Workspace     `json:"workspace"`
	Projects  []ProjectNode `json:"projects"`
}

type ProjectNode struct {
	Project Project     `json:"project"`
	Topics  []TopicNode `json:"topics"`
}

type TopicNode struct {
	Topic   Topic   `json:"topic"`
	Stories []Story `json:"stories"`
}
