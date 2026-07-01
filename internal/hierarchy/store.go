package hierarchy

import (
	"database/sql"
	"fmt"
	"time"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) EnsureTables() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS workspaces (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			name        TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			status      TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')),
			created_at  INTEGER NOT NULL,
			updated_at  INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS projects (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
			name         TEXT NOT NULL,
			description  TEXT NOT NULL DEFAULT '',
			status       TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')),
			created_at   INTEGER NOT NULL,
			updated_at   INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS topics (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			project_id  INTEGER NOT NULL REFERENCES projects(id),
			name        TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			agent_type  TEXT DEFAULT '',
			status      TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')),
			created_at  INTEGER NOT NULL,
			updated_at  INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS stories (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			topic_id    INTEGER NOT NULL REFERENCES topics(id),
			name        TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			session_key TEXT UNIQUE,
			status      TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')),
			created_at  INTEGER NOT NULL,
			updated_at  INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS permissions (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id       INTEGER NOT NULL REFERENCES users(id),
			resource_type TEXT NOT NULL CHECK(resource_type IN ('workspace','project')),
			resource_id   INTEGER NOT NULL,
			level         INTEGER NOT NULL DEFAULT 10,
			granted_by    INTEGER REFERENCES users(id),
			created_at    INTEGER NOT NULL,
			UNIQUE(user_id, resource_type, resource_id)
		);
	`)
	return err
}

// ── Workspace CRUD ──

func (s *Store) CreateWorkspace(name, description string) (*Workspace, error) {
	now := time.Now().UnixMilli()
	res, err := s.db.Exec(
		`INSERT INTO workspaces (name, description, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		name, description, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}
	id, _ := res.LastInsertId()
	return &Workspace{ID: id, Name: name, Description: description, Status: "open", CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) GetWorkspace(id int64) (*Workspace, error) {
	var w Workspace
	err := s.db.QueryRow(
		`SELECT id, name, description, status, created_at, updated_at FROM workspaces WHERE id = ?`, id,
	).Scan(&w.ID, &w.Name, &w.Description, &w.Status, &w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &w, nil
}

func (s *Store) ListWorkspaces() ([]Workspace, error) {
	rows, err := s.db.Query(`SELECT id, name, description, status, created_at, updated_at FROM workspaces ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Workspace
	for rows.Next() {
		var w Workspace
		if err := rows.Scan(&w.ID, &w.Name, &w.Description, &w.Status, &w.CreatedAt, &w.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, w)
	}
	return list, rows.Err()
}

func (s *Store) UpdateWorkspace(id int64, name, description string) error {
	_, err := s.db.Exec(
		`UPDATE workspaces SET name=?, description=?, updated_at=? WHERE id=?`,
		name, description, time.Now().UnixMilli(), id,
	)
	return err
}

func (s *Store) DeleteWorkspace(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Cascade: delete permissions FIRST (while projects still exist),
	// then stories → topics → projects → workspace.
	tx.Exec(`DELETE FROM permissions WHERE resource_type='project' AND resource_id IN (SELECT id FROM projects WHERE workspace_id=?)`, id)
	tx.Exec(`DELETE FROM permissions WHERE resource_type='workspace' AND resource_id=?`, id)
	tx.Exec(`DELETE FROM stories WHERE topic_id IN (SELECT id FROM topics WHERE project_id IN (SELECT id FROM projects WHERE workspace_id=?))`, id)
	tx.Exec(`DELETE FROM topics WHERE project_id IN (SELECT id FROM projects WHERE workspace_id=?)`, id)
	tx.Exec(`DELETE FROM projects WHERE workspace_id=?`, id)
	if _, err := tx.Exec(`DELETE FROM workspaces WHERE id=?`, id); err != nil {
		return fmt.Errorf("delete workspace: %w", err)
	}
	return tx.Commit()
}

// ── Project CRUD ──

func (s *Store) CreateProject(workspaceID int64, name, description string) (*Project, error) {
	now := time.Now().UnixMilli()
	res, err := s.db.Exec(
		`INSERT INTO projects (workspace_id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		workspaceID, name, description, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("create project: %w", err)
	}
	id, _ := res.LastInsertId()
	return &Project{ID: id, WorkspaceID: workspaceID, Name: name, Description: description, Status: "open", CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) GetProject(id int64) (*Project, error) {
	var p Project
	err := s.db.QueryRow(
		`SELECT id, workspace_id, name, description, status, created_at, updated_at FROM projects WHERE id = ?`, id,
	).Scan(&p.ID, &p.WorkspaceID, &p.Name, &p.Description, &p.Status, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) ListProjects(workspaceID int64) ([]Project, error) {
	rows, err := s.db.Query(
		`SELECT id, workspace_id, name, description, status, created_at, updated_at FROM projects WHERE workspace_id=? ORDER BY id`,
		workspaceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Project
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.WorkspaceID, &p.Name, &p.Description, &p.Status, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, rows.Err()
}

func (s *Store) UpdateProject(id int64, name, description string) error {
	_, err := s.db.Exec(
		`UPDATE projects SET name=?, description=?, updated_at=? WHERE id=?`,
		name, description, time.Now().UnixMilli(), id,
	)
	return err
}

func (s *Store) DeleteProject(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	tx.Exec(`DELETE FROM permissions WHERE resource_type='project' AND resource_id=?`, id)
	tx.Exec(`DELETE FROM stories WHERE topic_id IN (SELECT id FROM topics WHERE project_id=?)`, id)
	tx.Exec(`DELETE FROM topics WHERE project_id=?`, id)
	if _, err := tx.Exec(`DELETE FROM projects WHERE id=?`, id); err != nil {
		return fmt.Errorf("delete project: %w", err)
	}
	return tx.Commit()
}

// ── Topic CRUD ──

func (s *Store) CreateTopic(projectID int64, name, description, agentType string) (*Topic, error) {
	now := time.Now().UnixMilli()
	res, err := s.db.Exec(
		`INSERT INTO topics (project_id, name, description, agent_type, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		projectID, name, description, agentType, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("create topic: %w", err)
	}
	id, _ := res.LastInsertId()
	return &Topic{ID: id, ProjectID: projectID, Name: name, Description: description, AgentType: agentType, Status: "open", CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) GetTopic(id int64) (*Topic, error) {
	var t Topic
	err := s.db.QueryRow(
		`SELECT id, project_id, name, description, agent_type, status, created_at, updated_at FROM topics WHERE id = ?`, id,
	).Scan(&t.ID, &t.ProjectID, &t.Name, &t.Description, &t.AgentType, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) ListTopics(projectID int64) ([]Topic, error) {
	rows, err := s.db.Query(
		`SELECT id, project_id, name, description, agent_type, status, created_at, updated_at FROM topics WHERE project_id=? ORDER BY id`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Topic
	for rows.Next() {
		var t Topic
		if err := rows.Scan(&t.ID, &t.ProjectID, &t.Name, &t.Description, &t.AgentType, &t.Status, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, t)
	}
	return list, rows.Err()
}

func (s *Store) FindTopicByAgentType(projectID int64, agentType string) (*Topic, error) {
	var t Topic
	err := s.db.QueryRow(
		`SELECT id, project_id, name, description, agent_type, status, created_at, updated_at FROM topics WHERE project_id=? AND agent_type=?`,
		projectID, agentType,
	).Scan(&t.ID, &t.ProjectID, &t.Name, &t.Description, &t.AgentType, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) UpdateTopic(id int64, name, description string) error {
	_, err := s.db.Exec(
		`UPDATE topics SET name=?, description=?, updated_at=? WHERE id=?`,
		name, description, time.Now().UnixMilli(), id,
	)
	return err
}

func (s *Store) DeleteTopic(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	tx.Exec(`DELETE FROM stories WHERE topic_id=?`, id)
	if _, err := tx.Exec(`DELETE FROM topics WHERE id=?`, id); err != nil {
		return fmt.Errorf("delete topic: %w", err)
	}
	return tx.Commit()
}

// ── Story CRUD ──

func (s *Store) CreateStory(topicID int64, name, description string) (*Story, error) {
	now := time.Now().UnixMilli()
	res, err := s.db.Exec(
		`INSERT INTO stories (topic_id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		topicID, name, description, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("create story: %w", err)
	}
	id, _ := res.LastInsertId()
	return &Story{ID: id, TopicID: topicID, Name: name, Description: description, Status: "open", CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) GetStory(id int64) (*Story, error) {
	var st Story
	var sessionKey sql.NullString
	err := s.db.QueryRow(
		`SELECT id, topic_id, name, description, session_key, status, created_at, updated_at FROM stories WHERE id = ?`, id,
	).Scan(&st.ID, &st.TopicID, &st.Name, &st.Description, &sessionKey, &st.Status, &st.CreatedAt, &st.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if sessionKey.Valid {
		st.SessionKey = sessionKey.String
	}
	return &st, nil
}

func (s *Store) ListStories(topicID int64) ([]Story, error) {
	rows, err := s.db.Query(
		`SELECT id, topic_id, name, description, COALESCE(session_key,''), status, created_at, updated_at FROM stories WHERE topic_id=? ORDER BY id`,
		topicID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Story
	for rows.Next() {
		var st Story
		if err := rows.Scan(&st.ID, &st.TopicID, &st.Name, &st.Description, &st.SessionKey, &st.Status, &st.CreatedAt, &st.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, st)
	}
	return list, rows.Err()
}

func (s *Store) LinkSessionToStory(storyID int64, sessionKey string) error {
	_, err := s.db.Exec(
		`UPDATE stories SET session_key=?, updated_at=? WHERE id=?`,
		sessionKey, time.Now().UnixMilli(), storyID,
	)
	return err
}

func (s *Store) GetProjectIDForStory(storyID int64) (int64, error) {
	var projectID int64
	err := s.db.QueryRow(`
		SELECT t.project_id
		FROM stories st
		JOIN topics t ON t.id = st.topic_id
		WHERE st.id = ?
	`, storyID).Scan(&projectID)
	if err != nil {
		return 0, err
	}
	return projectID, nil
}

func (s *Store) GetProjectIDForSessionKey(sessionKey string) (int64, error) {
	var projectID int64
	err := s.db.QueryRow(`
		SELECT t.project_id
		FROM stories st
		JOIN topics t ON t.id = st.topic_id
		WHERE st.session_key = ?
	`, sessionKey).Scan(&projectID)
	if err != nil {
		return 0, err
	}
	return projectID, nil
}

func (s *Store) UpdateStory(id int64, name, description string) error {
	_, err := s.db.Exec(
		`UPDATE stories SET name=?, description=?, updated_at=? WHERE id=?`,
		name, description, time.Now().UnixMilli(), id,
	)
	return err
}

func (s *Store) DeleteStory(id int64) error {
	_, err := s.db.Exec(`DELETE FROM stories WHERE id=?`, id)
	return err
}

// ── Inspiration ──

func (s *Store) EnsureInspiration() (*Workspace, *Project, error) {
	now := time.Now().UnixMilli()

	s.db.Exec(`INSERT OR IGNORE INTO workspaces (id, name, description, status, created_at, updated_at) VALUES (1, 'Inspiration', 'Default workspace', 'open', ?, ?)`, now, now)
	ws, err := s.GetWorkspace(1)
	if err != nil {
		return nil, nil, fmt.Errorf("get inspiration workspace: %w", err)
	}
	if ws == nil {
		return nil, nil, fmt.Errorf("inspiration workspace not found after creation")
	}
	proj, err := s.EnsureWorkspaceInspiration(ws.ID)
	return ws, proj, err
}

// EnsureWorkspaceInspiration creates the "Agent Sessions" project with agent-type topics
// for a given workspace. Idempotent — skips if already exists.
func (s *Store) EnsureWorkspaceInspiration(workspaceID int64) (*Project, error) {
	now := time.Now().UnixMilli()

	// Find or create the inspiration project in this workspace
	var projID int64
	err := s.db.QueryRow(`SELECT id FROM projects WHERE workspace_id=? AND name='Agent Sessions'`, workspaceID).Scan(&projID)
	if err != nil {
		res, err := s.db.Exec(
			`INSERT INTO projects (workspace_id, name, description, status, created_at, updated_at) VALUES (?, 'Agent Sessions', 'Auto-collected agent sessions', 'open', ?, ?)`,
			workspaceID, now, now,
		)
		if err != nil {
			return nil, fmt.Errorf("create inspiration project: %w", err)
		}
		projID, _ = res.LastInsertId()
	}

	// Ensure agent-type topics under this project
	for _, agentType := range []string{"claude", "codex", "opencode"} {
		var exists int
		s.db.QueryRow(`SELECT COUNT(*) FROM topics WHERE project_id=? AND agent_type=?`, projID, agentType).Scan(&exists)
		if exists == 0 {
			s.db.Exec(
				`INSERT INTO topics (project_id, name, description, agent_type, status, created_at, updated_at) VALUES (?, ?, ?, ?, 'open', ?, ?)`,
				projID, capitalize(agentType), "Auto-collected "+agentType+" sessions", agentType, now, now,
			)
		}
	}

	return s.GetProject(projID)
}

func (s *Store) FindStoryBySessionKey(sessionKey string) (*Story, error) {
	var st Story
	var sessionKeyStr sql.NullString
	err := s.db.QueryRow(
		`SELECT id, topic_id, name, description, COALESCE(session_key,''), status, created_at, updated_at FROM stories WHERE session_key=?`,
		sessionKey,
	).Scan(&st.ID, &st.TopicID, &st.Name, &st.Description, &sessionKeyStr, &st.Status, &st.CreatedAt, &st.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if sessionKeyStr.Valid {
		st.SessionKey = sessionKeyStr.String
	}
	return &st, nil
}

func (s *Store) FindOrCreateInspirationStory(agentType, sessionKey, sessionTitle string) (*Story, error) {
	return s.FindOrCreateAgentSessionStory(1, agentType, sessionKey, sessionTitle)
}

func (s *Store) FindOrCreateAgentSessionStory(workspaceID int64, agentType, sessionKey, sessionTitle string) (*Story, error) {
	existing, err := s.FindStoryBySessionKey(sessionKey)
	if err == nil {
		return existing, nil
	}
	if workspaceID == 0 {
		workspaceID = 1
	}
	if _, err := s.EnsureWorkspaceInspiration(workspaceID); err != nil {
		return nil, err
	}

	var projID, topicID int64
	err = s.db.QueryRow(`
		SELECT p.id, t.id FROM projects p
		JOIN topics t ON t.project_id = p.id
		WHERE p.workspace_id = ? AND p.name = 'Agent Sessions' AND t.agent_type = ?
		ORDER BY p.id ASC LIMIT 1
	`, workspaceID, agentType).Scan(&projID, &topicID)
	if err != nil {
		return nil, fmt.Errorf("find inspiration topic for %s: %w", agentType, err)
	}

	name := sessionTitle
	if name == "" {
		name = sessionKey
	}

	story, err := s.CreateStory(topicID, name, "")
	if err != nil {
		return nil, err
	}

	if err := s.LinkSessionToStory(story.ID, sessionKey); err != nil {
		return nil, err
	}

	return story, nil
}

// ── Full hierarchy tree ──

func (s *Store) GetFullHierarchy() (*HierarchyTree, error) {
	workspaces, err := s.ListWorkspaces()
	if err != nil {
		return nil, err
	}

	tree := &HierarchyTree{}
	for _, ws := range workspaces {
		projects, _ := s.ListProjects(ws.ID)
		wsNode := WorkspaceNode{Workspace: ws}
		for _, proj := range projects {
			topics, _ := s.ListTopics(proj.ID)
			projNode := ProjectNode{Project: proj}
			for _, topic := range topics {
				stories, _ := s.ListStories(topic.ID)
				projNode.Topics = append(projNode.Topics, TopicNode{Topic: topic, Stories: stories})
			}
			wsNode.Projects = append(wsNode.Projects, projNode)
		}
		tree.Workspaces = append(tree.Workspaces, wsNode)
	}
	return tree, nil
}

func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	if len(s) == 1 {
		return string(s[0] - 32)
	}
	switch s {
	case "claude":
		return "Claude Code"
	case "opencode":
		return "OpenCode"
	case "codex":
		return "Codex"
	}
	return s
}
