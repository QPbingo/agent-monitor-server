package registry

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ── Sentinel errors ──

var (
	ErrCapabilityNotAvailable = errors.New("capability is not available")
	ErrProfileNotFound        = errors.New("agent profile not found")
	ErrRunNotFound            = errors.New("story run not found")
)

// ── Store ──

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// DB returns the underlying *sql.DB for sharing with other packages.
func (s *Store) DB() *sql.DB { return s.db }

// ── Schema ──

func (s *Store) EnsureTables() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS agent_runtimes (
			id                     INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id                TEXT NOT NULL,
			device_id              TEXT NOT NULL,
			name                   TEXT NOT NULL,
			hostname               TEXT NOT NULL,
			default_workspace_root TEXT NOT NULL,
			last_seen_at           INTEGER NOT NULL,
			created_at             INTEGER NOT NULL,
			updated_at             INTEGER NOT NULL,
			UNIQUE(user_id, device_id)
		);

		CREATE TABLE IF NOT EXISTS agent_capabilities (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			runtime_id      INTEGER NOT NULL,
			provider        TEXT NOT NULL,
			binary_path     TEXT NOT NULL,
			version         TEXT NOT NULL,
			available       INTEGER NOT NULL,
			auth_status     TEXT NOT NULL,
			auth_message    TEXT NOT NULL DEFAULT '',
			hook_installed  INTEGER NOT NULL DEFAULT 0,
			hook_status     TEXT NOT NULL DEFAULT '',
			last_scanned_at INTEGER NOT NULL,
			created_at      INTEGER NOT NULL,
			updated_at      INTEGER NOT NULL,
			UNIQUE(runtime_id, provider)
		);

		CREATE TABLE IF NOT EXISTS agent_profiles (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id         TEXT NOT NULL,
			workspace_id    INTEGER NOT NULL,
			runtime_id      INTEGER NOT NULL,
			provider        TEXT NOT NULL,
			name            TEXT NOT NULL,
			description     TEXT NOT NULL DEFAULT '',
			default_cwd     TEXT NOT NULL DEFAULT '',
			model           TEXT NOT NULL DEFAULT '',
			permission_mode TEXT NOT NULL DEFAULT '',
			system_prompt   TEXT NOT NULL DEFAULT '',
			status          TEXT NOT NULL DEFAULT 'active',
			created_by      INTEGER NOT NULL,
			created_at      INTEGER NOT NULL,
			updated_at      INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS story_runs (
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
		);
	`)
	return err
}

// ── Runtime ──

func (s *Store) EnsureRuntime(userID, deviceID, name, defaultRoot string) (*Runtime, error) {
	now := time.Now().UnixMilli()
	// Use upsert: if the (user_id, device_id) pair exists, update; otherwise insert.
	res, err := s.db.Exec(`
		INSERT INTO agent_runtimes (user_id, device_id, name, hostname, default_workspace_root, last_seen_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id, device_id) DO UPDATE SET
			name = excluded.name,
			hostname = excluded.hostname,
			default_workspace_root = excluded.default_workspace_root,
			last_seen_at = excluded.last_seen_at,
			updated_at = excluded.updated_at
	`, userID, deviceID, name, name, defaultRoot, now, now, now)
	if err != nil {
		return nil, fmt.Errorf("ensure runtime: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("last insert id: %w", err)
	}
	// ON CONFLICT DO UPDATE may return 0 for updates.
	// We need to query to get the actual ID.
	if id == 0 {
		// This was an update — fetch the existing row.
		return s.getRuntimeByKey(userID, deviceID)
	}

	return s.GetRuntime(id)
}

// GetRuntimeByKey finds a runtime by user_id + device_id.
func (s *Store) GetRuntimeByKey(userID, deviceID string) (*Runtime, error) {
	return s.getRuntimeByKey(userID, deviceID)
}

func (s *Store) getRuntimeByKey(userID, deviceID string) (*Runtime, error) {
	r := &Runtime{}
	err := s.db.QueryRow(`
		SELECT id, user_id, device_id, name, hostname, default_workspace_root, last_seen_at, created_at, updated_at
		FROM agent_runtimes WHERE user_id = ? AND device_id = ?
	`, userID, deviceID).Scan(
		&r.ID, &r.UserID, &r.DeviceID, &r.Name, &r.Hostname,
		&r.DefaultWorkspaceRoot, &r.LastSeenAt, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get runtime by key: %w", err)
	}
	return r, nil
}

func (s *Store) GetRuntime(id int64) (*Runtime, error) {
	r := &Runtime{}
	err := s.db.QueryRow(`
		SELECT id, user_id, device_id, name, hostname, default_workspace_root, last_seen_at, created_at, updated_at
		FROM agent_runtimes WHERE id = ?
	`, id).Scan(
		&r.ID, &r.UserID, &r.DeviceID, &r.Name, &r.Hostname,
		&r.DefaultWorkspaceRoot, &r.LastSeenAt, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get runtime: %w", err)
	}
	return r, nil
}

// ── Capability ──

func (s *Store) UpsertCapability(c Capability) (*Capability, error) {
	now := time.Now().UnixMilli()
	available := 0
	if c.Available {
		available = 1
	}
	hookInstalled := 0
	if c.HookInstalled {
		hookInstalled = 1
	}

	res, err := s.db.Exec(`
		INSERT INTO agent_capabilities (runtime_id, provider, binary_path, version, available, auth_status, auth_message, hook_installed, hook_status, last_scanned_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(runtime_id, provider) DO UPDATE SET
			binary_path = excluded.binary_path,
			version = excluded.version,
			available = excluded.available,
			auth_status = excluded.auth_status,
			auth_message = excluded.auth_message,
			hook_installed = excluded.hook_installed,
			hook_status = excluded.hook_status,
			last_scanned_at = excluded.last_scanned_at,
			updated_at = excluded.updated_at
	`, c.RuntimeID, string(c.Provider), c.BinaryPath, c.Version, available,
		string(c.AuthStatus), c.AuthMessage, hookInstalled, c.HookStatus, now, now, now)
	if err != nil {
		return nil, fmt.Errorf("upsert capability: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("last insert id: %w", err)
	}
	if id == 0 {
		return s.getCapabilityByKey(c.RuntimeID, c.Provider)
	}
	return s.GetCapability(id)
}

func (s *Store) getCapabilityByKey(runtimeID int64, provider Provider) (*Capability, error) {
	c := &Capability{}
	var available, hookInstalled int
	err := s.db.QueryRow(`
		SELECT id, runtime_id, provider, binary_path, version, available, auth_status, auth_message, hook_installed, hook_status, last_scanned_at, created_at, updated_at
		FROM agent_capabilities WHERE runtime_id = ? AND provider = ?
	`, runtimeID, string(provider)).Scan(
		&c.ID, &c.RuntimeID, &c.Provider, &c.BinaryPath, &c.Version,
		&available, &c.AuthStatus, &c.AuthMessage, &hookInstalled, &c.HookStatus,
		&c.LastScannedAt, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get capability by key: %w", err)
	}
	c.Available = available == 1
	c.HookInstalled = hookInstalled == 1
	return c, nil
}

func (s *Store) GetCapability(id int64) (*Capability, error) {
	c := &Capability{}
	var available, hookInstalled int
	err := s.db.QueryRow(`
		SELECT id, runtime_id, provider, binary_path, version, available, auth_status, auth_message, hook_installed, hook_status, last_scanned_at, created_at, updated_at
		FROM agent_capabilities WHERE id = ?
	`, id).Scan(
		&c.ID, &c.RuntimeID, &c.Provider, &c.BinaryPath, &c.Version,
		&available, &c.AuthStatus, &c.AuthMessage, &hookInstalled, &c.HookStatus,
		&c.LastScannedAt, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get capability: %w", err)
	}
	c.Available = available == 1
	c.HookInstalled = hookInstalled == 1
	return c, nil
}

func (s *Store) ListCapabilities(runtimeID int64) ([]Capability, error) {
	rows, err := s.db.Query(`
		SELECT id, runtime_id, provider, binary_path, version, available, auth_status, auth_message, hook_installed, hook_status, last_scanned_at, created_at, updated_at
		FROM agent_capabilities WHERE runtime_id = ? ORDER BY provider
	`, runtimeID)
	if err != nil {
		return nil, fmt.Errorf("list capabilities: %w", err)
	}
	defer rows.Close()

	var caps []Capability
	for rows.Next() {
		var c Capability
		var available, hookInstalled int
		if err := rows.Scan(
			&c.ID, &c.RuntimeID, &c.Provider, &c.BinaryPath, &c.Version,
			&available, &c.AuthStatus, &c.AuthMessage, &hookInstalled, &c.HookStatus,
			&c.LastScannedAt, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan capability: %w", err)
		}
		c.Available = available == 1
		c.HookInstalled = hookInstalled == 1
		caps = append(caps, c)
	}
	return caps, rows.Err()
}

// ── AgentProfile ──

func (s *Store) CreateProfile(input ProfileInput) (*AgentProfile, error) {
	if input.Name == "" {
		return nil, errors.New("profile name must not be blank")
	}

	// Verify capability exists and is available
	cap, err := s.getCapabilityByKey(input.RuntimeID, input.Provider)
	if err != nil {
		return nil, fmt.Errorf("capability lookup: %w", err)
	}
	if !cap.Available {
		return nil, ErrCapabilityNotAvailable
	}

	now := time.Now().UnixMilli()
	res, err := s.db.Exec(`
		INSERT INTO agent_profiles (user_id, workspace_id, runtime_id, provider, name, description, default_cwd, model, permission_mode, system_prompt, status, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, input.UserID, input.WorkspaceID, input.RuntimeID, string(input.Provider),
		input.Name, input.Description, input.DefaultCwd, input.Model,
		input.PermissionMode, input.SystemPrompt,
		string(ProfileActive), input.CreatedBy, now, now)
	if err != nil {
		return nil, fmt.Errorf("create profile: %w", err)
	}

	id, _ := res.LastInsertId()
	return s.GetProfile(id)
}

func (s *Store) GetProfile(id int64) (*AgentProfile, error) {
	p := &AgentProfile{}
	err := s.db.QueryRow(`
		SELECT id, user_id, workspace_id, runtime_id, provider, name, description, default_cwd, model, permission_mode, system_prompt, status, created_by, created_at, updated_at
		FROM agent_profiles WHERE id = ?
	`, id).Scan(
		&p.ID, &p.UserID, &p.WorkspaceID, &p.RuntimeID, &p.Provider,
		&p.Name, &p.Description, &p.DefaultCwd, &p.Model, &p.PermissionMode,
		&p.SystemPrompt, &p.Status, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrProfileNotFound
		}
		return nil, fmt.Errorf("get profile: %w", err)
	}
	return p, nil
}

func (s *Store) UpdateProfile(id int64, input ProfileInput) (*AgentProfile, error) {
	// Fetch existing to check existence
	existing, err := s.GetProfile(id)
	if err != nil {
		return nil, err
	}

	// Merge: only update fields that are provided (non-zero)
	name := existing.Name
	if input.Name != "" {
		name = input.Name
	}
	desc := existing.Description
	if input.Description != "" {
		desc = input.Description
	}
	cwd := existing.DefaultCwd
	if input.DefaultCwd != "" {
		cwd = input.DefaultCwd
	}
	model := existing.Model
	if input.Model != "" {
		model = input.Model
	}
	permMode := existing.PermissionMode
	if input.PermissionMode != "" {
		permMode = input.PermissionMode
	}
	sysPrompt := existing.SystemPrompt
	if input.SystemPrompt != "" {
		sysPrompt = input.SystemPrompt
	}

	now := time.Now().UnixMilli()
	_, err = s.db.Exec(`
		UPDATE agent_profiles SET name=?, description=?, default_cwd=?, model=?, permission_mode=?, system_prompt=?, updated_at=?
		WHERE id=?
	`, name, desc, cwd, model, permMode, sysPrompt, now, id)
	if err != nil {
		return nil, fmt.Errorf("update profile: %w", err)
	}

	return s.GetProfile(id)
}

func (s *Store) DisableProfile(id int64) error {
	now := time.Now().UnixMilli()
	res, err := s.db.Exec(`
		UPDATE agent_profiles SET status = 'disabled', updated_at = ? WHERE id = ?
	`, now, id)
	if err != nil {
		return fmt.Errorf("disable profile: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrProfileNotFound
	}
	return nil
}

func (s *Store) ListProfilesForWorkspace(workspaceID int64) ([]AgentProfile, error) {
	rows, err := s.db.Query(`
		SELECT id, user_id, workspace_id, runtime_id, provider, name, description, default_cwd, model, permission_mode, system_prompt, status, created_by, created_at, updated_at
		FROM agent_profiles WHERE workspace_id = ? ORDER BY name
	`, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}
	defer rows.Close()

	var profiles []AgentProfile
	for rows.Next() {
		var p AgentProfile
		if err := rows.Scan(
			&p.ID, &p.UserID, &p.WorkspaceID, &p.RuntimeID, &p.Provider,
			&p.Name, &p.Description, &p.DefaultCwd, &p.Model, &p.PermissionMode,
			&p.SystemPrompt, &p.Status, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan profile: %w", err)
		}
		profiles = append(profiles, p)
	}
	return profiles, rows.Err()
}

// ── StoryRun ──

func (s *Store) CreateRun(input StoryRunInput) (*StoryRun, error) {
	now := time.Now().UnixMilli()
	res, err := s.db.Exec(`
		INSERT INTO story_runs (story_id, agent_profile_id, runtime_id, provider, session_key, agent_session_id, exec_id, prompt, effective_prompt, permission_mode, cwd, session_title, status, error, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, input.StoryID, input.AgentProfileID, input.RuntimeID, string(input.Provider),
		input.SessionKey, input.AgentSessionID, input.ExecID,
		input.Prompt, input.EffectivePrompt, input.PermissionMode, input.Cwd,
		input.SessionTitle, string(RunQueued), "", input.CreatedBy, now)
	if err != nil {
		return nil, fmt.Errorf("create run: %w", err)
	}

	id, _ := res.LastInsertId()
	return s.GetRun(id)
}

func (s *Store) GetRun(id int64) (*StoryRun, error) {
	r := &StoryRun{}
	err := s.db.QueryRow(`
		SELECT id, story_id, agent_profile_id, runtime_id, provider, session_key, agent_session_id, exec_id, prompt, effective_prompt, permission_mode, cwd, session_title, status, error, created_by, created_at, started_at, finished_at
		FROM story_runs WHERE id = ?
	`, id).Scan(
		&r.ID, &r.StoryID, &r.AgentProfileID, &r.RuntimeID, &r.Provider,
		&r.SessionKey, &r.AgentSessionID, &r.ExecID,
		&r.Prompt, &r.EffectivePrompt, &r.PermissionMode, &r.Cwd,
		&r.SessionTitle, &r.Status, &r.Error,
		&r.CreatedBy, &r.CreatedAt, &r.StartedAt, &r.FinishedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRunNotFound
		}
		return nil, fmt.Errorf("get run: %w", err)
	}
	return r, nil
}

func (s *Store) UpdateRunStatus(id int64, status RunStatus, errText string, finishedAt int64) (*StoryRun, error) {
	now := time.Now().UnixMilli()

	switch status {
	case RunRunning:
		_, err := s.db.Exec(`
			UPDATE story_runs SET status=?, started_at=? WHERE id=?
		`, string(status), now, id)
		if err != nil {
			return nil, fmt.Errorf("update run to running: %w", err)
		}
	case RunCompleted, RunFailed, RunCancelled:
		finish := finishedAt
		if finish == 0 {
			finish = now
		}
		_, err := s.db.Exec(`
			UPDATE story_runs SET status=?, error=?, finished_at=? WHERE id=?
		`, string(status), errText, finish, id)
		if err != nil {
			return nil, fmt.Errorf("update run to %s: %w", status, err)
		}
	default:
		_, err := s.db.Exec(`
			UPDATE story_runs SET status=?, error=? WHERE id=?
		`, string(status), errText, id)
		if err != nil {
			return nil, fmt.Errorf("update run status: %w", err)
		}
	}

	return s.GetRun(id)
}

// UpdateRunSession updates the session-related fields on a StoryRun.
func (s *Store) UpdateRunSession(id int64, sessionKey, agentSessionID, sessionTitle string) error {
	now := time.Now().UnixMilli()
	_, err := s.db.Exec(`
		UPDATE story_runs SET session_key=?, agent_session_id=?, session_title=?, updated_at=?
		WHERE id=?
	`, sessionKey, agentSessionID, sessionTitle, now, id)
	return err
}

// UpdateRunExecID sets the exec_id on a StoryRun.
func (s *Store) UpdateRunExecID(id int64, execID string) error {
	_, err := s.db.Exec(`UPDATE story_runs SET exec_id=? WHERE id=?`, execID, id)
	return err
}

func (s *Store) ListRunsForStory(storyID int64) ([]StoryRun, error) {
	return s.listRuns(0, "story_id = ?", storyID)
}

func (s *Store) ListRunsForProfile(profileID int64, limit int) ([]StoryRun, error) {
	return s.listRuns(limit, "agent_profile_id = ?", profileID)
}

func (s *Store) listRuns(limit int, where string, args ...interface{}) ([]StoryRun, error) {
	query := fmt.Sprintf(`
		SELECT id, story_id, agent_profile_id, runtime_id, provider, session_key, agent_session_id, exec_id, prompt, effective_prompt, permission_mode, cwd, session_title, status, error, created_by, created_at, started_at, finished_at
		FROM story_runs WHERE %s ORDER BY id DESC
	`, where)

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}
	defer rows.Close()

	var runs []StoryRun
	for rows.Next() {
		var r StoryRun
		if err := rows.Scan(
			&r.ID, &r.StoryID, &r.AgentProfileID, &r.RuntimeID, &r.Provider,
			&r.SessionKey, &r.AgentSessionID, &r.ExecID,
			&r.Prompt, &r.EffectivePrompt, &r.PermissionMode, &r.Cwd,
			&r.SessionTitle, &r.Status, &r.Error,
			&r.CreatedBy, &r.CreatedAt, &r.StartedAt, &r.FinishedAt,
		); err != nil {
			return nil, fmt.Errorf("scan run: %w", err)
		}
		runs = append(runs, r)
	}
	return runs, rows.Err()
}
