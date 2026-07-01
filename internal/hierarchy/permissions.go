package hierarchy

import (
	"fmt"
	"time"
)

const (
	LevelWorkspaceAdmin  = 100
	LevelProjectAdmin    = 50
	LevelProjectViewer   = 10
	LevelWorkspaceViewer = 5
)

type Permission struct {
	ID           int64  `json:"id"`
	UserID       int64  `json:"user_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   int64  `json:"resource_id"`
	Level        int    `json:"level"`
	GrantedBy    int64  `json:"granted_by,omitempty"`
	CreatedAt    int64  `json:"created_at"`
}

func (s *Store) SetPermission(userID int64, resourceType string, resourceID int64, level int, grantedBy int64) error {
	now := time.Now().UnixMilli()
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO permissions (user_id, resource_type, resource_id, level, granted_by, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		userID, resourceType, resourceID, level, grantedBy, now,
	)
	return err
}

func (s *Store) RemovePermission(userID int64, resourceType string, resourceID int64) error {
	_, err := s.db.Exec(
		`DELETE FROM permissions WHERE user_id=? AND resource_type=? AND resource_id=?`,
		userID, resourceType, resourceID,
	)
	return err
}

func (s *Store) GetPermission(userID int64, resourceType string, resourceID int64) (*Permission, error) {
	var p Permission
	err := s.db.QueryRow(
		`SELECT id, user_id, resource_type, resource_id, level, COALESCE(granted_by,0), created_at FROM permissions WHERE user_id=? AND resource_type=? AND resource_id=?`,
		userID, resourceType, resourceID,
	).Scan(&p.ID, &p.UserID, &p.ResourceType, &p.ResourceID, &p.Level, &p.GrantedBy, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) ListPermissions(resourceType string, resourceID int64) ([]Permission, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, resource_type, resource_id, level, COALESCE(granted_by,0), created_at FROM permissions WHERE resource_type=? AND resource_id=?`,
		resourceType, resourceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.UserID, &p.ResourceType, &p.ResourceID, &p.Level, &p.GrantedBy, &p.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, rows.Err()
}

// ── Permission checks ──

// CheckWorkspacePermission returns true if user has at least minLevel on the workspace.
func (s *Store) CheckWorkspacePermission(userID int64, workspaceID int64, minLevel int) (bool, error) {
	var level int
	err := s.db.QueryRow(
		`SELECT level FROM permissions WHERE user_id=? AND resource_type='workspace' AND resource_id=?`,
		userID, workspaceID,
	).Scan(&level)
	if err != nil {
		return false, nil // no permission row = no access
	}
	return level >= minLevel, nil
}

// CheckProjectPermission returns true if user has at least minLevel on the project
// OR has workspace_admin on the parent workspace.
func (s *Store) CheckProjectPermission(userID int64, projectID int64, minLevel int) (bool, error) {
	// Direct project permission
	var level int
	err := s.db.QueryRow(
		`SELECT level FROM permissions WHERE user_id=? AND resource_type='project' AND resource_id=?`,
		userID, projectID,
	).Scan(&level)
	if err == nil && level >= minLevel {
		return true, nil
	}

	// Check parent workspace permission
	var workspaceID int64
	err = s.db.QueryRow(`SELECT workspace_id FROM projects WHERE id=?`, projectID).Scan(&workspaceID)
	if err != nil {
		return false, fmt.Errorf("find project workspace: %w", err)
	}

	ok, err := s.CheckWorkspacePermission(userID, workspaceID, LevelWorkspaceAdmin)
	if err != nil {
		return false, err
	}
	return ok, nil
}

// GetAuthorizedWorkspaceIDs returns workspace IDs the user can see.
func (s *Store) GetAuthorizedWorkspaceIDs(userID int64) ([]int64, error) {
	rows, err := s.db.Query(
		`SELECT DISTINCT resource_id FROM permissions WHERE user_id=? AND resource_type='workspace'`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}

	// Also include workspaces where user has a project-level permission
	projRows, err := s.db.Query(
		`SELECT DISTINCT p.workspace_id FROM projects p
		 JOIN permissions perm ON perm.resource_type='project' AND perm.resource_id=p.id
		 WHERE perm.user_id=?`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer projRows.Close()
	for projRows.Next() {
		var id int64
		if err := projRows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// GetAuthorizedProjectIDs returns project IDs the user can see in a workspace.
func (s *Store) GetAuthorizedProjectIDs(userID int64, workspaceID int64) ([]int64, error) {
	// If workspace admin, return all projects
	if ok, _ := s.CheckWorkspacePermission(userID, workspaceID, LevelWorkspaceAdmin); ok {
		projects, err := s.ListProjects(workspaceID)
		if err != nil {
			return nil, err
		}
		ids := make([]int64, len(projects))
		for i, p := range projects {
			ids[i] = p.ID
		}
		return ids, nil
	}

	// Otherwise, return projects where user has explicit permission
	rows, err := s.db.Query(
		`SELECT resource_id FROM permissions WHERE user_id=? AND resource_type='project' AND resource_id IN (SELECT id FROM projects WHERE workspace_id=?)`,
		userID, workspaceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
