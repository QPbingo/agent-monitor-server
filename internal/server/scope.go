package server

import (
	"github.com/heybox/agent-monitor-server/internal/hierarchy"
	"github.com/heybox/agent-monitor-server/internal/session"
)

func scopedHierarchyForUser(store *hierarchy.Store, userID int64) (*hierarchy.HierarchyTree, error) {
	if store == nil || userID == 0 {
		return &hierarchy.HierarchyTree{Workspaces: []hierarchy.WorkspaceNode{}}, nil
	}

	tree, err := store.GetFullHierarchy()
	if err != nil {
		return nil, err
	}
	workspaceIDs, err := store.GetAuthorizedWorkspaceIDs(userID)
	if err != nil {
		return nil, err
	}
	allowedWorkspaces := make(map[int64]bool, len(workspaceIDs))
	for _, id := range workspaceIDs {
		allowedWorkspaces[id] = true
	}

	filtered := &hierarchy.HierarchyTree{Workspaces: []hierarchy.WorkspaceNode{}}
	for _, ws := range tree.Workspaces {
		if !allowedWorkspaces[ws.Workspace.ID] {
			continue
		}

		projectIDs, err := store.GetAuthorizedProjectIDs(userID, ws.Workspace.ID)
		if err != nil {
			return nil, err
		}
		allowedProjects := make(map[int64]bool, len(projectIDs))
		for _, id := range projectIDs {
			allowedProjects[id] = true
		}

		wsNode := hierarchy.WorkspaceNode{Workspace: ws.Workspace}
		for _, proj := range ws.Projects {
			if allowedProjects[proj.Project.ID] {
				wsNode.Projects = append(wsNode.Projects, proj)
			}
		}
		workspaceVisible, _ := store.CheckWorkspacePermission(userID, ws.Workspace.ID, hierarchy.LevelWorkspaceViewer)
		if workspaceVisible || len(wsNode.Projects) > 0 {
			filtered.Workspaces = append(filtered.Workspaces, wsNode)
		}
	}
	return filtered, nil
}

func userCanAccessSession(store *hierarchy.Store, userID int64, sess *session.Session) bool {
	if store == nil {
		return true
	}
	if userID == 0 || sess == nil {
		return false
	}

	projectID, err := store.GetProjectIDForSessionKey(sess.SessionKey)
	if err != nil && sess.StoryID != nil {
		projectID, err = store.GetProjectIDForStory(*sess.StoryID)
	}
	if err != nil {
		return false
	}
	ok, _ := store.CheckProjectPermission(userID, projectID, hierarchy.LevelProjectViewer)
	return ok
}

func filterSessionsForUser(store *hierarchy.Store, userID int64, sessions []*session.Session) []*session.Session {
	if store == nil {
		return sessions
	}
	filtered := make([]*session.Session, 0, len(sessions))
	for _, sess := range sessions {
		if userCanAccessSession(store, userID, sess) {
			filtered = append(filtered, sess)
		}
	}
	return filtered
}
