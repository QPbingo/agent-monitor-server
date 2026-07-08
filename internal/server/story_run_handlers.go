package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/heybox/agent-monitor-hook/sdk"
	"github.com/heybox/agent-monitor-server/internal/hierarchy"
	"github.com/heybox/agent-monitor-server/internal/registry"
)

// ── Story Agent Binding ──

// handleBindAgent binds an agent profile to a story.
// POST /api/stories/{id}/bind-agent
func (h *Handlers) handleBindAgent(w http.ResponseWriter, r *http.Request) {
	storyID, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}

	story, err := h.hierStore.GetStory(storyID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "story not found"})
		return
	}

	wid, err := h.hierStore.GetWorkspaceIDForStory(storyID)
	if err != nil || !h.checkWSAdmin(w, r, wid) {
		if err == nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin access required"})
		}
		return
	}

	var req struct {
		AgentProfileID int64 `json:"agent_profile_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.AgentProfileID == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent_profile_id required"})
		return
	}

	// Verify profile belongs to same workspace
	profile, err := h.regStore.GetProfile(req.AgentProfileID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent profile not found"})
		return
	}
	if profile.WorkspaceID != wid {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "profile must belong to same workspace as story"})
		return
	}
	if profile.Status == registry.ProfileDisabled {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent profile is disabled"})
		return
	}

	// Bind the agent (with lock check)
	if err := h.hierStore.BindAgentToStory(storyID, req.AgentProfileID); err != nil {
		if err == hierarchy.ErrStoryAgentLocked {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "story agent is locked after first run"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.broadcastHierarchy()
	writeJSON(w, http.StatusOK, story)
}

// ── Story Run ──

// handleCreateRun creates and starts a new story run.
// POST /api/stories/{id}/runs
func (h *Handlers) handleCreateRun(w http.ResponseWriter, r *http.Request) {
	storyID, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}

	story, err := h.hierStore.GetStory(storyID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "story not found"})
		return
	}

	wid, err := h.hierStore.GetWorkspaceIDForStory(storyID)
	if err != nil || !h.checkWSAdmin(w, r, wid) {
		if err == nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin access required"})
		}
		return
	}

	// Validate story state
	if story.Status == "closed" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "story is closed"})
		return
	}
	if story.AgentProfileID == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "story has no agent profile bound"})
		return
	}

	// Get agent profile
	profile, err := h.regStore.GetProfile(*story.AgentProfileID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent profile not found"})
		return
	}
	if profile.Status == registry.ProfileDisabled {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent profile is disabled"})
		return
	}

	// Verify capability is available
	rt, err := h.regStore.GetRuntimeByKey(h.sessions.UserID(), h.sessions.DeviceID())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "runtime not found"})
		return
	}
	caps, err := h.regStore.ListCapabilities(rt.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var cap *registry.Capability
	for i := range caps {
		if caps[i].Provider == profile.Provider {
			cap = &caps[i]
			break
		}
	}
	if cap == nil || !cap.Available {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "capability not available"})
		return
	}
	if cap.AuthStatus == registry.AuthUnauthenticated {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent is not authenticated"})
		return
	}

	// Check no concurrent run
	hasRunning, err := h.hasRunningRun(storyID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if hasRunning {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "story already has a running run"})
		return
	}

	// Parse request
	var req struct {
		Prompt         string `json:"prompt"`
		PermissionMode string `json:"permission_mode"`
		Cwd            string `json:"cwd"`
		NewSession     bool   `json:"new_session"`
		SessionTitle   string `json:"session_title"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	// Resolve prompt: user override > story description
	prompt := req.Prompt
	if prompt == "" {
		prompt = story.Description
	}
	if prompt == "" {
		prompt = "Complete the task as described."
	}

	// Resolve effective prompt
	effectivePrompt := prompt
	if profile.SystemPrompt != "" {
		effectivePrompt = profile.SystemPrompt + "\n\n" + prompt
	}

	// Resolve CWD
	cwd := resolveCWD(req.Cwd, profile.DefaultCwd, wid)
	if cwd == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "could not resolve working directory"})
		return
	}

	// Resolve permission mode
	permMode := req.PermissionMode
	if permMode == "" {
		permMode = profile.PermissionMode
	}

	// Session title
	sessionTitle := req.SessionTitle
	if sessionTitle == "" {
		sessionTitle = truncatePrompt(story.Name+" · "+profile.Name, 120)
	}

	// Create StoryRun
	u := h.curUser(w, r)
	if u == nil {
		return
	}
	runInput := registry.StoryRunInput{
		StoryID:         storyID,
		AgentProfileID:  profile.ID,
		RuntimeID:       rt.ID,
		Provider:        profile.Provider,
		Prompt:          prompt,
		EffectivePrompt: effectivePrompt,
		PermissionMode:  permMode,
		Cwd:             cwd,
		SessionTitle:    sessionTitle,
		CreatedBy:       u.ID,
	}
	run, err := h.regStore.CreateRun(runInput)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Resolve session: new or reuse
	var sessionID, sessionKey, execID string
	agentType := sdk.AgentType(profile.Provider)

	if h.agentMgr == nil {
		// No agent manager — mark as failed
		h.regStore.UpdateRunStatus(run.ID, registry.RunFailed, "agent manager not configured", 0)
		h.hierStore.UpdateStoryRunSummary(storyID, run.ID, "", "failed")
		h.broadcastStoryRunUpdated(run.ID)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent manager not configured"})
		return
	}

	if req.NewSession {
		// Force new session
		sess, err := h.agentMgr.CreateSession(r.Context(), agentType, sdk.SessionOptions{
			Title: sessionTitle,
			CWD:   cwd,
		})
		if err != nil {
			h.regStore.UpdateRunStatus(run.ID, registry.RunFailed, err.Error(), 0)
			h.hierStore.UpdateStoryRunSummary(storyID, run.ID, "", "failed")
			h.broadcastStoryRunUpdated(run.ID)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		sessionID = sess.ID
		// Register as monitored session and bind to story
		monitored, err := h.sessions.RegisterSDKSession(string(agentType), sess, wid, 0, story.Name)
		if err != nil {
			h.regStore.UpdateRunStatus(run.ID, registry.RunFailed, err.Error(), 0)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		sessionKey = monitored.SessionKey
		// Bind session to story
		h.sessions.Store().RegisterSDKSessionForStory(
			h.sessions.UserID(), h.sessions.DeviceID(),
			string(agentType), sessionID, storyID,
		)
	} else {
		// Try to reuse latest usable session
		reusable, _ := h.sessions.Store().FindReusableSDKSessionForStory(storyID)
		if reusable != nil {
			// Resume existing session
			sess, err := h.agentMgr.ResumeSession(r.Context(), agentType, reusable.AgentSessionID)
			if err != nil {
				// Fall through to create new
				reusable = nil
			} else {
				sessionID = sess.ID
				sessionKey = reusable.SessionKey
			}
		}
		if reusable == nil {
			// Create new session
			sess, err := h.agentMgr.CreateSession(r.Context(), agentType, sdk.SessionOptions{
				Title: sessionTitle,
				CWD:   cwd,
			})
			if err != nil {
				h.regStore.UpdateRunStatus(run.ID, registry.RunFailed, err.Error(), 0)
				h.hierStore.UpdateStoryRunSummary(storyID, run.ID, "", "failed")
				h.broadcastStoryRunUpdated(run.ID)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			sessionID = sess.ID
			monitored, err := h.sessions.RegisterSDKSession(string(agentType), sess, wid, 0, story.Name)
			if err != nil {
				h.regStore.UpdateRunStatus(run.ID, registry.RunFailed, err.Error(), 0)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			sessionKey = monitored.SessionKey
			h.sessions.Store().RegisterSDKSessionForStory(
				h.sessions.UserID(), h.sessions.DeviceID(),
				string(agentType), sessionID, storyID,
			)
		}
	}

	// Update run with session info and set to running
	// We need to update session fields; let's use a direct update
	h.regStore.UpdateRunSession(run.ID, sessionKey, sessionID, sessionTitle)
	h.regStore.UpdateRunStatus(run.ID, registry.RunRunning, "", 0)
	h.hierStore.UpdateStoryRunSummary(storyID, run.ID, sessionKey, "running")

	// Broadcast run started
	h.broadcastStoryRunUpdated(run.ID)

	// Start execution in background
	execID, err = h.startAgentExecution(agentType, sessionID, sessionKey, effectivePrompt, 10)
	if err != nil {
		h.regStore.UpdateRunStatus(run.ID, registry.RunFailed, err.Error(), 0)
		h.hierStore.UpdateStoryRunSummary(storyID, run.ID, sessionKey, "failed")
		h.broadcastStoryRunUpdated(run.ID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Update run with exec_id
	h.regStore.UpdateRunExecID(run.ID, execID)

	// Broadcast agent session created
	if h.sseHub != nil {
		h.sseHub.BroadcastAgent(map[string]interface{}{
			"type":        "story_run_started",
			"run_id":      run.ID,
			"story_id":    storyID,
			"session_key": sessionKey,
			"exec_id":     execID,
		})
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"run_id":           run.ID,
		"story_id":         storyID,
		"agent_profile_id": profile.ID,
		"session_key":      sessionKey,
		"agent_session_id": sessionID,
		"exec_id":          execID,
		"status":           "running",
	})
}

// handleListRuns lists runs for a story.
// GET /api/stories/{id}/runs
func (h *Handlers) handleListRuns(w http.ResponseWriter, r *http.Request) {
	storyID, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}

	wid, err := h.hierStore.GetWorkspaceIDForStory(storyID)
	if err != nil || !h.checkWSViewer(w, r, wid) {
		if err == nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "viewer access required"})
		}
		return
	}

	runs, err := h.regStore.ListRunsForStory(storyID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if runs == nil {
		runs = []registry.StoryRun{}
	}

	writeJSON(w, http.StatusOK, runs)
}

// handleCancelRun cancels a running story run.
// POST /api/stories/{id}/runs/{run_id}/cancel
func (h *Handlers) handleCancelRun(w http.ResponseWriter, r *http.Request) {
	storyID, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	runID, ok := parsePathID(w, r, "run_id")
	if !ok {
		return
	}

	wid, err := h.hierStore.GetWorkspaceIDForStory(storyID)
	if err != nil || !h.checkWSAdmin(w, r, wid) {
		if err == nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin access required"})
		}
		return
	}

	run, err := h.regStore.GetRun(runID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "run not found"})
		return
	}
	if run.StoryID != storyID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "run does not belong to this story"})
		return
	}
	if run.Status != registry.RunRunning {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "run is not running"})
		return
	}

	// Cancel via SDK
	if h.agentMgr != nil && run.AgentSessionID != "" {
		agentType := sdk.AgentType(run.Provider)
		if run.ExecID != "" {
			h.agentMgr.Executions.Cancel(run.ExecID)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		h.agentMgr.CancelExecution(ctx, agentType, run.AgentSessionID)

		// Mark session stopped
		sessionKey := h.monitoredSessionKey(agentType, run.AgentSessionID)
		h.sessions.MarkSDKSessionStopped(sessionKey)
	}

	// Update run status
	h.regStore.UpdateRunStatus(run.ID, registry.RunCancelled, "", 0)
	h.hierStore.UpdateStoryRunSummary(storyID, run.ID, run.SessionKey, "cancelled")

	h.broadcastStoryRunUpdated(run.ID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

// ── Helpers ──

// hasRunningRun checks if a story has any run in 'running' or 'queued' status.
func (h *Handlers) hasRunningRun(storyID int64) (bool, error) {
	runs, err := h.regStore.ListRunsForStory(storyID)
	if err != nil {
		return false, err
	}
	for _, r := range runs {
		if r.Status == registry.RunRunning || r.Status == registry.RunQueued {
			return true, nil
		}
	}
	return false, nil
}

// resolveCWD resolves the working directory for a run.
// Priority: run.cwd > profile.default_cwd > ~/.agent-monitor/workspaces/{wid}
func resolveCWD(runCWD, profileCWD string, workspaceID int64) string {
	if runCWD != "" {
		return runCWD
	}
	if profileCWD != "" {
		return profileCWD
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	_ = os.MkdirAll(filepath.Join(home, ".agent-monitor", "workspaces", fmt.Sprintf("%d", workspaceID)), 0700)
	return filepath.Join(home, ".agent-monitor", "workspaces", fmt.Sprintf("%d", workspaceID))
}

// broadcastStoryRunUpdated sends a story run update via SSE.
func (h *Handlers) broadcastStoryRunUpdated(runID int64) {
	if h.sseHub == nil {
		return
	}
	run, err := h.regStore.GetRun(runID)
	if err != nil {
		return
	}
	h.sseHub.Notify("story_run_updated", run)
}
