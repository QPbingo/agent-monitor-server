package server

import (
	"encoding/json"
	"net/http"

	"github.com/heybox/agent-monitor-server/internal/auth"
	"github.com/heybox/agent-monitor-server/internal/hierarchy"
	"github.com/heybox/agent-monitor-server/internal/registry"
)

// ── Runtime & Capability ──

// handleGetCurrentRuntime returns the current daemon runtime.
// GET /api/agent-runtimes/current
func (h *Handlers) handleGetCurrentRuntime(w http.ResponseWriter, r *http.Request) {
	u := h.curUser(w, r)
	if u == nil {
		return
	}

	rt, err := h.regStore.GetRuntimeByKey(h.sessions.UserID(), h.sessions.DeviceID())
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "runtime not found — run scan first"})
		return
	}

	writeJSON(w, http.StatusOK, rt)
}

// handleScanCapabilities scans local agents and upserts capabilities.
// POST /api/agent-runtimes/scan
func (h *Handlers) handleScanCapabilities(w http.ResponseWriter, r *http.Request) {
	u := h.curUser(w, r)
	if u == nil {
		return
	}

	rt, err := h.regStore.EnsureRuntime(h.sessions.UserID(), h.sessions.DeviceID(), "", "")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	scanner := registry.NewScanner(h.regStore)
	caps, err := scanner.ScanAll(rt.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Broadcast capabilities update
	if h.sseHub != nil {
		h.sseHub.Notify("agent_capabilities_updated", caps)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"runtime":      rt,
		"capabilities": caps,
	})
}

// handleListCapabilities returns capabilities for the current runtime.
// GET /api/agent-capabilities
func (h *Handlers) handleListCapabilities(w http.ResponseWriter, r *http.Request) {
	u := h.curUser(w, r)
	if u == nil {
		return
	}

	rt, err := h.regStore.GetRuntimeByKey(h.sessions.UserID(), h.sessions.DeviceID())
	if err != nil {
		writeJSON(w, http.StatusOK, []interface{}{})
		return
	}

	caps, err := h.regStore.ListCapabilities(rt.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, caps)
}

// ── AgentProfile ──

// handleListProfiles returns agent profiles for a workspace.
// GET /api/workspaces/{workspace_id}/agent-profiles
func (h *Handlers) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	u := h.curUser(w, r)
	if u == nil {
		return
	}

	wid, ok := parsePathID(w, r, "workspace_id")
	if !ok {
		return
	}

	if !h.checkWSViewer(w, r, wid) {
		return
	}

	profiles, err := h.regStore.ListProfilesForWorkspace(wid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if profiles == nil {
		profiles = []registry.AgentProfile{}
	}

	writeJSON(w, http.StatusOK, profiles)
}

// handleCreateProfile creates a new agent profile in a workspace.
// POST /api/workspaces/{workspace_id}/agent-profiles
func (h *Handlers) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	u := h.curUser(w, r)
	if u == nil {
		return
	}

	wid, ok := parsePathID(w, r, "workspace_id")
	if !ok {
		return
	}

	if !h.checkWSAdmin(w, r, wid) {
		return
	}

	var input registry.ProfileInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	// Runtime must be current daemon runtime
	rt, err := h.regStore.GetRuntimeByKey(h.sessions.UserID(), h.sessions.DeviceID())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no runtime — run scan first"})
		return
	}

	input.UserID = h.sessions.UserID()
	input.WorkspaceID = wid
	input.RuntimeID = rt.ID
	input.CreatedBy = u.ID

	profile, err := h.regStore.CreateProfile(input)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Broadcast profile update
	if h.sseHub != nil {
		h.sseHub.Notify("agent_profile_updated", profile)
	}

	writeJSON(w, http.StatusCreated, profile)
}

// handleGetProfile returns a single agent profile.
// GET /api/agent-profiles/{id}
func (h *Handlers) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	u := h.curUser(w, r)
	if u == nil {
		return
	}

	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}

	profile, err := h.regStore.GetProfile(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "profile not found"})
		return
	}

	// Viewer check on the workspace
	if !h.checkWSViewer(w, r, profile.WorkspaceID) {
		return
	}

	writeJSON(w, http.StatusOK, profile)
}

// handleUpdateProfile updates an agent profile.
// PUT /api/agent-profiles/{id}
func (h *Handlers) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	u := h.curUser(w, r)
	if u == nil {
		return
	}

	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}

	profile, err := h.regStore.GetProfile(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "profile not found"})
		return
	}

	if !h.checkWSAdmin(w, r, profile.WorkspaceID) {
		return
	}

	var input registry.ProfileInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	updated, err := h.regStore.UpdateProfile(id, input)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if h.sseHub != nil {
		h.sseHub.Notify("agent_profile_updated", updated)
	}

	writeJSON(w, http.StatusOK, updated)
}

// handleDeleteProfile soft-deletes (disables) an agent profile.
// DELETE /api/agent-profiles/{id}
func (h *Handlers) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	u := h.curUser(w, r)
	if u == nil {
		return
	}

	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}

	profile, err := h.regStore.GetProfile(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "profile not found"})
		return
	}

	if !h.checkWSAdmin(w, r, profile.WorkspaceID) {
		return
	}

	if err := h.regStore.DisableProfile(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if h.sseHub != nil {
		h.sseHub.Notify("agent_profile_updated", nil)
	}

	w.WriteHeader(http.StatusNoContent)
}

// ── Permission helpers ──

// checkWSViewer checks if the current user has at least viewer access to a workspace.
func (h *Handlers) checkWSViewer(w http.ResponseWriter, r *http.Request, wid int64) bool {
	if h.hierStore == nil {
		return true
	}
	u := auth.GetUser(r)
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "auth required"})
		return false
	}
	ok, _ := h.hierStore.CheckWorkspacePermission(u.ID, wid, hierarchy.LevelWorkspaceViewer)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "viewer access required"})
	}
	return ok
}
