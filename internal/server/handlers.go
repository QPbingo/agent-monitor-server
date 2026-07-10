package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/heybox/agent-monitor-hook/sdk"
	"github.com/heybox/agent-monitor-server/internal/auth"
	"github.com/heybox/agent-monitor-server/internal/hierarchy"
	"github.com/heybox/agent-monitor-server/internal/registry"
	"github.com/heybox/agent-monitor-server/internal/session"
)

type Handlers struct {
	sessions  *session.SessionManager
	token     string
	sseHub    *SSEHub
	authStore *auth.Store
	hierStore *hierarchy.Store
	agentMgr  *sdk.AgentManager
	regStore  *registry.Store
}

func NewHandlers(s *session.SessionManager, tok string, sse *SSEHub, as *auth.Store, hs *hierarchy.Store, am *sdk.AgentManager, rs *registry.Store) *Handlers {
	return &Handlers{sessions: s, token: tok, sseHub: sse, authStore: as, hierStore: hs, agentMgr: am, regStore: rs}
}

// parsePathID extracts an int64 path value and writes 400 on failure.
func parsePathID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	v, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid %s", name)})
		return 0, false
	}
	return v, true
}

// broadcastHierarchy pushes the latest hierarchy tree to all SSE clients.
func (h *Handlers) broadcastHierarchy() {
	if h.sseHub == nil || h.hierStore == nil {
		return
	}
	h.sseHub.Notify("hierarchy_updated", nil)
}

// Register wires routes onto mux using a grouped layout with group-level
// auth middleware. This replaces the previous per-route manual wrapping and
// guarantees every web-facing API is authenticated.
//
// Groups:
//   - public:  /api/auth/{register,login}        — no auth
//   - machine: /health, /api/poll-input,
//     /api/sessions/{key}/pending-input — X-Daemon-Token (MachineAuth)
//   - web:     all other /api/* + /api/events/stream — cookie/Bearer (WebAuth)
//
// NOTE: logout is placed in the web group (requires valid token to revoke).
func (h *Handlers) Register(mux *http.ServeMux) {
	// ── Public group: registration & login (no auth) ──
	mux.HandleFunc("POST /api/auth/register", h.handleRegister)
	mux.HandleFunc("POST /api/auth/login", h.handleLogin)

	// ── Machine group: hooks / plugins (X-Daemon-Token) ──
	machine := http.NewServeMux()
	machine.HandleFunc("GET /health", h.handleHealth)
	machine.HandleFunc("GET /api/poll-input", h.handlePollInput)
	machine.HandleFunc("GET /api/sessions/{key}/pending-input", h.handlePendingInput)
	mux.Handle("/health", auth.MachineAuth(h.token)(machine))
	mux.Handle("/api/poll-input", auth.MachineAuth(h.token)(machine))
	mux.Handle("/api/sessions/{key}/pending-input", auth.MachineAuth(h.token)(machine))

	// ── Web group: all user-facing APIs + SSE stream (cookie/Bearer) ──
	web := http.NewServeMux()
	web.HandleFunc("POST /api/auth/logout", h.handleLogout)
	web.HandleFunc("GET /api/auth/me", h.handleMe)
	web.HandleFunc("GET /api/sessions", h.handleListSessions)
	web.HandleFunc("GET /api/sessions/{key}", h.handleGetSession)
	web.HandleFunc("POST /api/sessions/{key}/input", h.handleSendInput)
	web.HandleFunc("GET /api/events/stream", h.sseHub.HandleStream)

	web.HandleFunc("GET /api/hierarchy", h.handleGetHierarchy)
	web.HandleFunc("POST /api/workspaces", h.handleCreateWorkspace)
	web.HandleFunc("PUT /api/workspaces/{id}", h.handleUpdateWorkspace)
	web.HandleFunc("DELETE /api/workspaces/{id}", h.handleDeleteWorkspace)
	web.HandleFunc("GET /api/workspaces/{wid}/projects", h.handleListProjects)
	web.HandleFunc("POST /api/workspaces/{wid}/projects", h.handleCreateProject)
	web.HandleFunc("PUT /api/workspaces/{wid}/projects/{id}", h.handleUpdateProject)
	web.HandleFunc("DELETE /api/workspaces/{wid}/projects/{id}", h.handleDeleteProject)
	web.HandleFunc("GET /api/workspaces/{wid}/projects/{pid}/topics", h.handleListTopics)
	web.HandleFunc("POST /api/workspaces/{wid}/projects/{pid}/topics", h.handleCreateTopic)
	web.HandleFunc("PUT /api/workspaces/{wid}/projects/{pid}/topics/{id}", h.handleUpdateTopic)
	web.HandleFunc("DELETE /api/workspaces/{wid}/projects/{pid}/topics/{id}", h.handleDeleteTopic)
	web.HandleFunc("GET /api/workspaces/{wid}/projects/{pid}/topics/{tid}/stories", h.handleListStories)
	web.HandleFunc("POST /api/workspaces/{wid}/projects/{pid}/topics/{tid}/stories", h.handleCreateStory)
	web.HandleFunc("PUT /api/stories/{id}", h.handleUpdateStory)
	web.HandleFunc("DELETE /api/stories/{id}", h.handleDeleteStory)

	web.HandleFunc("GET /api/permissions/workspace/{id}", h.handleListWorkspacePerms)
	web.HandleFunc("PUT /api/permissions/workspace/{id}", h.handleSetWorkspacePerm)
	web.HandleFunc("DELETE /api/permissions/workspace/{id}/{uid}", h.handleRemoveWorkspacePerm)
	web.HandleFunc("GET /api/permissions/project/{id}", h.handleListProjectPerms)
	web.HandleFunc("PUT /api/permissions/project/{id}", h.handleSetProjectPerm)
	web.HandleFunc("DELETE /api/permissions/project/{id}/{uid}", h.handleRemoveProjectPerm)
	web.HandleFunc("GET /api/users", h.handleListUsers)

	// Agent SDK control
	web.HandleFunc("POST /api/agent/{type}/sessions", h.handleAgentCreateSession)
	web.HandleFunc("GET /api/agent/{type}/sessions", h.handleAgentListSessions)
	web.HandleFunc("POST /api/agent/{type}/sessions/{id}/prompt", h.handleAgentSendPrompt)
	web.HandleFunc("POST /api/agent/{type}/sessions/{id}/cancel", h.handleAgentCancel)
	web.HandleFunc("POST /api/agent/{type}/sessions/{id}/resume", h.handleAgentResume)
	web.HandleFunc("PUT /api/agent/{type}/sessions/{id}/rename", h.handleAgentRename)
	web.HandleFunc("PUT /api/agent/{type}/sessions/{id}/permissions", h.handleAgentSetPermissions)
	web.HandleFunc("GET /api/agent/{type}/sessions/{id}/diff", h.handleAgentDiff)

		// Agent Registry
		web.HandleFunc("GET /api/agent-runtimes/current", h.handleGetCurrentRuntime)
		web.HandleFunc("POST /api/agent-runtimes/scan", h.handleScanCapabilities)
		web.HandleFunc("GET /api/agent-capabilities", h.handleListCapabilities)
		web.HandleFunc("GET /api/workspaces/{workspace_id}/agent-profiles", h.handleListProfiles)
		web.HandleFunc("POST /api/workspaces/{workspace_id}/agent-profiles", h.handleCreateProfile)
		web.HandleFunc("GET /api/agent-profiles/{id}", h.handleGetProfile)
		web.HandleFunc("PUT /api/agent-profiles/{id}", h.handleUpdateProfile)
		web.HandleFunc("DELETE /api/agent-profiles/{id}", h.handleDeleteProfile)

		// Story Run
		web.HandleFunc("POST /api/stories/{id}/bind-agent", h.handleBindAgent)
		web.HandleFunc("POST /api/stories/{id}/runs", h.handleCreateRun)
		web.HandleFunc("GET /api/stories/{id}/runs", h.handleListRuns)
		web.HandleFunc("POST /api/stories/{id}/runs/{run_id}/cancel", h.handleCancelRun)

		mux.Handle("/api/", auth.WebAuth(h.authStore)(web))

	// ── Root: redirect to frontend ──
	mux.HandleFunc("GET /{$}", h.handleRoot)
}

// ── Permission helpers ──

func (h *Handlers) curUser(w http.ResponseWriter, r *http.Request) *auth.User {
	u := auth.GetUser(r)
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "auth required"})
	}
	return u
}

func (h *Handlers) checkWSAdmin(w http.ResponseWriter, r *http.Request, wid int64) bool {
	if h.hierStore == nil {
		return true
	}
	u := h.curUser(w, r)
	if u == nil {
		return false
	}
	ok, _ := h.hierStore.CheckWorkspacePermission(u.ID, wid, hierarchy.LevelWorkspaceAdmin)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace admin required"})
	}
	return ok
}

func (h *Handlers) checkProjAdmin(w http.ResponseWriter, r *http.Request, pid int64) bool {
	if h.hierStore == nil {
		return true
	}
	u := h.curUser(w, r)
	if u == nil {
		return false
	}
	ok, _ := h.hierStore.CheckProjectPermission(u.ID, pid, hierarchy.LevelProjectAdmin)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "project admin required"})
	}
	return ok
}

func (h *Handlers) projWS(pid int64) int64 {
	if p, _ := h.hierStore.GetProject(pid); p != nil {
		return p.WorkspaceID
	}
	return 0
}
func (h *Handlers) topProj(tid int64) int64 {
	if t, _ := h.hierStore.GetTopic(tid); t != nil {
		return t.ProjectID
	}
	return 0
}
func (h *Handlers) stoTop(sid int64) int64 {
	if s, _ := h.hierStore.GetStory(sid); s != nil {
		return s.TopicID
	}
	return 0
}

// ── Auth ──

// isCrossOrigin reports whether the request's Origin header indicates a
// cross-origin caller (different scheme/host/port than the request's Host).
// Used to pick the cookie SameSite/Secure policy: cross-origin production
// needs SameSite=None; Secure, while same-origin dev uses Lax without Secure.
func isCrossOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	// Compare origin host to request host. A simple host match suffices for
	// the local daemon use case (no reverse-proxy host rewriting in dev).
	// Strip scheme from origin for comparison.
	host := r.Host
	originHost := origin
	for _, scheme := range []string{"https://", "http://"} {
		if strings.HasPrefix(originHost, scheme) {
			originHost = originHost[len(scheme):]
			break
		}
	}
	// Drop path/query if present.
	if i := strings.Index(originHost, "/"); i >= 0 {
		originHost = originHost[:i]
	}
	return originHost != host
}

func (h *Handlers) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password required"})
		return
	}
	userCountBefore := 0
	if h.authStore != nil {
		if n, err := h.authStore.UserCount(); err == nil {
			userCountBefore = n
		}
	}
	u, err := h.authStore.Register(req.Username, req.Password)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	if userCountBefore == 0 && h.hierStore != nil {
		h.hierStore.EnsureInspiration()
		h.hierStore.SetPermission(u.ID, "workspace", 1, hierarchy.LevelWorkspaceAdmin, u.ID)
	}
	tok, _ := h.authStore.CreateToken(u.ID)
	auth.SetSessionCookie(w, tok, isCrossOrigin(r))
	writeJSON(w, http.StatusOK, map[string]interface{}{"token": tok, "user": u})
}

func (h *Handlers) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	u, err := h.authStore.Login(req.Username, req.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	tok, _ := h.authStore.CreateToken(u.ID)
	auth.SetSessionCookie(w, tok, isCrossOrigin(r))
	writeJSON(w, http.StatusOK, map[string]interface{}{"token": tok, "user": u})
}

func (h *Handlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Revoke the token from either cookie or Bearer header, then clear cookie.
	// WebAuth already validated the token before reaching here, so revoking is
	// safe. We check both sources so scripts using Bearer can also log out.
	if c, err := r.Cookie(auth.SessionCookieName); err == nil && c.Value != "" {
		h.authStore.RevokeToken(c.Value)
	} else if ah := r.Header.Get("Authorization"); strings.HasPrefix(ah, "Bearer ") {
		h.authStore.RevokeToken(strings.TrimPrefix(ah, "Bearer "))
	}
	auth.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// handleMe returns the currently authenticated user. Used by the SPA to
// restore the username on page reload when the HttpOnly cookie is still valid
// (replaces the old "User" placeholder). Requires WebAuth (injected via the
// web route group).
func (h *Handlers) handleMe(w http.ResponseWriter, r *http.Request) {
	u := auth.GetUser(r)
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"user": u})
}

// ── Hierarchy ──

func (h *Handlers) handleGetHierarchy(w http.ResponseWriter, r *http.Request) {
	if h.hierStore == nil {
		writeJSON(w, http.StatusOK, &hierarchy.HierarchyTree{})
		return
	}
	user := h.curUser(w, r)
	if user == nil {
		return
	}
	tree, err := scopedHierarchyForUser(h.hierStore, user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, tree)
}

func (h *Handlers) handleCreateWorkspace(w http.ResponseWriter, r *http.Request) {
	var req struct{ Name, Description string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}
	ws, err := h.hierStore.CreateWorkspace(req.Name, req.Description)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	h.hierStore.EnsureWorkspaceInspiration(ws.ID)
	if u := auth.GetUser(r); u != nil {
		h.hierStore.SetPermission(u.ID, "workspace", ws.ID, hierarchy.LevelWorkspaceAdmin, u.ID)
	}
	writeJSON(w, http.StatusCreated, ws)
	h.broadcastHierarchy()
}

func (h *Handlers) handleUpdateWorkspace(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	if !h.checkWSAdmin(w, r, id) {
		return
	}
	var req struct{ Name, Description string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	h.hierStore.UpdateWorkspace(id, req.Name, req.Description)
	w.WriteHeader(http.StatusNoContent)
	h.broadcastHierarchy()
}

func (h *Handlers) handleDeleteWorkspace(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	if !h.checkWSAdmin(w, r, id) {
		return
	}
	h.hierStore.DeleteWorkspace(id)
	w.WriteHeader(http.StatusNoContent)
	h.broadcastHierarchy()
}

func (h *Handlers) handleListProjects(w http.ResponseWriter, r *http.Request) {
	wid, ok := parsePathID(w, r, "wid")
	if !ok {
		return
	}
	projects, _ := h.hierStore.ListProjects(wid)
	writeJSON(w, http.StatusOK, projects)
}

func (h *Handlers) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	wid, ok := parsePathID(w, r, "wid")
	if !ok {
		return
	}
	if !h.checkWSAdmin(w, r, wid) {
		return
	}
	var req struct{ Name, Description string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}
	proj, err := h.hierStore.CreateProject(wid, req.Name, req.Description)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if u := auth.GetUser(r); u != nil {
		h.hierStore.SetPermission(u.ID, "project", proj.ID, hierarchy.LevelProjectAdmin, u.ID)
	}
	writeJSON(w, http.StatusCreated, proj)
	h.broadcastHierarchy()
}

func (h *Handlers) handleUpdateProject(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	if !h.checkProjAdmin(w, r, id) {
		return
	}
	var req struct{ Name, Description string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	h.hierStore.UpdateProject(id, req.Name, req.Description)
	w.WriteHeader(http.StatusNoContent)
	h.broadcastHierarchy()
}

func (h *Handlers) handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	if !h.checkWSAdmin(w, r, h.projWS(id)) {
		return
	}
	h.hierStore.DeleteProject(id)
	w.WriteHeader(http.StatusNoContent)
	h.broadcastHierarchy()
}

func (h *Handlers) handleListTopics(w http.ResponseWriter, r *http.Request) {
	pid, ok := parsePathID(w, r, "pid")
	if !ok {
		return
	}
	topics, _ := h.hierStore.ListTopics(pid)
	writeJSON(w, http.StatusOK, topics)
}

func (h *Handlers) handleCreateTopic(w http.ResponseWriter, r *http.Request) {
	pid, ok := parsePathID(w, r, "pid")
	if !ok {
		return
	}
	if !h.checkProjAdmin(w, r, pid) {
		return
	}
	var req struct {
		Name, Description string
		AgentType         string `json:"agent_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}
	topic, err := h.hierStore.CreateTopic(pid, req.Name, req.Description, req.AgentType)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, topic)
	h.broadcastHierarchy()
}

func (h *Handlers) handleUpdateTopic(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	if !h.checkProjAdmin(w, r, h.topProj(id)) {
		return
	}
	var req struct{ Name, Description string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	h.hierStore.UpdateTopic(id, req.Name, req.Description)
	w.WriteHeader(http.StatusNoContent)
	h.broadcastHierarchy()
}

func (h *Handlers) handleDeleteTopic(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	if !h.checkProjAdmin(w, r, h.topProj(id)) {
		return
	}
	h.hierStore.DeleteTopic(id)
	w.WriteHeader(http.StatusNoContent)
	h.broadcastHierarchy()
}

func (h *Handlers) handleListStories(w http.ResponseWriter, r *http.Request) {
	tid, ok := parsePathID(w, r, "tid")
	if !ok {
		return
	}
	stories, _ := h.hierStore.ListStories(tid)
	writeJSON(w, http.StatusOK, stories)
}

func (h *Handlers) handleCreateStory(w http.ResponseWriter, r *http.Request) {
	pid, ok := parsePathID(w, r, "pid")
	if !ok {
		return
	}
	tid, ok := parsePathID(w, r, "tid")
	if !ok {
		return
	}
	if !h.checkProjAdmin(w, r, pid) {
		return
	}
	// Verify tid actually belongs to pid (ancestry check).
	topic, err := h.hierStore.GetTopic(tid)
	if err != nil || topic.ProjectID != pid {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "topic not found in this project"})
		return
	}
	var req struct{ Name, Description string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}
	story, err := h.hierStore.CreateStory(tid, req.Name, req.Description)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, story)
	h.broadcastHierarchy()
}

func (h *Handlers) handleUpdateStory(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	if !h.checkProjAdmin(w, r, h.topProj(h.stoTop(id))) {
		return
	}
	var req struct{ Name, Description string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	h.hierStore.UpdateStory(id, req.Name, req.Description)
	w.WriteHeader(http.StatusNoContent)
	h.broadcastHierarchy()
}

func (h *Handlers) handleDeleteStory(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	if !h.checkProjAdmin(w, r, h.topProj(h.stoTop(id))) {
		return
	}
	h.hierStore.DeleteStory(id)
	w.WriteHeader(http.StatusNoContent)
	h.broadcastHierarchy()
}

// ── Permissions ──

func (h *Handlers) handleListWorkspacePerms(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	if !h.checkWSAdmin(w, r, id) {
		return
	}
	perms, _ := h.hierStore.ListPermissions("workspace", id)
	writeJSON(w, http.StatusOK, perms)
}

func (h *Handlers) handleSetWorkspacePerm(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	if !h.checkWSAdmin(w, r, id) {
		return
	}
	var req struct {
		UserID int64 `json:"user_id"`
		Level  int   `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Level != 10 && req.Level != 50 && req.Level != 100 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "level must be 10 (viewer) or 100 (admin)"})
		return
	}
	h.hierStore.SetPermission(req.UserID, "workspace", id, req.Level, auth.GetUser(r).ID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handleRemoveWorkspacePerm(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	uid, ok := parsePathID(w, r, "uid")
	if !ok {
		return
	}
	if !h.checkWSAdmin(w, r, id) {
		return
	}
	h.hierStore.RemovePermission(uid, "workspace", id)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handleListProjectPerms(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	if !h.checkProjAdmin(w, r, id) {
		return
	}
	perms, _ := h.hierStore.ListPermissions("project", id)
	writeJSON(w, http.StatusOK, perms)
}

func (h *Handlers) handleSetProjectPerm(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	if !h.checkProjAdmin(w, r, id) {
		return
	}
	var req struct {
		UserID int64 `json:"user_id"`
		Level  int   `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Level != 10 && req.Level != 50 && req.Level != 100 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "level must be 10 (viewer) or 100 (admin)"})
		return
	}
	h.hierStore.SetPermission(req.UserID, "project", id, req.Level, auth.GetUser(r).ID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handleRemoveProjectPerm(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	uid, ok := parsePathID(w, r, "uid")
	if !ok {
		return
	}
	if !h.checkProjAdmin(w, r, id) {
		return
	}
	h.hierStore.RemovePermission(uid, "project", id)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handleListUsers(w http.ResponseWriter, r *http.Request) {
	u := h.curUser(w, r)
	if u == nil {
		return
	}
	ids, _ := h.hierStore.GetAuthorizedWorkspaceIDs(u.ID)
	isAdmin := false
	for _, id := range ids {
		if ok, _ := h.hierStore.CheckWorkspacePermission(u.ID, id, hierarchy.LevelWorkspaceAdmin); ok {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace admin required"})
		return
	}
	users, _ := h.authStore.ListUsers()
	writeJSON(w, http.StatusOK, users)
}

// ── Sessions ──

func (h *Handlers) handleListSessions(w http.ResponseWriter, r *http.Request) {
	u := h.curUser(w, r)
	if u == nil {
		return
	}
	writeJSON(w, http.StatusOK, filterSessionsForUser(h.hierStore, u.ID, h.sessions.GetSessions()))
}

func (h *Handlers) handleGetSession(w http.ResponseWriter, r *http.Request) {
	u := h.curUser(w, r)
	if u == nil {
		return
	}
	sess := h.sessions.GetSession(r.PathValue("key"))
	if sess == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	if !userCanAccessSession(h.hierStore, u.ID, sess) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "session access denied"})
		return
	}
	writeJSON(w, http.StatusOK, sess)
}

// handleRoot redirects to the frontend dashboard (Vite dev server or
// production static host). The daemon itself only serves the API.
func (h *Handlers) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	http.Redirect(w, r, "http://localhost:5173", http.StatusFound)
}

func (h *Handlers) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version": "1.0.0", "session_count": len(h.sessions.GetSessions()),
	})
}

// handleSendInput accepts web input for a session, replacing the former
// WebSocket send_input message. The input is enqueued for the agent plugin
// to poll via GET /api/poll-input, and a delta is broadcast via SSE.
func (h *Handlers) handleSendInput(w http.ResponseWriter, r *http.Request) {
	u := h.curUser(w, r)
	if u == nil {
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Text == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "text required"})
		return
	}
	key := r.PathValue("key")
	sess := h.sessions.GetSession(key)
	if sess == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	if !userCanAccessSession(h.hierStore, u.ID, sess) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "session access denied"})
		return
	}
	if sess.Source == "sdk" {
		if h.agentMgr == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent manager not configured"})
			return
		}
		execID, err := h.startAgentExecution(sdk.AgentType(sess.AgentType), sess.AgentSessionID, sess.SessionKey, req.Text, 10)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"exec_id": execID, "session_id": sess.AgentSessionID, "session_key": sess.SessionKey})
		return
	}
	if !h.sessions.HandleWebInput(key, req.Text) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handlePendingInput(w http.ResponseWriter, r *http.Request) {
	if text := h.sessions.GetPendingInput(r.PathValue("key")); text != "" {
		writeJSON(w, http.StatusOK, map[string]string{"text": text})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handlePollInput(w http.ResponseWriter, r *http.Request) {
	at := r.URL.Query().Get("agent_type")
	sid := r.URL.Query().Get("agent_session_id")
	if at == "" || sid == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	key := session.ComputeSessionKey(h.sessions.UserID(), h.sessions.DeviceID(), at, sid)
	if text := h.sessions.GetPendingInput(key); text != "" {
		writeJSON(w, http.StatusOK, map[string]string{"text": text})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Agent SDK control ──

var validPermissionModes = map[string]bool{
	"": true, "default": true, "acceptEdits": true, "bypassPermissions": true,
	"plan": true, "readOnly": true, "auto": true,
}

func isValidPermissionMode(mode string) bool {
	return validPermissionModes[mode]
}

func (h *Handlers) agentType(r *http.Request) sdk.AgentType {
	return sdk.AgentType(r.PathValue("type"))
}

func (h *Handlers) resolveWorkspaceForSDK(w http.ResponseWriter, r *http.Request, workspaceID int64) (int64, bool) {
	if h.hierStore == nil {
		return workspaceID, true
	}
	u := h.curUser(w, r)
	if u == nil {
		return 0, false
	}
	if workspaceID == 0 {
		ids, _ := h.hierStore.GetAuthorizedWorkspaceIDs(u.ID)
		if len(ids) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "workspace_id required"})
			return 0, false
		}
		workspaceID = ids[0]
	}
	ok, _ := h.hierStore.CheckWorkspacePermission(u.ID, workspaceID, hierarchy.LevelWorkspaceViewer)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access required"})
		return 0, false
	}
	return workspaceID, true
}

// resolveWorkspaceOrTopicForSDK resolves the effective workspace ID for an
// agent session request. When topicID is non-zero it is the sole source of
// truth: the workspace is derived from the topic via GetWorkspaceIDForTopic
// and workspaceID is ignored entirely, so a client can never create a
// mismatch between "the workspace I said" and "the topic I said" (design
// doc §4.1). Falls back to resolveWorkspaceForSDK when topicID is zero,
// preserving existing behavior exactly.
func (h *Handlers) resolveWorkspaceOrTopicForSDK(w http.ResponseWriter, r *http.Request, workspaceID int64, topicID int64) (int64, bool) {
	if topicID == 0 {
		return h.resolveWorkspaceForSDK(w, r, workspaceID)
	}
	if h.hierStore == nil {
		return 0, true
	}
	u := h.curUser(w, r)
	if u == nil {
		return 0, false
	}
	resolvedWorkspaceID, err := h.hierStore.GetWorkspaceIDForTopic(topicID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "topic not found"})
		return 0, false
	}
	ok, _ := h.hierStore.CheckWorkspacePermission(u.ID, resolvedWorkspaceID, hierarchy.LevelWorkspaceViewer)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access required"})
		return 0, false
	}
	return resolvedWorkspaceID, true
}

func (h *Handlers) monitoredSessionKey(agentType sdk.AgentType, sessionID string) string {
	return session.ComputeSessionKey(h.sessions.UserID(), h.sessions.DeviceID(), string(agentType), sessionID)
}

func (h *Handlers) startAgentExecution(agentType sdk.AgentType, sessionID string, sessionKey string, prompt string, timeoutMin int) (string, error) {
	execID := generateExecID()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMin)*time.Minute)
	h.agentMgr.Executions.Create(execID, sessionID, agentType, prompt, cancel)
	h.sessions.RecordSDKPrompt(sessionKey, prompt)
	h.sseHub.BroadcastAgent(map[string]interface{}{"type": "agent_exec_started", "exec_id": execID, "agent_type": string(agentType), "session_id": sessionID, "prompt": prompt})

	go func() {
		defer cancel()
		ch, err := h.agentMgr.SendPrompt(ctx, agentType, sessionID, prompt)
		if err != nil {
			h.agentMgr.Executions.Fail(execID, err.Error())
			h.sessions.MarkSDKSessionError(sessionKey, err.Error())
			h.sseHub.BroadcastAgent(map[string]interface{}{"type": "agent_error", "exec_id": execID, "error": err.Error()})
			return
		}
		for msg := range ch {
			h.agentMgr.Executions.AppendMessage(execID, msg)
			h.sessions.RecordSDKMessage(sessionKey, msg)
			h.sseHub.BroadcastAgent(map[string]interface{}{"type": "agent_message", "exec_id": execID, "agent_type": string(agentType), "session_id": sessionID, "msg_type": string(msg.Type), "content": msg.Content, "tool_name": msg.ToolName, "tool_input": msg.ToolInput, "raw_json": msg.RawJSON, "is_final": msg.IsFinal, "error": msg.Error})
			if msg.Type == sdk.MessageTypeError && msg.IsFinal {
				h.agentMgr.Executions.Fail(execID, msg.Error)
				h.sessions.MarkSDKSessionError(sessionKey, msg.Error)
				return
			}
		}
		if exec := h.agentMgr.Executions.Get(execID); exec == nil || exec.Status != sdk.ExecutionCancelled {
			h.agentMgr.Executions.Complete(execID)
			h.sessions.MarkSDKSessionIdle(sessionKey)
		}
	}()
	return execID, nil
}

func (h *Handlers) handleAgentCreateSession(w http.ResponseWriter, r *http.Request) {
	if h.agentMgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent manager not configured"})
		return
	}
	var req struct {
		CWD            string   `json:"cwd"`
		Model          string   `json:"model"`
		PermissionMode string   `json:"permission_mode"`
		AllowedTools   []string `json:"allowed_tools"`
		MaxTurns       int      `json:"max_turns"`
		Title          string   `json:"title"`
		WorkspaceID    int64    `json:"workspace_id"`
		TopicID        int64    `json:"topic_id"`
		StoryName      string   `json:"story_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	workspaceID, ok := h.resolveWorkspaceOrTopicForSDK(w, r, req.WorkspaceID, req.TopicID)
	if !ok {
		return
	}
	agentType := h.agentType(r)
	sess, err := h.agentMgr.CreateSession(r.Context(), agentType, sdk.SessionOptions{
		CWD: req.CWD, Model: req.Model, PermissionMode: sdk.PermissionMode(req.PermissionMode),
		AllowedTools: req.AllowedTools, MaxTurns: req.MaxTurns, Title: req.Title,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	monitored, err := h.sessions.RegisterSDKSession(string(agentType), sess, workspaceID, req.TopicID, req.StoryName)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"id": sess.ID, "agent_type": sess.AgentType, "title": sess.Title, "cwd": sess.CWD, "created_at": sess.CreatedAt, "session_key": monitored.SessionKey})
}

func (h *Handlers) handleAgentListSessions(w http.ResponseWriter, r *http.Request) {
	if h.agentMgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent manager not configured"})
		return
	}
	list, err := h.agentMgr.ListSessions(r.Context(), h.agentType(r), r.URL.Query().Get("dir"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// handleAgentSendPrompt starts an agent execution and returns immediately with
// the exec_id. The execution runs in the background; its messages are
// broadcast to ALL connected dashboards via the SSEHub (cross-client
// broadcast, AG-10). This replaces the former per-request SSE streaming so
// that every open dashboard observes the live execution, and reconnecting
// clients recover the full history via the `agent_executions` snapshot.
//
// Constraint C (from T002 design): the REST response MUST contain exec_id so
// the initiating client can correlate subsequent SSE `agent_message` events
// with the execution it started — even if the SSE event arrives slightly
// later than the REST response.
func (h *Handlers) handleAgentSendPrompt(w http.ResponseWriter, r *http.Request) {
	if h.agentMgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent manager not configured"})
		return
	}
	var req struct {
		Prompt         string `json:"prompt"`
		SessionID      string `json:"session_id"`
		TimeoutMinutes int    `json:"timeout_minutes"`
		WorkspaceID    int64  `json:"workspace_id"`
		TopicID        int64  `json:"topic_id"`
		StoryName      string `json:"story_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Prompt == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "prompt required"})
		return
	}

	agentType := h.agentType(r)
	sessionID := req.SessionID

	// Parse timeout — default 10m, cap 120m (AG-08).
	timeoutMin := 10
	if req.TimeoutMinutes > 0 {
		timeoutMin = req.TimeoutMinutes
		if timeoutMin > 120 {
			timeoutMin = 120
		}
	}

	workspaceID, ok := h.resolveWorkspaceOrTopicForSDK(w, r, req.WorkspaceID, req.TopicID)
	if !ok {
		return
	}

	// Auto-create a session if none was provided (AG-01).
	var sessionKey string
	if sessionID == "" {
		sess, err := h.agentMgr.CreateSession(r.Context(), agentType, sdk.SessionOptions{Title: truncatePrompt(req.Prompt, 60)})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		sessionID = sess.ID
		monitored, err := h.sessions.RegisterSDKSession(string(agentType), sess, workspaceID, req.TopicID, req.StoryName)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		sessionKey = monitored.SessionKey
		// Inform all clients (including the initiator) of the new session id.
		h.sseHub.BroadcastAgent(map[string]interface{}{
			"type": "agent_session_created", "agent_type": string(agentType),
			"session_id": sessionID, "session_key": sessionKey,
		})
	} else {
		sessionKey = h.monitoredSessionKey(agentType, sessionID)
		if h.sessions.GetSession(sessionKey) == nil {
			monitored, err := h.sessions.RegisterSDKSession(string(agentType), &sdk.Session{ID: sessionID, AgentType: agentType, CreatedAt: time.Now()}, workspaceID, req.TopicID, req.StoryName)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			sessionKey = monitored.SessionKey
		}
	}

	execID, err := h.startAgentExecution(agentType, sessionID, sessionKey, req.Prompt, timeoutMin)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Respond immediately with exec_id (constraint C). The execution continues
	// in the background; messages flow over the global SSE stream.
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"exec_id":     execID,
		"session_id":  sessionID,
		"session_key": sessionKey,
	})
}

// handleAgentCancel cancels a running execution and broadcasts agent_cancelled
// to all dashboards via SSE (AG-07).
func (h *Handlers) handleAgentCancel(w http.ResponseWriter, r *http.Request) {
	if h.agentMgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent manager not configured"})
		return
	}
	agentType := h.agentType(r)
	sessionID := r.PathValue("id")
	// exec_id may be passed as a query param so the store can cancel the
	// specific execution's context.
	execID := r.URL.Query().Get("exec_id")
	if execID != "" {
		h.agentMgr.Executions.Cancel(execID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.agentMgr.CancelExecution(ctx, agentType, sessionID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	sessionKey := h.monitoredSessionKey(agentType, sessionID)
	h.sessions.MarkSDKSessionStopped(sessionKey)
	h.sseHub.BroadcastAgent(map[string]interface{}{
		"type": "agent_cancelled", "exec_id": execID, "session_id": sessionID,
	})
	w.WriteHeader(http.StatusNoContent)
}

func generateExecID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "exec_" + hex.EncodeToString(b)
}

func truncatePrompt(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func (h *Handlers) handleAgentResume(w http.ResponseWriter, r *http.Request) {
	if h.agentMgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent manager not configured"})
		return
	}
	sess, err := h.agentMgr.ResumeSession(r.Context(), h.agentType(r), r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, sess)
}

func (h *Handlers) handleAgentRename(w http.ResponseWriter, r *http.Request) {
	if h.agentMgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent manager not configured"})
		return
	}
	var req struct {
		Title string `json:"title"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if err := h.agentMgr.RenameSession(r.Context(), h.agentType(r), r.PathValue("id"), req.Title); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handleAgentSetPermissions(w http.ResponseWriter, r *http.Request) {
	if h.agentMgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent manager not configured"})
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if err := h.agentMgr.SetPermissionMode(h.agentType(r), r.PathValue("id"), sdk.PermissionMode(req.Mode)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
