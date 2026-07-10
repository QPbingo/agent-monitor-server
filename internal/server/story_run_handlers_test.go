package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/heybox/agent-monitor-hook/sdk"
	"github.com/heybox/agent-monitor-server/internal/auth"
	"github.com/heybox/agent-monitor-server/internal/hierarchy"
	"github.com/heybox/agent-monitor-server/internal/registry"
	"github.com/heybox/agent-monitor-server/internal/session"
)

// fakeFailingSDK is a fake AgentSDK that fails ResumeSession and counts
// CreateSession calls so we can assert no new session is created as fallback.
type fakeFailingSDK struct {
	CreateSessionCalls int
}

func (f *fakeFailingSDK) AgentType() sdk.AgentType { return sdk.AgentClaude }
func (f *fakeFailingSDK) CreateSession(ctx context.Context, opts sdk.SessionOptions) (*sdk.Session, error) {
	f.CreateSessionCalls++
	id := fmt.Sprintf("sdk-session-%d", f.CreateSessionCalls)
	return &sdk.Session{ID: id, AgentType: sdk.AgentClaude, Title: opts.Title, CWD: opts.CWD, CreatedAt: time.Now(), Options: opts}, nil
}
func (f *fakeFailingSDK) SendPrompt(ctx context.Context, sessionID, prompt string) (<-chan sdk.Message, error) {
	ch := make(chan sdk.Message, 1)
	ch <- sdk.Message{Type: sdk.MessageTypeText, SessionID: sessionID, Content: "ok", IsFinal: true, Timestamp: time.Now()}
	close(ch)
	return ch, nil
}
func (f *fakeFailingSDK) ResumeSession(ctx context.Context, sessionID string) (*sdk.Session, error) {
	return nil, errors.New("resume failed")
}
func (f *fakeFailingSDK) CancelExecution(ctx context.Context, sessionID string) error { return nil }
func (f *fakeFailingSDK) RenameSession(ctx context.Context, sessionID, title string) error {
	return nil
}
func (f *fakeFailingSDK) ListSessions(ctx context.Context, dir string) ([]sdk.SessionInfo, error) {
	return nil, nil
}
func (f *fakeFailingSDK) SetPermissionMode(sessionID string, mode sdk.PermissionMode) error {
	return nil
}
func (f *fakeFailingSDK) Close() error { return nil }

// mustLatestRunForStory returns the most recent run for a story (ordered by id
// DESC), failing the test if none exist.
func mustLatestRunForStory(t *testing.T, store *registry.Store, storyID int64) *registry.StoryRun {
	t.Helper()
	runs, err := store.ListRunsForStory(storyID)
	if err != nil {
		t.Fatalf("list runs for story %d: %v", storyID, err)
	}
	if len(runs) == 0 {
		t.Fatalf("no runs found for story %d", storyID)
	}
	return &runs[0]
}

// newStoryRunTestServer creates a full test server with registry store and a
// fakeFailingSDK that fails on ResumeSession.  Returns the server, auth cookie,
// the fake SDK, registry store, session manager, and workspace ID.
func newStoryRunTestServer(t *testing.T) (*Server, string, *fakeFailingSDK, *registry.Store, *session.SessionManager, int64) {
	t.Helper()
	store, err := session.NewStore(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("session store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	db, err := store.DB()
	if err != nil {
		t.Fatalf("db: %v", err)
	}

	mgr := session.NewSessionManager(store, "local", "device-1")

	authStore := auth.NewStore(db)
	if err := authStore.EnsureTables(); err != nil {
		t.Fatalf("auth tables: %v", err)
	}

	hierStore := hierarchy.NewStore(db)
	if err := hierStore.EnsureTables(); err != nil {
		t.Fatalf("hier tables: %v", err)
	}

	regStore := registry.NewStore(db)
	if err := regStore.EnsureTables(); err != nil {
		t.Fatalf("reg tables: %v", err)
	}

	user, err := authStore.Register("story-owner", "pw")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	tok, err := authStore.CreateToken(user.ID)
	if err != nil {
		t.Fatalf("token: %v", err)
	}

	ws, err := hierStore.CreateWorkspace("story-ws", "")
	if err != nil {
		t.Fatalf("workspace: %v", err)
	}
	hierStore.SetPermission(user.ID, "workspace", ws.ID, hierarchy.LevelWorkspaceAdmin, user.ID)

	mgr.SetHierarchyStore(hierStore)
	agentMgr := sdk.NewAgentManager()
	fake := &fakeFailingSDK{}
	agentMgr.Register(sdk.AgentClaude, fake)

	srv := New("127.0.0.1:0", mgr, "daemon-tok", authStore, hierStore, agentMgr, regStore, "http://localhost:5173")
	srv.Start()
	t.Cleanup(srv.Shutdown)

	return srv, tok, fake, regStore, mgr, ws.ID
}

// TestCreateRunDoesNotCreateReplacementSessionWhenResumeFails verifies that
// when a Story has an existing SDK session and ResumeSession fails, the handler
// does NOT create a replacement session — it marks the run as failed and
// returns a 500 error.
func TestCreateRunDoesNotCreateReplacementSessionWhenResumeFails(t *testing.T) {
	srv, tok, fake, regStore, mgr, wsID := newStoryRunTestServer(t)
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)

	// ── Bootstrap registry data ──

	rt, err := regStore.EnsureRuntime("local", "device-1", "test-host", "/tmp")
	if err != nil {
		t.Fatalf("ensure runtime: %v", err)
	}

	_, err = regStore.UpsertCapability(registry.Capability{
		RuntimeID:  rt.ID,
		Provider:   registry.ProviderClaude,
		BinaryPath: "/usr/bin/claude",
		Version:    "1.0",
		Available:  true,
		AuthStatus: registry.AuthAuthenticated,
	})
	if err != nil {
		t.Fatalf("upsert capability: %v", err)
	}

	profile, err := regStore.CreateProfile(registry.ProfileInput{
		UserID:      "story-owner",
		WorkspaceID: wsID,
		RuntimeID:   rt.ID,
		Provider:    registry.ProviderClaude,
		Name:        "Test Agent",
		CreatedBy:   1,
	})
	if err != nil {
		t.Fatalf("create profile: %v", err)
	}

	// ── Create project and topic via the API ──

	projResp := authedPost(ts.URL, "/api/workspaces/"+itoa(wsID)+"/projects",
		`{"name":"proj","description":""}`, tok)
	if projResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(projResp.Body)
		projResp.Body.Close()
		t.Fatalf("create project status = %d, want 201; body=%s", projResp.StatusCode, string(body))
	}
	var proj struct{ ID int64 `json:"id"` }
	json.NewDecoder(projResp.Body).Decode(&proj)
	projResp.Body.Close()

	topicResp := authedPost(ts.URL, "/api/workspaces/"+itoa(wsID)+"/projects/"+itoa(proj.ID)+"/topics",
		`{"name":"story-topic","agent_type":"claude"}`, tok)
	if topicResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(topicResp.Body)
		topicResp.Body.Close()
		t.Fatalf("create topic status = %d, want 201; body=%s", topicResp.StatusCode, string(body))
	}
	var topic struct{ ID int64 `json:"id"` }
	json.NewDecoder(topicResp.Body).Decode(&topic)
	topicResp.Body.Close()

	// ── Create an SDK session linked to a story under the topic ──

	sdkSess := &sdk.Session{ID: "existing-sdk-session", AgentType: sdk.AgentClaude, CreatedAt: time.Now()}
	monitored, err := mgr.RegisterSDKSession("claude", sdkSess, 0, topic.ID, "Test Story")
	if err != nil {
		t.Fatalf("register sdk session: %v", err)
	}
	if monitored.StoryID == nil {
		t.Fatalf("session has no StoryID after registration")
	}
	storyID := *monitored.StoryID

	// ── Bind the agent profile to the story via API ──

	bindResp := authedPost(ts.URL, "/api/stories/"+itoa(storyID)+"/bind-agent",
		`{"agent_profile_id":`+itoa(profile.ID)+`}`, tok)
	if bindResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(bindResp.Body)
		bindResp.Body.Close()
		t.Fatalf("bind agent status = %d, want 200; body=%s", bindResp.StatusCode, string(body))
	}
	bindResp.Body.Close()

	// ── Execute: POST /api/stories/{id}/runs ──
	// The story has an existing SDK session, and ResumeSession will fail.
	// The handler MUST NOT create a replacement session.

	runResp := authedPost(ts.URL, "/api/stories/"+itoa(storyID)+"/runs",
		`{"prompt":"do it"}`, tok)

	// ── Assertions ──

	if runResp.StatusCode != http.StatusInternalServerError {
		body, _ := io.ReadAll(runResp.Body)
		runResp.Body.Close()
		t.Fatalf("POST /api/stories/%d/runs status = %d, want 500; body=%s",
			storyID, runResp.StatusCode, string(body))
	}
	runResp.Body.Close()

	if fake.CreateSessionCalls != 0 {
		t.Fatalf("CreateSessionCalls = %d, want 0 (no replacement session)", fake.CreateSessionCalls)
	}

	run := mustLatestRunForStory(t, regStore, storyID)
	if run.Status != registry.RunFailed {
		t.Fatalf("run status = %q, want %q", run.Status, registry.RunFailed)
	}
}

// ── Permission tests ──

// permTestFixture sets up a full test environment with admin and viewer users,
// one workspace with a project/topic/story, and a seeded agent profile.
// Returns the server URL, the viewer's auth cookie, admin's auth cookie, the
// workspace ID, the story ID, and the agent profile ID.
func permTestFixture(t *testing.T) (tsURL, viewerCookie, adminCookie string, wsID, storyID, profileID int64) {
	t.Helper()
	store, err := session.NewStore(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("session store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	db, err := store.DB()
	if err != nil {
		t.Fatalf("db: %v", err)
	}

	mgr := session.NewSessionManager(store, "local", "device-1")

	authStore := auth.NewStore(db)
	if err := authStore.EnsureTables(); err != nil {
		t.Fatalf("auth tables: %v", err)
	}

	hierStore := hierarchy.NewStore(db)
	if err := hierStore.EnsureTables(); err != nil {
		t.Fatalf("hier tables: %v", err)
	}

	regStore := registry.NewStore(db)
	if err := regStore.EnsureTables(); err != nil {
		t.Fatalf("reg tables: %v", err)
	}

	// Register admin user
	admin, err := authStore.Register("admin", "pw")
	if err != nil {
		t.Fatalf("register admin: %v", err)
	}
	adminTok, err := authStore.CreateToken(admin.ID)
	if err != nil {
		t.Fatalf("admin token: %v", err)
	}

	// Register viewer user
	viewer, err := authStore.Register("viewer", "pw")
	if err != nil {
		t.Fatalf("register viewer: %v", err)
	}
	viewerTok, err := authStore.CreateToken(viewer.ID)
	if err != nil {
		t.Fatalf("viewer token: %v", err)
	}

	mgr.SetHierarchyStore(hierStore)

	// Create agent manager with a fake SDK — needed for CreateRun handler.
	agentMgr := sdk.NewAgentManager()
	fake := &fakeFailingSDK{}
	agentMgr.Register(sdk.AgentClaude, fake)

	srv := New("127.0.0.1:0", mgr, "daemon-tok", authStore, hierStore, agentMgr, regStore, "http://localhost:5173")
	srv.Start()
	t.Cleanup(srv.Shutdown)
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)

	// Admin creates a workspace
	wsResp := authedPost(ts.URL, "/api/workspaces", `{"name":"perm-ws","description":""}`, adminTok)
	if wsResp.StatusCode != http.StatusCreated {
		t.Fatalf("admin create ws status=%d", wsResp.StatusCode)
	}
	var ws struct{ ID int64 `json:"id"` }
	json.NewDecoder(wsResp.Body).Decode(&ws)
	wsResp.Body.Close()

	// Admin grants viewer level=10 to viewer
	permResp := authedPut(ts.URL, "/api/permissions/workspace/"+itoa(ws.ID),
		fmt.Sprintf(`{"user_id":%d,"level":10}`, viewer.ID), adminTok)
	if permResp.StatusCode != http.StatusNoContent {
		t.Fatalf("grant viewer perm status=%d", permResp.StatusCode)
	}
	permResp.Body.Close()

	// Admin creates project
	projResp := authedPost(ts.URL, "/api/workspaces/"+itoa(ws.ID)+"/projects",
		`{"name":"perm-proj","description":""}`, adminTok)
	if projResp.StatusCode != http.StatusCreated {
		t.Fatalf("admin create proj status=%d", projResp.StatusCode)
	}
	var proj struct{ ID int64 `json:"id"` }
	json.NewDecoder(projResp.Body).Decode(&proj)
	projResp.Body.Close()

	// Admin creates topic
	topicResp := authedPost(ts.URL, "/api/workspaces/"+itoa(ws.ID)+"/projects/"+itoa(proj.ID)+"/topics",
		`{"name":"perm-topic","agent_type":"claude"}`, adminTok)
	if topicResp.StatusCode != http.StatusCreated {
		t.Fatalf("admin create topic status=%d", topicResp.StatusCode)
	}
	var topic struct{ ID int64 `json:"id"` }
	json.NewDecoder(topicResp.Body).Decode(&topic)
	topicResp.Body.Close()

	// Admin creates story
	storyResp := authedPost(ts.URL, "/api/workspaces/"+itoa(ws.ID)+"/projects/"+itoa(proj.ID)+"/topics/"+itoa(topic.ID)+"/stories",
		`{"name":"perm-story","description":"test description"}`, adminTok)
	if storyResp.StatusCode != http.StatusCreated {
		t.Fatalf("admin create story status=%d", storyResp.StatusCode)
	}
	var story struct{ ID int64 `json:"id"` }
	json.NewDecoder(storyResp.Body).Decode(&story)
	storyResp.Body.Close()
	storyID = story.ID

	// Seed runtime and capability for agent profile
	rt, err := regStore.EnsureRuntime("local", "device-1", "test-host", "/tmp")
	if err != nil {
		t.Fatalf("ensure runtime: %v", err)
	}
	_, err = regStore.UpsertCapability(registry.Capability{
		RuntimeID:  rt.ID,
		Provider:   registry.ProviderClaude,
		BinaryPath: "/usr/bin/claude",
		Version:    "1.0",
		Available:  true,
		AuthStatus: registry.AuthAuthenticated,
	})
	if err != nil {
		t.Fatalf("upsert capability: %v", err)
	}

	// Admin creates agent profile
	profile, err := regStore.CreateProfile(registry.ProfileInput{
		UserID:      "local",
		WorkspaceID: ws.ID,
		RuntimeID:   rt.ID,
		Provider:    registry.ProviderClaude,
		Name:        "Test Agent",
		CreatedBy:   admin.ID,
	})
	if err != nil {
		t.Fatalf("create profile: %v", err)
	}

	return ts.URL, viewerTok, adminTok, ws.ID, storyID, profile.ID
}

// TestViewerCannotScanWorkspaceAgents verifies that a workspace viewer gets 403
// when trying to scan capabilities with a workspace_id.
func TestViewerCannotScanWorkspaceAgents(t *testing.T) {
	tsURL, viewerTok, _, _, _, _ := permTestFixture(t)

	resp := authedPost(tsURL, "/api/agent-runtimes/scan",
		`{"workspace_id":1}`, viewerTok) // workspace_id=1 is the Inspiration workspace
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("viewer scan workspace agents status = %d, want 403; body=%s", resp.StatusCode, string(body))
	}
	resp.Body.Close()
}

// TestViewerCannotBindAgentToStory verifies that a workspace viewer gets 403
// when trying to bind an agent to a story.
func TestViewerCannotBindAgentToStory(t *testing.T) {
	tsURL, viewerTok, _, _, storyID, profileID := permTestFixture(t)

	resp := authedPost(tsURL, "/api/stories/"+itoa(storyID)+"/bind-agent",
		fmt.Sprintf(`{"agent_profile_id":%d}`, profileID), viewerTok)
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("viewer bind agent to story status = %d, want 403; body=%s", resp.StatusCode, string(body))
	}
	resp.Body.Close()
}

// TestViewerCannotRunStory verifies that a workspace viewer gets 403 when
// trying to create a run on a story.
func TestViewerCannotRunStory(t *testing.T) {
	tsURL, viewerTok, adminTok, _, storyID, profileID := permTestFixture(t)

	// Bind the agent as admin first so the story has an agent_profile_id
	bindResp := authedPost(tsURL, "/api/stories/"+itoa(storyID)+"/bind-agent",
		fmt.Sprintf(`{"agent_profile_id":%d}`, profileID), adminTok)
	if bindResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(bindResp.Body)
		bindResp.Body.Close()
		t.Fatalf("admin bind agent status = %d, want 200; body=%s", bindResp.StatusCode, string(body))
	}
	bindResp.Body.Close()

	// Now try to run as viewer
	runResp := authedPost(tsURL, "/api/stories/"+itoa(storyID)+"/runs",
		`{"prompt":"test run"}`, viewerTok)
	if runResp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(runResp.Body)
		runResp.Body.Close()
		t.Fatalf("viewer create run status = %d, want 403; body=%s", runResp.StatusCode, string(body))
	}
	runResp.Body.Close()
}
