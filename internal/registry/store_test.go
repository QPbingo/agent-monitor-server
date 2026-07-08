package registry

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:?_journal_mode=WAL")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		t.Fatalf("enable foreign keys: %v", err)
	}
	return db
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db := openTestDB(t)
	store := NewStore(db)
	if err := store.EnsureTables(); err != nil {
		t.Fatalf("ensure tables: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return store
}

func TestEnsureRuntimeCreatesAndRefreshes(t *testing.T) {
	store := newTestStore(t)

	r1, err := store.EnsureRuntime("user1", "dev1", "macbook", "/root")
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	if r1.ID != 1 {
		t.Errorf("expected ID 1, got %d", r1.ID)
	}
	if r1.UserID != "user1" || r1.DeviceID != "dev1" {
		t.Errorf("expected user1/dev1, got %s/%s", r1.UserID, r1.DeviceID)
	}
	if r1.Name != "macbook" {
		t.Errorf("expected name macbook, got %s", r1.Name)
	}
	if r1.Hostname != "macbook" {
		t.Errorf("expected hostname macbook, got %s", r1.Hostname)
	}
	if r1.DefaultWorkspaceRoot != "/root" {
		t.Errorf("expected /root, got %s", r1.DefaultWorkspaceRoot)
	}

	// Second call with same user_id+device_id should refresh, not create new
	r2, err := store.EnsureRuntime("user1", "dev1", "renamed", "/newroot")
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if r2.ID != r1.ID {
		t.Errorf("expected same ID %d, got %d", r1.ID, r2.ID)
	}
	if r2.Name != "renamed" {
		t.Errorf("expected name renamed, got %s", r2.Name)
	}
	if r2.DefaultWorkspaceRoot != "/newroot" {
		t.Errorf("expected /newroot, got %s", r2.DefaultWorkspaceRoot)
	}

	// Different device should create a new runtime
	r3, err := store.EnsureRuntime("user1", "dev2", "other", "/root")
	if err != nil {
		t.Fatalf("third ensure: %v", err)
	}
	if r3.ID == r1.ID {
		t.Errorf("expected different ID from r1 (%d), got %d", r1.ID, r3.ID)
	}
}

func TestUpsertCapabilityReplacesProviderForRuntime(t *testing.T) {
	store := newTestStore(t)
	r, _ := store.EnsureRuntime("user1", "dev1", "mac", "/root")

	cap1 := Capability{
		RuntimeID:    r.ID,
		Provider:     ProviderClaude,
		BinaryPath:   "/usr/local/bin/claude",
		Version:      "2.0.0",
		Available:    true,
		AuthStatus:   AuthAuthenticated,
		AuthMessage:  "logged in",
		HookInstalled: true,
		HookStatus:   "ok",
	}
	got1, err := store.UpsertCapability(cap1)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if got1.ID != 1 {
		t.Errorf("expected ID 1, got %d", got1.ID)
	}
	if got1.Version != "2.0.0" {
		t.Errorf("expected version 2.0.0, got %s", got1.Version)
	}

	// Upsert with same runtime_id+provider should replace
	cap2 := Capability{
		RuntimeID:    r.ID,
		Provider:     ProviderClaude,
		BinaryPath:   "/usr/local/bin/claude",
		Version:      "2.1.0",
		Available:    true,
		AuthStatus:   AuthAuthenticated,
		AuthMessage:  "renewed",
		HookInstalled: true,
		HookStatus:   "ok",
	}
	got2, err := store.UpsertCapability(cap2)
	if err != nil {
		t.Fatalf("upsert again: %v", err)
	}
	if got2.ID != got1.ID {
		t.Errorf("expected same ID %d, got %d", got1.ID, got2.ID)
	}
	if got2.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %s", got2.Version)
	}

	// Different provider creates new
	cap3 := Capability{
		RuntimeID:   r.ID,
		Provider:    ProviderCodex,
		BinaryPath:  "/usr/local/bin/codex",
		Version:     "1.0.0",
		Available:   true,
		AuthStatus:  AuthUnknown,
	}
	got3, err := store.UpsertCapability(cap3)
	if err != nil {
		t.Fatalf("upsert codex: %v", err)
	}
	if got3.ID == got1.ID {
		t.Errorf("expected different ID from claude cap (%d), got %d", got1.ID, got3.ID)
	}

	list, err := store.ListCapabilities(r.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("expected 2 capabilities, got %d", len(list))
	}
}

func TestCreateProfileRequiresAvailableCapability(t *testing.T) {
	store := newTestStore(t)
	r, _ := store.EnsureRuntime("user1", "dev1", "mac", "/root")

	// Create a capability first
	store.UpsertCapability(Capability{
		RuntimeID:  r.ID,
		Provider:   ProviderClaude,
		BinaryPath: "/usr/local/bin/claude",
		Version:    "2.0.0",
		Available:  true,
		AuthStatus: AuthAuthenticated,
	})

	// Create profile with valid capability
	input := ProfileInput{
		UserID:      "user1",
		WorkspaceID: 1,
		RuntimeID:   r.ID,
		Provider:    ProviderClaude,
		Name:        "My Claude Agent",
		Description: "test agent",
		CreatedBy:   1,
	}
	profile, err := store.CreateProfile(input)
	if err != nil {
		t.Fatalf("create profile: %v", err)
	}
	if profile.ID != 1 {
		t.Errorf("expected ID 1, got %d", profile.ID)
	}
	if profile.Status != ProfileActive {
		t.Errorf("expected status active, got %s", profile.Status)
	}

	// Create profile with unavailable capability should fail
	store.UpsertCapability(Capability{
		RuntimeID:  r.ID,
		Provider:   ProviderCodex,
		BinaryPath: "/usr/local/bin/codex",
		Version:    "1.0.0",
		Available:  false,
		AuthStatus: AuthUnknown,
	})
	input2 := ProfileInput{
		UserID:      "user1",
		WorkspaceID: 1,
		RuntimeID:   r.ID,
		Provider:    ProviderCodex,
		Name:        "Codex Agent",
		CreatedBy:   1,
	}
	_, err = store.CreateProfile(input2)
	if err == nil {
		t.Fatal("expected error for unavailable capability")
	}
	if err != ErrCapabilityNotAvailable {
		t.Errorf("expected ErrCapabilityNotAvailable, got %v", err)
	}

	// Create profile with blank name should fail
	input3 := ProfileInput{
		UserID:      "user1",
		WorkspaceID: 1,
		RuntimeID:   r.ID,
		Provider:    ProviderClaude,
		Name:        "",
		CreatedBy:   1,
	}
	_, err = store.CreateProfile(input3)
	if err == nil {
		t.Fatal("expected error for blank name")
	}
}

func TestDisableProfileSoftDeletes(t *testing.T) {
	store := newTestStore(t)
	r, _ := store.EnsureRuntime("user1", "dev1", "mac", "/root")
	store.UpsertCapability(Capability{
		RuntimeID:  r.ID,
		Provider:   ProviderClaude,
		BinaryPath: "/usr/local/bin/claude",
		Version:    "2.0.0",
		Available:  true,
		AuthStatus: AuthAuthenticated,
	})

	profile, _ := store.CreateProfile(ProfileInput{
		UserID:      "user1",
		WorkspaceID: 1,
		RuntimeID:   r.ID,
		Provider:    ProviderClaude,
		Name:        "My Agent",
		CreatedBy:   1,
	})

	// Disable
	if err := store.DisableProfile(profile.ID); err != nil {
		t.Fatalf("disable: %v", err)
	}

	// Re-fetch
	got, err := store.GetProfile(profile.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != ProfileDisabled {
		t.Errorf("expected disabled, got %s", got.Status)
	}

	// Disable again should be idempotent
	if err := store.DisableProfile(profile.ID); err != nil {
		t.Fatalf("disable again: %v", err)
	}

	// Disable nonexistent should return error
	if err := store.DisableProfile(999); err == nil {
		t.Fatal("expected error for nonexistent profile")
	}
}

func TestCreateAndUpdateStoryRun(t *testing.T) {
	store := newTestStore(t)
	r, _ := store.EnsureRuntime("user1", "dev1", "mac", "/root")

	// Create run with full fields
	input := StoryRunInput{
		StoryID:        1,
		AgentProfileID: 1,
		RuntimeID:      r.ID,
		Provider:       ProviderClaude,
		Prompt:         "Fix the bug",
		EffectivePrompt: "You are helpful\n\nFix the bug",
		PermissionMode: "default",
		Cwd:            "/tmp",
		SessionTitle:   "Bug fix session",
		CreatedBy:      1,
	}
	run, err := store.CreateRun(input)
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	if run.ID != 1 {
		t.Errorf("expected ID 1, got %d", run.ID)
	}
	if run.Status != RunQueued {
		t.Errorf("expected queued, got %s", run.Status)
	}
	if run.Prompt != "Fix the bug" {
		t.Errorf("expected prompt preserved, got %s", run.Prompt)
	}
	if run.EffectivePrompt != "You are helpful\n\nFix the bug" {
		t.Errorf("expected effective_prompt preserved, got %s", run.EffectivePrompt)
	}

	// Create run with empty session fields (pre-session failure scenario)
	input2 := StoryRunInput{
		StoryID:        1,
		AgentProfileID: 1,
		RuntimeID:      r.ID,
		Provider:       ProviderClaude,
		Prompt:         "Another task",
		EffectivePrompt: "Another task",
		CreatedBy:      1,
	}
	run2, err := store.CreateRun(input2)
	if err != nil {
		t.Fatalf("create run with empty session: %v", err)
	}
	if run2.SessionKey != "" {
		t.Errorf("expected empty session_key, got %s", run2.SessionKey)
	}

	// Update run to running
	updated, err := store.UpdateRunStatus(run.ID, RunRunning, "", 0)
	if err != nil {
		t.Fatalf("update to running: %v", err)
	}
	if updated.Status != RunRunning {
		t.Errorf("expected running, got %s", updated.Status)
	}
	if updated.StartedAt == 0 {
		t.Error("expected started_at to be set")
	}

	// Update run to completed
	completed, err := store.UpdateRunStatus(run.ID, RunCompleted, "", 0)
	if err != nil {
		t.Fatalf("update to completed: %v", err)
	}
	if completed.Status != RunCompleted {
		t.Errorf("expected completed, got %s", completed.Status)
	}
	if completed.FinishedAt == 0 {
		t.Error("expected finished_at to be set")
	}

	// Update run to failed with error
	failed, err := store.UpdateRunStatus(run2.ID, RunFailed, "something went wrong", 0)
	if err != nil {
		t.Fatalf("update to failed: %v", err)
	}
	if failed.Status != RunFailed {
		t.Errorf("expected failed, got %s", failed.Status)
	}
	if failed.Error != "something went wrong" {
		t.Errorf("expected error text, got %s", failed.Error)
	}

	// List runs for story
	runs, err := store.ListRunsForStory(1)
	if err != nil {
		t.Fatalf("list runs: %v", err)
	}
	if len(runs) != 2 {
		t.Errorf("expected 2 runs, got %d", len(runs))
	}

	// List runs for profile
	pRuns, err := store.ListRunsForProfile(1, 10)
	if err != nil {
		t.Fatalf("list runs for profile: %v", err)
	}
	if len(pRuns) != 2 {
		t.Errorf("expected 2 runs for profile, got %d", len(pRuns))
	}
}

func TestUpdateProfile(t *testing.T) {
	store := newTestStore(t)
	r, _ := store.EnsureRuntime("user1", "dev1", "mac", "/root")
	store.UpsertCapability(Capability{
		RuntimeID:  r.ID,
		Provider:   ProviderClaude,
		BinaryPath: "/usr/local/bin/claude",
		Version:    "2.0.0",
		Available:  true,
		AuthStatus: AuthAuthenticated,
	})

	profile, _ := store.CreateProfile(ProfileInput{
		UserID:      "user1",
		WorkspaceID: 1,
		RuntimeID:   r.ID,
		Provider:    ProviderClaude,
		Name:        "My Agent",
		CreatedBy:   1,
	})

	updated, err := store.UpdateProfile(profile.ID, ProfileInput{
		Name:           "Renamed Agent",
		Description:    "new desc",
		DefaultCwd:     "/home/user/projects",
		Model:          "claude-sonnet-4-6",
		PermissionMode: "default",
		SystemPrompt:   "You are a coding assistant",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "Renamed Agent" {
		t.Errorf("expected Renamed Agent, got %s", updated.Name)
	}
	if updated.Description != "new desc" {
		t.Errorf("expected new desc, got %s", updated.Description)
	}
	if updated.DefaultCwd != "/home/user/projects" {
		t.Errorf("expected cwd, got %s", updated.DefaultCwd)
	}
	if updated.Model != "claude-sonnet-4-6" {
		t.Errorf("expected model, got %s", updated.Model)
	}
	if updated.SystemPrompt != "You are a coding assistant" {
		t.Errorf("expected system_prompt, got %s", updated.SystemPrompt)
	}

	// Update nonexistent
	_, err = store.UpdateProfile(999, ProfileInput{Name: "x"})
	if err == nil {
		t.Fatal("expected error for nonexistent profile")
	}
}

func TestListProfilesForWorkspace(t *testing.T) {
	store := newTestStore(t)
	r, _ := store.EnsureRuntime("user1", "dev1", "mac", "/root")
	store.UpsertCapability(Capability{
		RuntimeID:  r.ID,
		Provider:   ProviderClaude,
		BinaryPath: "/usr/local/bin/claude",
		Version:    "2.0.0",
		Available:  true,
		AuthStatus: AuthAuthenticated,
	})
	store.UpsertCapability(Capability{
		RuntimeID:  r.ID,
		Provider:   ProviderCodex,
		BinaryPath: "/usr/local/bin/codex",
		Version:    "1.0.0",
		Available:  true,
		AuthStatus: AuthUnknown,
	})

	store.CreateProfile(ProfileInput{
		UserID: "user1", WorkspaceID: 1, RuntimeID: r.ID, Provider: ProviderClaude,
		Name: "Agent A", CreatedBy: 1,
	})
	store.CreateProfile(ProfileInput{
		UserID: "user1", WorkspaceID: 1, RuntimeID: r.ID, Provider: ProviderCodex,
		Name: "Agent B", CreatedBy: 1,
	})
	store.CreateProfile(ProfileInput{
		UserID: "user1", WorkspaceID: 2, RuntimeID: r.ID, Provider: ProviderClaude,
		Name: "Agent C", CreatedBy: 1,
	})

	// Workspace 1 should have 2 profiles
	list1, err := store.ListProfilesForWorkspace(1)
	if err != nil {
		t.Fatalf("list ws1: %v", err)
	}
	if len(list1) != 2 {
		t.Errorf("expected 2 profiles for ws1, got %d", len(list1))
	}

	// Workspace 2 should have 1
	list2, err := store.ListProfilesForWorkspace(2)
	if err != nil {
		t.Fatalf("list ws2: %v", err)
	}
	if len(list2) != 1 {
		t.Errorf("expected 1 profile for ws2, got %d", len(list2))
	}

	// After disabling one in ws1, list should still include it
	store.DisableProfile(list1[0].ID)
	list1After, _ := store.ListProfilesForWorkspace(1)
	if len(list1After) != 2 {
		t.Errorf("expected 2 profiles after disable, got %d", len(list1After))
	}
}
