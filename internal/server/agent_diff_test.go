package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heybox/agent-monitor-server/internal/auth"
)

func runGitT(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func initGitRepoWithCommit(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	runGitT(t, dir, "init")
	if err := os.WriteFile(filepath.Join(dir, "foo.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatalf("write foo.go: %v", err)
	}
	runGitT(t, dir, "add", "foo.go")
	runGitT(t, dir, "commit", "-m", "init")
	return dir
}

func createSDKSessionWithCWD(t *testing.T, ts *httptest.Server, tok string, wsID int64, cwd string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/agent/claude/sessions", strings.NewReader(`{"cwd":"`+cwd+`","workspace_id":`+itoa(wsID)+`}`))
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: tok})
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	defer resp.Body.Close()
	var created struct {
		ID string `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&created)
	return created.ID
}

func TestAgentDiff_NonGitRepo(t *testing.T) {
	srv, tok, _, _, wsID := newAgentManagerTestServer(t)
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)
	dir := t.TempDir() // never git-initialized

	id := createSDKSessionWithCWD(t, ts, tok, wsID, dir)
	resp := authedGet(ts.URL, "/api/agent/claude/sessions/"+id+"/diff", tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	var body struct {
		IsGitRepo bool `json:"is_git_repo"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if body.IsGitRepo {
		t.Fatalf("expected is_git_repo=false for a plain tempdir")
	}
}

func TestAgentDiff_GitRepoWithTrackedChangeAndUntrackedFile(t *testing.T) {
	srv, tok, _, _, wsID := newAgentManagerTestServer(t)
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)
	dir := initGitRepoWithCommit(t)
	if err := os.WriteFile(filepath.Join(dir, "foo.go"), []byte("package main\n\nfunc main() {}\n"), 0644); err != nil {
		t.Fatalf("modify foo.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bar.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatalf("write bar.go: %v", err)
	}

	id := createSDKSessionWithCWD(t, ts, tok, wsID, dir)
	resp := authedGet(ts.URL, "/api/agent/claude/sessions/"+id+"/diff", tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	var body struct {
		IsGitRepo      bool     `json:"is_git_repo"`
		Diff           string   `json:"diff"`
		Stat           string   `json:"stat"`
		UntrackedFiles []string `json:"untracked_files"`
		Truncated      bool     `json:"truncated"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if !body.IsGitRepo {
		t.Fatalf("expected is_git_repo=true")
	}
	if !strings.Contains(body.Diff, "func main") {
		t.Fatalf("diff missing expected change: %q", body.Diff)
	}
	if body.Stat == "" {
		t.Fatalf("expected non-empty stat summary")
	}
	if len(body.UntrackedFiles) != 1 || body.UntrackedFiles[0] != "bar.go" {
		t.Fatalf("untracked_files=%v, want [bar.go]", body.UntrackedFiles)
	}
	if body.Truncated {
		t.Fatalf("did not expect truncation for a tiny diff")
	}
}

func TestAgentDiff_SessionNotFound(t *testing.T) {
	srv, tok := newTestServer(t)
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)

	resp := authedGet(ts.URL, "/api/agent/claude/sessions/does-not-exist/diff", tok)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", resp.StatusCode)
	}
}

func TestAgentDiff_EmptyCWD(t *testing.T) {
	srv, tok, _, _, wsID := newAgentManagerTestServer(t)
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)

	id := createSDKSessionWithCWD(t, ts, tok, wsID, "")
	resp := authedGet(ts.URL, "/api/agent/claude/sessions/"+id+"/diff", tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	var body struct {
		IsGitRepo bool `json:"is_git_repo"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if body.IsGitRepo {
		t.Fatalf("expected is_git_repo=false for an empty cwd")
	}
}

func TestAgentDiff_LargeDiffIsTruncated(t *testing.T) {
	srv, tok, _, _, wsID := newAgentManagerTestServer(t)
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)
	dir := initGitRepoWithCommit(t)
	var b strings.Builder
	b.WriteString("package main\n")
	for i := 0; i < 20000; i++ {
		b.WriteString("// padding line to exceed the 200KB diff cap 0123456789\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "foo.go"), []byte(b.String()), 0644); err != nil {
		t.Fatalf("rewrite foo.go: %v", err)
	}

	id := createSDKSessionWithCWD(t, ts, tok, wsID, dir)
	resp := authedGet(ts.URL, "/api/agent/claude/sessions/"+id+"/diff", tok)
	var body struct {
		Truncated bool   `json:"truncated"`
		Diff      string `json:"diff"`
		Stat      string `json:"stat"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if !body.Truncated {
		t.Fatalf("expected truncated=true for a >200KB diff")
	}
	if body.Diff != "" {
		t.Fatalf("expected empty diff body when truncated, got %d bytes", len(body.Diff))
	}
	if body.Stat == "" {
		t.Fatalf("expected stat summary even when truncated")
	}
}
