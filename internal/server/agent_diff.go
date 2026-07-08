package server

import (
	"bytes"
	"context"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

const (
	gitCommandTimeout = 10 * time.Second
	maxDiffBytes      = 200 * 1024
)

type diffResponse struct {
	CWD            string   `json:"cwd"`
	IsGitRepo      bool     `json:"is_git_repo"`
	Stat           string   `json:"stat"`
	Diff           string   `json:"diff"`
	UntrackedFiles []string `json:"untracked_files"`
	Truncated      bool     `json:"truncated"`
}

// handleAgentDiff computes a live, read-only git diff for a monitored
// session's working directory. Nothing is persisted or mutated — every call
// re-runs git against the current on-disk state, so the result always
// reflects reality and never goes stale (design doc §4.3).
func (h *Handlers) handleAgentDiff(w http.ResponseWriter, r *http.Request) {
	u := h.curUser(w, r)
	if u == nil {
		return
	}
	agentType := h.agentType(r)
	sessionID := r.PathValue("id")
	sessionKey := h.monitoredSessionKey(agentType, sessionID)
	sess := h.sessions.GetSession(sessionKey)
	if sess == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	if !userCanAccessSession(h.hierStore, u.ID, sess) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "session access denied"})
		return
	}

	resp := diffResponse{CWD: sess.CWD, UntrackedFiles: []string{}}
	if sess.CWD == "" || !isGitRepo(sess.CWD) {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	resp.IsGitRepo = true
	resp.Stat = runGit(sess.CWD, "diff", "--stat")
	resp.UntrackedFiles = untrackedFiles(sess.CWD)

	diff := runGit(sess.CWD, "diff")
	if len(diff) > maxDiffBytes {
		resp.Truncated = true
	} else {
		resp.Diff = diff
	}

	writeJSON(w, http.StatusOK, resp)
}

func isGitRepo(cwd string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), gitCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", cwd, "rev-parse", "--is-inside-work-tree")
	out, err := cmd.Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// runGit runs a read-only git command and returns its stdout, or "" on any
// error (nonexistent repo, timeout, etc.) — callers treat "" as "nothing to
// show" rather than surfacing git's stderr to the client.
func runGit(cwd string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), gitCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", cwd}, args...)...)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return ""
	}
	return out.String()
}

// untrackedFiles lists new, untracked file paths via `git status --porcelain`
// (the `??` prefix). Only paths are returned, never file content — showing
// an agent-generated file's full content unasked is unnecessary and could be
// large/binary; the untracked list is enough for a human to know what's new.
func untrackedFiles(cwd string) []string {
	raw := runGit(cwd, "status", "--porcelain")
	files := []string{}
	if raw == "" {
		return files
	}
	for _, line := range strings.Split(strings.TrimRight(raw, "\n"), "\n") {
		if strings.HasPrefix(line, "??") {
			files = append(files, strings.TrimSpace(line[2:]))
		}
	}
	return files
}
