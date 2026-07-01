// Recovery implements session recovery from agent transcript files.
//
// When the daemon starts, it may have been offline while agent sessions
// were active. Recovery scans agent transcript JSONL files from the last
// 24 hours to find and restore these sessions. Each recovered session is
// then matched against running OS processes to determine if the agent is
// still running.
//
// Transcript sources by agent type:
//
//	OpenCode:   ~/.config/opencode/sessions/*.jsonl
//	  Each file is a session transcript. File names are session IDs.
//
//	Claude Code: ~/.claude/projects/<project-hash>/*.jsonl
//	  Each project directory contains one or more session transcript files.
//	  Note: scanner incorrectly sets agentType to "codex" for Claude files
//	  (bug in scanClaudeTranscripts line 127).
//
//	Codex:      ~/.codex/sessions/**/rollout-*.jsonl
//	  Session files are prefixed with "rollout-" in nested directories.
//
// Recovery flow:
//
//	For each transcript file (last 24h):
//	  1. Parse JSONL lines to extract session metadata.
//	  2. Deduplicate by session_id (first occurrence wins).
//	  3. Skip if session is already tracked in SessionManager.
//	  4. Create session with Status=unknown.
//	  5. Add to SessionManager via AddRecoveredSession().
//	  6. Try to match against running process via FindProcessBySession().
//	  7. If matched, bind PID and promote to Status=active.
//
// After recovery, the PID Scanner will verify and update all recovered
// sessions in its first scan cycle.
package session

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/heybox/agent-monitor-server/internal/scanner"
)

// Recovery handles session restoration from agent transcript files.
//
// It is created once at daemon startup and runs synchronously before the
// EventWatcher and PID Scanner start, ensuring that the session map is
// populated with both persisted (SQLite) and recovered (transcript) sessions
// before real-time event processing begins.
type Recovery struct {
	userID   string          // User identifier for SessionKey generation
	deviceID string          // Device identifier for SessionKey generation
	manager  *SessionManager // Session manager to populate with recovered sessions
}

// NewRecovery creates a new Recovery instance.
func NewRecovery(userID, deviceID string, manager *SessionManager) *Recovery {
	return &Recovery{
		userID:   userID,
		deviceID: deviceID,
		manager:  manager,
	}
}

// Run executes the full recovery process.
//
// Steps:
//  1. Compute cutoff time: 24 hours before now.
//  2. Scan all agent transcript directories for JSONL files.
//  3. For each transcript session found (unique by session_id):
//     a. Skip if already tracked in SessionManager.
//     b. Create a new Session with Status=unknown.
//     c. Add to SessionManager (persist to SQLite).
//     d. Try to match against running OS process:
//        - Matches by agent_type + CWD hash (SHA256[:8]).
//        - If found → BindPIDToSession (promote to active, set process fields).
//  4. Log recovery statistics.
//
// Recovered sessions with Status=unknown that were not matched to a running
// process will remain unknown until a hook event or PID scan matches them.
func (r *Recovery) Run() {
	now := time.Now()
	cutoff := now.Add(-24 * time.Hour)

	// ── Phase 1: Scan all transcript directories ────────────────────────
	// Collects all unique sessions from agent transcripts in the last 24 hours.
	// Duplicate session_ids (within the same file) are deduplicated.
	// Multiple files for the same session_id are NOT deduplicated across files
	// (commented out original code did this, but current code doesn't).
	candidates := r.scanAllTranscripts(cutoff)

	// ── Phase 2: Process each candidate ─────────────────────────────────
	for _, c := range candidates {
		// Generate SessionKey from identity fields
		key := ComputeSessionKey(r.userID, r.deviceID, c.AgentType, c.AgentSessionID)

		// Skip if this session is already being tracked
		if r.manager.HasSession(key) {
			continue
		}

		// Create a new session with recovered metadata
		// Status=unknown: we don't know if the agent process is still running.
		// The PID match below and subsequent scans will determine the actual status.
		sess := &Session{
			UserID:         r.userID,
			DeviceID:       r.deviceID,
			AgentType:      c.AgentType,
			AgentSessionID: c.AgentSessionID,
			SessionKey:     key,
			Status:         StatusUnknown,
			StartTimeMs:    c.StartTimeMs,
			LastEventTimeMs: c.StartTimeMs,
			LastEventType:  c.LastEventType,
			LastFile:       c.LastFile,
			LastCommand:    c.LastCommand,
			TurnCount:      c.TurnCount,
			GitBranch:      c.GitBranch,
			CWD:            c.CWD,
			PID:            c.PID,
			Terminal:       c.Terminal,
			lastHookTime:   c.StartTimeMs,
		}

		// Add to session manager (persists to SQLite if store is available)
		r.manager.AddRecoveredSession(sess)

		// ── Try to match with a running process ─────────────────────────
		// Search for a process with matching agentType and CWD.
		// If found, bind the session to this PID and promote to active.
		// FindProcessBySession() uses gopsutil to check all running processes.
		if c.AgentSessionID != "" {
			info := scanner.FindProcessBySession(c.AgentType, c.AgentSessionID, c.CWDHash)
			if info != nil {
				r.manager.BindPIDToSession(key, info)
				log.Printf("[recovery] matched session %s with running PID %d (%s)", key, info.PID, info.Name)
			}
		}
	}

	log.Printf("[recovery] recovered %d sessions from transcript files", len(candidates))
}

// scanAllTranscripts collects recovery candidates from all three agent sources.
//
// Scans:
//   1. OpenCode transcripts   (~/.config/opencode/sessions/*.jsonl)
//   2. Claude Code transcripts (~/.claude/projects/*/*.jsonl)
//   3. Codex transcripts      (~/.codex/sessions/**/rollout-*.jsonl)
//
// All transcripts are filtered to only include entries from the last 24 hours.
func (r *Recovery) scanAllTranscripts(cutoff time.Time) []RecoveryCandidate {
	var candidates []RecoveryCandidate

	candidates = append(candidates, r.scanOpenCodeTranscripts(cutoff)...)
	candidates = append(candidates, r.scanClaudeTranscripts(cutoff)...)
	candidates = append(candidates, r.scanCodexTranscripts(cutoff)...)

	return candidates
}

// scanOpenCodeTranscripts scans OpenCode session transcript files.
//
// OpenCode stores transcripts in:
//
//	~/.config/opencode/sessions/<session_id>.jsonl
//
// Each file is a single session's transcript. File naming is <session_id>.jsonl.
// The session_id is extracted from the file name.
//
// All files in the directory with .jsonl extension are scanned.
func (r *Recovery) scanOpenCodeTranscripts(cutoff time.Time) []RecoveryCandidate {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	dir := filepath.Join(homeDir, ".config", "opencode", "sessions")
	return r.scanTranscriptDir(dir, "opencode", cutoff)
}

// scanClaudeTranscripts scans Claude Code session transcript files.
//
// Claude Code stores transcripts in:
//
//	~/.claude/projects/<project-hash>/<timestamp>.jsonl
//
// Each project directory (named by project hash) contains one or more
// session transcript files. The session_id is extracted from the JSONL
// entries themselves.
//
// NOTE: There is a known bug – the agent type is set to "codex" instead
// of "claude" for these transcripts (see line 127 in the original code).
// This means Claude sessions recovered from transcripts will have the
// wrong agent_type until corrected by a hook event or PID match.
func (r *Recovery) scanClaudeTranscripts(cutoff time.Time) []RecoveryCandidate {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	var candidates []RecoveryCandidate
	projectsDir := filepath.Join(homeDir, ".claude", "projects")
	entries, err := os.ReadDir(projectsDir)
	if err != nil {
		return candidates
	}

	// Walk through each project directory
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		projectDir := filepath.Join(projectsDir, entry.Name())
		filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(info.Name(), ".jsonl") {
				return nil
			}
			cands := r.scanTranscriptFile(path, "claude", cutoff)
			candidates = append(candidates, cands...)
			return nil
		})
	}

	return candidates
}

// scanCodexTranscripts scans Codex session transcript files.
//
// Codex stores transcripts in:
//
//	~/.codex/sessions/<subdirectory>/rollout-<session_id>.jsonl
//
// Session files are named with the prefix "rollout-" and stored in
// nested subdirectories. The session_id is extracted from the JSONL
// entries themselves.
func (r *Recovery) scanCodexTranscripts(cutoff time.Time) []RecoveryCandidate {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	var candidates []RecoveryCandidate
	codexDir := filepath.Join(homeDir, ".codex", "sessions")
	filepath.Walk(codexDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		// Codex session files are prefixed with "rollout-"
		if !strings.HasPrefix(info.Name(), "rollout-") || !strings.HasSuffix(info.Name(), ".jsonl") {
			return nil
		}
		cands := r.scanTranscriptFile(path, "codex", cutoff)
		candidates = append(candidates, cands...)
		return nil
	})

	return candidates
}

// scanTranscriptDir scans a flat directory of .jsonl transcript files.
//
// Used for OpenCode transcripts where each file in the directory is a
// separate session transcript. File names are not parsed for session IDs;
// session IDs are extracted from the JSONL entries.
func (r *Recovery) scanTranscriptDir(dir, agentType string, cutoff time.Time) []RecoveryCandidate {
	var candidates []RecoveryCandidate
	entries, err := os.ReadDir(dir)
	if err != nil {
		return candidates
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		cands := r.scanTranscriptFile(path, agentType, cutoff)
		candidates = append(candidates, cands...)
	}

	return candidates
}

// scanTranscriptFile scans a single transcript JSONL file for session entries.
//
// Processing:
//
//	1. Open the file.
//	2. Scan line by line (2MB buffer for large JSON payloads).
//	3. For each line:
//	   a. Parse JSON → extract session metadata.
//	   b. Extract/validate session_id.
//	   c. Deduplicate within the file (first entry for each session_id wins).
//	   d. Check timestamp cutoff (24 hours).
//	   e. Compute CWD hash for process matching.
//	   f. Create RecoveryCandidate.
//
// Session deduplication is per-file only (seenSessions map).
// If the same session appears in multiple files, it will be a separate
// candidate entry.
//
// Timestamp format: flexible parsing – looks for fields named "timestamp_ms",
// "timestampMs", "ts", "timestamp", "start_time_ms", "time". Handles both
// integer and string formats, and both millisecond and microsecond (> 1e15)
// timestamps.
func (r *Recovery) scanTranscriptFile(path, agentType string, cutoff time.Time) []RecoveryCandidate {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var candidates []RecoveryCandidate
	seenSessions := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 2*1024*1024), 2*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Parse the JSONL entry
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		// Extract session ID (different agents use different field names)
		sessionID, _ := entry["session_id"].(string)
		if sessionID == "" {
			sessionID, _ = entry["sessionId"].(string)
		}
		if sessionID == "" || seenSessions[sessionID] {
			continue
		}

		// Check if this entry is within the 24-hour window
		ts := extractTimestamp(entry)
		if ts < cutoff.UnixMilli() {
			continue
		}

		// Extract working directory and compute its hash for process matching
		cwd, _ := entry["cwd"].(string)
		cwdHash := ""
		if cwd != "" {
			h := sha256.Sum256([]byte(cwd))
			cwdHash = hex.EncodeToString(h[:8])
		}

		// Extract other session metadata
		eventType, _ := entry["type"].(string)
		lastFile := extractLastFile(entry)
		lastCommand := extractLastCommand(entry)

		turnCount := 0
		if tc, ok := entry["turn_count"].(float64); ok {
			turnCount = int(tc)
		}

		gitBranch, _ := entry["git_branch"].(string)

		terminal := ""
		pid := 0
		if p, ok := entry["pid"].(float64); ok {
			pid = int(p)
		}

		candidates = append(candidates, RecoveryCandidate{
			AgentType:      agentType,
			AgentSessionID: sessionID,
			CWDHash:        cwdHash,
			StartTimeMs:    ts,
			LastEventType:  eventType,
			LastFile:       lastFile,
			LastCommand:    lastCommand,
			TurnCount:      turnCount,
			GitBranch:      gitBranch,
			Terminal:       terminal,
			PID:            pid,
			CWD:            cwd,
			TranscriptPath: path,
		})

		seenSessions[sessionID] = true // deduplicate within this file
	}

	return candidates
}

// extractTimestamp extracts a millisecond Unix timestamp from a JSON entry.
//
// Searches for common timestamp field names across different agents:
//
//	"timestamp_ms", "timestampMs", "ts", "timestamp", "start_time_ms", "time"
//
// Handles multiple formats:
//   - float64: Direct JSON number (most common).
//   - string:  String representation of an integer.
//
// Automatic unit detection:
//   - If value > 1e15: assumed to be microseconds, converted to milliseconds.
//   - Otherwise: assumed to already be milliseconds.
func extractTimestamp(entry map[string]interface{}) int64 {
	fields := []string{"timestamp_ms", "timestampMs", "ts", "timestamp", "start_time_ms", "time"}
	for _, f := range fields {
		switch v := entry[f].(type) {
		case float64:
			ts := int64(v)
			if ts > 1e15 {
				ts /= 1000 // convert microseconds to milliseconds
			}
			return ts
		case string:
			var ts int64
			fmt.Sscanf(v, "%d", &ts)
			if ts > 0 {
				if ts > 1e15 {
					ts /= 1000 // convert microseconds to milliseconds
				}
				return ts
			}
		}
	}
	return 0
}

// extractLastFile extracts a file path from a JSON entry.
//
// Searches for:
//
//	Direct fields: "filePath", "file_path", "file", "last_file"
//	Nested:        "input.filePath", "input.file_path"
//
// Returns empty string if no file path found.
func extractLastFile(entry map[string]interface{}) string {
	fields := []string{"filePath", "file_path", "file", "last_file"}
	for _, f := range fields {
		if v, ok := entry[f].(string); ok {
			return v
		}
	}
	if input, ok := entry["input"].(map[string]interface{}); ok {
		if fp, ok := input["filePath"].(string); ok {
			return fp
		}
		if fp, ok := input["file_path"].(string); ok {
			return fp
		}
	}
	return ""
}

// extractLastCommand extracts a command or tool name from a JSON entry.
//
// Searches for: "tool", "tool_name", "command", "last_command", "type"
//
// Returns empty string if no command found.
func extractLastCommand(entry map[string]interface{}) string {
	fields := []string{"tool", "tool_name", "command", "last_command", "type"}
	for _, f := range fields {
		if v, ok := entry[f].(string); ok {
			return v
		}
	}
	return ""
}
