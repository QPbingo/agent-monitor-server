package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// Scanner periodically discovers agent processes via gopsutil, matches them
// to tracked sessions, and updates process-level metrics.
//
// It runs a background goroutine that, every interval (default 15 seconds):
//
//	1. GetKnownPIDs()      – collect all known session→PID mappings from SessionManager.
//	2. gopsutil.Processes() – enumerate all running OS processes.
//	3. collectAgentProcesses() – filter for agent processes (opencode/claude/codex binaries
//	                           or node processes with agent command-line patterns).
//	4. Two-round matching:
//	   a. Direct PID match       → HandlePidUpdate(key, info)
//	   b. Fallback agent_type+CWD → HandlePidUpdate(key, info) (handles PID changes)
//	5. Detect disappeared processes: known PIDs not found in scan → MarkDisappeared(key)
//	6. CheckIdleSessions()      – mark sessions idle if no hook events for >5 minutes.
//
// The scanner and EventWatcher operate independently on the same SessionManager,
// protected by sync.RWMutex.
type Scanner struct {
	updater  SessionUpdater     // Interface to SessionManager (handle pid updates, disappearance, idle)
	interval time.Duration      // Time between scan cycles (default 15s)
	detector *TerminalDetector  // Detects which terminal emulator the agent runs in
	stopCh   chan struct{}      // Close this channel to signal the scanner to stop
}

// NewScanner creates a new PID scanner.
//
// Parameters:
//   - updater:  SessionUpdater implementation (typically SessionManager)
//   - interval: Duration between scan cycles (from --scan-interval flag)
func NewScanner(updater SessionUpdater, interval time.Duration) *Scanner {
	return &Scanner{
		updater:  updater,
		interval: interval,
		detector: NewTerminalDetector(),
		stopCh:   make(chan struct{}),
	}
}

// Start launches the background scanning goroutine.
//
// The goroutine runs until Stop() is called, then exits cleanly after
// the current tick completes.
func (s *Scanner) Start() {
	go s.loop()
}

// Stop signals the scanner goroutine to stop.
//
// Does not block – the goroutine will exit on the next tick boundary.
// Called via defer in main() during shutdown.
func (s *Scanner) Stop() {
	close(s.stopCh)
}

// loop is the main scanning loop, running on a timer.
//
// Each tick executes the full scan() procedure:
//   - Discover all processes
//   - Match running processes to known sessions
//   - Detect disappeared sessions
//   - Check idle timeout
//
// Exits when stopCh is closed.
func (s *Scanner) loop() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.scan()
		}
	}
}

// scan performs a single full scan cycle.
//
// Algorithm outline:
//
//	PHASE 1: Collect known PIDs from SessionManager.
//	         GetKnownPIDs() returns map[PID]→SessionPIDInfo for all sessions
//	         that have been matched to a process.
//
//	PHASE 2: Discover all running processes via gopsutil.
//	         Filter for agent processes (opencode/claude/codex).
//	         For each agent process, collect metrics (PID, CWD, CPU%, RSS, terminal).
//
//	PHASE 3: Match discovered processes to sessions (two rounds):
//	         ROUND A – Direct PID match:
//	           For each discovered agent process, check if its PID is in knownPIDs.
//	           If yes → HandlePidUpdate(key, info) – updates metrics directly.
//	         ROUND B – Fallback by AgentType + CWD:
//	           For each discovered agent process not matched by PID, try to find
//	           a known session with the same AgentType and CWD. This handles cases
//	           where the agent restarted with a new PID but is working in the same
//	           directory (e.g., after a crash recovery).
//
//	PHASE 4: Detect disappeared processes.
//	         For each known PID that was NOT seen among discovered processes:
//	           Try a second pass – check if any discovered process matches by
//	           AgentType + CWD (handles PID change without duplicate matching).
//	           If still not found → MarkDisappeared(key).
//
//	PHASE 5: Check idle sessions.
//	         CheckIdleSessions() iterates all sessions and marks those with
//	         no hook activity for >5 minutes as idle.
func (s *Scanner) scan() {
	// ── Phase 1: Collect known session→PID mappings ──────────────────────
	// These are sessions that have been matched to a process in previous scans.
	// Format: map[PID]SessionPIDInfo{SessionKey, PID, AgentType, CWD}
	knownPIDs := s.updater.GetKnownPIDs()

	// ── Phase 2: Discover all running processes ─────────────────────────
	procs, err := process.Processes()
	if err != nil {
		log.Printf("[scanner] get processes: %v", err)
		return
	}

	seenPIDs := make(map[int32]bool)           // Track which PIDs were found in this scan
	agentProcs := s.collectAgentProcesses(procs) // Only agent processes

	log.Printf("[scanner] found %d agent processes, tracking %d sessions", len(agentProcs), len(knownPIDs))

	// ── Phase 3: Match discovered processes to sessions ─────────────────
	for pid, info := range agentProcs {
		seenPIDs[int32(pid)] = true

		// ROUND A: Direct PID match – most common case.
		// The PID Scanner saw the same PID last time, just update metrics.
		key, isKnown := knownPIDs[pid]
		if isKnown {
			s.updater.HandlePidUpdate(key.SessionKey, info)
			continue
		}

		// ROUND B: Fallback match by AgentType + CWD.
		// The PID changed (e.g., agent restarted), but the working directory
		// and agent type should be the same. This links the new PID to the
		// existing session.
		for _, known := range knownPIDs {
			if strings.EqualFold(known.AgentType, info.MatchedType) && known.CWD == info.CWD && known.CWD != "" {
				s.updater.HandlePidUpdate(known.SessionKey, info)
				break
			}
		}
	}

	// ── Phase 4: Detect disappeared processes ───────────────────────────
	// For each known PID that wasn't found among discovered processes:
	//   - First try to re-match by AgentType + CWD (the process may have a
	//     new PID but still be running in the same directory).
	//   - If re-match fails, the process has truly terminated.
	for pid, known := range knownPIDs {
		// Already found and handled in Phase 3
		if seenPIDs[int32(pid)] {
			continue
		}

		// Second chance: try AgentType + CWD match
		found := false
		for _, agentInfo := range agentProcs {
			if strings.EqualFold(known.AgentType, agentInfo.MatchedType) && known.CWD != "" && known.CWD == agentInfo.CWD {
				s.updater.HandlePidUpdate(known.SessionKey, agentInfo)
				found = true
				break
			}
		}

		// Process truly gone – mark the session as disappeared
		if !found {
			s.updater.MarkDisappeared(known.SessionKey)
		}
	}

	// ── Phase 5: Check idle sessions ──────────────────────────────────
	// Active sessions with >5 minutes since last hook event → Idle
	s.updater.CheckIdleSessions()
}

// collectAgentProcesses filters the full process list down to AI agent processes
// and collects their metrics.
//
// For each process in the system:
//   1. Get process name (binary name).
//   2. Use matchAgentProcess() to determine if it's a known agent.
//   3. If yes, collectProcessInfo() gathers PID, CWD, CPU%, RSS memory, terminal.
//   4. Set MatchedType (which agent type was matched).
//
// Returns a map of PID → ProcessInfo for all discovered agent processes.
func (s *Scanner) collectAgentProcesses(procs []*process.Process) map[int]*ProcessInfo {
	result := make(map[int]*ProcessInfo)
	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			continue
		}

		// Check if this process belongs to a known AI agent
		agentType := matchAgentProcess(name, p)
		if agentType == "" {
			continue
		}

		// Collect detailed metrics for this agent process
		info := collectProcessInfo(p, s.detector)
		if info != nil {
			info.MatchedType = agentType
			result[int(p.Pid)] = info
		}
	}
	return result
}

// matchAgentProcess identifies whether a system process belongs to a known
// AI coding agent.
//
// Matching strategy:
//
//	1. Exact binary name match (case-insensitive):
//	   - "opencode"  → opencode
//	   - "claude"    → claude
//	   - "codex"     → codex (also matches names containing "codex")
//
//	2. Node.js process: Check command-line arguments for agent-specific patterns:
//	   - "@anthropic-ai/claude-code" → claude (Claude Code is a Node.js CLI tool)
//	   - "opencode"                  → opencode (OpenCode may run under Node)
//	   - "codex"                     → codex (Codex may run under Node)
//
// Returns empty string if the process is not a recognized agent.
func matchAgentProcess(name string, p *process.Process) string {
	nameLower := strings.ToLower(name)

	// Direct binary name matches
	if nameLower == "opencode" {
		return "opencode"
	}
	if nameLower == "claude" {
		return "claude"
	}
	if nameLower == "codex" || strings.Contains(nameLower, "codex") {
		return "codex"
	}

	// Node.js processes: inspect command-line for agent package references
	if nameLower == "node" {
		cmdline, err := p.Cmdline()
		if err != nil {
			return ""
		}
		cmdLower := strings.ToLower(cmdline)
		if strings.Contains(cmdLower, "@anthropic-ai/claude-code") {
			return "claude"
		}
		if strings.Contains(cmdLower, "opencode") {
			return "opencode"
		}
		if strings.Contains(cmdLower, "codex") {
			return "codex"
		}
	}

	return ""
}

// collectProcessInfo gathers OS-level metrics for an agent process.
//
// Collected metrics:
//   - PID:           Process ID (from gopsutil).
//   - Name:          Terminal emulator name (via TerminalDetector).
//   - CWD:           Current working directory of the process.
//   - MemoryMB:      Resident Set Size (RSS) in megabytes.
//   - CPUPercent:    CPU usage percentage (gopsutil calculates over interval).
//   - CreateTimeMs:  Process creation time in milliseconds since epoch.
//
// gopsutil's MemoryInfo() and CPUPercent() may return errors if the process
// has terminated between discovery and metric collection. These are non-fatal
// – the field is left at its zero value.
func collectProcessInfo(p *process.Process, detector *TerminalDetector) *ProcessInfo {
	cwd, err := p.Cwd()
	if err != nil {
		cwd = ""
	}

	var memoryMB, cpuPercent float64
	memInfo, err := p.MemoryInfo()
	if err == nil {
		memoryMB = float64(memInfo.RSS) / (1024 * 1024)
	}
	cpu, err := p.CPUPercent()
	if err == nil {
		cpuPercent = cpu
	}

	createTimeMs := int64(0)
	ct, err := p.CreateTime()
	if err == nil {
		createTimeMs = ct
	}

	// Walk the PPID chain to find which terminal emulator hosts this agent
	terminal := ""
	if detector != nil {
		terminal = detector.Detect(p.Pid)
	}

	return &ProcessInfo{
		PID:          p.Pid,
		Name:         terminal,
		CWD:          cwd,
		MemoryMB:     memoryMB,
		CPUPercent:   cpuPercent,
		CreateTimeMs: createTimeMs,
	}
}

// FindProcessBySession searches for a running agent process matching a specific
// session's agentType and cwdHash.
//
// Used during session recovery at startup to match recovered transcript sessions
// to currently running agent processes.
//
// Matching criteria:
//   - Binary name must match agentType (opencode/claude/codex).
//   - If cwdHash is provided, the process's CWD SHA256[:8] must match.
//     This ensures we match the same project directory, not just any agent.
//
// Returns the first matching process's metrics, or nil if no match found.
//
// Note: This is a point-in-time check, not continuous scanning. It's only
// called during recovery.Run() at daemon startup.
func FindProcessBySession(agentType, agentSessionID, cwdHash string) *ProcessInfo {
	procs, err := process.Processes()
	if err != nil {
		return nil
	}

	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			continue
		}

		detectedType := matchAgentProcess(name, p)
		if detectedType != agentType {
			continue
		}

		cwd, err := p.Cwd()
		if err != nil {
			continue
		}

		// Verify CWD hash matches the session's expected working directory
		if cwdHash != "" {
			h := sha256.Sum256([]byte(cwd))
			procCwdHash := hex.EncodeToString(h[:8])
			if procCwdHash != cwdHash {
				continue
			}
		}

		memInfo, _ := p.MemoryInfo()
		var memMB float64
		if memInfo != nil {
			memMB = float64(memInfo.RSS) / (1024 * 1024)
		}

		cpu, _ := p.CPUPercent()

		createTimeMs := int64(0)
		ct, _ := p.CreateTime()
		createTimeMs = ct

		return &ProcessInfo{
			PID:          p.Pid,
			Name:         name,
			CWD:          cwd,
			MemoryMB:     memMB,
			CPUPercent:   cpu,
			CreateTimeMs: createTimeMs,
		}
	}

	return nil
}
