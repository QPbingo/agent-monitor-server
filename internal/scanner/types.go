// Package scanner implements PID scanning and terminal detection.
//
// The Scanner is a background component that periodically scans the OS process
// table to track the health and resource usage of AI agent processes.
//
// Architecture:
//
//	Scanner (background goroutine)
//	  │
//	  ├── gopsutil.Processes()  ← enumerate all OS processes
//	  │
//	  ├── matchAgentProcess()   ← filter for agent processes
//	  │     "opencode", "claude", "codex" by binary name
//	  │     or "node" with agent command-line patterns
//	  │
//	  ├── collectProcessInfo()  ← gather metrics (PID, CWD, CPU%, RSS, terminal)
//	  │
//	  ├── Two-round matching    ← link discovered processes to sessions
//	  │     ├── Round A: Direct PID match
//	  │     └── Round B: Fallback agent_type + CWD match
//	  │
//	  └── SessionUpdater interface ← push results to SessionManager
//	        ├── HandlePidUpdate()    → process alive, update metrics
//	        ├── MarkDisappeared()     → process vanished
//	        └── CheckIdleSessions()  → mark idle (5min no hook events)
//
// TerminalDetector walks the PPID chain to identify which terminal emulator
// hosts each agent process.
package scanner

// ProcessInfo holds OS-level metrics collected for an agent process.
//
// Collected by collectProcessInfo() using gopsutil system calls.
// MatchedType is set by collectAgentProcesses() after process identification.
//
// Fields:
//
//	PID          – OS process ID (unique per process, may change on restart).
//	PPID         – Parent process ID (reserved for future use).
//	Name         – Terminal emulator name from TerminalDetector (e.g. "iTerm2").
//	CWD          – Current working directory of the process.
//	MemoryMB     – Resident Set Size (RSS) in megabytes.
//	CPUPercent   – CPU usage percentage (0–100 per core).
//	CreateTimeMs – Process creation time in milliseconds since Unix epoch.
//	MatchedType  – Which agent this process belongs to: "opencode", "claude", or "codex".
type ProcessInfo struct {
	PID          int32
	PPID         int32
	Name         string
	CWD          string
	MemoryMB     float64
	CPUPercent   float64
	CreateTimeMs int64
	MatchedType  string
}

// SessionPIDInfo is the per-PID session reference returned by GetKnownPIDs().
//
// The PID Scanner uses this to match discovered OS processes to their
// corresponding session entries in SessionManager.
//
// Fields:
//
//	SessionKey – Identifies the session in SessionManager's map.
//	             Used as the key argument for HandlePidUpdate/MarkDisappeared.
//	PID         – The process ID this session was last known to have.
//	             Used for direct PID matching (Round A).
//	AgentType   – The agent type ("opencode", "claude", "codex").
//	             Used for fallback matching when PID doesn't match (Round B).
//	CWD         – Current working directory of the session.
//	             Used for fallback matching when PID doesn't match (Round B).
type SessionPIDInfo struct {
	SessionKey string
	PID        int
	AgentType  string
	CWD        string
}

// SessionUpdater is the interface that SessionManager implements to receive
// updates from the PID Scanner.
//
// This decouples the scanner from the session management layer, making both
// independently testable. The scanner only depends on this interface.
//
// Methods:
//
//	HandlePidUpdate(key, info):
//	  Called when an agent process is found alive. Updates the session's
//	  PID, CWD, CPU%, Memory, Terminal. If the session was disappeared,
//	  resurrects it to active.
//
//	MarkDisappeared(key):
//	  Called when a previously known agent process is no longer found.
//	  Marks the session as disappeared (can be resurrected if process reappears).
//
//	CheckIdleSessions():
//	  Called once per scan cycle. Marks sessions with >5 minutes since
//	  last hook event as idle.
//
//	GetKnownPIDs():
//	  Returns all known session→PID mappings. The scanner uses this to
//	  know which sessions to match against during the scan.
type SessionUpdater interface {
	HandlePidUpdate(key string, info *ProcessInfo)
	MarkDisappeared(key string)
	CheckIdleSessions()
	GetKnownPIDs() map[int]SessionPIDInfo
}
