package scanner

import (
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

// TerminalWhitelist defines the set of recognized terminal emulator process names.
//
// The TerminalDetector walks the parent process chain from an agent process
// upward, checking each parent's name against this whitelist. The first match
// identifies which terminal emulator the agent is running in.
//
// Supported terminals:
//
//	ghostty       – Ghostty (modern GPU-accelerated terminal)
//	iterm2        – iTerm2 (macOS terminal emulator)
//	terminal      – Terminal.app (macOS built-in)
//	warp          – Warp (modern terminal)
//	kitty         – Kitty (GPU-accelerated terminal)
//	alacritty     – Alacritty (GPU-accelerated terminal)
//	wezterm-gui   – WezTerm (GPU-accelerated terminal)
//	code          – Visual Studio Code (integrated terminal)
//	cursor        – Cursor (AI-powered editor, integrated terminal)
//	hyper         – Hyper (Electron-based terminal)
var TerminalWhitelist = map[string]bool{
	"ghostty":     true,
	"iterm2":      true,
	"terminal":    true,
	"warp":        true,
	"kitty":       true,
	"alacritty":   true,
	"wezterm-gui": true,
	"code":        true,
	"cursor":      true,
	"hyper":       true,
}

// TerminalDetector identifies which terminal emulator a process runs in.
//
// It walks the parent process chain (via PPID) starting from the agent process,
// checking each ancestor against the TerminalWhitelist. This is efficient
// because terminal emulators typically sit 1-3 hops above the agent in the
// process tree:
//
//	Terminal → Shell → Shell Script/CLI → Agent Process
//	(e.g. ghostty → zsh → node → claude/cli)
//
// The walk is limited to 10 hops to prevent infinite loops on corrupted
// process trees or PID 1 (init/launchd) ancestors.
type TerminalDetector struct{}

func NewTerminalDetector() *TerminalDetector {
	return &TerminalDetector{}
}

// Detect walks the parent process chain of agentPID to find the terminal emulator.
//
// Algorithm:
//
//	1. Start from agentPID (the AI agent process).
//	2. Get the parent process ID (PPID) of the current process.
//	3. Look up the parent process by PID.
//	4. Check if the parent's name is in TerminalWhitelist.
//	5. If yes → return the process name (terminal identified).
//	6. If no → move up to the parent's parent (set currentPID = ppid).
//	7. Repeat up to 10 times.
//	8. If no terminal found → return "Unknown".
//
// Boundary conditions:
//   - agentPID ≤ 1: returns "Unknown" (init/launchd has no meaningful ancestor).
//   - Intermediate process doesn't exist: returns "Unknown" (process tree changed).
//   - PPID ≤ 1: returns "Unknown" (reached OS root without finding terminal).
func (td *TerminalDetector) Detect(agentPID int32) string {
	if agentPID <= 1 {
		return "Unknown"
	}

	currentPID := agentPID
	for i := 0; i < 10; i++ {
		proc, err := process.NewProcess(currentPID)
		if err != nil {
			return "Unknown"
		}

		ppid, err := proc.Ppid()
		if err != nil || ppid <= 1 {
			return "Unknown"
		}

		parentProc, err := process.NewProcess(ppid)
		if err != nil {
			return "Unknown"
		}

		parentName, err := parentProc.Name()
		if err != nil {
			return "Unknown"
		}

		parentNameLower := strings.ToLower(parentName)
		if TerminalWhitelist[parentNameLower] {
			return parentName
		}

		currentPID = ppid // move one level up
	}

	return "Unknown"
}
