package registry

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Scanner detects local agent CLI capabilities.
type Scanner struct {
	store *Store
}

func NewScanner(store *Store) *Scanner {
	return &Scanner{store: store}
}

// ScanAll detects all known providers and upserts their capabilities.
// Returns the list of detected capabilities.
func (s *Scanner) ScanAll(runtimeID int64) ([]Capability, error) {
	providers := []Provider{ProviderClaude, ProviderCodex, ProviderOpenCode}
	now := time.Now().UnixMilli()
	var caps []Capability

	for _, p := range providers {
		cap := s.detectProvider(p, runtimeID, now)
		upserted, err := s.store.UpsertCapability(cap)
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", p, err)
		}
		caps = append(caps, *upserted)
	}

	return caps, nil
}

// detectProvider checks for a single provider's CLI and returns its capability.
func (s *Scanner) detectProvider(provider Provider, runtimeID int64, now int64) Capability {
	cap := Capability{
		RuntimeID:     runtimeID,
		Provider:      provider,
		Available:     false,
		AuthStatus:    AuthUnknown,
		AuthMessage:   "",
		HookInstalled: false,
		HookStatus:    "unknown",
		LastScannedAt: now,
	}

	binaryName := string(provider)
	path, err := exec.LookPath(binaryName)
	if err != nil {
		cap.BinaryPath = binaryName
		cap.Version = "not found"
		cap.Available = false
		return cap
	}

	cap.BinaryPath = path
	cap.Available = true

	// Detect version via --version
	version := s.detectVersion(path)
	cap.Version = version

	// Auth status detection (v1: unknown for all)
	cap.AuthStatus = s.detectAuthStatus(provider, path)

	// Hook status detection
	cap.HookInstalled, cap.HookStatus = s.detectHookStatus(provider)

	return cap
}

// detectVersion runs `<binary> --version` and returns the first line of output.
func (s *Scanner) detectVersion(binaryPath string) string {
	cmd := exec.Command(binaryPath, "--version")
	out, err := cmd.Output()
	if err != nil {
		// Try -v as fallback
		cmd2 := exec.Command(binaryPath, "-v")
		out2, err2 := cmd2.Output()
		if err2 != nil {
			return "unknown"
		}
		out = out2
	}
	version := strings.TrimSpace(string(out))
	// Take first line only
	if idx := strings.Index(version, "\n"); idx >= 0 {
		version = version[:idx]
	}
	return version
}

// detectAuthStatus detects authentication status for a provider.
// v1: returns unknown for all providers since auth detection is complex.
func (s *Scanner) detectAuthStatus(provider Provider, binaryPath string) AuthStatus {
	return AuthUnknown
}

// detectHookStatus checks if the agent-monitor hook is installed for a provider.
// Returns (installed, status_description).
func (s *Scanner) detectHookStatus(provider Provider) (bool, string) {
	// Check if hook setup binary can report status
	// v1: check via setup binary if available
	setupPath, err := exec.LookPath("agent-monitor-setup")
	if err != nil {
		return false, "setup binary not found"
	}

	cmd := exec.Command(setupPath, "status", "--provider", string(provider))
	out, err := cmd.Output()
	if err != nil {
		return false, "status check failed"
	}

	status := strings.TrimSpace(string(out))
	if strings.Contains(status, "installed") || strings.Contains(status, "active") {
		return true, status
	}
	return false, status
}
