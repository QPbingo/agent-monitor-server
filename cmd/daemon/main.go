// Package main is the entry point for agent-monitor-daemon.
//
// The daemon is a long-running process that performs three primary functions:
//  1. Ingests real-time hook events from AI coding agents (opencode, claude, codex)
//     via a shared events.jsonl file, using fsnotify for file watching.
//  2. Periodically scans the OS process table to track agent process health,
//     resource usage (CPU/Memory), and detect process death.
//  3. Serves an HTTP API and SSE endpoint for a browser-based dashboard
//     that displays live session data.
//
// Startup sequence (each step depends on the previous):
//
//	Step 1: Create ~/.agent-monitor/ working directory (0700 for security).
//	Step 2: Read or generate a persistent device UUID → device-id file.
//	Step 3: Read or generate a 256-bit random auth token → local-token file.
//	Step 4: Open SQLite database (WAL mode, single writer) at daemon.db,
//	        create daemon_sessions table, run light migrations.
//	Step 5: Initialize SessionManager, load all persistent sessions from SQLite
//	        into the in-memory session map.
//	Step 6: Run session recovery – scan agent transcript JSONL files (last 24h)
//	        to find sessions that were active while the daemon was offline.
//	        For recovered sessions, try to match them to running OS processes
//	        via agent_type + cwd_hash.
//	Step 7: Start EventWatcher – monitors events.jsonl with fsnotify,
//	        restores consumption offset from events.offset, processes any
//	        unread lines, then enters a background event loop.
//	Step 8: Start PID Scanner – a background goroutine that scans system
//	        processes every N seconds (default 15), matches agent processes
//	        to known sessions, updates CPU/Memory metrics, detects death.
//	Step 9: Start HTTP/SSE server – registers REST API routes in grouped
//	        middleware (public/machine/web), starts the SSE Hub goroutine,
//	        starts the HTTP listener. Wires SessionManager notifications to
//	        SSE broadcasts. CORS allows the separately-deployed frontend.
//	Step 10: Block on SIGINT/SIGTERM, then gracefully shutdown.
//
// Graceful shutdown:
//   - Receives signal → calls srv.Shutdown() with 5s timeout.
//   - HTTP server stops accepting new connections, drains existing ones.
//   - defers execute in LIFO order:
//     pidScanner.Stop() → closes stopCh, scanner goroutine exits.
//     ew.Stop() → closes done channel, fsnotify watcher closes.
//     store.Close() → SQLite connection closes.
//   - events.offset is persisted on every processed line, so no data loss.
//
// Data flow during runtime:
//
//	Agent Actions
//	     │
//	     ├──▶ agent-monitor-hook writes to events.jsonl
//	     │         │
//	     │         ▼
//	     │    EventWatcher (fsnotify) → parse JSON → validate token
//	     │         │
//	     │         ▼
//	     │    SessionManager.HandleEvent() → update session state
//	     │         │
//	     │         ├──▶ SQLite upsert
//	     │         │
//	     │         ▼
//	     │    computeDelta() → SetNotify callback
//	     │         │
//	     │         ▼
//	     │    SSE Hub → broadcast to all connected dashboards
//	     │
//	     └──▶ OS process runs, consumes resources
//	               │
//	               ▼
//	          PID Scanner (gopsutil, every 15s)
//	               │
//	               ├──▶ SessionManager.HandlePidUpdate()  (process alive)
//	               ├──▶ SessionManager.MarkDisappeared()   (process dead)
//	               └──▶ SessionManager.CheckIdleSessions() (idle timeout)
//	                        │
//	                        ▼
//	                   SetNotify → SSE broadcast
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/heybox/agent-monitor-server/internal/auth"
	"github.com/heybox/agent-monitor-server/internal/hierarchy"
	"github.com/heybox/agent-monitor-server/internal/hook"
	"github.com/heybox/agent-monitor-server/internal/registry"
	"github.com/heybox/agent-monitor-server/internal/scanner"
	"github.com/heybox/agent-monitor-server/internal/server"
	"github.com/heybox/agent-monitor-server/internal/session"
	"github.com/heybox/agent-monitor-server/internal/token"
	"github.com/heybox/agent-monitor-hook/sdk"
)

func main() {
	// ── Parse command-line flags ──────────────────────────────────────────
	// --listen:       HTTP/WebSocket listen address, default 127.0.0.1:9101
	// --scan-interval: PID scan interval in seconds, default 15
	// --user-id:      User identifier, default "local"
	listen := flag.String("listen", "127.0.0.1:9101", "HTTP listen address")
	scanInterval := flag.Int("scan-interval", 15, "PID scan interval in seconds")
	userID := flag.String("user-id", "local", "User identifier")
	corsOrigins := flag.String("cors-origins", "http://localhost:5173", "Comma-separated allowed CORS origins (frontend origin(s))")
	flag.Parse()

	// ── Step 1: Prepare the working directory ─────────────────────────────
	// All daemon state lives under ~/.agent-monitor/
	//   - device-id:    persistent UUID v4 device identifier
	//   - local-token:  256-bit base64 auth token for daemon↔hook communication
	//   - events.jsonl: hook event buffer (line-delimited JSON)
	//   - events.offset:last consumed byte position in events.jsonl
	//   - daemon.db:    SQLite database for session persistence
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("get home dir: %v", err)
	}

	monitorDir := filepath.Join(homeDir, ".agent-monitor")

	// MkdirAll with 0700 ensures only the current user can read daemon state,
	// protecting the auth token from other users on the system.
	if err := os.MkdirAll(monitorDir, 0700); err != nil {
		log.Fatalf("create monitor dir: %v", err)
	}

	// ── Step 2: Device identification ──────────────────────────────────────
	// Generates a UUID v4 on first run, persists it to device-id file.
	// This ID ties sessions to a specific machine for multi-device scenarios.
	deviceID := readOrCreateDeviceID(monitorDir)
	log.Printf("device-id: %s", deviceID)

	// ── Step 3: Daemon authentication token ─────────────────────────────────
	// Generates a 256-bit random token on first run, persists to local-token.
	// This token authenticates:
	//   - hook binary → daemon (included in every hook event's daemon_token field)
	//   - machine API → daemon (X-Daemon-Token header for /health, /api/poll-input, ...)
	// Uses constant-time comparison to prevent timing attacks.
	tok := readOrCreateToken(monitorDir)
	log.Printf("daemon token: %s", tok[:8]+"...")

	// ── Step 4: SQLite storage initialization ─────────────────────────────
	// Uses modernc.org/sqlite (pure Go, no CGO required).
	// WAL mode for concurrent reads, busy_timeout=5000ms for write contention.
	// single writer (SetMaxOpenConns(1)) to avoid SQLITE_BUSY.
	// Creates daemon_sessions table on first run, runs ADD COLUMN migrations.
	dbPath := filepath.Join(monitorDir, "daemon.db")
	store, err := session.NewStore(dbPath)
	if err != nil {
		log.Fatalf("init sqlite: %v", err)
	}
	defer store.Close() // guaranteed to run on shutdown

	// ── Step 5: Session manager initialization ────────────────────────────
	// Creates the in-memory session map (map[SessionKey]*Session).
	// LoadFromStore() restores all sessions from SQLite into memory,
	// so sessions survive daemon restarts.
	// SessionKey = hex(SHA256(userID|deviceID|agentType|agentSessionID))[:16]
	mgr := session.NewSessionManager(store, *userID, deviceID)
	mgr.LoadFromStore()

	// ── Step 5.5: Auth + hierarchy initialization ──────────────────────────
	var authStore *auth.Store
	var hierStore *hierarchy.Store
	if sdb, err := store.DB(); err == nil {
		authStore = auth.NewStore(sdb)
		if err := authStore.EnsureTables(); err != nil {
			log.Printf("[auth] create tables: %v", err)
		}

		hierStore = hierarchy.NewStore(sdb)
		if err := hierStore.EnsureTables(); err != nil {
			log.Printf("[hierarchy] create tables: %v", err)
		}
		if err := hierStore.RunMigrations(); err != nil {
			log.Printf("[hierarchy] run migrations: %v", err)
		}

		// Ensure inspiration workspace exists
		if _, _, err := hierStore.EnsureInspiration(); err != nil {
			log.Printf("[hierarchy] ensure inspiration: %v", err)
		} else {
			mgr.SetHierarchyStore(hierStore)
		}
	}

	// ── Step 5.6: Registry initialization ──────────────────────────────
	var regStore *registry.Store
	if sdb, err := store.DB(); err == nil {
		regStore = registry.NewStore(sdb)
		if err := regStore.EnsureTables(); err != nil {
			log.Printf("[registry] create tables: %v", err)
		}
	}

	// ── Step 6: Session recovery from agent transcripts ────────────────────
	// When the daemon starts, it may have missed sessions that were active
	// while the daemon was offline. Recovery scans agent transcript JSONL files
	// from the last 24 hours to find and restore these sessions.
	//
	// Sources:
	//   - OpenCode:   ~/.config/opencode/sessions/*.jsonl
	//   - Claude Code: ~/.claude/projects/*/*.jsonl
	//   - Codex:      ~/.codex/sessions/**/rollout-*.jsonl
	//
	// Recovered sessions start with Status=unknown.
	// FindProcessBySession() attempts to match each recovered session to a
	// running OS process by agent_type + cwd_hash. If matched, the session
	// is bound to the PID and promoted to Status=active.
	recovery := session.NewRecovery(*userID, deviceID, mgr)
	recovery.Run()

	// ── Step 7: Event watcher startup ─────────────────────────────────────
	// EventWatcher monitors events.jsonl using fsnotify (inotify/FSEvents).
	// On startup:
	//   1. Reads events.offset to determine last consumed position.
	//   2. If no offset file, defaults to end of file (skip existing data).
	//   3. Processes any unread lines between lastPos and EOF.
	//   4. Launches a background goroutine (ew.loop()) that watches for:
	//      - fsnotify.Write: new data appended → handleNewLines()
	//      - fsnotify.Create: file recreated → reset offset to 0, re-read
	//
	// Each line is a JSON object with fields:
	//   event, agent_type, session_id, daemon_token, pid, cwd, timestamp_ms, payload
	//
	// Processing per-line:
	//   1. Parse JSON → HookEvent struct
	//   2. Validate daemon_token via constant-time comparison
	//   3. Forward to SessionManager.HandleEvent()
	//   4. Persist byte offset to events.offset (prevents data loss on crash)
	//   5. Incomplete lines (no trailing \n) are left for next restart
	ew, err := hook.NewEventWatcher(monitorDir, tok, mgr)
	if err != nil {
		log.Fatalf("init event watcher: %v", err)
	}
	if err := ew.Start(); err != nil {
		log.Fatalf("start event watcher: %v", err)
	}
	defer ew.Stop() // closes done channel + fsnotify watcher

	// ── Step 8: PID scanner startup ───────────────────────────────────────
	// The PID scanner is a background goroutine that runs every scanInterval
	// seconds (default 15). Each cycle:
	//
	//   1. GetKnownPIDs() – collect all session→PID mappings from SessionManager.
	//   2. gopsutil.Processes() – enumerate all OS processes.
	//   3. matchAgentProcess() – filter for agent processes by binary name
	//      (opencode/claude/codex) or node command-line patterns.
	//   4. collectProcessInfo() – gather PID, CWD, CPU%, RSS memory,
	//      terminal emulator name (via PPID chain walk).
	//   5. Two-round matching:
	//      a. Direct PID match → HandlePidUpdate(key, info)
	//      b. Fallback agent_type + CWD match → HandlePidUpdate(key, info)
	//   6. Detect disappeared processes → MarkDisappeared(key)
	//   7. CheckIdleSessions() → mark sessions idle if 5min without hook events
	//
	// The scanner and EventWatcher operate independently on the same
	// SessionManager, protected by a sync.RWMutex.
	scanIntervalDur := time.Duration(*scanInterval) * time.Second
	pidScanner := scanner.NewScanner(mgr, scanIntervalDur)
	pidScanner.Start()
	defer pidScanner.Stop() // closes stopCh, scanner goroutine exits

	// ── Step 9: HTTP/SSE server startup ────────────────────────────────────
	// Creates the HTTP server with routes registered in three auth groups:
	//
	//   public  → POST /api/auth/{register,login}     (no auth)
	//   machine → /health, /api/poll-input, ...        (X-Daemon-Token)
	//   web     → /api/* + /api/events/stream          (cookie/Bearer)
	//
	// The frontend is deployed separately; CORS (--cors-origins) permits the
	// configured frontend origin(s) to call the API cross-origin with
	// credentials (HttpOnly cookies). SSE (GET /api/events/stream) replaces
	// the former WebSocket transport for real-time session/agent updates.
	//
	// On connect, SSE clients receive:
	//   1. Full snapshot of all sessions
	//   2. Hierarchy snapshot
	//   3. Execution history
	//   4. Real-time delta/session_added/hierarchy_updated/agent_* events
	// Initialize agent SDK manager
	agentMgr := sdk.NewAgentManager()
	agentMgr.Register(sdk.AgentClaude, sdk.NewClaudeSDK(sdk.ClaudeOptions{}))
	agentMgr.Register(sdk.AgentOpenCode, sdk.NewOpenCodeSDK(sdk.OpenCodeOptions{}))
	agentMgr.Register(sdk.AgentCodex, sdk.NewCodexSDK(sdk.CodexOptions{}))
	defer agentMgr.CloseAll()

	srv := server.New(*listen, mgr, tok, authStore, hierStore, agentMgr, regStore, *corsOrigins)

	// Wire SessionManager notifications to SSE broadcasts.
	// Whenever a session is created or modified, SetNotify calls back
	// with the event type ("delta" or "session_added") and the changed data.
	// The SSE hub serializes this and broadcasts to all connected dashboards.
	mgr.SetNotify(func(eventType string, data interface{}) {
		srv.GetSSEHub().Notify(eventType, data)
	})
	mgr.SetHierarchyNotify(func(eventType string, data interface{}) {
		srv.GetSSEHub().Notify(eventType, data)
	})

	// Start the HTTP server in a background goroutine.
	// Internally this starts:
	//   - go hub.Run()        → WebSocket Hub event loop
	//   - go ListenAndServe() → HTTP listener
	if err := srv.Start(); err != nil {
		log.Fatalf("start server: %v", err)
	}

	log.Printf("agent-monitor-daemon started on %s", *listen)
	log.Printf("API: http://%s  (frontend deployed separately)", *listen)

	fmt.Println("[daemon] ready")

	// ── Step 10: Wait for shutdown signal ─────────────────────────────────
	// Blocks the main goroutine until SIGINT (Ctrl+C) or SIGTERM is received.
	// After signal, calls srv.Shutdown() with 5s timeout for graceful HTTP drain,
	// then defers execute to clean up scanner, watcher, and database.
	server.WaitForSignal()

	log.Println("shutting down...")
	srv.Shutdown()
}

// readOrCreateDeviceID returns an existing device ID or generates a new UUID v4.
//
// UUID v4 format: XXXXXXXX-XXXX-4XXX-8XXX-XXXXXXXXXXXX
// Uses crypto/rand for randomness, sets version bits (byte 6) and variant bits (byte 8).
// Persisted to $MONITOR_DIR/device-id with 0600 permissions.
func readOrCreateDeviceID(dir string) string {
	path := filepath.Join(dir, "device-id")
	data, err := os.ReadFile(path)
	if err == nil && len(data) > 0 {
		return string(data)
	}

	// Generate UUID v4
	u := make([]byte, 16)
	rand.Read(u)
	u[6] = (u[6] & 0x0f) | 0x40 // set UUID version to 4
	u[8] = (u[8] & 0x3f) | 0x80 // set UUID variant to 10xx
	id := fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(u[0:4]),
		hex.EncodeToString(u[4:6]),
		hex.EncodeToString(u[6:8]),
		hex.EncodeToString(u[8:10]),
		hex.EncodeToString(u[10:16]),
	)
	os.WriteFile(path, []byte(id), 0600)
	return id
}

// readOrCreateToken returns an existing daemon token or generates a new one.
//
// The token is a 256-bit random value, base64-encoded for storage.
// It authenticates communication between the hook binary, the daemon API,
// and the WebSocket dashboard.
// Uses token.Generate() (crypto/rand) for generation and token.Read/Write
// for persistence to $MONITOR_DIR/local-token (0600).
func readOrCreateToken(dir string) string {
	tok, err := token.Read(dir)
	if err == nil && tok != "" {
		return tok
	}

	tok, err = token.Generate()
	if err != nil {
		log.Fatalf("generate token: %v", err)
	}
	if err := token.Write(dir, tok); err != nil {
		log.Fatalf("write token: %v", err)
	}
	return tok
}
