// Package server provides the HTTP and SSE API for the agent-monitor daemon.
//
// The server exposes:
//
//	GET /api/events/stream – SSE stream of session/hierarchy/agent events (auth: cookie/Bearer)
//	GET /health            – Health check with version + session count (auth: X-Daemon-Token)
//	GET /api/sessions      – List all sessions as JSON (auth: cookie/Bearer)
//	GET /api/sessions/{key} – Get a single session by SessionKey (auth: cookie/Bearer)
//	... plus hierarchy / permissions / agent control routes (auth: cookie/Bearer)
//
// Authentication is enforced at the route-group level (see Handlers.Register):
//   - public group:  POST /api/auth/{register,login}   — no auth
//   - machine group: /health, /api/poll-input, ...     — X-Daemon-Token (MachineAuth)
//   - web group:     all other /api/* + events/stream   — cookie/Bearer (WebAuth)
//
// The frontend is deployed separately; CORS is applied so the browser can call
// the API cross-origin. Because HttpOnly cookies authenticate requests, CORS
// uses Access-Control-Allow-Credentials: true and echoes the specific origin
// (never "*").
//
// SSE (Server-Sent Events) replaces the former WebSocket transport. The SSEHub
// broadcasts session deltas, hierarchy updates, and agent execution events to
// all connected dashboards. Each client's writes are mutex-guarded so the
// initial snapshot and subsequent deltas never interleave on the byte stream.
//
// Architecture:
//
//	HTTP Server (goroutine, CORS-wrapped mux)
//	  ├── Public routes      → Handlers (no auth)
//	  ├── Machine routes     → MachineAuth → Handlers
//	  └── Web routes + SSE   → WebAuth → Handlers / SSEHub.HandleStream
//
//	SSEHub (goroutine)
//	  └── register/unregister/broadcast event loop
//	        └── per-client send channel → writePump (mutex-guarded flush)
package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/heybox/agent-monitor-server/internal/auth"
	"github.com/heybox/agent-monitor-server/internal/hierarchy"
	"github.com/heybox/agent-monitor-server/internal/session"
	"github.com/heybox/agent-monitor-hook/sdk"
)

// Server wraps the HTTP server and SSE Hub.
//
// Lifecycle:
//  1. New()     – creates the server, SSE hub, and route handlers.
//  2. Start()   – launches hub and HTTP listener goroutines.
//  3. Shutdown() – gracefully stops the HTTP server with a 5s timeout.
type Server struct {
	addr    string
	httpSrv *http.Server
	sseHub  *SSEHub
}

// New creates a new server with all routes registered.
//
// Parameters:
//   - addr:          HTTP listen address (e.g. "127.0.0.1:9101").
//   - sessions:      SessionManager instance (shared with EventWatcher and PID Scanner).
//   - daemonToken:   Machine auth token for /health, /api/poll-input, etc.
//   - authStore:     User/token store for web (cookie/Bearer) auth.
//   - hierStore:     Hierarchy store.
//   - agentMgr:      Agent SDK manager.
//   - corsOrigins:   Comma-separated list of allowed CORS origins.
//
// Routes are registered immediately. The server doesn't start listening until
// Start() is called. The mux is wrapped in a CORS middleware so cross-origin
// frontend requests (with credentials) are permitted.
func New(addr string, sessions *session.SessionManager, daemonToken string, authStore *auth.Store, hierStore *hierarchy.Store, agentMgr *sdk.AgentManager, corsOrigins string) *Server {
	// Create the SSE Hub (manages all connected dashboard clients)
	sseHub := NewSSEHub(sessions, hierStore, authStore, agentMgr)

	// Create HTTP route handlers
	handlers := NewHandlers(sessions, daemonToken, sseHub, authStore, hierStore, agentMgr)

	// Register all routes on the ServeMux
	mux := http.NewServeMux()
	handlers.Register(mux)

	// Wrap with CORS middleware (credentials mode → echo specific origins).
	allowed := parseOrigins(corsOrigins)
	handler := corsMiddleware(allowed, mux)

	return &Server{
		addr: addr,
		httpSrv: &http.Server{
			Addr:    addr,
			Handler: handler,
		},
		sseHub: sseHub,
	}
}

// Start launches the server's background goroutines.
//
// Starts two goroutines:
//  1. go sseHub.Run() – SSE Hub event loop (register/unregister/broadcast).
//  2. go ListenAndServe() – HTTP listener that blocks until shutdown.
//
// Returns nil immediately – the goroutines run in the background.
func (s *Server) Start() error {
	go s.sseHub.Run()
	go func() {
		log.Printf("[server] listening on %s", s.addr)
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[server] listen: %v", err)
		}
	}()
	return nil
}

// GetSSEHub returns the SSE Hub for wiring SessionManager notifications.
//
// Used in main.go to bridge SessionManager to SSE broadcasts:
//
//	mgr.SetNotify(func(eventType string, data interface{}) {
//	    srv.GetSSEHub().Notify(eventType, data)
//	})
func (s *Server) GetSSEHub() *SSEHub {
	return s.sseHub
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.httpSrv.Shutdown(ctx); err != nil {
		log.Printf("[server] shutdown: %v", err)
	}
}

// WaitForSignal blocks the calling goroutine until SIGINT or SIGTERM is received.
func WaitForSignal() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	fmt.Fprintf(os.Stderr, "\nReceived signal: %v, shutting down...\n", sig)
}
