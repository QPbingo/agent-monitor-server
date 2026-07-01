package server

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/heybox/agent-monitor-server/internal/auth"
	"github.com/heybox/agent-monitor-server/internal/hierarchy"
	"github.com/heybox/agent-monitor-server/internal/session"
	_ "modernc.org/sqlite"
)

// newTestServer builds a real Server with in-memory SQLite + a registered user,
// returning the server and that user's token (for cookie-authed requests).
func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	dbPath := t.TempDir() + "/test.db"
	store, err := session.NewStore(dbPath)
	if err != nil {
		t.Fatalf("session store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	db, err := store.DB()
	if err != nil {
		t.Fatalf("get db: %v", err)
	}

	mgr := session.NewSessionManager(store, "local", "device-1")
	mgr.LoadFromStore()

	authStore := auth.NewStore(db)
	if err := authStore.EnsureTables(); err != nil {
		t.Fatalf("auth tables: %v", err)
	}
	hierStore := hierarchy.NewStore(db)
	if err := hierStore.EnsureTables(); err != nil {
		t.Fatalf("hier tables: %v", err)
	}
	if _, _, err := hierStore.EnsureInspiration(); err != nil {
		t.Fatalf("ensure inspiration: %v", err)
	}
	mgr.SetHierarchyStore(hierStore)

	u, err := authStore.Register("tester", "pw")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	tok, err := authStore.CreateToken(u.ID)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	srv := New("127.0.0.1:0", mgr, "daemon-tok", authStore, hierStore, nil, "http://localhost:5173")
	srv.Start()
	t.Cleanup(srv.Shutdown)
	return srv, tok
}

// TestGETRootReturns404 covers DEP-04: the dashboard static route is removed.
func TestGETRootReturns404(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	srv.httpSrv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET / status = %d, want 404", rec.Code)
	}
}

// TestSSE_InitialPush covers SSE-01: an authed SSE connection receives
// snapshot + hierarchy_snapshot (executions omitted because agentMgr is nil).
func TestSSE_InitialPush(t *testing.T) {
	srv, tok := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/events/stream", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: tok})
	rec := httptest.NewRecorder()
	// Run the SSE handler in a goroutine and give it time to send initial events.
	done := make(chan struct{})
	go func() {
		srv.httpSrv.Handler.ServeHTTP(rec, req)
		close(done)
	}()
	// The handler blocks until the request context is cancelled. We can't easily
	// read the streaming recorder incrementally, so cancel after a short wait to
	// capture whatever was flushed, then inspect the body.
	time.Sleep(100 * time.Millisecond)
	// There's no way to cancel an httptest.ResponseRecorder request; use a real
	// server instead.
	_ = done
	t.Skip("httptest.ResponseRecorder does not stream; see TestSSE_RealServer")
}

// TestSSE_RealServer verifies SSE initial push (SSE-01) and that the SSE stream
// is valid text/event-stream with snapshot + hierarchy_snapshot events.
func TestSSE_RealServer(t *testing.T) {
	srv, tok := newTestServer(t)

	// Use the real http.Server via httptest.NewServer to get streaming behavior.
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/events/stream", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: tok})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("connect SSE: %v", err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", resp.Header.Get("Content-Type"))
	}

	// Read a few SSE events. We expect at least snapshot + hierarchy_snapshot.
	br := bufio.NewReader(resp.Body)
	gotSnapshot, gotHierarchy := false, false
	deadline := time.After(1 * time.Second)
	for !gotSnapshot || !gotHierarchy {
		select {
		case <-deadline:
			t.Fatalf("timed out: snapshot=%v hierarchy=%v", gotSnapshot, gotHierarchy)
		default:
		}
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read SSE: %v", err)
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data: ") {
			payload := line[len("data: "):]
			if strings.Contains(payload, `"type":"snapshot"`) {
				gotSnapshot = true
			}
			if strings.Contains(payload, `"type":"hierarchy_snapshot"`) {
				gotHierarchy = true
			}
		}
	}
}

// TestSSE_CORSHeadersOnStream covers DEP-06: SSE cross-origin with credentials.
func TestSSE_CORSHeadersOnStream(t *testing.T) {
	srv, tok := newTestServer(t)
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodOptions, ts.URL+"/api/events/stream", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: tok})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Fatalf("Allow-Origin = %q, want echo", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Allow-Credentials = %q, want true", got)
	}
}

// TestWebGroupRequiresAuth covers AUTH-MID-01: a web-group route without
// credentials returns 401.
func TestWebGroupRequiresAuth(t *testing.T) {
	srv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/api/hierarchy")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-cred /api/hierarchy status = %d, want 401", resp.StatusCode)
	}
}

// TestMachineGroupRequiresDaemonToken covers AUTH-MID-02: /health without
// X-Daemon-Token returns 401.
func TestMachineGroupRequiresDaemonToken(t *testing.T) {
	srv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-token /health status = %d, want 401", resp.StatusCode)
	}
}

// TestMachineGroupWithDaemonToken verifies /health succeeds with the token.
func TestMachineGroupWithDaemonToken(t *testing.T) {
	srv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/health", nil)
	req.Header.Set("X-Daemon-Token", "daemon-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/health with token status = %d, want 200", resp.StatusCode)
	}
}

// TestPublicGroupNoAuth covers AUTH-MID-03: register is reachable without
// any credentials (returns 400 for missing fields, NOT 401 — proving the
// middleware did not block it).
func TestPublicGroupNoAuth(t *testing.T) {
	srv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/api/auth/register", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	// 400 (bad request, missing fields) proves the request reached the handler,
	// i.e. was NOT blocked by auth middleware (which would return 401).
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("register returned 401 — public group is not actually public")
	}
}

// TestWebGroupCookieAllowed verifies a cookie-authed request reaches the
// handler (end-to-end through the full mux + CORS + WebAuth stack).
func TestWebGroupCookieAllowed(t *testing.T) {
	srv, tok := newTestServer(t)
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/hierarchy", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: tok})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cookie /api/hierarchy status = %d, want 200", resp.StatusCode)
	}
}

// TestLoginSetsCookie covers AUTH-01/04: login response includes a Set-Cookie
// with HttpOnly + 7-day Max-Age.
func TestLoginSetsCookie(t *testing.T) {
	srv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)

	// Register first (so login has a user). Register also sets a cookie, but
	// we test login specifically.
	resp, err := http.Post(ts.URL+"/api/auth/register", "application/json", strings.NewReader(`{"username":"alice","password":"pw"}`))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	resp.Body.Close()

	resp, err = http.Post(ts.URL+"/api/auth/login", "application/json", strings.NewReader(`{"username":"alice","password":"pw"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}
	setCookies := resp.Cookies()
	if len(setCookies) == 0 {
		t.Fatalf("login response has no Set-Cookie")
	}
	var sc *http.Cookie
	for _, c := range setCookies {
		if c.Name == auth.SessionCookieName {
			sc = c
		}
	}
	if sc == nil {
		t.Fatalf("login Set-Cookie has no session_token")
	}
	if !sc.HttpOnly {
		t.Fatalf("session cookie not HttpOnly")
	}
	if sc.MaxAge != auth.CookieMaxAge {
		t.Fatalf("cookie MaxAge = %d, want %d", sc.MaxAge, auth.CookieMaxAge)
	}
}

// TestLoginCookieAuthenticates covers AUTH-09: the cookie from login can
// authenticate a subsequent web-group request.
func TestLoginCookieAuthenticates(t *testing.T) {
	srv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/api/auth/register", "application/json", strings.NewReader(`{"username":"bob","password":"pw"}`))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	var sc *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookieName {
			sc = c
		}
	}
	resp.Body.Close()
	if sc == nil {
		t.Fatalf("register did not set session cookie")
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/hierarchy", nil)
	req.AddCookie(sc)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cookie-authed /api/hierarchy status = %d, want 200", resp.StatusCode)
	}
}

// TestMeEndpoint covers the /api/auth/me endpoint: returns the authenticated
// user's username (used by the SPA to restore the display name on reload).
func TestMeEndpoint(t *testing.T) {
	srv, tok := newTestServer(t)
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)

	// Without cookie → 401.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/auth/me", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-cred /api/auth/me status = %d, want 401", resp.StatusCode)
	}

	// With valid cookie → 200 + username "tester" (registered in newTestServer).
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: tok})
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/auth/me status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"username":"tester"`) {
		t.Fatalf("/api/auth/me body = %s, want username tester", string(body))
	}
}

// TestLogoutClearsCookie covers AUTH-06: logout clears the cookie and revokes
// the token (subsequent use of the old cookie → 401).
func TestLogoutClearsCookie(t *testing.T) {
	srv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/api/auth/register", "application/json", strings.NewReader(`{"username":"carol","password":"pw"}`))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	var sc *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookieName {
			sc = c
		}
	}
	resp.Body.Close()

	// Logout with the cookie.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/logout", nil)
	req.AddCookie(sc)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status = %d, want 204", resp.StatusCode)
	}
	// Response should clear the cookie.
	cleared := false
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("logout did not clear session cookie")
	}

	// Old cookie should now be rejected (token revoked).
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/hierarchy", nil)
	req.AddCookie(sc)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get after logout: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-logout /api/hierarchy status = %d, want 401 (token revoked)", resp.StatusCode)
	}
}
