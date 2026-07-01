package auth

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "modernc.org/sqlite"
)

// newTestStore creates an in-memory SQLite auth.Store with tables ready.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	s := NewStore(db)
	if err := s.EnsureTables(); err != nil {
		t.Fatalf("ensure tables: %v", err)
	}
	return s
}

// registerAndLogin is a helper that registers a user and returns its raw token.
func registerAndLogin(t *testing.T, s *Store, username, password string) string {
	t.Helper()
	u, err := s.Register(username, password)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	tok, err := s.CreateToken(u.ID)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	return tok
}

// TestWebAuth_CookieAllowed covers AUTH-MID-04: a valid cookie authenticates
// and injects the user into the request context.
func TestWebAuth_CookieAllowed(t *testing.T) {
	s := newTestStore(t)
	tok := registerAndLogin(t, s, "alice", "pw")

	called := false
	h := WebAuth(s)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := GetUser(r)
		if u == nil || u.Username != "alice" {
			t.Fatalf("GetUser = %v, want alice", u)
		}
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/hierarchy", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !called {
		t.Fatalf("next handler not called")
	}
}

// TestWebAuth_BearerAllowed verifies Bearer header fallback (for scripts).
func TestWebAuth_BearerAllowed(t *testing.T) {
	s := newTestStore(t)
	tok := registerAndLogin(t, s, "bob", "pw")

	h := WebAuth(s)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if GetUser(r) == nil {
			t.Fatalf("GetUser nil, want user")
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/hierarchy", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bearer status = %d, want 200", rec.Code)
	}
}

// TestWebAuth_NoCredentialsRejected covers AUTH-MID-01: no cookie, no Bearer.
func TestWebAuth_NoCredentialsRejected(t *testing.T) {
	s := newTestStore(t)
	h := WebAuth(s)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next must not be called without credentials")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/hierarchy", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestWebAuth_ForgedCookieRejected covers AUTH-08.
func TestWebAuth_ForgedCookieRejected(t *testing.T) {
	s := newTestStore(t)
	h := WebAuth(s)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next must not be called for forged cookie")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/hierarchy", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "fake"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestMachineAuth_TokenAllowed covers AUTH-MID-02 (valid daemon token).
func TestMachineAuth_TokenAllowed(t *testing.T) {
	daemonTok := "secret-daemon-token"
	called := false
	h := MachineAuth(daemonTok)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Daemon-Token", daemonTok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !called {
		t.Fatalf("next not called for valid daemon token")
	}
}

// TestMachineAuth_NoTokenRejected covers AUTH-MID-02 (missing token).
func TestMachineAuth_NoTokenRejected(t *testing.T) {
	h := MachineAuth("secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next must not be called without daemon token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestMachineAuth_ForgedTokenRejected ensures constant-time compare rejects
// wrong tokens.
func TestMachineAuth_ForgedTokenRejected(t *testing.T) {
	h := MachineAuth("secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next must not be called for forged daemon token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Daemon-Token", "wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
