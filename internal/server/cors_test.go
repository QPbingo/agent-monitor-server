package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCORS_AllowedOrigin echoes the origin and sets credentials header.
// Covers DEP-01 (CORS preflight pass) and the credentials-mode requirement
// that Allow-Origin must echo (never "*").
func TestCORS_AllowedOrigin(t *testing.T) {
	allowed := parseOrigins("http://localhost:5173,https://app.example.com")
	h := corsMiddleware(allowed, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Preflight from allowed origin
	req := httptest.NewRequest(http.MethodOptions, "/api/sessions", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Fatalf("Allow-Origin = %q, want echo http://localhost:5173", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Allow-Credentials = %q, want true", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "GET") {
		t.Fatalf("Allow-Methods = %q, want to contain GET", got)
	}
}

// TestCORS_DisallowedOrigin omits CORS headers so the browser blocks the call.
// Covers DEP-02.
func TestCORS_DisallowedOrigin(t *testing.T) {
	allowed := parseOrigins("http://localhost:5173")
	h := corsMiddleware(allowed, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/sessions", nil)
	req.Header.Set("Origin", "http://evil.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("disallowed origin must NOT get Allow-Origin header, got %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

// TestCORS_OptionsAlways204 ensures preflight returns 204 even for disallowed
// origins (browser then blocks the actual request; the server does not leak
// whether the origin is allowed via a non-204).
func TestCORS_OptionsAlways204(t *testing.T) {
	allowed := parseOrigins("http://localhost:5173")
	h := corsMiddleware(allowed, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/sessions", nil)
	req.Header.Set("Origin", "http://evil.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("disallowed preflight status = %d, want 204", rec.Code)
	}
}

// TestCORS_NoOriginSameOrigin passes through without CORS headers (same-origin
// requests are not subject to CORS).
func TestCORS_NoOriginSameOrigin(t *testing.T) {
	allowed := parseOrigins("http://localhost:5173")
	h := corsMiddleware(allowed, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("same-origin status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("same-origin must not set CORS headers")
	}
}

// TestParseOrigins verifies comma-separated parsing with whitespace trimming.
// Covers DEP-07 (--cors-origins parsing).
func TestParseOrigins(t *testing.T) {
	got := parseOrigins(" https://a.com , http://b.com , ")
	if !got["https://a.com"] || !got["http://b.com"] {
		t.Fatalf("parsed set = %v, want both origins", got)
	}
	if len(got) != 2 {
		t.Fatalf("set size = %d, want 2", len(got))
	}
	if len(parseOrigins("")) != 0 {
		t.Fatalf("empty input should yield empty set")
	}
}
