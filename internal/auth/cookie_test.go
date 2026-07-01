package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSetSessionCookie_HttpOnlyAndMaxAge covers AUTH-01/11: the cookie is
// HttpOnly with a 7-day Max-Age.
func TestSetSessionCookie_HttpOnlyAndMaxAge(t *testing.T) {
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, "tok-123", false)

	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "HttpOnly") {
		t.Fatalf("Set-Cookie = %q, want HttpOnly", setCookie)
	}
	if !strings.Contains(setCookie, "session_token=tok-123") {
		t.Fatalf("Set-Cookie = %q, want session_token=tok-123", setCookie)
	}
	if !strings.Contains(setCookie, "Max-Age=604800") {
		t.Fatalf("Set-Cookie = %q, want Max-Age=604800 (7 days)", setCookie)
	}
	if !strings.Contains(setCookie, "Path=/") {
		t.Fatalf("Set-Cookie = %q, want Path=/", setCookie)
	}
}

// TestSetSessionCookie_SameSiteLax covers dev (same-origin) cookie policy.
func TestSetSessionCookie_SameSiteLax(t *testing.T) {
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, "tok", false)
	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "SameSite=Lax") {
		t.Fatalf("dev Set-Cookie = %q, want SameSite=Lax", setCookie)
	}
	if strings.Contains(setCookie, "Secure") {
		t.Fatalf("dev Set-Cookie = %q, must NOT be Secure (http)", setCookie)
	}
}

// TestSetSessionCookie_CrossOriginNoneSecure covers AUTH-12: production
// cross-origin cookie needs SameSite=None; Secure.
func TestSetSessionCookie_CrossOriginNoneSecure(t *testing.T) {
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, "tok", true)
	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "SameSite=None") {
		t.Fatalf("cross-origin Set-Cookie = %q, want SameSite=None", setCookie)
	}
	if !strings.Contains(setCookie, "Secure") {
		t.Fatalf("cross-origin Set-Cookie = %q, want Secure", setCookie)
	}
}

// TestClearSessionCookie covers AUTH-06: logout clears the cookie (Max-Age<0).
func TestClearSessionCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	ClearSessionCookie(rec)
	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "session_token=") {
		t.Fatalf("clear Set-Cookie = %q, want session_token=", setCookie)
	}
	if !strings.Contains(setCookie, "Max-Age=0") && !strings.Contains(setCookie, "Max-Age=-1") && !strings.Contains(setCookie, "Expires=") {
		t.Fatalf("clear Set-Cookie = %q, want Max-Age=0/-1 or Expires in past", setCookie)
	}
}

// TestValidateAndMaybeRenew_NoRenewalWithinThreshold: a fresh token (>1 day
// left) is NOT renewed.
func TestValidateAndMaybeRenew_NoRenewalWithinThreshold(t *testing.T) {
	s := newTestStore(t)
	tok := registerAndLogin(t, s, "alice", "pw")

	u, renewed, err := s.ValidateAndMaybeRenew(tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if u == nil || u.Username != "alice" {
		t.Fatalf("user = %v, want alice", u)
	}
	if renewed {
		t.Fatalf("fresh token was renewed, want no renewal (>1 day left)")
	}
}

// TestValidateAndMaybeRenew_RenewsWhenNearExpiry covers AUTH-10: a token
// within 1 day of expiry is extended by 7 days.
func TestValidateAndMaybeRenew_RenewsWhenNearExpiry(t *testing.T) {
	s := newTestStore(t)
	tok := registerAndLogin(t, s, "bob", "pw")

	// Force the token's expiry to 12 hours from now (within the 1-day threshold).
	db := s.db
	now := time.Now().UnixMilli()
	nearExpiry := now + 12*60*60*1000
	hashedTok := hashTokenForTest(t, tok)
	if _, err := db.Exec(`UPDATE auth_tokens SET expires_at = ? WHERE token = ?`, nearExpiry, hashedTok); err != nil {
		t.Fatalf("update expiry: %v", err)
	}

	_, renewed, err := s.ValidateAndMaybeRenew(tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !renewed {
		t.Fatalf("near-expiry token was NOT renewed, want renewal")
	}

	// Verify the expiry was extended to ~now+7days.
	var newExpiry int64
	if err := db.QueryRow(`SELECT expires_at FROM auth_tokens WHERE token = ?`, hashedTok).Scan(&newExpiry); err != nil {
		t.Fatalf("query expiry: %v", err)
	}
	if newExpiry < now+6*24*60*60*1000 {
		t.Fatalf("new expiry = %d, want >= now+6days", newExpiry)
	}
}

// TestValidateAndMaybeRenew_ExpiredRejected: an expired token is rejected.
func TestValidateAndMaybeRenew_ExpiredRejected(t *testing.T) {
	s := newTestStore(t)
	tok := registerAndLogin(t, s, "carol", "pw")
	hashedTok := hashTokenForTest(t, tok)
	pastExpiry := time.Now().Add(-1 * time.Hour).UnixMilli()
	if _, err := s.db.Exec(`UPDATE auth_tokens SET expires_at = ? WHERE token = ?`, pastExpiry, hashedTok); err != nil {
		t.Fatalf("update expiry: %v", err)
	}
	_, _, err := s.ValidateAndMaybeRenew(tok)
	if err == nil {
		t.Fatalf("expired token accepted, want error")
	}
}

// hashTokenForTest reproduces the SHA256 hashing used by the store.
func hashTokenForTest(t *testing.T, raw string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// ── WebAuth renewal integration: verify the middleware re-sends the cookie
// when the token is renewed. ──

// TestWebAuth_RenewalResendsCookie covers AUTH-10 end-to-end: when WebAuth
// renews a near-expiry token, the response includes a fresh Set-Cookie.
func TestWebAuth_RenewalResendsCookie(t *testing.T) {
	s := newTestStore(t)
	tok := registerAndLogin(t, s, "dave", "pw")
	hashedTok := hashTokenForTest(t, tok)
	// Set expiry to 12h from now (within 1-day threshold).
	nearExpiry := time.Now().Add(12 * time.Hour).UnixMilli()
	if _, err := s.db.Exec(`UPDATE auth_tokens SET expires_at = ? WHERE token = ?`, nearExpiry, hashedTok); err != nil {
		t.Fatalf("update expiry: %v", err)
	}

	h := WebAuth(s)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/hierarchy", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	setCookie := rec.Header().Get("Set-Cookie")
	if setCookie == "" {
		t.Fatalf("renewed token did not re-send Set-Cookie")
	}
	if !strings.Contains(setCookie, "session_token="+tok) {
		t.Fatalf("re-sent cookie = %q, want session_token=%s", setCookie, tok)
	}
}

// TestWebAuth_NoRenewalNoCookie: a fresh token does not trigger a Set-Cookie.
func TestWebAuth_NoRenewalNoCookie(t *testing.T) {
	s := newTestStore(t)
	tok := registerAndLogin(t, s, "eve", "pw")

	h := WebAuth(s)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/hierarchy", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if setCookie := rec.Header().Get("Set-Cookie"); setCookie != "" {
		t.Fatalf("fresh token unexpectedly re-sent Set-Cookie: %q", setCookie)
	}
}
