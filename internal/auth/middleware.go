package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/heybox/agent-monitor-server/internal/token"
)

type contextKey string

const (
	UserContextKey contextKey = "user"
	// SessionCookieName is the HttpOnly cookie carrying the web user's token.
	SessionCookieName = "session_token"
)

// WebAuth authenticates web-frontend requests. It accepts, in order:
//  1. An HttpOnly cookie named "session_token" (primary — used by EventSource,
//     which cannot set custom headers).
//  2. An "Authorization: Bearer <token>" header (secondary — for scripts and
//     transitional clients).
//
// On success the authenticated *User is injected into the request context
// (retrievable via GetUser). On failure it responds 401 and does not call next.
//
// This is the single auth gate for the "web" route group: every web-facing
// API is protected by it, eliminating the previous per-route manual wrapping
// that allowed endpoints (e.g. the old GET / dashboard) to slip through
// unauthenticated.
//
// Token auto-renewal: when the server-side token expires within 1 day,
// WebAuth extends it by 7 days and re-sends the Set-Cookie header so the
// client cookie stays in sync. This means an active user never sees a
// mid-session logout (constraint from the T002 design: cookie Max-Age=7d
// with auto-renewal).
func WebAuth(store *Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawTok := webAuthRawToken(store, r)
			if rawTok == "" {
				writeUnauthorized(w)
				return
			}
			u, renewed, err := store.ValidateAndMaybeRenew(rawTok)
			if err != nil {
				writeUnauthorized(w)
				return
			}
			if renewed {
				// Re-send the cookie with the refreshed token so client and
				// server expiries stay aligned.
				SetSessionCookie(w, rawTok, false)
			}
			ctx := context.WithValue(r.Context(), UserContextKey, u)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// webAuthRawToken returns the raw token from cookie or Bearer header, or "".
// It does NOT validate the token (that's the caller's job).
func webAuthRawToken(store *Store, r *http.Request) string {
	if store == nil {
		return ""
	}
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	if ah := r.Header.Get("Authorization"); strings.HasPrefix(ah, "Bearer ") {
		return strings.TrimPrefix(ah, "Bearer ")
	}
	return ""
}

// MachineAuth authenticates machine-to-machine callers (hooks, agent plugins)
// via the X-Daemon-Token header, using constant-time comparison. It does NOT
// inject a user context — these callers operate outside the user/permission
// model. This is the auth gate for the "machine" route group (health,
// poll-input, pending-input).
func MachineAuth(daemonToken string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if daemonToken != "" {
				if t := r.Header.Get("X-Daemon-Token"); t != "" && token.ConstantTimeCompare(t, daemonToken) {
					next.ServeHTTP(w, r)
					return
				}
			}
			writeUnauthorized(w)
		})
	}
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error":"unauthorized"}`))
}

// CookieMaxAge is the session cookie lifetime in seconds (7 days), kept in sync
// with the server-side tokenTTLms so cookie and token expire together.
const CookieMaxAge = 7 * 24 * 60 * 60

// SetSessionCookie sets the HttpOnly session cookie on the response.
//
// Cookie attributes:
//   - HttpOnly:   not readable from JS (XSS protection)
//   - Max-Age=7d: persistent across browser restarts (matches server token TTL)
//   - Path=/:     sent to all API routes
//   - SameSite:   Lax for same-origin dev, None for cross-origin production
//   - Secure:     only set for cross-origin (HTTPS) production
//
// crossOrigin selects the production cookie policy (SameSite=None; Secure).
// For local dev (Vite proxy, same-origin), pass false → SameSite=Lax; no Secure
// (so it works over plain http://localhost).
func SetSessionCookie(w http.ResponseWriter, token string, crossOrigin bool) {
	c := &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   CookieMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if crossOrigin {
		c.SameSite = http.SameSiteNoneMode
		c.Secure = true
	}
	http.SetCookie(w, c)
}

// ClearSessionCookie clears the session cookie on the response.
func ClearSessionCookie(w http.ResponseWriter) {
	c := &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, c)
}

// Middleware checks both X-Daemon-Token (existing) and Authorization: Bearer (new).
// If a valid bearer token is found, the user is injected into the request context.
// If only the daemon token matches, the request passes through without a user (legacy mode).
//
// Deprecated: prefer WebAuth (web group) and MachineAuth (machine group) for
// new code. Retained for backward compatibility.
func Middleware(daemonToken string, store *Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try bearer token first
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				rawToken := strings.TrimPrefix(authHeader, "Bearer ")
				user, err := store.ValidateToken(rawToken)
				if err == nil {
					ctx := context.WithValue(r.Context(), UserContextKey, user)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// Fall back to daemon token
			if daemonToken != "" {
				tokenHeader := r.Header.Get("X-Daemon-Token")
				if tokenHeader == daemonToken {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		})
	}
}

// RequireAuth is a stricter middleware that requires a valid user context.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Value(UserContextKey).(*User); !ok {
			http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// GetUser extracts the authenticated user from the request context.
func GetUser(r *http.Request) *User {
	user, _ := r.Context().Value(UserContextKey).(*User)
	return user
}
