package server

import (
	"net/http"
	"strings"
)

// corsMiddleware enables cross-origin requests from the separately-deployed
// frontend. Because the frontend uses HttpOnly cookies for authentication
// (EventSource cannot set custom headers), credentials must be allowed, which
// means the Allow-Origin value CANNOT be "*" — it must echo the request origin.
//
// allowedOrigins is a set of origins (scheme://host[:port]) permitted to make
// cross-origin requests. An empty set denies all cross-origin requests; same-
// origin requests are never subject to CORS and pass through unaffected.
//
// Behavior:
//   - OPTIONS preflight → 204 with CORS headers (when origin allowed).
//   - All other methods → CORS headers added (when origin allowed), then next.
//   - Disallowed origin → no CORS headers (browser blocks the response).
func corsMiddleware(allowedOrigins map[string]bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && allowedOrigins[origin] {
			setCorsHeaders(w, origin)
		}
		if r.Method == http.MethodOptions {
			// Preflight: respond 204. Even if origin disallowed, return 204
			// without CORS headers so the browser blocks the actual request.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func setCorsHeaders(w http.ResponseWriter, origin string) {
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Daemon-Token")
	// Allow browsers to cache preflight results for 10 minutes.
	w.Header().Set("Access-Control-Max-Age", "600")
}

// parseOrigins parses a comma-separated list of origins into a set.
// Whitespace around each origin is trimmed. Empty input yields an empty set.
func parseOrigins(s string) map[string]bool {
	set := make(map[string]bool)
	for _, o := range strings.Split(s, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			set[o] = true
		}
	}
	return set
}
