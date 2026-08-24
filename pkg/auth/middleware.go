package auth

import (
	"encoding/json"
	"net/http"
	"strings"
)

// KeyValidator defines the interface required to authenticate an API key.
type KeyValidator interface {
	ValidateKey(rawKey string) bool
}

// ExtractAPIKey extracts the API key token from request headers (X-API-Key or Authorization: Bearer).
func ExtractAPIKey(r *http.Request) string {
	if key := strings.TrimSpace(r.Header.Get("X-API-Key")); key != "" {
		return key
	}

	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader != "" {
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			return strings.TrimSpace(authHeader[7:])
		}
		if strings.HasPrefix(strings.ToLower(authHeader), "apikey ") {
			return strings.TrimSpace(authHeader[7:])
		}
		return authHeader
	}

	return ""
}

// RequireAuth wraps an http.HandlerFunc to enforce API key authentication and handle CORS.
func RequireAuth(validator KeyValidator, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers for all incoming requests
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, X-API-Key, Content-Type, Accept")

		// Handle preflight OPTIONS unauthenticated
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if validator == nil {
			http.Error(w, `{"error":"unauthorized","message":"Authentication not configured"}`, http.StatusUnauthorized)
			return
		}

		apiKey := ExtractAPIKey(r)
		if apiKey == "" || !validator.ValidateKey(apiKey) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "unauthorized",
				"message": "Invalid or missing API key. Provide via 'X-API-Key' or 'Authorization: Bearer <key>' header.",
			})
			return
		}

		next(w, r)
	}
}

// CORSMiddleware wraps a handler with standard permissive CORS headers.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, X-API-Key, Content-Type, Accept")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
