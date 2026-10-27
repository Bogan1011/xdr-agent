package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Building the handler registers every route; a duplicate or conflicting
// pattern panics here instead of when the server starts.
func TestHandlerRoutes(t *testing.T) {
	h := New(Config{}, nil, nil, nil, nil, nil, slog.Default()).Handler()
	for _, path := range []string{"/api/v1/me", "/api/v1/users", "/api/v1/agents"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s: got %d, want 401 (route missing?)", path, rec.Code)
		}
	}
}
