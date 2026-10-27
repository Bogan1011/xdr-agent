package api

import (
	"log/slog"
	"testing"
)

// Building the handler registers every route; a duplicate or conflicting
// pattern panics here instead of when the server starts.
func TestHandlerRoutes(t *testing.T) {
	New(Config{}, nil, nil, nil, nil, nil, slog.Default()).Handler()
}
