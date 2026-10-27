package api

import (
	"io"
	"log/slog"
	"testing"
)

// Duplicate route patterns panic at startup; building the handler catches them.
func TestHandlerRegistersRoutes(t *testing.T) {
	a := New(Config{}, nil, nil, nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	a.Handler()
}
