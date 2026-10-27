package pipeline

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

// remoteQueue is how many batches wait for xdr-detect before new ones are
// dropped; ingest never blocks on detection.
const remoteQueue = 1024

// Remote hands batches to a separate xdr-detect service over HTTP.
type Remote struct {
	URL, Token string
	Log        *slog.Logger

	queue   chan []store.Event
	client  *http.Client
	dropped atomic.Uint64
}

// NewRemote returns a detector that posts to the xdr-detect at url; Run
// delivers the batches.
func NewRemote(url, token string, log *slog.Logger) *Remote {
	return &Remote{URL: strings.TrimSuffix(url, "/"), Token: token, Log: log,
		queue: make(chan []store.Event, remoteQueue), client: &http.Client{Timeout: 30 * time.Second}}
}

// Process queues a batch for xdr-detect.
func (r *Remote) Process(_ context.Context, events []store.Event) {
	select {
	case r.queue <- events:
	default:
		if n := r.dropped.Add(1); n == 1 || n%100 == 0 {
			r.Log.Warn("detection service is not keeping up, batches skipped detection", "batches", n)
		}
	}
}

// Run delivers queued batches until ctx ends, retrying each a few times.
func (r *Remote) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-r.queue:
			r.deliver(ctx, b)
		}
	}
}

func (r *Remote) deliver(ctx context.Context, events []store.Event) {
	body, err := json.Marshal(events)
	if err != nil {
		r.Log.Error("encode batch for detection", "err", err)
		return
	}
	backoff := time.Second
	for try := 1; ; try++ {
		err := r.post(ctx, "/v1/events", body)
		if err == nil {
			return
		}
		if try == 5 || ctx.Err() != nil {
			r.Log.Error("detection service unreachable, batch skipped detection", "events", len(events), "err", err)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}

// Reload tells xdr-detect that rules or IOCs changed.
func (r *Remote) Reload(ctx context.Context) {
	if err := r.post(ctx, "/v1/reload", nil); err != nil {
		r.Log.Warn("reload detection service", "err", err)
	}
}

func (r *Remote) post(ctx context.Context, path string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// maxBody bounds one posted batch; agent batches hold at most 5000 events.
const maxBody = 64 << 20

// Handler is the xdr-detect API: POST /v1/events runs detection on a batch,
// POST /v1/reload reloads rules and IOCs. Both need the shared token.
func Handler(det Detector, reload func(context.Context) error, token string, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("POST /v1/events", auth(func(w http.ResponseWriter, r *http.Request) {
		var events []store.Event
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&events); err != nil {
			http.Error(w, "invalid batch", http.StatusBadRequest)
			return
		}
		det.Process(r.Context(), events)
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("POST /v1/reload", auth(func(w http.ResponseWriter, r *http.Request) {
		if err := reload(r.Context()); err != nil {
			log.Error("reload detection content", "err", err)
			http.Error(w, "reload failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	return mux
}
