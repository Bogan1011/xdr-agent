// Command xdr-detect is the detection service on its own: xdr-server stores
// each enriched batch and posts it here for detection and correlation.
// Alerts and response commands go to the shared Postgres, where xdr-server
// picks the commands up and pushes them to the agents.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Bogan1011/xdr-agent/internal/server/detect"
	"github.com/Bogan1011/xdr-agent/internal/server/pipeline"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

// reloadInterval also reloads content on a timer, in case a reload request
// from xdr-server was missed.
const reloadInterval = 5 * time.Minute

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("service", "xdr-detect")
	if err := run(log); err != nil {
		log.Error("xdr-detect stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	token := env("XDR_DETECT_TOKEN", "")
	if len(token) < 16 {
		return errors.New("XDR_DETECT_TOKEN must be set and at least 16 characters")
	}
	var db *store.Postgres
	var err error
	for i := 0; ; i++ {
		if db, err = store.OpenPostgres(ctx, env("XDR_POSTGRES_URL", "postgres://xdr:xdr@localhost:5432/xdr")); err == nil {
			break
		}
		if i == 30 {
			return fmt.Errorf("postgres: %w", err)
		}
		log.Warn("postgres not ready, retrying", "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	defer db.Close()

	det := &detect.Service{DB: db, Log: log}
	if err := det.Init(ctx); err != nil {
		return fmt.Errorf("detection: %w", err)
	}
	go func() {
		t := time.NewTicker(reloadInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := det.Reload(ctx); err != nil {
					log.Warn("reload detection content", "err", err)
				}
			}
		}
	}()

	srv := &http.Server{
		Addr:              env("XDR_DETECT_ADDR", ":8090"),
		Handler:           pipeline.Handler(det, det.Reload, token, log),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", srv.Addr)
		errc <- srv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}
