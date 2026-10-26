// Command xdr-server is the backend: agent enrollment and ingest over gRPC,
// and the dashboard and its REST API over HTTP.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/server/api"
	"github.com/Bogan1011/xdr-agent/internal/server/deploy"
	"github.com/Bogan1011/xdr-agent/internal/server/detect"
	"github.com/Bogan1011/xdr-agent/internal/server/grpcsvc"
	"github.com/Bogan1011/xdr-agent/internal/server/pki"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("xdr-server stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	publicHost := env("XDR_PUBLIC_HOST", "")
	if publicHost == "" {
		return errors.New("XDR_PUBLIC_HOST must be set to the IP or DNS name agents use to reach this server")
	}
	adminPassword := env("XDR_ADMIN_PASSWORD", "")
	if len(adminPassword) < 12 {
		return errors.New("XDR_ADMIN_PASSWORD must be set and at least 12 characters")
	}
	enrollPort, agentPort := envInt("XDR_ENROLL_PORT", 8443), envInt("XDR_AGENT_PORT", 8444)

	ca, err := pki.LoadOrCreate(env("XDR_DATA_DIR", "/data") + "/pki")
	if err != nil {
		return fmt.Errorf("CA: %w", err)
	}
	log.Info("CA ready", "sha256", ca.Fingerprint())

	names := []string{publicHost, "localhost", "127.0.0.1"}
	for _, n := range strings.Split(env("XDR_SERVER_NAMES", ""), ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	serverCert, err := ca.ServerCert(names)
	if err != nil {
		return fmt.Errorf("server cert: %w", err)
	}

	db, err := connect(ctx, log, "postgres", func() (*store.Postgres, error) {
		return store.OpenPostgres(ctx, env("XDR_POSTGRES_URL", "postgres://xdr:xdr@localhost:5432/xdr"))
	})
	if err != nil {
		return err
	}
	defer db.Close()

	events, err := connect(ctx, log, "clickhouse", func() (*store.ClickHouse, error) {
		return store.OpenClickHouse(ctx, store.ClickHouseOptions{
			Addr:     env("XDR_CLICKHOUSE_ADDR", "localhost:9000"),
			Database: env("XDR_CLICKHOUSE_DB", "default"),
			User:     env("XDR_CLICKHOUSE_USER", "default"),
			Password: env("XDR_CLICKHOUSE_PASSWORD", ""),
			TTLDays:  envInt("XDR_EVENT_TTL_DAYS", 30),
		})
	})
	if err != nil {
		return err
	}
	defer events.Close()

	if err := db.FailStaleDeployJobs(ctx); err != nil {
		log.Warn("mark stale deploy jobs", "err", err)
	}

	det := &detect.Service{DB: db, Log: log}
	if err := det.Init(ctx); err != nil {
		return fmt.Errorf("detection: %w", err)
	}
	go det.RunFeeds(ctx)

	// Enrollment: server-authenticated TLS only, the token is the credential.
	enrollTLS := &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13}
	enrollSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(enrollTLS)))
	xdrv1.RegisterEnrollmentServiceServer(enrollSrv, &grpcsvc.Enrollment{CA: ca, DB: db, Log: log})

	// Agents: mutual TLS against our CA.
	agentTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    ca.Pool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	agents := &grpcsvc.Agents{DB: db, Events: events, Detect: det, Log: log}
	agentSrv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(agentTLS)),
		grpc.UnaryInterceptor(agents.AuthInterceptor),
		grpc.MaxRecvMsgSize(32<<20),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 30 * time.Second, PermitWithoutStream: true}),
	)
	xdrv1.RegisterAgentServiceServer(agentSrv, agents)

	httpSrv := &http.Server{
		Addr: env("XDR_HTTP_ADDR", ":8080"),
		Handler: api.New(api.Config{
			AdminUser:     env("XDR_ADMIN_USER", "admin"),
			AdminPassword: adminPassword,
			PublicHost:    publicHost,
			EnrollPort:    enrollPort,
			AgentPort:     agentPort,
			WebDir:        env("XDR_WEB_DIR", ""),
			DownloadsDir:  env("XDR_DOWNLOADS_DIR", ""),
		}, db, events, ca, &deploy.Deployer{DB: db, Log: log}, det, log).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errc := make(chan error, 3)
	serveGRPC := func(name string, s *grpc.Server, port int) {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			errc <- fmt.Errorf("%s listen: %w", name, err)
			return
		}
		log.Info("listening", "service", name, "port", port)
		errc <- s.Serve(l)
	}
	go serveGRPC("enrollment", enrollSrv, enrollPort)
	go serveGRPC("agent", agentSrv, agentPort)
	go func() {
		log.Info("listening", "service", "http", "addr", httpSrv.Addr)
		errc <- httpSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(sctx)
	enrollSrv.GracefulStop()
	agentSrv.GracefulStop()
	return nil
}

// connect retries a store connection while the database container starts.
func connect[T any](ctx context.Context, log *slog.Logger, name string, open func() (T, error)) (T, error) {
	var zero T
	for i := 0; ; i++ {
		v, err := open()
		if err == nil {
			log.Info("connected", "store", name)
			return v, nil
		}
		if i == 30 {
			return zero, fmt.Errorf("%s: %w", name, err)
		}
		log.Warn("store not ready, retrying", "store", name, "err", err)
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
