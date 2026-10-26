package agent

import (
	"context"
	"crypto/tls"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/agent/collector"
	"github.com/Bogan1011/xdr-agent/internal/agent/procfs"
)

const heartbeatInterval = 30 * time.Second

type Agent struct {
	cfg   *Config
	log   *slog.Logger
	queue chan *xdrv1.Event
	start time.Time

	sent    atomic.Uint64
	dropped atomic.Uint64
}

func New(cfg *Config, log *slog.Logger) *Agent {
	return &Agent{
		cfg:   cfg,
		log:   log,
		queue: make(chan *xdrv1.Event, cfg.QueueSize),
		start: time.Now(),
	}
}

// emit never blocks a collector: when the backend is unreachable and the
// queue is full, new events are dropped and counted.
func (a *Agent) emit(e *xdrv1.Event) {
	select {
	case a.queue <- e:
	default:
		a.dropped.Add(1)
	}
}

func (a *Agent) Run(ctx context.Context) error {
	host := HostInfo()
	var id *Identity
	for {
		var err error
		id, err = LoadOrEnroll(ctx, a.cfg, host)
		if err == nil {
			break
		}
		a.log.Error("enrollment failed, retrying in 30s", "err", err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(30 * time.Second):
		}
	}
	a.log.Info("agent identity loaded", "agent_id", id.AgentID)

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{id.Cert},
		RootCAs:      id.CAPool,
		ServerName:   a.cfg.ServerName,
		MinVersion:   tls.VersionTLS13,
	})
	conn, err := grpc.NewClient(a.cfg.Server,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.UseCompressor(gzip.Name)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 60 * time.Second, Timeout: 20 * time.Second}),
	)
	if err != nil {
		return err
	}
	defer conn.Close()
	client := xdrv1.NewAgentServiceClient(conn)

	hasher := procfs.NewHasher(50000)
	collectors := []collector.Collector{
		&collector.Process{Hasher: hasher, Log: a.log.With("collector", "process")},
		&collector.File{
			Paths: a.cfg.FilePaths, Exclude: a.cfg.FileExclude, MaxWatches: a.cfg.MaxFileWatches,
			Hasher: hasher, Log: a.log.With("collector", "file"),
		},
		&collector.Network{Interval: a.cfg.NetworkInterval},
	}

	var wg sync.WaitGroup
	for _, c := range collectors {
		wg.Add(1)
		go func(c collector.Collector) {
			defer wg.Done()
			a.runCollector(ctx, c)
		}(c)
	}
	wg.Add(2)
	go func() { defer wg.Done(); a.sendLoop(ctx, client) }()
	go func() { defer wg.Done(); a.heartbeatLoop(ctx, client, host) }()
	wg.Wait()
	return nil
}

// runCollector restarts a collector that fails, so one broken source does not
// take the agent down.
func (a *Agent) runCollector(ctx context.Context, c collector.Collector) {
	for ctx.Err() == nil {
		a.log.Info("collector starting", "collector", c.Name())
		err := c.Run(ctx, a.emit)
		if ctx.Err() != nil {
			return
		}
		a.log.Error("collector stopped, restarting in 10s", "collector", c.Name(), "err", err)
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
		}
	}
}

func (a *Agent) sendLoop(ctx context.Context, client xdrv1.AgentServiceClient) {
	batch := make([]*xdrv1.Event, 0, a.cfg.BatchSize)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	backoff := time.Second

	flush := func() {
		for len(batch) > 0 && ctx.Err() == nil {
			cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			_, err := client.SendEvents(cctx, &xdrv1.EventBatch{Events: batch})
			cancel()
			if err == nil {
				a.sent.Add(uint64(len(batch)))
				batch = batch[:0]
				backoff = time.Second
				return
			}
			a.log.Warn("sending events failed", "err", err, "batch", len(batch), "retry_in", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Minute)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case e := <-a.queue:
			batch = append(batch, e)
			if len(batch) >= a.cfg.BatchSize {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context, client xdrv1.AgentServiceClient, host *xdrv1.HostInfo) {
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	for {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		resp, err := client.Heartbeat(cctx, &xdrv1.HeartbeatRequest{Host: host, Stats: a.stats()})
		cancel()
		if err != nil && ctx.Err() == nil {
			a.log.Warn("heartbeat failed", "err", err)
		}
		for _, c := range resp.GetCommands() {
			a.runCommand(c)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			host = HostInfo()
		}
	}
}

func (a *Agent) stats() *xdrv1.AgentStats {
	s := &xdrv1.AgentStats{
		EventsSent:    a.sent.Load(),
		EventsDropped: a.dropped.Load(),
		UptimeSeconds: uint64(time.Since(a.start).Seconds()),
	}
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) == nil {
		cpu := time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
		if up := time.Since(a.start); up > 0 {
			s.CpuPercent = 100 * cpu.Seconds() / up.Seconds()
		}
	}
	// The second field of statm is the resident set size in pages.
	if raw, err := os.ReadFile("/proc/self/statm"); err == nil {
		if f := strings.Fields(string(raw)); len(f) > 1 {
			rss, _ := strconv.ParseUint(f[1], 10, 64)
			s.RssBytes = rss * uint64(os.Getpagesize())
		}
	}
	return s
}
