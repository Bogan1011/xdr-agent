// Command xdr-agent is the Linux endpoint sensor.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Bogan1011/xdr-agent/internal/agent"
)

func main() {
	cfgPath := flag.String("config", "/etc/xdr-agent/agent.yaml", "path to the agent config")
	version := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *version {
		fmt.Println(agent.Version)
		return
	}

	cfg, err := agent.LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xdr-agent:", err)
		os.Exit(1)
	}
	var level slog.Level
	_ = level.UnmarshalText([]byte(cfg.LogLevel))
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if os.Geteuid() != 0 {
		log.Error("xdr-agent must run as root to read process events and all of /proc")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("xdr-agent starting", "version", agent.Version, "server", cfg.Server)
	if err := agent.New(cfg, log).Run(ctx); err != nil {
		log.Error("agent stopped", "err", err)
		os.Exit(1)
	}
}
