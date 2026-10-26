// Command xdr-agent is the Linux endpoint sensor.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Bogan1011/xdr-agent/internal/agent"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "maintenance" {
		maintenance(os.Args[2:])
		return
	}
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

	a := agent.New(cfg, log)
	// Every signal that would end the process goes through tamper protection,
	// which ignores it unless protection is off, suspended or the host is
	// shutting down.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for s := range sigs {
			if a.StopAllowed(s) {
				log.Info("stopping", "signal", s.String())
				a.Stop()
				return
			}
		}
	}()

	log.Info("xdr-agent starting", "version", agent.Version, "server", cfg.Server)
	if err := a.Run(); err != nil {
		log.Error("agent stopped", "err", err)
		os.Exit(1)
	}
}

// maintenance suspends tamper protection with the console's maintenance token,
// so the agent can be stopped or uninstalled on a host that cannot reach the
// console.
func maintenance(args []string) {
	fs := flag.NewFlagSet("maintenance", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/xdr-agent/agent.yaml", "path to the agent config")
	token := fs.String("token", "", "maintenance token from the endpoint's page in the console")
	d := fs.Duration("duration", time.Hour, "how long protection stays suspended")
	_ = fs.Parse(args)
	cfg, err := agent.LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xdr-agent:", err)
		os.Exit(1)
	}
	msg, err := agent.EnterMaintenance(cfg, *token, *d)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xdr-agent:", err)
		os.Exit(1)
	}
	fmt.Println(msg)
}
