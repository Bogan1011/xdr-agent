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
	if len(os.Args) > 1 && os.Args[1] == "elevate" {
		elevate(os.Args[2:])
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

// elevate asks the console for just-in-time sudo and waits for the decision.
// Any local user can run it; the agent identifies them from the socket.
func elevate(args []string) {
	fs := flag.NewFlagSet("elevate", flag.ExitOnError)
	reason := fs.String("reason", "", "why you need root (required)")
	d := fs.Duration("duration", time.Hour, "how long you need sudo (the approver may shorten it)")
	wait := fs.Duration("wait", 15*time.Minute, "how long to wait for a decision; 0 returns at once")
	status := fs.String("status", "", "show the state of an earlier request id")
	_ = fs.Parse(args)
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, "xdr-agent:", err)
		os.Exit(1)
	}
	var m agent.ElevateMsg
	var err error
	if *status != "" {
		m, err = agent.AskElevation(agent.ElevateMsg{Op: "status", ID: *status})
	} else {
		if *reason == "" {
			fail(fmt.Errorf("-reason is required"))
		}
		m, err = agent.AskElevation(agent.ElevateMsg{Op: "request", Reason: *reason, Duration: int64(d.Seconds())})
		if err == nil {
			fmt.Printf("Request %s sent to the console for approval.\n", m.ID)
		}
	}
	if err != nil {
		fail(err)
	}
	deadline := time.Now().Add(*wait)
	for m.Status == "pending" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
		if m, err = agent.AskElevation(agent.ElevateMsg{Op: "status", ID: m.ID}); err != nil {
			fail(err)
		}
	}
	switch m.Status {
	case "pending":
		fmt.Printf("Still waiting for approval. Check later with: xdr-agent elevate -status %s\n", m.ID)
	case "approved":
		fmt.Println("Approved. sudo becomes available within a few seconds.")
	case "active":
		fmt.Printf("Approved: sudo is available until %s. Sessions are recorded.\n", time.Unix(m.Expires, 0).Format(time.Kitchen))
	default:
		msg := "Request " + m.Status
		if m.Note != "" {
			msg += ": " + m.Note
		}
		fmt.Println(msg)
		os.Exit(1)
	}
}
