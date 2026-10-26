package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

// uninstallScript mirrors the console's uninstall.sh. It runs outside the
// agent's own service so that stopping the service does not kill it.
const uninstallScript = `sleep 2
nft delete table inet xdr_isolation 2>/dev/null || true
systemctl disable --now xdr-agent 2>/dev/null || true
rm -rf /etc/systemd/system/xdr-agent.service /etc/systemd/system/xdr-agent.service.d
systemctl daemon-reload
rm -f /usr/local/bin/xdr-agent
rm -rf /etc/xdr-agent /var/lib/xdr-agent`

func (a *Agent) runCommand(ctx context.Context, c *xdrv1.AgentCommand) {
	switch c.Type {
	case xdrv1.CommandType_COMMAND_TYPE_UNINSTALL:
		a.log.Warn("uninstall requested by the console", "command_id", c.Id)
		a.tamper.Release()
		cmd := exec.Command("systemd-run", "--unit=xdr-agent-uninstall", "--collect", "/bin/sh", "-c", uninstallScript)
		if _, err := exec.LookPath("systemd-run"); err != nil {
			// No systemd-run: detach into a new session instead.
			cmd = exec.Command("setsid", "/bin/sh", "-c", uninstallScript)
		}
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Start(); err != nil {
			a.log.Error("start uninstall", "err", err)
			return
		}
		go cmd.Wait()
	default:
		// Response actions run off the heartbeat loop and report back.
		go a.respond(ctx, c)
	}
}

func (a *Agent) respond(ctx context.Context, c *xdrv1.AgentCommand) {
	a.log.Warn("response action requested by the console", "command_id", c.Id, "type", c.Type.String(), "args", c.Args)
	var msg string
	var err error
	switch c.Type {
	case xdrv1.CommandType_COMMAND_TYPE_KILL_PROCESS:
		msg, err = killProcess(c.Args)
	case xdrv1.CommandType_COMMAND_TYPE_QUARANTINE_FILE:
		msg, err = a.quarantineFile(c.Args)
	case xdrv1.CommandType_COMMAND_TYPE_RESTORE_FILE:
		msg, err = a.restoreFile(c.Args)
	case xdrv1.CommandType_COMMAND_TYPE_ISOLATE_HOST:
		msg, err = a.isolate(c.Args)
	case xdrv1.CommandType_COMMAND_TYPE_UNISOLATE_HOST:
		msg, err = a.unisolate()
	case xdrv1.CommandType_COMMAND_TYPE_SCAN_PATH:
		sctx, cancel := context.WithTimeout(ctx, time.Hour)
		msg, err = a.scanner.ScanPath(sctx, c.Args["path"])
		cancel()
	case xdrv1.CommandType_COMMAND_TYPE_UPDATE_AGENT:
		msg, err = a.selfUpdate(ctx, c.Args)
	default:
		err = fmt.Errorf("unsupported command %s", c.Type)
	}
	res := &xdrv1.CommandResult{CommandId: c.Id, Success: err == nil, Message: msg}
	if err != nil {
		res.Message = err.Error()
		a.log.Error("response action failed", "command_id", c.Id, "err", err)
	} else {
		a.log.Info("response action done", "command_id", c.Id, "result", msg)
	}
	if c.Type == xdrv1.CommandType_COMMAND_TYPE_ISOLATE_HOST || c.Type == xdrv1.CommandType_COMMAND_TYPE_UNISOLATE_HOST {
		a.wakeHeartbeat()
	}
	for i := 0; i < 5 && ctx.Err() == nil; i++ {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, rerr := a.client.ReportCommandResult(cctx, res)
		cancel()
		if rerr == nil {
			break
		}
		a.log.Warn("reporting command result failed", "err", rerr)
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(i+1) * 5 * time.Second):
		}
	}
	if c.Type == xdrv1.CommandType_COMMAND_TYPE_UPDATE_AGENT && err == nil && a.loadPending() != nil {
		a.log.Info("restarting into the updated agent")
		a.Stop()
	}
}
