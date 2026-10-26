package agent

import (
	"os"
	"os/exec"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

// uninstallScript mirrors the console's uninstall.sh. It runs outside the
// agent's own service so that stopping the service does not kill it.
const uninstallScript = `sleep 2
systemctl disable --now xdr-agent 2>/dev/null || true
rm -f /etc/systemd/system/xdr-agent.service
systemctl daemon-reload
rm -f /usr/local/bin/xdr-agent
rm -rf /etc/xdr-agent /var/lib/xdr-agent`

func (a *Agent) runCommand(c *xdrv1.AgentCommand) {
	switch c.Type {
	case xdrv1.CommandType_COMMAND_TYPE_UNINSTALL:
		a.log.Warn("uninstall requested by the console", "command_id", c.Id)
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
		a.log.Warn("ignoring unknown command", "type", c.Type.String())
	}
}
