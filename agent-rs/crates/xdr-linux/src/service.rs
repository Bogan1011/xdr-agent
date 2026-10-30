//! Keeps the agent's systemd unit hardened on hosts installed before these
//! settings were part of the installer: a drop-in, rewritten when it differs,
//! so a console update brings them to every endpoint.

use std::path::Path;

const UNIT: &str = "/etc/systemd/system/xdr-agent.service";
const DROP_IN_DIR: &str = "/etc/systemd/system/xdr-agent.service.d";
const DROP_IN: &str = "/etc/systemd/system/xdr-agent.service.d/20-hardening.conf";

/// Restarted forever (no start-rate limit), even after a crash loop; a lower
/// CPU and I/O share than the host's workloads; a bounded stop.
pub const DROP_IN_CONTENT: &str = "# Managed by xdr-agent; rewritten when it differs.\n\
[Unit]\n\
StartLimitIntervalSec=0\n\
\n\
[Service]\n\
Restart=always\n\
RestartSec=5\n\
CPUWeight=50\n\
IOWeight=50\n\
TimeoutStopSec=30\n";

/// Writes the drop-in when the agent runs from the installed unit.
pub fn ensure_hardening() {
    if !Path::new(UNIT).exists() || std::fs::read_to_string(DROP_IN).ok().as_deref() == Some(DROP_IN_CONTENT) {
        return;
    }
    let res = std::fs::create_dir_all(DROP_IN_DIR).and_then(|_| std::fs::write(DROP_IN, DROP_IN_CONTENT));
    match res {
        Ok(()) => {
            let _ = std::process::Command::new("systemctl")
                .arg("daemon-reload")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            tracing::info!(path = DROP_IN, "systemd unit hardening applied");
        }
        Err(err) => tracing::warn!(path = DROP_IN, "writing the unit hardening drop-in failed: {err}"),
    }
}
