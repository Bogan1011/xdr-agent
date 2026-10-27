//! Clean-up after the Go agent this one replaced in place. It keeps the Go
//! agent's identity, config and state directory, but enforcement it does not
//! implement yet must not stay behind unmanaged: tamper locks would stop the
//! agent from being updated or removed, the firewall table would never change
//! again and JIT sudo grants would never expire.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::response::FIREWALL_TABLE;

const UNIT: &str = "/etc/systemd/system/xdr-agent.service";
const DROP_IN: &str = "/etc/systemd/system/xdr-agent.service.d/10-tamper-protection.conf";
const SUDOERS: &str = "/etc/sudoers.d";

/// Runs at every start; it does nothing once the host is clean.
pub fn cleanup_go_agent() {
    release_tamper();
    if run("nft", &["list", "table", "inet", FIREWALL_TABLE])
        && run("nft", &["delete", "table", "inet", FIREWALL_TABLE])
    {
        tracing::warn!("removed the Go agent's firewall rules; the firewall module is not ported yet");
    }
    if let Ok(dir) = fs::read_dir(SUDOERS) {
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if (name.starts_with("xdr-jit-") || name == "xdr-session-recording") && fs::remove_file(e.path()).is_ok() {
                tracing::warn!(file = %name, "removed a Go agent PAM sudoers file; PAM is not ported yet");
            }
        }
    }
}

/// Clears the immutable flags and the RefuseManualStop drop-in that the Go
/// agent's tamper protection set. Also what `xdr-agent maintenance` does, so
/// the console's install and uninstall scripts keep working.
pub fn release_tamper() -> bool {
    let mut paths = vec![UNIT.to_string(), DROP_IN.to_string()];
    if let Ok(dir) = fs::read_dir("/etc/xdr-agent") {
        paths.extend(dir.flatten().map(|e| e.path().to_string_lossy().into_owned()));
    }
    if let Ok(exe) = std::env::current_exe() {
        paths.push(exe.to_string_lossy().into_owned());
    }
    for p in paths.iter().filter(|p| Path::new(p).exists()) {
        let _ = run("chattr", &["-i", p]);
    }
    if !Path::new(DROP_IN).exists() {
        return false;
    }
    if let Err(err) = fs::remove_file(DROP_IN) {
        tracing::error!("removing the Go agent's tamper drop-in failed: {err}");
        return false;
    }
    let _ = run("systemctl", &["daemon-reload"]);
    tracing::warn!("released the Go agent's tamper protection; tamper protection is not ported yet");
    true
}

fn run(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}
