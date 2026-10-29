//! Clean-up after the Go agent this one replaced in place. It keeps the Go
//! agent's identity, config and state directory. Prevention (firewall,
//! tamper protection) took over the Go agent's tables, files and drop-in;
//! PAM sudoers files it does not manage yet must not stay behind, or JIT sudo
//! grants would never expire.

use std::fs;

const SUDOERS: &str = "/etc/sudoers.d";

/// Runs at every start; it does nothing once the host is clean.
pub fn cleanup_go_agent() {
    if let Ok(dir) = fs::read_dir(SUDOERS) {
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if (name.starts_with("xdr-jit-") || name == "xdr-session-recording") && fs::remove_file(e.path()).is_ok() {
                tracing::warn!(file = %name, "removed a Go agent PAM sudoers file; PAM is not ported yet");
            }
        }
    }
}
