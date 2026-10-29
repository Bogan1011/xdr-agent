//! Tamper protection raises the bar for stopping or removing the agent
//! without the console. Root can always undo it, so every attempt is also
//! reported. While it is on:
//!   - the binary, config, CA and unit file are immutable (chattr +i), so rm,
//!     mv and editors fail;
//!   - a unit drop-in sets RefuseManualStop, so systemctl stop is refused;
//!   - SIGTERM is ignored unless the host is shutting down;
//!   - a restart after SIGKILL or a crash is reported.
//!
//! The console's maintenance token, or the policy's self-protection password,
//! suspends it locally (`xdr-agent maintenance --token ...` or
//! `--password ...`), e.g. to uninstall without the console. tamper.json and
//! the drop-in match the Go agent's.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use xdr_core::bus::new_event;
use xdr_core::pb::{self, EventType};

use super::Emitter;
use super::fim::write_private;

const UNIT: &str = "/etc/systemd/system/xdr-agent.service";
const DROP_IN_DIR: &str = "/etc/systemd/system/xdr-agent.service.d";
pub const DROP_IN: &str = "/etc/systemd/system/xdr-agent.service.d/10-tamper-protection.conf";
const DROP_IN_CONTENT: &str =
    "# Managed by xdr-agent tamper protection; removed when it is turned off.\n[Unit]\nRefuseManualStop=yes\n";
const INTERVAL: Duration = Duration::from_secs(30);
const PASSWORD_ITERATIONS: u32 = 200_000;
const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
const FS_IOC_SETFLAGS: libc::c_ulong = 0x4008_6602;
const FS_IMMUTABLE_FL: libc::c_int = 0x10;

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Debug)]
pub struct Policy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub token_sha256: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password_salt: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password_hash: String,
}

impl Policy {
    /// Whether secret is the maintenance token or the admin password.
    pub fn unlocks(&self, secret: &str) -> bool {
        token_matches(secret, &self.token_sha256) || password_matches(secret, &self.password_salt, &self.password_hash)
    }
}

#[derive(Serialize, Deserialize)]
struct Maintenance {
    token: String,
    #[serde(default)]
    until_unix: i64,
}

struct Inner {
    policy: Policy,
    applied: bool,
    released: bool,
    /// The maintenance window last reported, so it is reported once.
    maint_reported: i64,
}

pub struct Tamper {
    emit: Emitter,
    state_dir: PathBuf,
    paths: Vec<String>,
    inner: Mutex<Inner>,
    tx: mpsc::SyncSender<()>,
    rx: Mutex<Option<mpsc::Receiver<()>>>,
}

impl Tamper {
    /// files are the agent's config and CA, protected with the binary and unit.
    pub fn new(emit: Emitter, state_dir: PathBuf, files: &[PathBuf]) -> Self {
        let policy = load_policy(&state_dir);
        let mut paths = vec![UNIT.to_string(), DROP_IN.to_string()];
        paths.extend(files.iter().map(|p| p.to_string_lossy().into_owned()));
        paths.push(exe_path());
        let (tx, rx) = mpsc::sync_channel(1);
        Tamper {
            emit,
            state_dir,
            paths,
            inner: Mutex::new(Inner {
                policy,
                applied: false,
                released: false,
                maint_reported: 0,
            }),
            tx,
            rx: Mutex::new(Some(rx)),
        }
    }

    /// Applies the console's policy from a heartbeat.
    pub fn set_policy(&self, p: &pb::TamperPolicy) {
        let np = Policy {
            enabled: p.enabled,
            token_sha256: p.maintenance_token_sha256.clone(),
            password_salt: p.password_salt.clone(),
            password_hash: p.password_hash.clone(),
        };
        let mut i = self.inner.lock().unwrap();
        if i.policy == np {
            return;
        }
        i.policy = np.clone();
        drop(i);
        if let Err(err) = write_private(&self.state_dir.join("tamper.json"), &serde_json::to_vec(&np).unwrap()) {
            tracing::warn!("saving tamper policy: {err}");
        }
        tracing::info!(
            enabled = np.enabled,
            password = !np.password_hash.is_empty(),
            "tamper protection policy changed"
        );
        let _ = self.tx.try_send(());
    }

    pub fn applied(&self) -> bool {
        self.inner.lock().unwrap().applied
    }

    /// Removes protection for good, before an uninstall the console asked for.
    pub fn release(&self) {
        let mut i = self.inner.lock().unwrap();
        i.released = true;
        self.remove(&mut i);
    }

    /// Whether a termination signal may stop the agent.
    pub fn stop_allowed(&self) -> bool {
        if !self.applied() || self.maintenance_active() || shutting_down() {
            return true;
        }
        tracing::warn!("termination signal ignored, tamper protection is on");
        self.event("signal_ignored", "SIGTERM ignored: tamper protection is on");
        false
    }

    pub fn run(&self) {
        let rx = self.rx.lock().unwrap().take().expect("tamper runs once");
        loop {
            self.reconcile();
            if let Err(mpsc::RecvTimeoutError::Disconnected) = rx.recv_timeout(INTERVAL) {
                return;
            }
        }
    }

    fn reconcile(&self) {
        let maint = self.maintenance_active();
        let mut i = self.inner.lock().unwrap();
        let want = i.policy.enabled && !i.released && !maint;
        if !want {
            if i.applied || Path::new(DROP_IN).exists() {
                self.remove(&mut i);
                tracing::info!(maintenance = maint, "tamper protection removed");
            }
            return;
        }
        if i.applied {
            // Someone cleared a flag or deleted the drop-in: report, restore.
            for p in &self.paths {
                match immutable(p) {
                    Ok(false) => self.event("protection_removed", &format!("immutable flag cleared on {p}")),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound && p == DROP_IN => {
                        self.event("protection_removed", &format!("{p} deleted"))
                    }
                    _ => {}
                }
            }
        }
        if let Err(err) = self.apply() {
            tracing::warn!("applying tamper protection: {err:#}");
        }
        if !i.applied {
            i.applied = true;
            tracing::info!("tamper protection applied");
        }
    }

    fn apply(&self) -> Result<()> {
        if std::fs::read_to_string(DROP_IN).ok().as_deref() != Some(DROP_IN_CONTENT) {
            let _ = set_immutable(DROP_IN, false);
            std::fs::create_dir_all(DROP_IN_DIR)?;
            std::fs::write(DROP_IN, DROP_IN_CONTENT)?;
            daemon_reload();
        }
        let errs: Vec<String> = self
            .paths
            .iter()
            .filter_map(|p| match set_immutable(p, true) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Some(format!("{p}: {e}")),
                _ => None,
            })
            .collect();
        if !errs.is_empty() {
            bail!(errs.join("; "));
        }
        Ok(())
    }

    fn remove(&self, i: &mut Inner) {
        release_files(&self.paths);
        i.applied = false;
    }

    /// Whether a valid maintenance token or password was entered locally and
    /// has not expired. Reports the start of each window once.
    fn maintenance_active(&self) -> bool {
        let Some(m) = read_maintenance(&self.state_dir) else {
            return false;
        };
        if m.until_unix <= unix_now() {
            return false;
        }
        let mut i = self.inner.lock().unwrap();
        let first = i.maint_reported != m.until_unix;
        i.maint_reported = m.until_unix;
        let ok = i.policy.unlocks(&m.token);
        drop(i);
        if first {
            if ok {
                self.event(
                    "maintenance",
                    "tamper protection suspended locally with the maintenance token or self-protection password",
                );
            } else {
                self.event(
                    "maintenance_rejected",
                    "maintenance file with a wrong token or password",
                );
            }
        }
        ok
    }

    fn event(&self, action: &str, detail: &str) {
        let mut e = new_event(EventType::AgentTamper);
        e.payload = Some(pb::event::Payload::Tamper(pb::TamperEvent {
            action: action.into(),
            detail: detail.into(),
            pid: std::process::id(),
            ..Default::default()
        }));
        self.emit.emit(e);
    }

    /// Reports when the previous agent process in this boot did not shut
    /// down cleanly (SIGKILL or a crash), then marks this one as running.
    pub fn check_unclean_exit(&self) {
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default();
        let marker = self.state_dir.join("running");
        if !boot.is_empty() && std::fs::read_to_string(&marker).is_ok_and(|prev| prev == boot) {
            self.event(
                "unclean_restart",
                "the previous agent process ended without a clean shutdown (killed with SIGKILL or crashed)",
            );
        }
        let _ = write_private(&marker, boot.as_bytes());
    }

    pub fn clear_running_marker(&self) {
        let _ = std::fs::remove_file(self.state_dir.join("running"));
    }
}

fn load_policy(state_dir: &Path) -> Policy {
    std::fs::read(state_dir.join("tamper.json"))
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or_default()
}

fn read_maintenance(state_dir: &Path) -> Option<Maintenance> {
    serde_json::from_slice(&std::fs::read(state_dir.join("maintenance.json")).ok()?).ok()
}

/// The local `xdr-agent maintenance` command: checks the secret against the
/// last policy from the console, suspends protection for d and removes it at
/// once so the service can be stopped or the agent uninstalled.
pub fn enter_maintenance(state_dir: &Path, files: &[PathBuf], secret: &str, d: Duration) -> Result<String> {
    let pol = load_policy(state_dir);
    if !pol.enabled && !Path::new(DROP_IN).exists() {
        return Ok("tamper protection is off; nothing to do".into());
    }
    if !pol.unlocks(secret) {
        bail!(
            "wrong maintenance token or password (the token is on the endpoint's page in the console; the password is set in the policy's Self-protection module)"
        );
    }
    let until = unix_now() + d.as_secs() as i64;
    let m = Maintenance {
        token: secret.into(),
        until_unix: until,
    };
    write_private(&state_dir.join("maintenance.json"), &serde_json::to_vec(&m)?)?;
    let mut paths = vec![UNIT.to_string(), DROP_IN.to_string()];
    paths.extend(files.iter().map(|p| p.to_string_lossy().into_owned()));
    paths.push(exe_path());
    release_files(&paths);
    Ok(format!(
        "tamper protection suspended for {} minutes; the agent can now be stopped or uninstalled",
        d.as_secs() / 60
    ))
}

/// Clears the immutable flags and removes the drop-in.
pub fn release_files(paths: &[String]) {
    for p in paths {
        let _ = set_immutable(p, false);
    }
    if Path::new(DROP_IN).exists() {
        let _ = std::fs::remove_file(DROP_IN);
        let _ = std::fs::remove_dir(DROP_IN_DIR);
        daemon_reload();
    }
}

fn exe_path() -> String {
    let p = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/usr/local/bin/xdr-agent".into());
    p.trim_end_matches(" (deleted)").to_string()
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// True while systemd is stopping the system, the one time a protected agent
/// honors SIGTERM.
fn shutting_down() -> bool {
    let Ok(mut child) = std::process::Command::new("systemctl")
        .arg("is-system-running")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return false;
    };
    for _ in 0..30 {
        if let Ok(Some(_)) = child.try_wait() {
            let mut s = String::new();
            let _ = std::io::Read::read_to_string(&mut child.stdout.take().unwrap(), &mut s);
            return matches!(s.trim(), "stopping" | "offline");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    false
}

fn daemon_reload() {
    let _ = std::process::Command::new("systemctl")
        .arg("daemon-reload")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

fn immutable(path: &str) -> std::io::Result<bool> {
    let f = std::fs::File::open(path)?;
    let mut flags: libc::c_int = 0;
    if unsafe { libc::ioctl(f.as_raw_fd(), FS_IOC_GETFLAGS as _, &mut flags) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(flags & FS_IMMUTABLE_FL != 0)
}

pub fn set_immutable(path: &str, on: bool) -> std::io::Result<()> {
    let f = std::fs::File::open(path)?;
    let mut flags: libc::c_int = 0;
    if unsafe { libc::ioctl(f.as_raw_fd(), FS_IOC_GETFLAGS as _, &mut flags) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let nf = if on {
        flags | FS_IMMUTABLE_FL
    } else {
        flags & !FS_IMMUTABLE_FL
    };
    if nf == flags {
        return Ok(());
    }
    if unsafe { libc::ioctl(f.as_raw_fd(), FS_IOC_SETFLAGS as _, &nf) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn token_matches(token: &str, hash: &str) -> bool {
    if token.is_empty() || hash.is_empty() {
        return false;
    }
    let sum = hex::encode(Sha256::digest(token.as_bytes()));
    ct_eq(sum.as_bytes(), hash.to_lowercase().as_bytes())
}

/// Checks a password against the salt and hash the console stores
/// (PBKDF2-HMAC-SHA256, 200 000 iterations, 32 bytes, hex).
pub fn password_matches(pw: &str, salt_hex: &str, hash_hex: &str) -> bool {
    if pw.is_empty() || salt_hex.is_empty() || hash_hex.is_empty() {
        return false;
    }
    let Ok(salt) = hex::decode(salt_hex) else { return false };
    let key = hex::encode(pbkdf2_sha256(pw.as_bytes(), &salt, PASSWORD_ITERATIONS));
    ct_eq(key.as_bytes(), hash_hex.to_lowercase().as_bytes())
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    for p in parts {
        inner.update(p);
    }
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// PBKDF2-HMAC-SHA256 with one 32-byte block, the length the console uses.
fn pbkdf2_sha256(pw: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut u = hmac_sha256(pw, &[salt, &1u32.to_be_bytes()]);
    let mut out = u;
    for _ in 1..iterations {
        u = hmac_sha256(pw, &[&u]);
        for (o, x) in out.iter_mut().zip(u) {
            *o ^= x;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_matches_rfc7914_vector() {
        // RFC 7914 section 11: P="passwd", S="salt", c=1, first 32 bytes.
        assert_eq!(
            hex::encode(pbkdf2_sha256(b"passwd", b"salt", 1)),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
        // RFC 6070-style vector for SHA-256, c=4096.
        assert_eq!(
            hex::encode(pbkdf2_sha256(b"password", b"salt", 4096)),
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
        );
    }

    #[test]
    fn secrets_unlock() {
        let salt = "00112233445566778899aabbccddeeff";
        let hash = hex::encode(pbkdf2_sha256(
            b"S3cret-pass",
            &hex::decode(salt).unwrap(),
            PASSWORD_ITERATIONS,
        ));
        let p = Policy {
            enabled: true,
            token_sha256: hex::encode(Sha256::digest(b"tok")),
            password_salt: salt.into(),
            password_hash: hash.to_uppercase(),
        };
        assert!(p.unlocks("tok"));
        assert!(p.unlocks("S3cret-pass"));
        assert!(!p.unlocks("wrong"));
        assert!(!p.unlocks(""));
    }

    #[test]
    fn maintenance_needs_the_secret() {
        let tmp = tempfile::tempdir().unwrap();
        let p = Policy {
            enabled: true,
            token_sha256: hex::encode(Sha256::digest(b"tok")),
            ..Default::default()
        };
        std::fs::write(tmp.path().join("tamper.json"), serde_json::to_vec(&p).unwrap()).unwrap();
        assert!(enter_maintenance(tmp.path(), &[], "nope", Duration::from_secs(60)).is_err());
        assert!(read_maintenance(tmp.path()).is_none());
        // Reads the Go agent's tamper.json.
        let go = r#"{"enabled":true,"token_sha256":"ab"}"#;
        let gp: Policy = serde_json::from_str(go).unwrap();
        assert!(gp.enabled && gp.token_sha256 == "ab");
    }
}
