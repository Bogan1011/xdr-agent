//! Self-update. The console sends the version and SHA-256 it offers; the
//! agent downloads the binary over its mTLS connection, checks the hash and
//! that the binary reports that version, swaps it in and restarts so systemd
//! starts the new one. The new binary must reach the console within
//! CONFIRM_TIMEOUT and within MAX_STARTS starts, or the previous binary is put
//! back. The state file matches the Go agent's, so a Go-to-Rust update is
//! confirmed the same way.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tonic::transport::Channel;

use crate::pb::{self, agent_service_client::AgentServiceClient};

const MAX_BINARY_SIZE: u64 = 200 << 20;
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(180);
const MAX_STARTS: u32 = 3;

#[derive(Serialize, Deserialize, Default, Debug)]
struct Pending {
    from: String,
    to: String,
    #[serde(default)]
    starts: u32,
    /// RFC 3339 from the Go agent, Unix seconds from this one.
    #[serde(default)]
    started: serde_json::Value,
    #[serde(default)]
    rolled_back: bool,
}

pub struct Updater {
    dir: PathBuf,
    exe: PathBuf,
    confirmed: AtomicBool,
}

impl Updater {
    pub fn new(state_dir: &Path) -> Self {
        Updater {
            dir: state_dir.join("update"),
            exe: current_exe(),
            confirmed: AtomicBool::new(false),
        }
    }

    fn pending_path(&self) -> PathBuf {
        self.dir.join("pending.json")
    }

    fn prev_path(&self) -> PathBuf {
        self.dir.join("xdr-agent.prev")
    }

    fn load(&self) -> Option<Pending> {
        serde_json::from_slice(&fs::read(self.pending_path()).ok()?).ok()
    }

    fn save(&self, p: &Pending) -> Result<()> {
        fs::create_dir_all(&self.dir)?;
        fs::write(self.pending_path(), serde_json::to_vec(p)?)?;
        Ok(())
    }

    fn clear(&self) {
        let _ = fs::remove_file(self.pending_path());
        let _ = fs::remove_file(self.prev_path());
    }

    /// Runs at start. After an update it counts starts of the new binary and
    /// arms the rollback timer; `confirm` disarms it.
    pub fn check(self: &Arc<Self>) {
        let Some(mut p) = self.load() else { return };
        if p.to != crate::VERSION {
            // The old binary is running again: a rollback, or a manual reinstall.
            tracing::warn!(from = %p.from, to = %p.to, running = crate::VERSION, rolled_back = p.rolled_back,
                "agent update did not stick");
            self.clear();
            return;
        }
        p.starts += 1;
        let _ = self.save(&p);
        if p.starts > MAX_STARTS {
            self.rollback(
                p,
                &format!("version {} failed to start {MAX_STARTS} times", crate::VERSION),
            );
            return;
        }
        tracing::info!(from = %p.from, to = %p.to, "running updated agent, waiting to reach the console");
        let this = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(CONFIRM_TIMEOUT).await;
            if !this.confirmed.load(Ordering::SeqCst) {
                let reason = format!(
                    "version {} did not reach the console within {CONFIRM_TIMEOUT:?}",
                    crate::VERSION
                );
                if let Some(p) = this.load() {
                    this.rollback(p, &reason);
                }
            }
        });
    }

    /// Called after each successful heartbeat.
    pub fn confirm(&self) {
        if self.confirmed.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(p) = self.load().filter(|p| p.to == crate::VERSION) {
            tracing::info!(from = %p.from, to = %p.to, "agent update confirmed");
            self.clear();
        }
    }

    /// Puts the previous binary back and exits; systemd starts it.
    fn rollback(&self, mut p: Pending, reason: &str) {
        tracing::error!(reason, to = %p.from, "rolling back agent update");
        if let Err(err) = replace(&self.exe, &self.prev_path()) {
            tracing::error!("rollback failed, keeping the new binary: {err:#}");
            return;
        }
        p.rolled_back = true;
        let _ = self.save(&p);
        std::process::exit(1);
    }

    /// Downloads, verifies and installs the offered version. On success the
    /// caller reports the result and restarts the agent.
    pub async fn update(
        &self,
        client: &AgentServiceClient<Channel>,
        arch: &str,
        want: &str,
        sum: &str,
    ) -> Result<String> {
        let sum = sum.to_ascii_lowercase();
        if want.is_empty() || sum.len() != 64 {
            bail!("version and sha256 are required");
        }
        if want == crate::VERSION {
            return Ok(format!("already running {want}"));
        }
        fs::create_dir_all(&self.dir)?;
        fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))?;
        let staged = self.dir.join("xdr-agent.new");
        if let Err(err) = download(client.clone(), arch, &staged, &sum).await {
            let _ = fs::remove_file(&staged);
            return Err(err);
        }
        let out = tokio::time::timeout(
            Duration::from_secs(15),
            tokio::process::Command::new(&staged).arg("-version").output(),
        )
        .await;
        let got = match &out {
            Ok(Ok(o)) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => String::new(),
        };
        if got != want {
            let _ = fs::remove_file(&staged);
            bail!("downloaded binary does not run or reports version {got:?}, want {want:?}");
        }
        fs::copy(&self.exe, self.prev_path()).context("back up current binary")?;
        replace(&self.exe, &staged)?;
        let _ = fs::remove_file(&staged);
        self.save(&Pending {
            from: crate::VERSION.into(),
            to: want.into(),
            started: unix_now().into(),
            ..Default::default()
        })?;
        Ok(format!("installed {want} (was {}), restarting", crate::VERSION))
    }
}

async fn download(mut client: AgentServiceClient<Channel>, arch: &str, path: &Path, sum: &str) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o700)
        .open(path)?;
    let mut h = Sha256::new();
    let mut off = 0u64;
    loop {
        let mut tries = 0u64;
        let chunk = loop {
            let mut req = tonic::Request::new(pb::AgentBinaryRequest {
                arch: arch.into(),
                offset: off,
            });
            req.set_timeout(Duration::from_secs(60));
            match client.get_agent_binary(req).await {
                Ok(r) => break r.into_inner(),
                Err(status) if tries < 3 => {
                    tries += 1;
                    tracing::warn!(offset = off, msg = status.message(), "agent download failed, retrying");
                    tokio::time::sleep(Duration::from_secs(2 * tries)).await;
                }
                Err(status) => return Err(anyhow!("download at offset {off}: {}", status.message())),
            }
        };
        if chunk.total_size > MAX_BINARY_SIZE {
            bail!("binary is {} bytes, larger than allowed", chunk.total_size);
        }
        f.write_all(&chunk.data)?;
        h.update(&chunk.data);
        off += chunk.data.len() as u64;
        if off >= chunk.total_size {
            break;
        }
        if chunk.data.is_empty() {
            bail!("download stalled at offset {off}");
        }
    }
    f.sync_all()?;
    let got = hex::encode(h.finalize());
    if got != sum {
        bail!("checksum mismatch: got {got}, console offered {sum}");
    }
    Ok(())
}

/// Swaps src in at exe atomically.
fn replace(exe: &Path, src: &Path) -> Result<()> {
    let mut tmp = exe.as_os_str().to_owned();
    tmp.push(".new");
    let tmp = PathBuf::from(tmp);
    fs::copy(src, &tmp).with_context(|| format!("copy to {}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
    if let Err(err) = fs::rename(&tmp, exe) {
        let _ = fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("replace {}", exe.display()));
    }
    Ok(())
}

/// The running binary's path, also after it was replaced on disk.
fn current_exe() -> PathBuf {
    let p = std::env::current_exe().unwrap_or_else(|_| "/usr/local/bin/xdr-agent".into());
    match p.to_str().and_then(|s| s.strip_suffix(" (deleted)")) {
        Some(s) => PathBuf::from(s),
        None => p,
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn updater(dir: &Path) -> Updater {
        Updater {
            dir: dir.join("update"),
            exe: dir.join("xdr-agent"),
            confirmed: AtomicBool::new(false),
        }
    }

    #[test]
    fn reads_go_pending_file_and_confirms() {
        let tmp = tempfile::tempdir().unwrap();
        let u = updater(tmp.path());
        fs::create_dir_all(&u.dir).unwrap();
        let go = format!(
            r#"{{"from":"0.9.1","to":"{}","starts":1,"started":"2026-10-27T12:00:00Z","rolled_back":false}}"#,
            crate::VERSION
        );
        fs::write(u.pending_path(), go).unwrap();
        fs::write(u.prev_path(), b"old").unwrap();
        assert_eq!(u.load().unwrap().from, "0.9.1");
        u.confirm();
        assert!(!u.pending_path().exists() && !u.prev_path().exists());
    }

    #[test]
    fn replace_swaps_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = tmp.path().join("xdr-agent");
        let new = tmp.path().join("new");
        fs::write(&exe, b"old").unwrap();
        fs::write(&new, b"new").unwrap();
        replace(&exe, &new).unwrap();
        assert_eq!(fs::read(&exe).unwrap(), b"new");
        assert_eq!(fs::metadata(&exe).unwrap().permissions().mode() & 0o777, 0o755);
    }

    #[tokio::test]
    async fn rejects_bad_arguments_and_same_version() {
        let tmp = tempfile::tempdir().unwrap();
        let u = updater(tmp.path());
        let ch = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        let c = AgentServiceClient::new(ch);
        assert!(u.update(&c, "amd64", "", "x").await.is_err());
        let ok = u.update(&c, "amd64", crate::VERSION, &"a".repeat(64)).await.unwrap();
        assert!(ok.starts_with("already running"));
    }
}
