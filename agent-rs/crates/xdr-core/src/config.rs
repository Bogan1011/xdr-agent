use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// Agent configuration from /etc/xdr-agent/agent.yaml, as written by the
/// installer. Unknown keys are ignored.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: String,
    pub enroll_server: String,
    pub server_name: String,
    pub ca_file: PathBuf,
    pub enrollment_token: String,
    pub state_dir: PathBuf,
    pub file_paths: Vec<String>,
    pub file_exclude: Vec<String>,
    pub max_file_watches: usize,
    #[serde(deserialize_with = "duration")]
    pub network_interval: Duration,
    /// Byte budget of the on-disk event queue.
    pub queue_bytes: u64,
    /// Free disk space the queue never eats into; it shrinks below
    /// queue_bytes when the state directory's filesystem runs low.
    pub queue_disk_reserve_bytes: u64,
    pub batch_size: usize,
    pub log_level: String,
    /// Refuses remote shells from the console on this host.
    pub disable_remote_shell: bool,
    /// "off" keeps the inotify and /proc collectors even where eBPF works.
    pub ebpf: String,
    /// Largest file the YARA scanner reads.
    pub scan_max_bytes: u64,
    /// The agent restarts itself when its resident memory stays above this
    /// for a minute (a leak or runaway buffer); 0 turns the check off.
    pub max_memory_bytes: u64,
    /// The file this was loaded from.
    #[serde(skip)]
    pub config_path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server: String::new(),
            enroll_server: String::new(),
            server_name: String::new(),
            ca_file: "/etc/xdr-agent/ca.crt".into(),
            enrollment_token: String::new(),
            state_dir: "/var/lib/xdr-agent".into(),
            file_paths: [
                "/etc",
                "/usr/bin",
                "/usr/sbin",
                "/usr/local/bin",
                "/usr/local/sbin",
                "/bin",
                "/sbin",
                "/tmp",
                "/var/tmp",
                "/dev/shm",
                "/root",
                "/home",
                "/var/www",
                "/var/spool/cron",
                "/lib/systemd/system",
                "/etc/systemd/system",
            ]
            .map(String::from)
            .to_vec(),
            file_exclude: ["/var/lib/xdr-agent", "/etc/ld.so.cache"].map(String::from).to_vec(),
            max_file_watches: 8192,
            network_interval: Duration::from_secs(5),
            queue_bytes: 256 << 20,
            queue_disk_reserve_bytes: 512 << 20,
            batch_size: 500,
            log_level: "info".into(),
            disable_remote_shell: false,
            ebpf: String::new(),
            scan_max_bytes: 32 << 20,
            max_memory_bytes: 1 << 30,
            config_path: PathBuf::new(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let mut c: Config = serde_yaml_ng::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
        if c.server.is_empty() {
            bail!("{}: server is required", path.display());
        }
        if c.enroll_server.is_empty() {
            bail!("{}: enroll_server is required", path.display());
        }
        c.config_path = path.to_path_buf();
        Ok(c)
    }

    pub fn state_path(&self, name: &str) -> PathBuf {
        self.state_dir.join(name)
    }

    /// The name checked on the server certificate: server_name, else the host
    /// part of `addr`.
    pub fn tls_name(&self, addr: &str) -> String {
        if !self.server_name.is_empty() {
            return self.server_name.clone();
        }
        host_of(addr).to_string()
    }
}

fn host_of(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    addr.rsplit_once(':').map_or(addr, |(h, _)| h)
}

/// Parses Go-style durations such as "5s", "500ms", "2m" or "1h".
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit() && c != '.')?;
    let (num, unit) = s.split_at(split);
    let n: f64 = num.parse().ok()?;
    let secs = match unit {
        "ms" => n / 1000.0,
        "s" => n,
        "m" => n * 60.0,
        "h" => n * 3600.0,
        _ => return None,
    };
    Some(Duration::from_secs_f64(secs))
}

fn duration<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    let s = String::deserialize(d)?;
    parse_duration(&s).ok_or_else(|| serde::de::Error::custom(format!("invalid duration {s:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_config() {
        let c: Config = serde_yaml_ng::from_str(
            "server: 10.0.0.1:8444\nenroll_server: 10.0.0.1:8443\nnetwork_interval: 10s\nebpf: auto\n",
        )
        .unwrap();
        assert_eq!(c.network_interval, Duration::from_secs(10));
        assert_eq!(c.tls_name(&c.server), "10.0.0.1");
        assert_eq!(c.max_file_watches, 8192);
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(host_of("[::1]:8444"), "::1");
    }
}
