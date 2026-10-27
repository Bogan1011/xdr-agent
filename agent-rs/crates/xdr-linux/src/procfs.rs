//! Process metadata from /proc, stable process GUIDs and cached file hashes.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::sync::{Mutex, OnceLock};

use sha2::{Digest, Sha256};

/// Largest file the agent hashes (64 MiB), as in the Go agent.
pub const MAX_HASH_SIZE: u64 = 64 << 20;
/// USER_HZ is 100 on every architecture we ship.
const CLOCK_TICKS: i64 = 100;

#[derive(Debug, Default, Clone)]
pub struct Info {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub user: String,
    pub exe: String,
    pub args: Vec<String>,
    pub cwd: String,
}

/// What /proc knows about pid; None once the process has exited.
pub fn read(pid: u32) -> Option<Info> {
    let base = format!("/proc/{pid}");
    let status = fs::read_to_string(format!("{base}/status")).ok()?;
    let mut info = Info {
        pid,
        ..Default::default()
    };
    for line in status.lines() {
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let first = val.split_whitespace().next().unwrap_or("");
        match key {
            "PPid" => info.ppid = first.parse().unwrap_or(0),
            "Uid" => info.uid = first.parse().unwrap_or(0),
            "Gid" => info.gid = first.parse().unwrap_or(0),
            _ => {}
        }
    }
    info.exe = readlink(&format!("{base}/exe"));
    info.cwd = readlink(&format!("{base}/cwd"));
    if let Ok(raw) = fs::read(format!("{base}/cmdline")) {
        let raw = raw.strip_suffix(&[0]).unwrap_or(&raw);
        if !raw.is_empty() {
            info.args = raw
                .split(|b| *b == 0)
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect();
        }
    }
    info.user = username(info.uid);
    Some(info)
}

pub fn readlink(path: &str) -> String {
    fs::read_link(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Resolves a uid to a login name from /etc/passwd, caching results.
pub fn username(uid: u32) -> String {
    static CACHE: OnceLock<Mutex<HashMap<u32, String>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(n) = cache.lock().unwrap().get(&uid) {
        return n.clone();
    }
    let name = fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|p| {
            p.lines().find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.len() > 2 && f[2] == uid.to_string()).then(|| f[0].to_string())
            })
        })
        .unwrap_or_else(|| uid.to_string());
    cache.lock().unwrap().insert(uid, name.clone());
    name
}

struct Boot {
    id: String,
    time: i64,
}

fn boot() -> &'static Boot {
    static BOOT: OnceLock<Boot> = OnceLock::new();
    BOOT.get_or_init(|| Boot {
        id: fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
        time: fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("btime ").and_then(|v| v.trim().parse().ok()))
            })
            .unwrap_or(0),
    })
}

/// Start time in clock ticks since boot, field 22 of /proc/<pid>/stat.
pub fn start_ticks(pid: u32) -> Option<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name may contain spaces; fields follow the last ')'.
    let rest = &s[s.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

pub fn start_time_unix_nano(ticks: u64) -> i64 {
    let b = boot();
    if b.time == 0 {
        return 0;
    }
    b.time * 1_000_000_000 + ticks as i64 * (1_000_000_000 / CLOCK_TICKS)
}

/// Stable process identity, identical to the Go agent's
/// (docs/architecture.md): SHA-256("<boot_id>/<pid>/<start_ticks>"), first 16
/// bytes formatted like a UUID.
pub fn process_guid(pid: u32, start_ticks: u64) -> String {
    guid_for(&boot().id, pid, start_ticks)
}

fn guid_for(boot_id: &str, pid: u32, start_ticks: u64) -> String {
    let sum = Sha256::digest(format!("{boot_id}/{pid}/{start_ticks}").as_bytes());
    let h = hex::encode(&sum[..16]);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[derive(Hash, PartialEq, Eq)]
struct HashKey {
    path: String,
    size: u64,
    mtime: i64,
    mtime_ns: i64,
    ino: u64,
}

/// SHA-256 of files, reused while size, mtime and inode are unchanged.
pub struct Hasher {
    cache: Mutex<HashMap<HashKey, String>>,
    limit: usize,
}

impl Hasher {
    pub fn new(limit: usize) -> Hasher {
        Hasher {
            cache: Mutex::new(HashMap::new()),
            limit,
        }
    }

    pub fn hash(&self, path: &str) -> String {
        // Strip the suffix the kernel appends to replaced binaries.
        let path = path.strip_suffix(" (deleted)").unwrap_or(path);
        let Ok(mut f) = fs::File::open(path) else {
            return String::new();
        };
        let Ok(st) = f.metadata() else {
            return String::new();
        };
        if !st.is_file() || st.len() > MAX_HASH_SIZE {
            return String::new();
        }
        let key = HashKey {
            path: path.to_string(),
            size: st.len(),
            mtime: st.mtime(),
            mtime_ns: st.mtime_nsec(),
            ino: st.ino(),
        };
        if let Some(h) = self.cache.lock().unwrap().get(&key) {
            return h.clone();
        }
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buf[..n]),
                Err(_) => return String::new(),
            }
        }
        let h = hex::encode(hasher.finalize());
        let mut c = self.cache.lock().unwrap();
        if c.len() >= self.limit {
            c.clear();
        }
        c.insert(key, h.clone());
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_matches_go_derivation() {
        // Same input as the Go agent: sha256("b/1/2")[:16] in 8-4-4-4-12 form.
        let g = guid_for("b", 1, 2);
        let sum = hex::encode(&Sha256::digest(b"b/1/2")[..16]);
        assert_eq!(g.replace('-', ""), sum);
        assert_eq!(g.len(), 36);
        // Shared vector with internal/agent/procfs/guid_test.go.
        assert_eq!(g, "ff16d78f-6c31-9e86-59f9-c481be0a2194");
    }

    #[test]
    fn reads_self() {
        let pid = std::process::id();
        let info = read(pid).expect("own /proc entry");
        assert!(!info.exe.is_empty());
        let t = start_ticks(pid).expect("start ticks");
        assert_eq!(process_guid(pid, t), process_guid(pid, start_ticks(pid).unwrap()));
        assert!(start_time_unix_nano(t) > 0);
    }
}
