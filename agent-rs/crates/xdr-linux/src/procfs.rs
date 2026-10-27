//! Process metadata from /proc, stable process GUIDs and cached file hashes.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use md5::Md5;
use sha1::Sha1;
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
    pub euid: u32,
    pub group: String,
    pub tty: String,
    pub session_id: u32,
    /// audit loginuid: the uid of the original login, kept across sudo/su.
    pub login_uid: u32,
    /// CapEff from /proc/<pid>/status, hex.
    pub cap_eff: String,
    pub pid_ns: u64,
    pub mnt_ns: u64,
    pub net_ns: u64,
    pub exe_uid: u32,
    pub exe_mode: u32,
    /// XDR_CONSOLE_SESSION from the environment: set in console shells.
    pub console_session: String,
}

/// Environment variable that marks processes started from a console shell.
pub const CONSOLE_SESSION_ENV: &str = "XDR_CONSOLE_SESSION";

/// One variable from /proc/<pid>/environ (the environment at exec).
pub fn environ_var(pid: u32, name: &str) -> Option<String> {
    let raw = fs::read(format!("/proc/{pid}/environ")).ok()?;
    let prefix = format!("{name}=");
    raw.split(|b| *b == 0)
        .find_map(|kv| kv.strip_prefix(prefix.as_bytes()))
        .map(|v| String::from_utf8_lossy(v).into_owned())
}

/// The unset audit loginuid.
pub const NO_LOGIN_UID: u32 = u32::MAX;

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
            "Uid" => {
                let mut ids = val.split_whitespace();
                info.uid = ids.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                info.euid = ids.next().and_then(|v| v.parse().ok()).unwrap_or(info.uid);
            }
            "Gid" => info.gid = first.parse().unwrap_or(0),
            "CapEff" => info.cap_eff = first.to_string(),
            _ => {}
        }
    }
    if let Some(st) = stat(pid) {
        info.session_id = st.session;
        info.tty = tty_name(st.tty_nr);
    }
    info.login_uid = fs::read_to_string(format!("{base}/loginuid"))
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(NO_LOGIN_UID);
    info.pid_ns = ns_inode(pid, "pid");
    info.mnt_ns = ns_inode(pid, "mnt");
    info.net_ns = ns_inode(pid, "net");
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
    if let Ok(m) = fs::metadata(&info.exe) {
        info.exe_uid = m.uid();
        info.exe_mode = m.mode();
    }
    info.user = username(info.uid);
    info.group = groupname(info.gid);
    info.console_session = environ_var(pid, CONSOLE_SESSION_ENV).unwrap_or_default();
    Some(info)
}

/// The inode of one of pid's namespaces, e.g. "net:[4026531840]" → 4026531840.
pub fn ns_inode(pid: u32, ns: &str) -> u64 {
    readlink(&format!("/proc/{pid}/ns/{ns}"))
        .rsplit_once('[')
        .and_then(|(_, r)| r.strip_suffix(']'))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

pub struct Stat {
    pub session: u32,
    pub tty_nr: u32,
    pub start_ticks: u64,
}

pub fn stat(pid: u32) -> Option<Stat> {
    parse_stat(&fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

fn parse_stat(s: &str) -> Option<Stat> {
    // The command name may contain spaces; fields follow the last ')'.
    let f: Vec<&str> = s[s.rfind(')')? + 1..].split_whitespace().collect();
    Some(Stat {
        session: f.get(3)?.parse().ok()?,
        tty_nr: f.get(4)?.parse().ok()?,
        start_ticks: f.get(19)?.parse().ok()?,
    })
}

/// Names a controlling terminal from its device number: pts/N, ttyN or ttySN.
pub fn tty_name(nr: u32) -> String {
    if nr == 0 {
        return String::new();
    }
    let major = (nr >> 8) & 0xfff;
    let minor = (nr & 0xff) | ((nr >> 12) & 0xfff00);
    match major {
        136..=143 => format!("pts/{}", minor + (major - 136) * 256),
        4 if minor < 64 => format!("tty{minor}"),
        4 => format!("ttyS{}", minor - 64),
        _ => format!("{major}:{minor}"),
    }
}

/// Resolves a gid to a group name from /etc/group, caching results.
pub fn groupname(gid: u32) -> String {
    static CACHE: OnceLock<Mutex<HashMap<u32, String>>> = OnceLock::new();
    lookup_name(CACHE.get_or_init(Default::default), "/etc/group", gid)
}

pub fn readlink(path: &str) -> String {
    fs::read_link(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Resolves a uid to a login name from /etc/passwd, caching results.
pub fn username(uid: u32) -> String {
    static CACHE: OnceLock<Mutex<HashMap<u32, String>>> = OnceLock::new();
    lookup_name(CACHE.get_or_init(Default::default), "/etc/passwd", uid)
}

fn lookup_name(cache: &Mutex<HashMap<u32, String>>, file: &str, uid: u32) -> String {
    if let Some(n) = cache.lock().unwrap().get(&uid) {
        return n.clone();
    }
    let name = fs::read_to_string(file)
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
    stat(pid).map(|s| s.start_ticks)
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

/// SHA-256, SHA-1 and MD5 of a file, computed in one read.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Hashes {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
}

/// File hashes, reused while size, mtime and inode are unchanged.
pub struct Hasher {
    cache: Mutex<HashMap<HashKey, Hashes>>,
    limit: usize,
}

impl Hasher {
    pub fn new(limit: usize) -> Hasher {
        Hasher {
            cache: Mutex::new(HashMap::new()),
            limit,
        }
    }

    /// SHA-256 only, hex.
    pub fn hash(&self, path: &str) -> String {
        self.hashes(path).sha256
    }

    pub fn hashes(&self, path: &str) -> Hashes {
        // Strip the suffix the kernel appends to replaced binaries.
        let path = path.strip_suffix(" (deleted)").unwrap_or(path);
        let Ok(mut f) = fs::File::open(path) else {
            return Hashes::default();
        };
        let Ok(st) = f.metadata() else {
            return Hashes::default();
        };
        if !st.is_file() || st.len() > MAX_HASH_SIZE {
            return Hashes::default();
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
        let (mut s256, mut s1, mut m5) = (Sha256::new(), Sha1::new(), Md5::new());
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    s256.update(&buf[..n]);
                    s1.update(&buf[..n]);
                    m5.update(&buf[..n]);
                }
                Err(_) => return Hashes::default(),
            }
        }
        let h = Hashes {
            sha256: hex::encode(s256.finalize()),
            sha1: hex::encode(s1.finalize()),
            md5: hex::encode(m5.finalize()),
        };
        let mut c = self.cache.lock().unwrap();
        if c.len() >= self.limit {
            c.clear();
        }
        c.insert(key, h.clone());
        h
    }
}

/// A mounted file system from /proc/self/mountinfo.
#[derive(Debug, Clone, PartialEq)]
pub struct Mount {
    pub point: String,
    pub fstype: String,
}

/// The mount holding path, from a mount table refreshed every 30 seconds.
pub fn mount_of(path: &str) -> Option<Mount> {
    static MOUNTS: OnceLock<Mutex<(Instant, Vec<Mount>)>> = OnceLock::new();
    let m = MOUNTS.get_or_init(|| Mutex::new((Instant::now() - Duration::from_secs(60), Vec::new())));
    let mut m = m.lock().unwrap();
    if m.0.elapsed() > Duration::from_secs(30) {
        m.1 = fs::read_to_string("/proc/self/mountinfo")
            .map(|s| parse_mountinfo(&s))
            .unwrap_or_default();
        m.0 = Instant::now();
    }
    longest_mount(&m.1, path).cloned()
}

fn longest_mount<'a>(mounts: &'a [Mount], path: &str) -> Option<&'a Mount> {
    mounts
        .iter()
        .filter(|m| {
            m.point == "/" || path == m.point || path.strip_prefix(m.point.as_str()).is_some_and(|r| r.starts_with('/'))
        })
        .max_by_key(|m| m.point.len())
}

pub fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|l| {
            // "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw"
            let (left, right) = l.split_once(" - ")?;
            let point = left.split_whitespace().nth(4)?.replace("\\040", " ");
            let fstype = right.split_whitespace().next()?.to_string();
            Some(Mount { point, fstype })
        })
        .collect()
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
        assert!(info.pid_ns > 0 && info.net_ns > 0);
        assert!(!info.group.is_empty());
    }

    #[test]
    fn decodes_stat_and_tty() {
        let st = parse_stat("42 (a b) S 1 42 42 34816 42 4194560 1 0 0 0 0 0 0 0 20 0 1 0 777 0").unwrap();
        assert_eq!((st.session, st.tty_nr, st.start_ticks), (42, 34816, 777));
        assert_eq!(tty_name(34816), "pts/0");
        assert_eq!(tty_name(1025), "tty1");
        assert_eq!(tty_name(0), "");
    }

    #[test]
    fn finds_mount() {
        let m = parse_mountinfo(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 0:5 / /proc rw - proc proc rw\n3 1 0:6 / /tmp rw - tmpfs tmpfs rw\n",
        );
        assert_eq!(longest_mount(&m, "/tmp/x").unwrap().fstype, "tmpfs");
        assert_eq!(longest_mount(&m, "/tmpx").unwrap().fstype, "ext4");
        assert_eq!(longest_mount(&m, "/etc/passwd").unwrap().point, "/");
    }

    #[test]
    fn hashes_in_one_pass() {
        let dir = std::env::temp_dir().join(format!("xdr-hash-{}", std::process::id()));
        fs::write(&dir, b"abc").unwrap();
        let h = Hasher::new(10).hashes(dir.to_str().unwrap());
        fs::remove_file(&dir).unwrap();
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(h.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert!(h.sha256.starts_with("ba7816bf"));
    }
}
