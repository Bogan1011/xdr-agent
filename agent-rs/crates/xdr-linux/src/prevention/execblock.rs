//! Exec blocking: denies execution of files whose SHA-256 is a hash IOC from
//! the detection content, or that an application control rule (block lists,
//! lockdown allow-list) stops. It uses fanotify exec permission events
//! (FAN_OPEN_EXEC_PERM, Linux 5.0+) on every local filesystem.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use xdr_core::bus::new_event;
use xdr_core::pb::{self, EventType};

use super::fanotify::{
    FAN_MARK_ADD, FAN_MARK_FILESYSTEM, FAN_MARK_MOUNT, FAN_OPEN_EXEC_PERM, Fanotify, Request, unescape_mount,
};
use super::{Emitter, app_control_event, policy};
use crate::procfs;

/// Pseudo and network filesystems are not marked: nothing worth blocking
/// runs from the former, and a slow server on the latter would stall every
/// exec.
const SKIP_FS: &[&str] = &[
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "devpts",
    "mqueue",
    "debugfs",
    "tracefs",
    "securityfs",
    "pstore",
    "bpf",
    "configfs",
    "fusectl",
    "hugetlbfs",
    "autofs",
    "binfmt_misc",
    "rpc_pipefs",
    "nsfs",
    "efivarfs",
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "9p",
];
const WORKERS: usize = 4;
const MAX_CACHE: usize = 20_000;

#[derive(Hash, PartialEq, Eq)]
struct FileKey {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    ctime: i64,
}

#[derive(Default)]
struct Rules {
    hashes: HashSet<[u8; 32]>,
    /// Enforce the hash IOCs.
    iocs: bool,
    /// Application control rules in block mode.
    app: Option<pb::ApplicationControlPolicy>,
}

pub struct ExecBlocker {
    emit: Emitter,
    max_bytes: u64,
    /// The agent's state directory (root only), where self-update stages and
    /// test-runs the new binary; application control does not apply there.
    trusted: [String; 1],
    rules: RwLock<Rules>,
    cache: Mutex<HashMap<FileKey, [u8; 32]>>,
    /// Set while a fanotify group is marked and answering.
    pub active: AtomicBool,
    pub error: Mutex<String>,
    stop: Mutex<Option<Arc<AtomicBool>>>,
}

impl ExecBlocker {
    pub fn new(emit: Emitter, max_bytes: u64, trusted: String) -> Self {
        ExecBlocker {
            emit,
            max_bytes,
            trusted: [trusted],
            rules: RwLock::new(Rules {
                iocs: true,
                ..Default::default()
            }),
            cache: Mutex::new(HashMap::new()),
            active: AtomicBool::new(false),
            error: Mutex::new(String::new()),
            stop: Mutex::new(None),
        }
    }

    /// Replaces the block list with concatenated 32-byte digests.
    pub fn set_hashes(&self, raw: &[u8]) -> usize {
        let set: HashSet<[u8; 32]> = raw.chunks_exact(32).map(|c| c.try_into().unwrap()).collect();
        let n = set.len();
        self.rules.write().unwrap().hashes = set;
        n
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.rules.read().unwrap().hashes.len()
    }

    /// Chooses what is enforced: the hash IOCs, and application control
    /// rules in block mode (None for none).
    pub fn set_rules(&self, iocs: bool, app: Option<pb::ApplicationControlPolicy>) {
        let mut r = self.rules.write().unwrap();
        r.iocs = iocs;
        r.app = app;
    }

    /// Whether any rule would block something.
    pub fn enforcing(&self) -> bool {
        let r = self.rules.read().unwrap();
        (r.iocs && !r.hashes.is_empty()) || r.app.is_some()
    }

    /// Starts or stops enforcement to match the rules.
    pub fn reconcile(self: &Arc<Self>) {
        let want = self.enforcing();
        let mut stop = self.stop.lock().unwrap();
        if want == stop.is_some() {
            return;
        }
        if let Some(s) = stop.take() {
            s.store(true, Ordering::Relaxed);
            tracing::info!("exec blocking stopped");
            return;
        }
        let flag = Arc::new(AtomicBool::new(false));
        *stop = Some(flag.clone());
        self.error.lock().unwrap().clear();
        let this = self.clone();
        std::thread::Builder::new()
            .name("exec-block".into())
            .spawn(move || {
                let res = this.run(&flag);
                this.active.store(false, Ordering::Relaxed);
                if let Err(err) = res {
                    tracing::error!("exec blocking unavailable: {err:#}");
                    *this.error.lock().unwrap() = format!("{err:#}");
                    // Retried on the next policy or block list change.
                    let mut stop = this.stop.lock().unwrap();
                    if stop.as_ref().is_some_and(|s| Arc::ptr_eq(s, &flag)) {
                        *stop = None;
                    }
                }
            })
            .expect("spawn exec-block thread");
    }

    fn run(self: &Arc<Self>, stop: &AtomicBool) -> Result<()> {
        let fan = Arc::new(Fanotify::new()?);
        let mut marked = HashSet::new();
        if mark_mounts(&fan, &mut marked)? == 0 {
            bail!("no filesystem could be marked for exec permission events");
        }
        self.active.store(true, Ordering::Relaxed);
        tracing::info!(hashes = self.len(), filesystems = marked.len(), "exec blocking active");
        let (tx, rx) = mpsc::sync_channel::<Request>(256);
        let rx = Arc::new(Mutex::new(rx));
        for _ in 0..WORKERS {
            let (rx, fan, this) = (rx.clone(), fan.clone(), self.clone());
            std::thread::spawn(move || {
                loop {
                    let Ok(r) = rx.lock().unwrap().recv() else { return };
                    this.handle(&fan, r);
                }
            });
        }
        let mut buf = vec![0u8; 64 * 24];
        let mut remark = Instant::now();
        while let Some(reqs) = fan.read(&mut buf, stop)? {
            for r in reqs {
                let _ = tx.send(r);
            }
            // Containers and new mounts bring new filesystems.
            if remark.elapsed() > Duration::from_secs(60) {
                let _ = mark_mounts(&fan, &mut marked);
                remark = Instant::now();
            }
        }
        Ok(())
    }

    fn handle(&self, fan: &Fanotify, r: Request) {
        let (pid, me) = (r.pid, r.pid == std::process::id());
        let (mut allow, mut sha, mut path, mut rule) = (true, None, String::new(), None);
        if !me {
            let rules = self.rules.read().unwrap();
            let iocs = rules.iocs && !rules.hashes.is_empty();
            if rules.app.is_some() {
                path = r.path();
            }
            if iocs || rules.app.as_ref().is_some_and(|a| policy::app_needs_hash(a, &path)) {
                sha = self.hash(&r);
            }
            if iocs && sha.is_some_and(|s| rules.hashes.contains(&s)) {
                allow = false;
            } else if let Some(app) = &rules.app
                && !policy::matches(&path, &self.trusted)
            {
                let hex = sha.map(hex::encode).unwrap_or_default();
                rule = policy::app_rule(app, &path, &hex);
                allow = rule.is_none();
            }
        }
        if allow {
            fan.answer(r, true);
            return;
        }
        if path.is_empty() {
            path = r.path();
        }
        fan.answer(r, false);
        let sha = sha.map(hex::encode).unwrap_or_default();
        match rule {
            Some(rule) => {
                tracing::warn!(path, rule, pid, "execution blocked by application control");
                self.emit.emit(app_control_event("blocked", &path, &sha, &rule, pid));
            }
            None => self.report(&path, pid, &sha),
        }
    }

    /// The file's SHA-256, cached by identity and change times so a binary
    /// that runs often is read once.
    fn hash(&self, r: &Request) -> Option<[u8; 32]> {
        let f = r.file();
        let st = f.metadata().ok()?;
        if !st.is_file() || (self.max_bytes > 0 && st.len() > self.max_bytes) {
            return None;
        }
        let key = FileKey {
            dev: st.dev(),
            ino: st.ino(),
            size: st.len(),
            mtime: st.mtime() * 1_000_000_000 + st.mtime_nsec(),
            ctime: st.ctime() * 1_000_000_000 + st.ctime_nsec(),
        };
        if let Some(s) = self.cache.lock().unwrap().get(&key) {
            return Some(*s);
        }
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 64 << 10];
        let mut off = 0u64;
        loop {
            let n = f.read_at(&mut buf, off).ok()?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            off += n as u64;
        }
        let sum: [u8; 32] = h.finalize().into();
        let mut c = self.cache.lock().unwrap();
        if c.len() >= MAX_CACHE {
            c.clear();
        }
        c.insert(key, sum);
        Some(sum)
    }

    fn report(&self, path: &str, pid: u32, sha: &str) {
        let mut pe = pb::ProcessEvent {
            pid,
            exe: path.into(),
            sha256: sha.into(),
            ..Default::default()
        };
        if let Some(i) = procfs::read(pid) {
            (pe.ppid, pe.uid, pe.gid, pe.user, pe.parent_exe, pe.cwd) = (i.ppid, i.uid, i.gid, i.user, i.exe, i.cwd);
        }
        tracing::warn!(path, sha256 = sha, pid, caller = %pe.parent_exe, "execution blocked");
        let mut e = new_event(EventType::ExecBlocked);
        e.payload = Some(pb::event::Payload::Process(pe));
        self.emit.emit(e);
    }
}

/// Adds a filesystem mark for every mounted filesystem not yet marked,
/// falling back to a mount mark on kernels without FAN_MARK_FILESYSTEM.
fn mark_mounts(fan: &Fanotify, marked: &mut HashSet<String>) -> Result<usize> {
    let mounts = std::fs::read_to_string("/proc/self/mounts")?;
    let (mut added, mut last_err) = (0, None);
    for line in mounts.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 {
            continue;
        }
        let (dir, fstype) = (unescape_mount(f[1]), f[2]);
        if marked.contains(&dir) || SKIP_FS.contains(&fstype) || fstype.starts_with("fuse") {
            continue;
        }
        let mut res = fan.mark(&dir, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_OPEN_EXEC_PERM);
        if res.as_ref().is_err_and(|e| e.raw_os_error() == Some(libc::EINVAL)) {
            res = fan.mark(&dir, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN_EXEC_PERM);
        }
        match res {
            Ok(()) => {
                marked.insert(dir);
                added += 1;
            }
            Err(e) if dir == "/" => {
                bail!("fanotify_mark /: {e} (exec blocking needs Linux 5.0 or later with fanotify permission events)")
            }
            Err(e) => last_err = Some(format!("fanotify_mark {dir}: {e}")),
        }
    }
    if added == 0
        && marked.is_empty()
        && let Some(e) = last_err
    {
        bail!(e);
    }
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_list_and_rules_decide_enforcement() {
        let b = ExecBlocker::new(Emitter::default(), 0, "/var/lib/xdr-agent".into());
        assert!(!b.enforcing());
        assert_eq!(b.set_hashes(&[7u8; 64]), 1);
        assert!(b.enforcing());
        b.set_rules(false, None);
        assert!(!b.enforcing());
        b.set_rules(false, Some(Default::default()));
        assert!(b.enforcing());
    }
}
