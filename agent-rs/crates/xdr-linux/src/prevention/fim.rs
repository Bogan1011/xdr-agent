//! File integrity monitoring: a baseline of the monitored files' hashes,
//! owners and modes, compared on file events under the monitored paths (after
//! a short debounce) and on a full rescan every interval. The baseline
//! changes only when the console asks for a new one, so drift stays visible
//! until someone accepts it. The state file matches the Go agent's.

use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use xdr_core::bus::new_event;
use xdr_core::pb::{self, EventType};

use super::{Emitter, policy};

const MAX_FILES: usize = 200_000;
/// Bytes hashed per file; larger files are compared by their first bytes
/// plus size and change time.
const MAX_HASH: u64 = 512 << 20;
/// Groups the file events of one change (write, chmod, rename).
const DEBOUNCE: Duration = Duration::from_secs(2);

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
pub struct Entry {
    #[serde(rename = "h", default, skip_serializing_if = "String::is_empty")]
    sha256: String,
    #[serde(rename = "l", default, skip_serializing_if = "String::is_empty")]
    link: String,
    #[serde(rename = "m")]
    mode: u32,
    #[serde(rename = "u")]
    uid: u32,
    #[serde(rename = "g")]
    gid: u32,
    #[serde(rename = "s")]
    size: i64,
    #[serde(rename = "i")]
    ino: u64,
    #[serde(rename = "c")]
    ctime: i64,
    #[serde(rename = "x", default, skip_serializing_if = "std::ops::Not::not")]
    removed: bool,
}

impl Entry {
    fn removed() -> Entry {
        Entry {
            removed: true,
            ..Default::default()
        }
    }

    /// Same content, permissions and owner. Inode and change time only
    /// decide whether to re-hash.
    fn same(&self, o: &Entry) -> bool {
        self.removed == o.removed
            && self.sha256 == o.sha256
            && self.link == o.link
            && self.mode == o.mode
            && self.uid == o.uid
            && self.gid == o.gid
    }
}

#[derive(Serialize, Deserialize, Default)]
struct State {
    #[serde(default)]
    roots: Vec<String>,
    #[serde(default)]
    baseline: BTreeMap<String, Entry>,
    /// The last drift reported per path, so one change raises one event
    /// however many scans see it.
    #[serde(default)]
    reported: BTreeMap<String, Entry>,
}

enum Msg {
    Policy,
    Rebaseline(mpsc::Sender<Result<usize>>),
}

struct Inner {
    policy: Option<pb::FimPolicy>,
    pending: HashSet<String>,
}

pub struct Fim {
    emit: Emitter,
    file: PathBuf,
    inner: Mutex<Inner>,
    /// Held while scanning, so the heartbeat reads the counters instead.
    st: Mutex<Option<State>>,
    files: AtomicUsize,
    has_baseline: AtomicBool,
    tx: mpsc::SyncSender<Msg>,
    rx: Mutex<Option<mpsc::Receiver<Msg>>>,
}

impl Fim {
    pub fn new(emit: Emitter, file: PathBuf) -> Self {
        let (tx, rx) = mpsc::sync_channel(4);
        let st = std::fs::read(&file)
            .ok()
            .and_then(|raw| match serde_json::from_slice::<State>(&raw) {
                Ok(s) => Some(s),
                Err(err) => {
                    tracing::warn!("FIM baseline unreadable, a new one will be recorded: {err}");
                    None
                }
            });
        Fim {
            emit,
            file,
            inner: Mutex::new(Inner {
                policy: None,
                pending: HashSet::new(),
            }),
            files: AtomicUsize::new(st.as_ref().map_or(0, |s| s.baseline.len())),
            has_baseline: AtomicBool::new(st.is_some()),
            st: Mutex::new(st),
            tx,
            rx: Mutex::new(Some(rx)),
        }
    }

    /// Applies a new policy; a change triggers a rescan.
    pub fn set_policy(&self, p: &pb::FimPolicy) {
        let mut i = self.inner.lock().unwrap();
        if i.policy.as_ref() == Some(p) {
            return;
        }
        i.policy = Some(p.clone());
        drop(i);
        let _ = self.tx.try_send(Msg::Policy);
    }

    fn active(&self) -> Option<pb::FimPolicy> {
        let i = self.inner.lock().unwrap();
        i.policy.clone().filter(|p| p.enabled && !p.paths.is_empty())
    }

    /// Whether FIM runs and how many files the baseline holds.
    pub fn status(&self) -> (bool, usize) {
        let on = self.inner.lock().unwrap().policy.as_ref().is_some_and(|p| p.enabled);
        (
            on && self.has_baseline.load(Ordering::Relaxed),
            self.files.load(Ordering::Relaxed),
        )
    }

    /// Queues a changed path for a check against the baseline.
    pub fn notify(&self, path: &str) {
        if path.is_empty() {
            return;
        }
        let mut i = self.inner.lock().unwrap();
        if i.pending.len() > 10_000 || !i.policy.as_ref().is_some_and(|p| p.enabled && covered(p, path)) {
            return;
        }
        i.pending.insert(path.to_string());
    }

    /// Accepts the current state of the monitored files. Blocks.
    pub fn rebaseline(&self) -> Result<String> {
        if self.active().is_none() {
            bail!("file integrity monitoring is not enabled on this endpoint");
        }
        let (tx, rx) = mpsc::channel();
        self.tx.send(Msg::Rebaseline(tx))?;
        let n = rx.recv_timeout(Duration::from_secs(1800))??;
        Ok(format!("new FIM baseline recorded ({n} files)"))
    }

    pub fn run(&self) {
        let rx = self.rx.lock().unwrap().take().expect("FIM runs once");
        let mut next: Option<Instant> = None;
        let schedule = |next: &mut Option<Instant>| {
            *next = self
                .active()
                .map(|p| Instant::now() + Duration::from_secs(p.interval_minutes.max(1) as u64 * 60));
        };
        loop {
            match rx.recv_timeout(DEBOUNCE) {
                Ok(Msg::Policy) => {
                    if self.active().is_none() {
                        self.reset();
                    } else {
                        self.scan(false);
                    }
                    schedule(&mut next);
                }
                Ok(Msg::Rebaseline(done)) => {
                    let _ = done.send(Ok(self.scan(true)));
                    schedule(&mut next);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if next.is_some_and(|t| Instant::now() >= t) {
                self.scan(false);
                schedule(&mut next);
            }
            let paths: Vec<String> = self.inner.lock().unwrap().pending.drain().collect();
            if !paths.is_empty() {
                self.check(&paths);
            }
        }
    }

    fn save(&self, st: &State) {
        self.files.store(st.baseline.len(), Ordering::Relaxed);
        self.has_baseline.store(true, Ordering::Relaxed);
        let res = serde_json::to_vec(st).map_err(anyhow::Error::from).and_then(|raw| {
            let tmp = self.file.with_extension("json.tmp");
            write_private(&tmp, &raw)?;
            std::fs::rename(&tmp, &self.file)?;
            Ok(())
        });
        if let Err(err) = res {
            tracing::error!("saving FIM baseline failed: {err:#}");
        }
    }

    /// Drops the baseline when FIM is switched off, so switching it on again
    /// records a fresh one instead of reporting everything since.
    fn reset(&self) {
        if self.st.lock().unwrap().take().is_some() {
            tracing::info!("FIM disabled, baseline removed");
        }
        self.files.store(0, Ordering::Relaxed);
        self.has_baseline.store(false, Ordering::Relaxed);
        let _ = std::fs::remove_file(&self.file);
    }

    /// Walks every monitored path and compares the result with the baseline.
    /// Returns the number of files in the baseline.
    fn scan(&self, rebaseline: bool) -> usize {
        let Some(p) = self.active() else { return 0 };
        let start = Instant::now();
        let mut cur: BTreeMap<String, Entry> = BTreeMap::new();
        let mut guard = self.st.lock().unwrap();
        {
            let prev = guard.as_ref();
            for root in &p.paths {
                walk(root, &p.exclude, &mut |path| {
                    if cur.len() >= MAX_FILES {
                        return false;
                    }
                    if let Some(e) = stat(path, prev) {
                        cur.insert(path.to_string(), e);
                    }
                    true
                });
            }
        }
        if cur.len() >= MAX_FILES {
            tracing::warn!(limit = MAX_FILES, "FIM file limit reached, narrow the monitored paths");
        }
        if guard.is_none() || rebaseline {
            let st = State {
                roots: p.paths.clone(),
                baseline: cur,
                reported: BTreeMap::new(),
            };
            let n = st.baseline.len();
            self.save(&st);
            *guard = Some(st);
            tracing::info!(
                files = n,
                took_ms = start.elapsed().as_millis() as u64,
                "FIM baseline recorded"
            );
            return n;
        }
        let st = guard.as_mut().unwrap();
        // Files under paths added to the policy join the baseline silently.
        let added: Vec<&String> = p.paths.iter().filter(|r| !st.roots.contains(r)).collect();
        for (path, e) in &cur {
            if !st.baseline.contains_key(path) && policy::matches(path, &added) {
                st.baseline.insert(path.clone(), e.clone());
            }
        }
        // Paths no longer monitored leave it.
        st.baseline.retain(|path, _| covered(&p, path));
        st.reported.retain(|path, _| covered(&p, path));
        st.roots = p.paths.clone();
        let mut drift = 0;
        let base: Vec<(String, Entry)> = st.baseline.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        for (path, b) in &base {
            let e = cur.get(path).cloned().unwrap_or_else(Entry::removed);
            drift += self.compare(st, path, Some(b), e) as usize;
        }
        for (path, e) in cur {
            if !st.baseline.contains_key(&path) {
                drift += self.compare(st, &path, None, e) as usize;
            }
        }
        let n = st.baseline.len();
        self.save(st);
        tracing::info!(
            files = n,
            new_drift = drift,
            took_ms = start.elapsed().as_millis() as u64,
            "FIM scan done"
        );
        n
    }

    /// Compares single paths reported by file events.
    fn check(&self, paths: &[String]) {
        let Some(p) = self.inner.lock().unwrap().policy.clone().filter(|p| p.enabled) else {
            return;
        };
        let mut guard = self.st.lock().unwrap();
        let Some(st) = guard.as_mut() else { return };
        let mut n = 0;
        for path in paths.iter().filter(|path| covered(&p, path)) {
            let e = match stat(path, Some(st)) {
                Some(e) => e,
                // A directory or something else not tracked.
                None if std::fs::symlink_metadata(path).is_ok() => continue,
                None => Entry::removed(),
            };
            let base = st.baseline.get(path).cloned();
            if base.is_none() && e.removed {
                st.reported.remove(path);
                continue;
            }
            n += self.compare(st, path, base.as_ref(), e) as usize;
        }
        if n > 0 {
            self.save(st);
        }
    }

    /// Reports drift of cur from base (None when the file is new) once per
    /// distinct state.
    fn compare(&self, st: &mut State, path: &str, base: Option<&Entry>, cur: Entry) -> bool {
        let c = change(base, &cur);
        if c.is_empty() {
            st.reported.remove(path);
            return false;
        }
        if st.reported.get(path).is_some_and(|last| last.same(&cur)) {
            return false;
        }
        let fe = pb::FileEvent {
            path: path.into(),
            change: c.clone(),
            sha256: cur.sha256.clone(),
            size: cur.size.max(0) as u64,
            mode: cur.mode,
            uid: cur.uid,
            old_sha256: base.map(|b| b.sha256.clone()).unwrap_or_default(),
            ..Default::default()
        };
        st.reported.insert(path.into(), cur);
        let mut e = new_event(EventType::FimChange);
        e.payload = Some(pb::event::Payload::File(fe));
        self.emit.emit(e);
        tracing::warn!(path, change = %c, "file integrity drift");
        true
    }
}

fn covered(p: &pb::FimPolicy, path: &str) -> bool {
    policy::matches(path, &p.paths) && !policy::matches(path, &p.exclude)
}

/// Visits the regular files and symlinks under root, skipping excluded paths,
/// until visit returns false.
fn walk(root: &str, exclude: &[String], visit: &mut dyn FnMut(&str) -> bool) -> bool {
    if policy::matches(root, exclude) {
        return true;
    }
    let Ok(md) = std::fs::symlink_metadata(root) else {
        return true;
    };
    if !md.is_dir() {
        return visit(root);
    }
    let Ok(rd) = std::fs::read_dir(root) else { return true };
    let mut names: Vec<String> = rd.flatten().map(|e| e.path().to_string_lossy().into_owned()).collect();
    names.sort();
    names.iter().all(|p| walk(p, exclude, visit))
}

/// Names what differs: added, removed, or a comma separated list of
/// content, permissions and owner.
fn change(base: Option<&Entry>, cur: &Entry) -> String {
    let b = match base {
        None if cur.removed => return String::new(),
        None => return "added".into(),
        Some(b) if cur.removed && !b.removed => return "removed".into(),
        Some(b) => b,
    };
    let mut c = Vec::new();
    if b.sha256 != cur.sha256 || b.link != cur.link {
        c.push("content");
    }
    if b.mode != cur.mode {
        c.push("permissions");
    }
    if b.uid != cur.uid || b.gid != cur.gid {
        c.push("owner");
    }
    c.join(",")
}

/// Records a regular file or symlink. The hash is reused from prev when the
/// inode, size and change time are unchanged; changing content always moves
/// the change time.
fn stat(path: &str, prev: Option<&State>) -> Option<Entry> {
    let md = std::fs::symlink_metadata(path).ok()?;
    let mut e = Entry {
        mode: md.mode() & 0o7777,
        uid: md.uid(),
        gid: md.gid(),
        size: md.size() as i64,
        ino: md.ino(),
        ctime: md.ctime() * 1_000_000_000 + md.ctime_nsec(),
        ..Default::default()
    };
    if md.file_type().is_symlink() {
        e.link = std::fs::read_link(path)
            .map(|l| l.to_string_lossy().into_owned())
            .unwrap_or_default();
        return Some(e);
    }
    if !md.is_file() {
        return None;
    }
    if let Some(prev) = prev {
        for m in [&prev.baseline, &prev.reported] {
            if let Some(old) = m.get(path)
                && !old.removed
                && old.ino == e.ino
                && old.size == e.size
                && old.ctime == e.ctime
                && !old.sha256.is_empty()
            {
                e.sha256 = old.sha256.clone();
                return Some(e);
            }
        }
    }
    if let Ok(f) = std::fs::File::open(path) {
        let mut h = Sha256::new();
        if std::io::copy(&mut f.take(MAX_HASH), &mut h).is_ok() {
            e.sha256 = hex::encode(h.finalize());
        }
    }
    Some(e)
}

pub fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    #[test]
    fn baseline_drift_and_rebaseline() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("etc");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("a"), b"one").unwrap();
        std::fs::write(root.join("sub/b"), b"two").unwrap();
        std::fs::write(root.join("skip.log"), b"x").unwrap();
        let (sink, mut rx) = xdr_core::bus::EventSink::channel(64);
        let emit = Emitter::default();
        emit.set(sink);
        let fim = Arc::new(Fim::new(emit, tmp.path().join("fim.json")));
        let p = pb::FimPolicy {
            enabled: true,
            paths: vec![root.to_string_lossy().into()],
            exclude: vec![format!("{}/*.log", root.display())],
            interval_minutes: 60,
        };
        fim.set_policy(&p);
        assert_eq!(fim.scan(false), 2);
        assert!(rx.try_recv().is_err());

        std::fs::write(root.join("a"), b"changed").unwrap();
        std::fs::set_permissions(root.join("sub/b"), std::fs::Permissions::from_mode(0o777)).unwrap();
        std::fs::write(root.join("new"), b"n").unwrap();
        fim.scan(false);
        let mut got: Vec<(String, String)> = std::iter::from_fn(|| rx.try_recv().ok())
            .map(|e| match e.payload {
                Some(pb::event::Payload::File(f)) => (f.path.rsplit('/').next().unwrap().to_string(), f.change),
                _ => panic!(),
            })
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("a".into(), "content".into()),
                ("b".into(), "permissions".into()),
                ("new".into(), "added".into())
            ]
        );
        // Reported once, not again on the next scan.
        fim.scan(false);
        assert!(rx.try_recv().is_err());
        // An event-driven check sees a removal.
        std::fs::remove_file(root.join("sub/b")).unwrap();
        fim.check(&[root.join("sub/b").to_string_lossy().into()]);
        assert_eq!(rx.try_recv().map(|e| e.r#type()).unwrap(), EventType::FimChange);

        assert_eq!(fim.scan(true), 2);
        fim.scan(false);
        assert!(rx.try_recv().is_err());
        // The state file loads back.
        let again = Fim::new(Emitter::default(), tmp.path().join("fim.json"));
        assert_eq!(again.status().1, 2);
    }

    #[test]
    fn reads_go_state() {
        let go = r#"{"roots":["/etc"],"baseline":{"/etc/x":{"h":"ab","m":420,"u":0,"g":0,"s":3,"i":7,"c":9}},"reported":{"/etc/y":{"m":0,"u":0,"g":0,"s":0,"i":0,"c":0,"x":true}}}"#;
        let st: State = serde_json::from_str(go).unwrap();
        assert_eq!(st.baseline["/etc/x"].sha256, "ab");
        assert!(st.reported["/etc/y"].removed);
    }
}
