//! File telemetry from inotify over the configured directory trees. It does
//! not know the writing process; the eBPF file collector, used instead when
//! the kernel supports it, does.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use xdr_core::bus::{EventSink, new_event};
use xdr_core::pb::{self, EventType};
use xdr_core::platform::Collector;

use crate::procfs::{self, Hasher};

pub struct File {
    pub paths: Vec<String>,
    pub exclude: Vec<String>,
    pub max_watches: usize,
    pub hasher: Arc<Hasher>,
}

struct State {
    ino: Inotify,
    watches: HashMap<WatchDescriptor, PathBuf>,
    max: usize,
    exclude: Vec<String>,
    warned: bool,
}

fn mask() -> WatchMask {
    WatchMask::CREATE
        | WatchMask::CLOSE_WRITE
        | WatchMask::DELETE
        | WatchMask::MOVED_FROM
        | WatchMask::MOVED_TO
        | WatchMask::ATTRIB
        | WatchMask::DELETE_SELF
        | WatchMask::ONLYDIR
}

impl Collector for File {
    fn name(&self) -> &'static str {
        "file"
    }

    fn run(&mut self, sink: &EventSink) -> Result<()> {
        let ino = Inotify::init().context("inotify init")?;
        let mut st = State {
            ino,
            watches: HashMap::new(),
            max: self.max_watches,
            exclude: self.exclude.clone(),
            warned: false,
        };
        for p in &self.paths {
            st.add_tree(Path::new(p));
        }
        tracing::info!(dirs = st.watches.len(), "file collector watching");

        let mut pending: HashMap<u32, PathBuf> = HashMap::new(); // move cookie → old path
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let mut pfd = libc::pollfd {
                fd: st.ino.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut pfd, 1, 500) };
            if n <= 0 {
                // A move out of the watched trees never gets its MOVED_TO.
                for (_, old) in pending.drain() {
                    self.emit_file(sink, EventType::FileDelete, &old, None);
                }
                continue;
            }
            let events: Vec<(WatchDescriptor, EventMask, u32, Option<PathBuf>)> = match st.ino.read_events(&mut buf) {
                Ok(evs) => evs
                    .map(|e| (e.wd, e.mask, e.cookie, e.name.map(|n: &OsStr| PathBuf::from(n))))
                    .collect(),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e).context("inotify read"),
            };
            for (wd, m, cookie, name) in events {
                if m.contains(EventMask::Q_OVERFLOW) {
                    tracing::warn!("inotify queue overflowed; some file events were lost");
                    continue;
                }
                let Some(dir) = st.watches.get(&wd).cloned() else {
                    continue;
                };
                if m.contains(EventMask::IGNORED) || m.contains(EventMask::DELETE_SELF) {
                    st.watches.remove(&wd);
                    continue;
                }
                let path = name.map_or(dir.clone(), |n| dir.join(n));
                if st.excluded(&path) {
                    continue;
                }
                let is_dir = m.contains(EventMask::ISDIR);
                if m.contains(EventMask::CREATE) {
                    if is_dir {
                        st.add_tree(&path);
                    }
                    self.emit_file(sink, EventType::FileCreate, &path, None);
                } else if m.contains(EventMask::CLOSE_WRITE) {
                    self.emit_file(sink, EventType::FileModify, &path, None);
                } else if m.contains(EventMask::DELETE) {
                    self.emit_file(sink, EventType::FileDelete, &path, None);
                } else if m.contains(EventMask::MOVED_FROM) {
                    pending.insert(cookie, path);
                } else if m.contains(EventMask::MOVED_TO) {
                    if is_dir {
                        st.add_tree(&path);
                    }
                    match pending.remove(&cookie) {
                        Some(old) => self.emit_file(sink, EventType::FileRename, &path, Some(&old)),
                        None => self.emit_file(sink, EventType::FileCreate, &path, None),
                    }
                } else if m.contains(EventMask::ATTRIB) {
                    self.emit_file(sink, EventType::FileAttrib, &path, None);
                }
            }
        }
    }
}

impl File {
    fn emit_file(&self, sink: &EventSink, t: EventType, path: &Path, old: Option<&Path>) {
        emit_file(sink, &self.hasher, t, path, old, None);
    }
}

/// The process behind a file change, when the source knows it (eBPF).
pub(crate) struct Actor {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
}

pub(crate) fn emit_file(
    sink: &EventSink,
    hasher: &Hasher,
    t: EventType,
    path: &Path,
    old: Option<&Path>,
    actor: Option<&Actor>,
) {
    let mut fe = pb::FileEvent {
        path: path.to_string_lossy().into_owned(),
        old_path: old.map(|o| o.to_string_lossy().into_owned()).unwrap_or_default(),
        ..Default::default()
    };
    if let Some(a) = actor {
        fe.pid = a.pid;
        fe.ppid = a.ppid;
        fe.exe = process_exe(a.pid, &a.comm);
        fe.user = procfs::username(a.uid);
        fe.uid = a.uid;
    }
    if t != EventType::FileDelete
        && let Ok(md) = std::fs::symlink_metadata(path)
    {
        fe.size = md.size();
        fe.mode = md.mode();
        fe.uid = md.uid();
        fe.gid = md.gid();
        fe.inode = md.ino();
        fe.device = md.dev();
        fe.owner = procfs::username(md.uid());
        if md.is_file() && matches!(t, EventType::FileModify | EventType::FileRename | EventType::FileCreate) {
            let h = hasher.hashes(&fe.path);
            (fe.sha256, fe.sha1, fe.md5) = (h.sha256, h.sha1, h.md5);
        }
    }
    if let Some(m) = procfs::mount_of(&fe.path) {
        (fe.mount_point, fe.filesystem) = (m.point, m.fstype);
    }
    let mut e = new_event(t);
    e.payload = Some(pb::event::Payload::File(fe));
    sink.emit(e);
}

/// Names the process behind an event. One that already exited is named by
/// its command name in brackets.
pub(crate) fn process_exe(pid: u32, comm: &str) -> String {
    match std::fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(p) => p.to_string_lossy().trim_end_matches(" (deleted)").to_string(),
        Err(_) if comm.is_empty() => String::new(),
        Err(_) => format!("[{comm}]"),
    }
}

impl State {
    fn excluded(&self, p: &Path) -> bool {
        let s = p.to_string_lossy();
        self.exclude
            .iter()
            .any(|ex| s == ex.as_str() || s.starts_with(&format!("{}/", ex.trim_end_matches('/'))))
    }

    fn add_tree(&mut self, root: &Path) {
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            if self.excluded(&dir) {
                continue;
            }
            if self.watches.len() >= self.max {
                if !self.warned {
                    tracing::warn!(
                        max = self.max,
                        "file watch limit reached; deeper directories are not watched"
                    );
                    self.warned = true;
                }
                return;
            }
            let Ok(md) = std::fs::symlink_metadata(&dir) else {
                continue;
            };
            if !md.is_dir() {
                continue;
            }
            match self.ino.watches().add(&dir, mask()) {
                Ok(wd) => {
                    self.watches.insert(wd, dir.clone());
                }
                Err(_) => continue,
            }
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for ent in rd.flatten() {
                    if ent.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        stack.push(ent.path());
                    }
                }
            }
        }
    }
}
