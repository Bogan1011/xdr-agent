//! Persistence telemetry: changes to the places Linux malware uses to survive
//! a reboot or a logout (cron, systemd units, init scripts, SSH keys, shell
//! profiles, the dynamic loader, udev, kernel module and sysctl configs,
//! sudoers and the account files). Watched with inotify; each event says
//! which kind of persistence changed and, for text files, which lines were
//! added and removed. Where the eBPF file hooks run, the process that made
//! the change comes from them.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use xdr_core::bus::{EventSink, new_event};
use xdr_core::pb::{self, EventType};
use xdr_core::platform::Collector;

use crate::procfs::{self, Hasher};
use crate::writers::{Writer, Writers};

/// Files larger than this are hashed but not diffed.
const MAX_DIFF_FILE: u64 = 256 << 10;
/// Most lines and bytes reported per side of a diff.
const MAX_DIFF_LINES: usize = 20;
const MAX_DIFF_BYTES: usize = 2048;

/// Directories watched for every file in them (and one level of
/// subdirectories, e.g. systemd's *.wants).
const DIRS: &[&str] = &[
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
    "/var/spool/cron/atjobs",
    "/etc/systemd/system",
    "/etc/systemd/user",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/etc/init.d",
    "/etc/rc.d",
    "/etc/sudoers.d",
    "/etc/profile.d",
    "/etc/ld.so.conf.d",
    "/etc/udev/rules.d",
    "/lib/udev/rules.d",
    "/etc/modules-load.d",
    "/etc/modprobe.d",
    "/etc/sysctl.d",
    "/etc/update-motd.d",
    "/etc/xdg/autostart",
    "/etc/ssh/sshd_config.d",
    "/etc/ssh/ssh_config.d",
];

/// Per-user locations, under each home directory and /root.
const HOME_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
];
const HOME_DIRS: &[&str] = &[".ssh", ".config/systemd/user", ".config/autostart"];

/// Never diffed: they hold secrets.
const SECRET: &[&str] = &["/etc/shadow", "/etc/gshadow"];

/// The persistence kind of a path, or None when it isn't one.
pub fn classify(path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next().unwrap_or("");
    if name.ends_with(".swp") || name.ends_with('~') || name.starts_with(".#") || name.ends_with(".dpkg-new") {
        return None;
    }
    let under = |dir: &str| path.strip_prefix(dir).is_some_and(|r| r.starts_with('/'));
    Some(match path {
        "/etc/crontab" | "/etc/anacrontab" => "cron",
        "/etc/sudoers" => "sudoers",
        "/etc/passwd" | "/etc/group" | "/etc/shadow" | "/etc/gshadow" => "passwd",
        "/etc/ld.so.preload" => "ld_preload",
        "/etc/ld.so.conf" => "ld_library_path",
        "/etc/environment" => "shell_profile",
        "/etc/profile" | "/etc/bash.bashrc" | "/etc/bashrc" | "/etc/zshrc" | "/etc/zsh/zshrc" | "/etc/zsh/zshenv" => {
            "shell_profile"
        }
        "/etc/rc.local" | "/etc/rc.d/rc.local" => "rc_local",
        "/etc/modules" => "kernel_module_config",
        "/etc/sysctl.conf" => "sysctl_config",
        "/etc/ssh/sshd_config" | "/etc/ssh/ssh_config" => "ssh_config",
        _ if under("/etc/cron.d") || under("/etc/cron.hourly") || under("/etc/cron.daily") => "cron",
        _ if under("/etc/cron.weekly") || under("/etc/cron.monthly") || under("/var/spool/cron/atjobs") => {
            if under("/var/spool/cron/atjobs") {
                "at_job"
            } else {
                "cron"
            }
        }
        _ if under("/var/spool/cron") => "cron",
        _ if under("/etc/systemd")
            || under("/lib/systemd/system")
            || under("/usr/lib/systemd/system")
            || path.contains("/.config/systemd/user/") =>
        {
            if name.ends_with(".timer") {
                "systemd_timer"
            } else {
                "systemd_service"
            }
        }
        _ if under("/etc/init.d") || under("/etc/rc.d") => "init_script",
        _ if under("/etc/sudoers.d") => "sudoers",
        _ if under("/etc/profile.d") => "shell_profile",
        _ if under("/etc/ld.so.conf.d") => "ld_library_path",
        _ if under("/etc/udev/rules.d") || under("/lib/udev/rules.d") => "udev_rule",
        _ if under("/etc/modules-load.d") || under("/etc/modprobe.d") => "kernel_module_config",
        _ if under("/etc/sysctl.d") => "sysctl_config",
        _ if under("/etc/update-motd.d") => "motd",
        _ if under("/etc/xdg/autostart") || path.contains("/.config/autostart/") => "autostart",
        _ if under("/etc/ssh") => "ssh_config",
        _ if path.contains("/.ssh/") => {
            if name.starts_with("authorized_keys") {
                "ssh_authorized_keys"
            } else if name == "rc" || name == "config" || name == "environment" {
                "ssh_config"
            } else {
                return None;
            }
        }
        _ if HOME_FILES.contains(&name) && (path.starts_with("/home/") || path.starts_with("/root/")) => {
            "shell_profile"
        }
        _ => return None,
    })
}

struct Known {
    sha256: String,
    mode: u32,
    lines: Option<Vec<String>>,
}

pub struct Persistence {
    pub hasher: Arc<Hasher>,
    /// Filled by the eBPF file collector; None without eBPF.
    pub writers: Option<Arc<Writers>>,
}

struct State {
    ino: Inotify,
    watches: HashMap<WatchDescriptor, PathBuf>,
    known: HashMap<String, Known>,
    hasher: Arc<Hasher>,
    writers: Option<Arc<Writers>>,
}

fn dir_mask() -> WatchMask {
    WatchMask::CREATE
        | WatchMask::CLOSE_WRITE
        | WatchMask::DELETE
        | WatchMask::MOVED_FROM
        | WatchMask::MOVED_TO
        | WatchMask::ATTRIB
        | WatchMask::ONLYDIR
}

impl Collector for Persistence {
    fn name(&self) -> &'static str {
        "persistence"
    }

    fn run(&mut self, sink: &EventSink) -> Result<()> {
        let mut st = State {
            ino: Inotify::init().context("inotify init")?,
            watches: HashMap::new(),
            known: HashMap::new(),
            hasher: self.hasher.clone(),
            writers: self.writers.clone(),
        };
        // /etc itself for its top-level files, then every persistence directory.
        st.watch(Path::new("/etc"), false);
        st.watch(Path::new("/etc/ssh"), false);
        st.watch(Path::new("/etc/zsh"), false);
        for d in DIRS {
            st.watch(Path::new(d), true);
        }
        st.watch(Path::new("/home"), false);
        for home in homes() {
            st.watch_home(&home);
        }
        tracing::info!(
            watches = st.watches.len(),
            files = st.known.len(),
            "persistence baseline taken"
        );

        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let events: Vec<(PathBuf, EventMask)> = st
                .ino
                .read_events_blocking(&mut buf)
                .context("read inotify events")?
                .filter_map(|ev| {
                    let dir = st.watches.get(&ev.wd)?;
                    let name: &OsStr = ev.name?;
                    Some((dir.join(name), ev.mask))
                })
                .collect();
            for (path, m) in events {
                if m.contains(EventMask::ISDIR) {
                    if m.intersects(EventMask::CREATE | EventMask::MOVED_TO) {
                        st.on_new_dir(&path, sink);
                    }
                    continue;
                }
                let p = path.to_string_lossy().into_owned();
                if classify(&p).is_none() {
                    continue;
                }
                if m.intersects(EventMask::DELETE | EventMask::MOVED_FROM) {
                    st.deleted(&p, sink);
                } else {
                    st.changed(&p, sink);
                }
            }
        }
    }
}

fn homes() -> Vec<PathBuf> {
    let mut out = vec![PathBuf::from("/root")];
    if let Ok(rd) = std::fs::read_dir("/home") {
        out.extend(rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()));
    }
    out
}

impl State {
    fn watch(&mut self, dir: &Path, sub: bool) {
        if !dir.is_dir() || self.watches.values().any(|d| d == dir) {
            return;
        }
        let Ok(wd) = self.ino.watches().add(dir, dir_mask()) else {
            return;
        };
        self.watches.insert(wd, dir.to_path_buf());
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for ent in rd.flatten() {
            let path = ent.path();
            if path.is_dir() {
                if sub {
                    self.watch(&path, false);
                }
                continue;
            }
            let p = path.to_string_lossy().into_owned();
            if classify(&p).is_some()
                && let Some(k) = self.snapshot(&p)
            {
                self.known.insert(p, k);
            }
        }
    }

    fn watch_home(&mut self, home: &Path) {
        self.watch(home, false);
        for d in HOME_DIRS {
            self.watch(&home.join(d), false);
        }
    }

    /// A directory appeared: a new home, ~/.ssh or a systemd *.wants. Files
    /// already in it are reported, since they were written before the watch.
    fn on_new_dir(&mut self, path: &Path, sink: &EventSink) {
        let before: HashSet<String> = self.known.keys().cloned().collect();
        if path.parent() == Some(Path::new("/home")) {
            self.watch_home(path);
        } else if self.watches.values().any(|d| Some(d.as_path()) == path.parent()) {
            self.watch(path, false);
        }
        let fresh: Vec<String> = self.known.keys().filter(|k| !before.contains(*k)).cloned().collect();
        for p in fresh {
            if let Some(k) = self.known.get(&p) {
                let lines = k.lines.as_ref().map(|l| diff(&[], l).1).unwrap_or_default();
                // Written before the watch: no writer is waited for.
                emit(sink, &p, "created", &k.sha256, "", String::new(), lines, None);
            }
        }
    }

    fn snapshot(&self, path: &str) -> Option<Known> {
        let md = std::fs::metadata(path).ok()?;
        if !md.is_file() {
            return None;
        }
        let lines = (md.len() <= MAX_DIFF_FILE && !SECRET.contains(&path))
            .then(|| std::fs::read(path).ok())
            .flatten()
            .filter(|b| !b.contains(&0))
            .map(|b| String::from_utf8_lossy(&b).lines().map(str::to_string).collect());
        Some(Known {
            sha256: self.hasher.hash(path),
            mode: md.mode(),
            lines,
        })
    }

    fn changed(&mut self, path: &str, sink: &EventSink) {
        let Some(now) = self.snapshot(path) else { return };
        let old = self.known.remove(path);
        match &old {
            Some(o) if o.sha256 == now.sha256 && o.mode == now.mode => {}
            Some(o) => {
                let (removed, added) = match (&o.lines, &now.lines) {
                    (Some(a), Some(b)) => diff(a, b),
                    _ => Default::default(),
                };
                let mut added = added;
                if o.mode != now.mode {
                    let note = format!("mode {:o} -> {:o}", o.mode & 0o7777, now.mode & 0o7777);
                    added = if added.is_empty() {
                        note
                    } else {
                        format!("{note}\n{added}")
                    };
                }
                emit(
                    sink,
                    path,
                    "modified",
                    &now.sha256,
                    &o.sha256,
                    removed,
                    added,
                    self.writer(path),
                );
            }
            None => {
                let added = now.lines.as_ref().map(|l| diff(&[], l).1).unwrap_or_default();
                emit(
                    sink,
                    path,
                    "created",
                    &now.sha256,
                    "",
                    String::new(),
                    added,
                    self.writer(path),
                );
            }
        }
        self.known.insert(path.to_string(), now);
    }

    fn deleted(&mut self, path: &str, sink: &EventSink) {
        let old = self.known.remove(path);
        let (sha, removed) = old
            .map(|o| (o.sha256, o.lines.map(|l| diff(&l, &[]).0).unwrap_or_default()))
            .unwrap_or_default();
        emit(
            sink,
            path,
            "deleted",
            "",
            &sha,
            removed,
            String::new(),
            self.writer(path),
        );
    }

    fn writer(&self, path: &str) -> Option<Writer> {
        self.writers.as_ref()?.lookup(path)
    }
}

#[allow(clippy::too_many_arguments)]
fn emit(
    sink: &EventSink,
    path: &str,
    op: &str,
    sha: &str,
    old_sha: &str,
    removed: String,
    added: String,
    writer: Option<Writer>,
) {
    let Some(kind) = classify(path) else { return };
    // Without the writer, the file's owner stands in.
    let (pid, exe, uid) = match writer {
        Some(w) => (w.pid, w.exe, w.uid),
        None => (
            0,
            String::new(),
            std::fs::metadata(path).map(|m| m.uid()).unwrap_or_default(),
        ),
    };
    let mut e = new_event(EventType::Persistence);
    e.payload = Some(pb::event::Payload::Persistence(pb::PersistenceEvent {
        persistence_type: kind.into(),
        path: path.into(),
        operation: op.into(),
        sha256: sha.into(),
        old_sha256: old_sha.into(),
        old_value: removed,
        new_value: added,
        pid,
        exe,
        uid,
        user: procfs::username(uid),
    }));
    sink.emit(e);
}

/// Lines only in `a` and lines only in `b`, "-"/"+" prefixed and capped.
/// Comments and blank lines are left out.
pub fn diff(a: &[String], b: &[String]) -> (String, String) {
    let sa: HashSet<&str> = a.iter().map(|s| s.trim()).collect();
    let sb: HashSet<&str> = b.iter().map(|s| s.trim()).collect();
    let side = |lines: &[String], other: &HashSet<&str>, sign: char| {
        let mut out = String::new();
        let mut n = 0;
        for l in lines.iter().map(|s| s.trim()) {
            if l.is_empty() || l.starts_with('#') || other.contains(l) {
                continue;
            }
            n += 1;
            if n > MAX_DIFF_LINES || out.len() + l.len() > MAX_DIFF_BYTES {
                out.push_str("...");
                break;
            }
            if !out.is_empty() {
                out.push('\n');
            }
            out.push(sign);
            out.push(' ');
            out.push_str(l);
        }
        out
    };
    (side(a, &sb, '-'), side(b, &sa, '+'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_locations() {
        let cases = [
            ("/etc/crontab", Some("cron")),
            ("/etc/cron.d/backdoor", Some("cron")),
            ("/var/spool/cron/crontabs/root", Some("cron")),
            ("/var/spool/cron/atjobs/a0001", Some("at_job")),
            ("/etc/systemd/system/evil.service", Some("systemd_service")),
            (
                "/etc/systemd/system/multi-user.target.wants/evil.service",
                Some("systemd_service"),
            ),
            ("/home/bob/.config/systemd/user/x.timer", Some("systemd_timer")),
            ("/root/.ssh/authorized_keys", Some("ssh_authorized_keys")),
            ("/home/bob/.ssh/authorized_keys2", Some("ssh_authorized_keys")),
            ("/home/bob/.ssh/id_rsa", None),
            ("/home/bob/.bashrc", Some("shell_profile")),
            ("/etc/profile.d/x.sh", Some("shell_profile")),
            ("/etc/ld.so.preload", Some("ld_preload")),
            ("/etc/ld.so.conf.d/x.conf", Some("ld_library_path")),
            ("/etc/udev/rules.d/99-x.rules", Some("udev_rule")),
            ("/etc/modules-load.d/x.conf", Some("kernel_module_config")),
            ("/etc/sysctl.d/99-x.conf", Some("sysctl_config")),
            ("/etc/sudoers.d/x", Some("sudoers")),
            ("/etc/passwd", Some("passwd")),
            ("/etc/ssh/sshd_config", Some("ssh_config")),
            ("/etc/hostname", None),
            ("/etc/cron.d/.x.swp", None),
        ];
        for (p, want) in cases {
            assert_eq!(classify(p), want, "{p}");
        }
    }

    #[test]
    fn diffs_lines() {
        let a: Vec<String> = ["# comment", "* * * * * root /bin/true", "x"]
            .map(String::from)
            .to_vec();
        let b: Vec<String> = ["* * * * * root /bin/true", "*/5 * * * * root /tmp/.x", ""]
            .map(String::from)
            .to_vec();
        assert_eq!(diff(&a, &b), ("- x".into(), "+ */5 * * * * root /tmp/.x".into()));
    }
}

#[cfg(test)]
mod live {
    use super::*;
    use std::time::Duration;

    /// Needs root: cargo test -p xdr-linux --lib live_persistence -- --ignored
    #[test]
    #[ignore]
    fn live_persistence() {
        let (sink, mut rx) = EventSink::channel(64);
        let hasher = Arc::new(Hasher::new(100));
        std::thread::spawn(move || Persistence { hasher, writers: None }.run(&sink));
        std::thread::sleep(Duration::from_secs(2));
        let path = "/etc/cron.d/xdr-live-test";
        std::fs::write(path, "* * * * * root /bin/true\n").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        std::fs::write(path, "* * * * * root /bin/true\n*/5 * * * * root /tmp/.x\n").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        std::fs::remove_file(path).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let mut ops = Vec::new();
        while let Ok(e) = rx.try_recv() {
            if let Some(pb::event::Payload::Persistence(p)) = e.payload
                && p.path == path
            {
                println!("{p:?}");
                ops.push((p.operation, p.new_value));
            }
        }
        assert_eq!(ops[0].0, "created");
        assert!(
            ops.contains(&("modified".into(), "+ */5 * * * * root /tmp/.x".into())),
            "{ops:?}"
        );
        assert_eq!(ops.last().unwrap().0, "deleted");
    }
}
