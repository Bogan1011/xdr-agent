//! Script blocking: stops shells and interpreters from running scripts kept
//! in the script folders (by default /tmp, /var/tmp and /dev/shm). The
//! folders are marked for open permission events and an open is denied when
//! the opener is an interpreter whose script argument is that file.
//! Subfolders made since the last rescan are not marked yet; application
//! control kills interpreters started on scripts there instead.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use xdr_core::pb;

use super::fanotify::{FAN_EVENT_ON_CHILD, FAN_MARK_ADD, FAN_OPEN_PERM, Fanotify, Request};
use super::{Emitter, app_control_event, policy};
use crate::procfs;

const MAX_DIRS: usize = 4096;
const RESCAN: Duration = Duration::from_secs(3);

pub struct ScriptBlocker {
    emit: Emitter,
    pol: RwLock<Option<pb::ApplicationControlPolicy>>,
    marked: Mutex<HashSet<String>>,
    pub active: AtomicBool,
    pub error: Mutex<String>,
    stop: Mutex<Option<Arc<AtomicBool>>>,
}

impl ScriptBlocker {
    pub fn new(emit: Emitter) -> Self {
        ScriptBlocker {
            emit,
            pol: RwLock::new(None),
            marked: Mutex::new(HashSet::new()),
            active: AtomicBool::new(false),
            error: Mutex::new(String::new()),
            stop: Mutex::new(None),
        }
    }

    /// Enforces script blocking when application control turns it on in
    /// block mode; restarts the fanotify group when the folders change.
    pub fn set_policy(self: &Arc<Self>, ac: &pb::ApplicationControlPolicy) {
        let want = (ac.enabled && ac.block && ac.block_scripts).then(|| ac.clone());
        let folders_changed = {
            let mut cur = self.pol.write().unwrap();
            let changed = cur.as_ref().map(|c| &c.script_paths) != want.as_ref().map(|w| &w.script_paths);
            *cur = want.clone();
            changed
        };
        let mut stop = self.stop.lock().unwrap();
        if !folders_changed && want.is_some() == stop.is_some() {
            return;
        }
        if let Some(s) = stop.take() {
            s.store(true, Ordering::Relaxed);
        }
        let Some(ac) = want else { return };
        let flag = Arc::new(AtomicBool::new(false));
        *stop = Some(flag.clone());
        let this = self.clone();
        std::thread::Builder::new()
            .name("script-block".into())
            .spawn(move || {
                let res = this.run(&ac.script_paths, &flag);
                this.active.store(false, Ordering::Relaxed);
                this.marked.lock().unwrap().clear();
                if let Err(err) = res {
                    tracing::error!("script blocking unavailable: {err:#}");
                    *this.error.lock().unwrap() = format!("{err:#}");
                    let mut stop = this.stop.lock().unwrap();
                    if stop.as_ref().is_some_and(|s| Arc::ptr_eq(s, &flag)) {
                        *stop = None;
                    }
                }
            })
            .expect("spawn script-block thread");
    }

    /// Whether opens in dir are being checked.
    pub fn covers(&self, dir: &str) -> bool {
        self.active.load(Ordering::Relaxed) && self.marked.lock().unwrap().contains(dir)
    }

    fn run(&self, roots: &[String], stop: &AtomicBool) -> Result<()> {
        let fan = Fanotify::new()?;
        self.mark(&fan, roots)?;
        self.active.store(true, Ordering::Relaxed);
        self.error.lock().unwrap().clear();
        tracing::info!(folders = self.marked.lock().unwrap().len(), "script blocking active");
        let mut buf = vec![0u8; 64 * 24];
        let mut rescan = Instant::now();
        while let Some(reqs) = fan.read(&mut buf, stop)? {
            for r in reqs {
                self.handle(&fan, r);
            }
            if rescan.elapsed() > RESCAN {
                let _ = self.mark(&fan, roots);
                rescan = Instant::now();
            }
        }
        Ok(())
    }

    /// Marks the script folders and their subfolders not yet marked. Marks of
    /// deleted folders go away with the inode.
    fn mark(&self, fan: &Fanotify, roots: &[String]) -> Result<()> {
        let mut first_err = None;
        let mut stack: Vec<String> = roots.to_vec();
        while let Some(dir) = stack.pop() {
            if !std::path::Path::new(&dir).is_dir() {
                continue;
            }
            {
                let m = self.marked.lock().unwrap();
                if m.len() >= MAX_DIRS {
                    break;
                }
                if !m.contains(&dir) {
                    drop(m);
                    match fan.mark(&dir, FAN_MARK_ADD, FAN_OPEN_PERM | FAN_EVENT_ON_CHILD) {
                        Ok(()) => {
                            self.marked.lock().unwrap().insert(dir.clone());
                        }
                        Err(e) => {
                            first_err.get_or_insert(format!("fanotify_mark {dir}: {e}"));
                            continue;
                        }
                    }
                }
            }
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    if e.file_type().is_ok_and(|t| t.is_dir()) {
                        stack.push(e.path().to_string_lossy().into_owned());
                    }
                }
            }
        }
        if self.marked.lock().unwrap().is_empty()
            && let Some(e) = first_err
        {
            bail!(e);
        }
        Ok(())
    }

    fn handle(&self, fan: &Fanotify, r: Request) {
        let pid = r.pid;
        let hit = self.check(&r);
        fan.answer(r, hit.is_none());
        if let Some((path, rule)) = hit {
            tracing::warn!(path, rule, pid, "script blocked");
            self.emit.emit(app_control_event("blocked", &path, "", &rule, pid));
        }
    }

    /// The script and rule that deny this open, if the opener is an
    /// interpreter opening the script it was started with.
    fn check(&self, r: &Request) -> Option<(String, String)> {
        if r.pid == std::process::id() {
            return None;
        }
        let pol = self.pol.read().unwrap();
        let ac = pol.as_ref()?;
        let exe = procfs::readlink(&format!("/proc/{}/exe", r.pid));
        if !policy::is_interpreter(&exe) {
            return None;
        }
        let raw = std::fs::read(format!("/proc/{}/cmdline", r.pid)).ok()?;
        let args: Vec<String> = raw
            .split(|b| *b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        let cwd = procfs::readlink(&format!("/proc/{}/cwd", r.pid));
        let (script, rule) = policy::script_rule(ac, exe.trim_end_matches(" (deleted)"), &args, &cwd)?;
        (script == r.path()).then_some((script, rule))
    }
}
