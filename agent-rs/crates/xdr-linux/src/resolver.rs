//! Process contexts with a stable process_guid, the Rust port of the Go
//! agent's internal/agent/envelope.go.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use xdr_core::bus::actor_pid;
use xdr_core::pb::{self, EventType};
use xdr_core::platform::ProcessResolver;

use crate::procfs::{self, Hasher};

const MAX_ENTRIES: usize = 20_000;
/// How long a cached context is trusted before its start time is compared
/// again, in case an exit event was missed.
const RECHECK_AFTER: Duration = Duration::from_secs(30);

struct Entry {
    ctx: pb::ProcessContext,
    start: Option<u64>,
    checked: Instant,
}

pub struct Resolver {
    by_pid: Mutex<HashMap<u32, Entry>>,
    hasher: Arc<Hasher>,
}

impl Resolver {
    pub fn new(hasher: Arc<Hasher>) -> Resolver {
        Resolver {
            by_pid: Mutex::new(HashMap::new()),
            hasher,
        }
    }

    /// A new process image. The GUID survives execve, since the start time
    /// does not change.
    fn exec(&self, pe: &pb::ProcessEvent, ts: i64) -> pb::ProcessContext {
        let start = procfs::start_ticks(pe.pid);
        let mut c = pb::ProcessContext {
            pid: pe.pid,
            ppid: pe.ppid,
            executable: pe.exe.clone(),
            command_line: pe.args.join(" "),
            user: pe.user.clone(),
            uid: pe.uid,
            sha256: pe.sha256.clone(),
            md5: pe.md5.clone(),
            sha1: pe.sha1.clone(),
            gid: pe.gid,
            group: pe.group.clone(),
            cwd: pe.cwd.clone(),
            tty: pe.tty.clone(),
            session_id: pe.session_id,
            euid: pe.euid,
            login_uid: pe.login_uid,
            pid_namespace: procfs::ns_inode(pe.pid, "pid"),
            mnt_namespace: procfs::ns_inode(pe.pid, "mnt"),
            net_namespace: procfs::ns_inode(pe.pid, "net"),
            console_session_id: procfs::environ_var(pe.pid, procfs::CONSOLE_SESSION_ENV).unwrap_or_default(),
            ..Default::default()
        };
        match start {
            Some(t) => {
                c.process_guid = procfs::process_guid(pe.pid, t);
                c.start_time_unix_nano = procfs::start_time_unix_nano(t);
            }
            None => {
                // Already gone: the exec time stands in for the start time.
                c.process_guid = procfs::process_guid(pe.pid, ts as u64);
                c.start_time_unix_nano = ts;
            }
        }
        self.set_parent(&mut c, ts, 0);
        self.put(
            pe.pid,
            Entry {
                ctx: c.clone(),
                start,
                checked: Instant::now(),
            },
        );
        c
    }

    fn lookup(&self, pid: u32, ts: i64, depth: u8) -> pb::ProcessContext {
        if let Some(c) = self.cached(pid) {
            return c;
        }
        let (Some(start), Some(info)) = (procfs::start_ticks(pid), procfs::read(pid)) else {
            return pb::ProcessContext {
                pid,
                ..Default::default()
            };
        };
        let h = if info.exe.is_empty() {
            procfs::Hashes::default()
        } else {
            self.hasher.hashes(&info.exe)
        };
        let mut c = pb::ProcessContext {
            process_guid: procfs::process_guid(pid, start),
            pid,
            ppid: info.ppid,
            sha256: h.sha256,
            sha1: h.sha1,
            md5: h.md5,
            gid: info.gid,
            group: info.group,
            cwd: info.cwd,
            tty: info.tty,
            session_id: info.session_id,
            euid: info.euid,
            login_uid: info.login_uid,
            pid_namespace: info.pid_ns,
            mnt_namespace: info.mnt_ns,
            net_namespace: info.net_ns,
            console_session_id: info.console_session,
            executable: info.exe,
            command_line: info.args.join(" "),
            user: info.user,
            uid: info.uid,
            start_time_unix_nano: procfs::start_time_unix_nano(start),
            ..Default::default()
        };
        self.set_parent(&mut c, ts, depth);
        self.put(
            pid,
            Entry {
                ctx: c.clone(),
                start: Some(start),
                checked: Instant::now(),
            },
        );
        c
    }

    /// A cached context still valid for pid; the start time is re-read now
    /// and then so a reused PID gets a fresh identity.
    fn cached(&self, pid: u32) -> Option<pb::ProcessContext> {
        let mut m = self.by_pid.lock().unwrap();
        let e = m.get_mut(&pid)?;
        if e.checked.elapsed() < RECHECK_AFTER {
            return Some(e.ctx.clone());
        }
        match procfs::start_ticks(pid) {
            // An exited process keeps its last identity for late events.
            None => {}
            Some(t) if Some(t) == e.start => {}
            Some(_) => {
                m.remove(&pid);
                return None;
            }
        }
        e.checked = Instant::now();
        Some(e.ctx.clone())
    }

    fn set_parent(&self, c: &mut pb::ProcessContext, ts: i64, depth: u8) {
        // The parent's own parent is resolved too, but the walk stays short.
        if c.ppid == 0 || depth > 8 {
            return;
        }
        let p = self.lookup(c.ppid, ts, depth + 1);
        c.parent_process_guid = p.process_guid;
        c.parent_executable = p.executable;
        c.parent_command_line = p.command_line;
        c.parent_user = p.user;
        c.parent_sha256 = p.sha256;
    }

    fn put(&self, pid: u32, e: Entry) {
        let mut m = self.by_pid.lock().unwrap();
        if m.len() >= MAX_ENTRIES {
            m.clear();
        }
        m.insert(pid, e);
    }
}

impl ProcessResolver for Resolver {
    fn context(&self, e: &pb::Event) -> Option<pb::ProcessContext> {
        let pid = actor_pid(e);
        if pid == 0 {
            return None;
        }
        let ts = e.timestamp_unix_nano;
        Some(match (e.r#type(), &e.payload) {
            (EventType::ProcessExec, Some(pb::event::Payload::Process(pe))) => self.exec(pe, ts),
            (EventType::ProcessExit, _) => {
                let c = self.lookup(pid, ts, 0);
                self.by_pid.lock().unwrap().remove(&pid);
                c
            }
            _ => self.lookup(pid, ts, 0),
        })
    }

    fn container(&self, e: &pb::Event) -> Option<pb::ContainerContext> {
        match actor_pid(e) {
            0 => None,
            pid => crate::container::of_pid(pid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xdr_core::bus::new_event;

    #[test]
    fn events_of_one_process_share_its_guid() {
        let r = Resolver::new(Arc::new(Hasher::new(10)));
        let pid = std::process::id();
        let mut exec = new_event(EventType::ProcessExec);
        exec.payload = Some(pb::event::Payload::Process(pb::ProcessEvent {
            pid,
            ppid: std::os::unix::process::parent_id(),
            exe: "/bin/test".into(),
            ..Default::default()
        }));
        let c = r.context(&exec).unwrap();
        assert!(!c.process_guid.is_empty());
        assert!(!c.parent_process_guid.is_empty() && !c.parent_executable.is_empty());

        let mut file = new_event(EventType::FileModify);
        file.payload = Some(pb::event::Payload::File(pb::FileEvent {
            pid,
            ..Default::default()
        }));
        assert_eq!(r.context(&file).unwrap().process_guid, c.process_guid);
    }
}
