//! Exec and exit events from the kernel's process events connector
//! (CONFIG_PROC_EVENTS), like the Go agent's netlink collector. Needs
//! CAP_NET_ADMIN, so the agent runs as root.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use anyhow::{Result, bail};
use xdr_core::bus::{EventSink, new_event};
use xdr_core::pb::{self, EventType};
use xdr_core::platform::Collector;

use crate::procfs::{self, Hasher};

const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;
const NLMSG_HDR: usize = 16;
const CN_MSG_HDR: usize = 20;
const PROC_EVENT_HDR: usize = 16;
const MAX_TRACKED: usize = 65_536;

pub struct Process {
    pub hasher: Arc<Hasher>,
    /// pid → exe, for exit events and parent lookup.
    procs: HashMap<u32, String>,
}

impl Process {
    pub fn new(hasher: Arc<Hasher>) -> Process {
        Process {
            hasher,
            procs: HashMap::new(),
        }
    }
}

struct Fd(i32);
impl Drop for Fd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

impl Collector for Process {
    fn name(&self) -> &'static str {
        "process"
    }

    fn run(&mut self, sink: &EventSink) -> Result<()> {
        self.seed();
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                libc::NETLINK_CONNECTOR,
            )
        };
        if fd < 0 {
            bail!("netlink socket: {}", io::Error::last_os_error());
        }
        let fd = Fd(fd);
        let me = std::process::id();
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_groups = CN_IDX_PROC;
        addr.nl_pid = me;
        let rc = unsafe {
            libc::bind(
                fd.0,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if rc < 0 {
            bail!("netlink bind: {}", io::Error::last_os_error());
        }
        subscribe(fd.0, me)?;

        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = unsafe { libc::recv(fd.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::ENOBUFS) => {
                        tracing::warn!("process events overflowed the socket buffer; some events were lost");
                        continue;
                    }
                    Some(libc::EINTR) => continue,
                    _ => bail!("netlink recv: {err}"),
                }
            }
            let mut msg = &buf[..n as usize];
            // Walk the netlink messages in the datagram.
            while msg.len() >= NLMSG_HDR {
                let len = u32le(msg, 0) as usize;
                if len < NLMSG_HDR || len > msg.len() {
                    break;
                }
                self.handle(&msg[NLMSG_HDR..len], me, sink);
                let next = (len + 3) & !3;
                if next >= msg.len() {
                    break;
                }
                msg = &msg[next..];
            }
        }
    }
}

fn subscribe(fd: i32, me: u32) -> Result<()> {
    let mut msg = [0u8; NLMSG_HDR + CN_MSG_HDR + 4];
    let total = msg.len() as u32;
    msg[0..4].copy_from_slice(&total.to_le_bytes());
    msg[4..6].copy_from_slice(&(libc::NLMSG_DONE as u16).to_le_bytes());
    msg[12..16].copy_from_slice(&me.to_le_bytes());
    let cn = &mut msg[NLMSG_HDR..];
    cn[0..4].copy_from_slice(&CN_IDX_PROC.to_le_bytes());
    cn[4..8].copy_from_slice(&CN_VAL_PROC.to_le_bytes());
    cn[16..18].copy_from_slice(&4u16.to_le_bytes());
    cn[CN_MSG_HDR..CN_MSG_HDR + 4].copy_from_slice(&PROC_CN_MCAST_LISTEN.to_le_bytes());
    let rc = unsafe { libc::send(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
    if rc < 0 {
        bail!("subscribe to process events: {}", io::Error::last_os_error());
    }
    Ok(())
}

impl Process {
    fn handle(&mut self, data: &[u8], me: u32, sink: &EventSink) {
        if data.len() < CN_MSG_HDR + PROC_EVENT_HDR {
            return;
        }
        let ev = &data[CN_MSG_HDR..];
        let what = u32le(ev, 0);
        let body = &ev[PROC_EVENT_HDR..];
        match what {
            PROC_EVENT_EXEC if body.len() >= 8 => {
                let (pid, tgid) = (u32le(body, 0), u32le(body, 4));
                if pid == tgid && pid != me {
                    self.on_exec(pid, sink);
                }
            }
            PROC_EVENT_EXIT if body.len() >= 12 => {
                let (pid, tgid, code) = (u32le(body, 0), u32le(body, 4), u32le(body, 8));
                if pid == tgid {
                    self.on_exit(pid, code, sink);
                }
            }
            _ => {}
        }
    }

    fn on_exec(&mut self, pid: u32, sink: &EventSink) {
        // A short-lived process may already be gone; report what we know.
        let info = procfs::read(pid).unwrap_or(procfs::Info {
            pid,
            ..Default::default()
        });
        if self.procs.len() >= MAX_TRACKED {
            self.procs.clear();
        }
        self.procs.insert(pid, info.exe.clone());
        let mut parent = self.procs.get(&info.ppid).cloned().unwrap_or_default();
        if parent.is_empty() && info.ppid != 0 {
            parent = procfs::readlink(&format!("/proc/{}/exe", info.ppid));
        }
        let mut e = new_event(EventType::ProcessExec);
        e.payload = Some(pb::event::Payload::Process(pb::ProcessEvent {
            pid: info.pid,
            ppid: info.ppid,
            uid: info.uid,
            gid: info.gid,
            user: info.user,
            sha256: self.hasher.hash(&info.exe),
            exe: info.exe,
            args: info.args,
            cwd: info.cwd,
            parent_exe: parent,
            exit_code: 0,
        }));
        sink.emit(e);
    }

    fn on_exit(&mut self, pid: u32, code: u32, sink: &EventSink) {
        let Some(exe) = self.procs.remove(&pid) else {
            return;
        };
        let mut e = new_event(EventType::ProcessExit);
        // The kernel reports the raw wait status; the high byte is the exit status.
        e.payload = Some(pb::event::Payload::Process(pb::ProcessEvent {
            pid,
            exe,
            exit_code: (code >> 8) as i32,
            ..Default::default()
        }));
        sink.emit(e);
    }

    /// Records running processes so their exits and children have context.
    fn seed(&mut self) {
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return;
        };
        for ent in dir.flatten() {
            if let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
                let exe = procfs::readlink(&format!("/proc/{pid}/exe"));
                if !exe.is_empty() {
                    self.procs.insert(pid, exe);
                }
            }
        }
    }
}
