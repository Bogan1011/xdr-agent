//! Credential access: opens of password hashes, sudoers and SSH private keys,
//! from fanotify open notifications on those files. The programs that read
//! them for a living (sshd, PAM helpers, sudo, su, login, passwd...) are left
//! out, so what remains is someone reading credentials by hand or a tool
//! harvesting them.
//!
//! It uses open permission events, answered with "allow" at once, so the
//! opening process is still alive while the agent reads who it is; a plain
//! notification often arrives after a short-lived `cat` has exited. If the
//! agent dies the kernel allows pending opens when the descriptor closes.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::io;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use xdr_core::bus::{EventSink, new_event};
use xdr_core::pb::{self, EventType};
use xdr_core::platform::Collector;

use crate::procfs;

const FAN_CLASS_CONTENT: u32 = 0x4;
const FAN_CLOEXEC: u32 = 1;
const FAN_MARK_ADD: u32 = 1;
const FAN_OPEN_PERM: u64 = 0x0001_0000;
const FAN_ALLOW: u32 = 1;
const FAN_EVENT_META: usize = 24;

/// Programs whose reads of these files are routine.
const ROUTINE: &[&str] = &[
    "sshd",
    "sshd-session",
    "sshd-auth",
    "unix_chkpwd",
    "sudo",
    "su",
    "login",
    "passwd",
    "chpasswd",
    "chage",
    "useradd",
    "usermod",
    "userdel",
    "groupadd",
    "groupmod",
    "groupdel",
    "gpasswd",
    "newgrp",
    "cron",
    "crond",
    "systemd",
    "systemd-logind",
    "systemd-userdbd",
    "accounts-daemon",
    "polkitd",
    "gdm-session-worker",
    "lightdm",
    "ssh",
    "ssh-add",
    "ssh-agent",
    "ssh-keygen",
    "scp",
    "sftp",
    "pkexec",
    "nscd",
    "sssd",
    "sssd_be",
    "xdr-agent",
    "xdr-agent-rs",
    "dpkg",
    "rpm",
    "unattended-upgrade",
    "pwck",
    "grpck",
    "vipw",
];

pub struct CredentialAccess;

struct Fd(i32);
impl Drop for Fd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// Files worth watching that exist now.
fn targets() -> Vec<String> {
    let mut out: Vec<String> = ["/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/security/opasswd"]
        .map(String::from)
        .to_vec();
    let mut homes = vec!["/root".to_string()];
    if let Ok(rd) = std::fs::read_dir("/home") {
        homes.extend(rd.flatten().map(|e| e.path().to_string_lossy().into_owned()));
    }
    for h in homes {
        if let Ok(rd) = std::fs::read_dir(format!("{h}/.ssh")) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if n.starts_with("id_") && !n.ends_with(".pub") {
                    out.push(e.path().to_string_lossy().into_owned());
                }
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir("/etc/ssh") {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with("ssh_host_") && n.ends_with("_key") {
                out.push(e.path().to_string_lossy().into_owned());
            }
        }
    }
    out.retain(|p| std::path::Path::new(p).is_file());
    out
}

pub fn routine(exe: &str) -> bool {
    let name = exe.rsplit('/').next().unwrap_or("").trim_end_matches(" (deleted)");
    ROUTINE.contains(&name)
}

impl Collector for CredentialAccess {
    fn name(&self) -> &'static str {
        "credential_access"
    }

    fn run(&mut self, sink: &EventSink) -> Result<()> {
        let fd = unsafe {
            libc::fanotify_init(
                FAN_CLASS_CONTENT | FAN_CLOEXEC,
                (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
            )
        };
        if fd < 0 {
            bail!("fanotify_init: {}", io::Error::last_os_error());
        }
        let fd = Fd(fd);
        let files = targets();
        for p in &files {
            let c = CString::new(p.as_str())?;
            let rc = unsafe { libc::fanotify_mark(fd.0, FAN_MARK_ADD, FAN_OPEN_PERM, libc::AT_FDCWD, c.as_ptr()) };
            if rc < 0 {
                tracing::warn!(path = %p, "fanotify mark: {}", io::Error::last_os_error());
            }
        }
        tracing::info!(files = files.len(), "watching credential files");
        let me = std::process::id();
        // (pid, path) reported in the last minute, so a loop reading a file
        // is one event.
        let mut recent: HashMap<(u32, String), Instant> = HashMap::new();
        let mut buf = vec![0u8; 8192];
        loop {
            let n = unsafe { libc::read(fd.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                bail!("fanotify read: {err}");
            }
            let mut off = 0usize;
            let n = n as usize;
            let mut seen_now: HashSet<(u32, String)> = HashSet::new();
            while off + FAN_EVENT_META <= n {
                let b = &buf[off..];
                let len = u32::from_ne_bytes(b[0..4].try_into().unwrap()) as usize;
                let efd = i32::from_ne_bytes(b[16..20].try_into().unwrap());
                let pid = i32::from_ne_bytes(b[20..24].try_into().unwrap()) as u32;
                if len < FAN_EVENT_META {
                    break;
                }
                off += len;
                if efd < 0 {
                    continue;
                }
                let path = procfs::readlink(&format!("/proc/self/fd/{efd}"));
                let (exe, user) = if pid == me {
                    Default::default()
                } else {
                    (
                        procfs::readlink(&format!("/proc/{pid}/exe")),
                        procfs::read(pid).map(|i| i.user).unwrap_or_default(),
                    )
                };
                allow(fd.0, efd);
                unsafe { libc::close(efd) };
                if pid == me {
                    continue;
                }
                if routine(&exe) {
                    continue;
                }
                let key = (pid, path.clone());
                if recent.get(&key).is_some_and(|t| t.elapsed() < Duration::from_secs(60))
                    || !seen_now.insert(key.clone())
                {
                    continue;
                }
                recent.insert(key, Instant::now());
                let mut e = new_event(EventType::FileOpen);
                e.payload = Some(pb::event::Payload::File(pb::FileEvent {
                    path,
                    pid,
                    exe,
                    user,
                    ..Default::default()
                }));
                sink.emit(e);
            }
            if recent.len() > 1024 {
                recent.retain(|_, t| t.elapsed() < Duration::from_secs(60));
            }
        }
    }
}

/// Lets the open go ahead.
fn allow(fan: i32, efd: i32) {
    let resp: [u32; 2] = [efd as u32, FAN_ALLOW];
    unsafe { libc::write(fan, resp.as_ptr() as *const libc::c_void, 8) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routine_readers_are_skipped() {
        assert!(routine("/usr/sbin/unix_chkpwd"));
        assert!(routine("/usr/lib/openssh/sshd-session"));
        assert!(!routine("/usr/bin/cat"));
        assert!(!routine("/usr/bin/python3.12"));
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// Needs root and /etc/shadow: cargo test -p xdr-linux --lib live_cred -- --ignored
    #[test]
    #[ignore]
    fn live_cred() {
        let (sink, mut rx) = EventSink::channel(64);
        std::thread::spawn(move || CredentialAccess.run(&sink));
        std::thread::sleep(Duration::from_millis(500));
        let out = std::process::Command::new("cat").arg("/etc/shadow").output().unwrap();
        assert!(out.status.success());
        std::thread::sleep(Duration::from_millis(500));
        let e = rx.try_recv().expect("an event");
        let Some(pb::event::Payload::File(f)) = e.payload else {
            panic!()
        };
        println!("{f:?}");
        assert_eq!((f.path.as_str(), f.exe.ends_with("/cat")), ("/etc/shadow", true));
    }
}
