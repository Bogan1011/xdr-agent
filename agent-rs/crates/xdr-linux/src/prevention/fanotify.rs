//! A small fanotify wrapper for the permission-event modules (exec and
//! script blocking). The kernel holds each marked open or exec until the
//! agent answers; closing the descriptor, e.g. when the agent stops, allows
//! everything again.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, bail};

pub const FAN_CLASS_CONTENT: u32 = 0x4;
const FAN_CLOEXEC: u32 = 0x1;
const FAN_NONBLOCK: u32 = 0x2;
pub const FAN_MARK_ADD: u32 = 0x1;
pub const FAN_MARK_MOUNT: u32 = 0x10;
pub const FAN_MARK_FILESYSTEM: u32 = 0x100;
pub const FAN_OPEN_PERM: u64 = 0x0001_0000;
pub const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;
pub const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;
const FAN_ALLOW: u32 = 1;
const FAN_DENY: u32 = 2;
const META_LEN: usize = 24;

pub struct Fanotify(i32);

/// One permission event: the opened file's descriptor and the process.
pub struct Request {
    pub fd: i32,
    pub pid: u32,
}

impl Request {
    /// The file's path, from the event's descriptor.
    pub fn path(&self) -> String {
        crate::procfs::readlink(&format!("/proc/self/fd/{}", self.fd))
    }

    /// The event's descriptor as a File, without taking ownership.
    pub fn file(&self) -> ManuallyDrop<File> {
        ManuallyDrop::new(unsafe { File::from_raw_fd(self.fd) })
    }
}

impl Drop for Fanotify {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

impl Fanotify {
    pub fn new() -> Result<Fanotify> {
        let fd = unsafe {
            libc::fanotify_init(
                FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
                (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32,
            )
        };
        if fd < 0 {
            bail!("fanotify_init: {}", io::Error::last_os_error());
        }
        Ok(Fanotify(fd))
    }

    pub fn mark(&self, path: &str, flags: u32, mask: u64) -> io::Result<()> {
        let c = CString::new(path).map_err(|_| io::ErrorKind::InvalidInput)?;
        let rc = unsafe { libc::fanotify_mark(self.0, flags, mask, libc::AT_FDCWD, c.as_ptr()) };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Waits up to half a second for events. Returns None once stop is set.
    pub fn read(&self, buf: &mut [u8], stop: &AtomicBool) -> Result<Option<Vec<Request>>> {
        loop {
            if stop.load(Ordering::Relaxed) {
                return Ok(None);
            }
            let mut pfd = libc::pollfd {
                fd: self.0,
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut pfd, 1, 500) } <= 0 {
                continue;
            }
            let n = unsafe { libc::read(self.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if matches!(err.raw_os_error(), Some(libc::EINTR) | Some(libc::EAGAIN)) {
                    continue;
                }
                bail!("fanotify read: {err}");
            }
            let (n, mut off, mut out) = (n as usize, 0usize, Vec::new());
            while off + META_LEN <= n {
                let b = &buf[off..];
                let len = u32::from_ne_bytes(b[0..4].try_into().unwrap()) as usize;
                if len < META_LEN {
                    break;
                }
                let fd = i32::from_ne_bytes(b[16..20].try_into().unwrap());
                let pid = i32::from_ne_bytes(b[20..24].try_into().unwrap()) as u32;
                off += len;
                if fd >= 0 {
                    out.push(Request { fd, pid });
                }
            }
            return Ok(Some(out));
        }
    }

    /// Answers a request and closes its descriptor.
    pub fn answer(&self, r: Request, allow: bool) {
        let resp: [u32; 2] = [r.fd as u32, if allow { FAN_ALLOW } else { FAN_DENY }];
        if unsafe { libc::write(self.0, resp.as_ptr() as *const libc::c_void, 8) } < 0 {
            tracing::warn!("fanotify response failed: {}", io::Error::last_os_error());
        }
        unsafe { libc::close(r.fd) };
    }
}

/// Decodes the octal escapes /proc/self/mounts uses for spaces.
pub fn unescape_mount(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 4 <= b.len()
            && let Some(v) = std::str::from_utf8(&b[i + 1..i + 4])
                .ok()
                .and_then(|o| u8::from_str_radix(o, 8).ok())
        {
            out.push(v);
            i += 4;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    #[test]
    fn unescapes_mount_points() {
        assert_eq!(super::unescape_mount("/mnt/my\\040disk"), "/mnt/my disk");
        assert_eq!(super::unescape_mount("/plain"), "/plain");
    }
}
