//! Remote shells opened from the console over the live stream: a login
//! shell for the requested user on a new pseudo-terminal. Every process in
//! it carries XDR_CONSOLE_SESSION, so its telemetry can be tied to the
//! console session.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::sync::mpsc::Sender;
use xdr_core::pb::{self, live_up};

const MAX_SHELLS: usize = 8;

struct Shell {
    user: String,
    tty: String,
    pid: i32,
    master: File,
}

#[derive(Default)]
pub struct Shells {
    disabled: bool,
    open: Arc<Mutex<HashMap<String, Arc<Shell>>>>,
}

fn valid_user(u: &str) -> bool {
    let b = u.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'.' | b'-'))
}

fn send(out: &Sender<pb::LiveUp>, m: live_up::Msg) {
    let _ = out.blocking_send(pb::LiveUp { msg: Some(m) });
}

fn exit(out: &Sender<pb::LiveUp>, id: &str, code: i32, error: String) {
    send(
        out,
        live_up::Msg::ShellExit(pb::ShellExit {
            session_id: id.into(),
            exit_code: code,
            error,
        }),
    );
}

impl Shells {
    pub fn new(disabled: bool) -> Self {
        Shells {
            disabled,
            ..Default::default()
        }
    }

    /// Starts the shell; output and its end go to `out`. Blocks briefly, so
    /// call it off the async runtime.
    pub fn open(&self, req: pb::ShellOpen, out: Sender<pb::LiveUp>) {
        let user = if req.user.is_empty() {
            "root".to_string()
        } else {
            req.user.clone()
        };
        let id = req.session_id.clone();
        if self.disabled {
            return exit(
                &out,
                &id,
                -1,
                "remote shell is turned off in this host's agent config".into(),
            );
        }
        if !valid_user(&user) {
            return exit(&out, &id, -1, "invalid user name".into());
        }
        let shell = {
            let mut open = self.open.lock().unwrap();
            if open.len() >= MAX_SHELLS {
                drop(open);
                return exit(&out, &id, -1, format!("at most {MAX_SHELLS} remote shells per host"));
            }
            match start(&user, &id, req.cols, req.rows) {
                Ok(s) => {
                    let s = Arc::new(s);
                    open.insert(id.clone(), s.clone());
                    s
                }
                Err(err) => {
                    drop(open);
                    tracing::warn!(user, "remote shell failed to start: {err:#}");
                    return exit(&out, &id, -1, format!("{err:#}"));
                }
            }
        };
        tracing::info!(session = %id, user, tty = %shell.tty, "remote shell opened from the console");
        let open = self.open.clone();
        std::thread::Builder::new()
            .name("remote-shell".into())
            .spawn(move || {
                let code = pump(&shell, &id, &out);
                open.lock().unwrap().remove(&id);
                tracing::info!(session = %id, user = %shell.user, exit_code = code, "remote shell closed");
                exit(&out, &id, code, String::new());
            })
            .expect("spawn shell thread");
    }

    fn get(&self, id: &str) -> Option<Arc<Shell>> {
        self.open.lock().unwrap().get(id).cloned()
    }

    pub fn input(&self, id: &str, data: &[u8]) {
        if let Some(s) = self.get(id) {
            let _ = (&s.master).write_all(data);
        }
    }

    pub fn resize(&self, id: &str, cols: u32, rows: u32) {
        if let Some(s) = self.get(id) {
            resize(&s.master, cols, rows);
        }
    }

    pub fn close(&self, id: &str) {
        if let Some(s) = self.get(id) {
            hang_up(s.pid);
        }
    }

    /// The console forgets its shells when the stream drops, so end them too.
    pub fn close_all(&self) {
        for s in self.open.lock().unwrap().values() {
            hang_up(s.pid);
        }
    }

    /// tty → user of the open console shells, for the live view.
    pub fn users(&self) -> HashMap<String, String> {
        self.open
            .lock()
            .unwrap()
            .values()
            .map(|s| (s.tty.clone(), s.user.clone()))
            .collect()
    }
}

fn start(user: &str, session: &str, cols: u32, rows: u32) -> Result<Shell> {
    let (mut master, mut slave) = (-1, -1);
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("allocate terminal");
    }
    let (master, slave) = unsafe { (File::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    let tty = std::fs::read_link(format!("/proc/self/fd/{}", slave.as_raw_fd()))
        .map(|p| p.to_string_lossy().trim_start_matches("/dev/").to_string())
        .unwrap_or_default();
    resize(&master, cols, rows);
    let su = ["/usr/bin/su", "/bin/su"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .unwrap_or("su");
    let mut cmd = Command::new(su);
    // su from root needs no password and gives the user's own login
    // environment, which drops everything else unless whitelisted.
    if su_keeps_env(su) {
        cmd.args(["-w", "XDR_CONSOLE_SESSION"]);
    }
    cmd.args(["-l", user])
        .env_clear()
        .env("TERM", "xterm-256color")
        .env("LANG", "C.UTF-8")
        .env("XDR_CONSOLE_SESSION", session)
        .current_dir("/")
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // The agent runs niced and shielded from the OOM killer; the shell should not.
            libc::setpriority(libc::PRIO_PROCESS, 0, 0);
            // Only async-signal-safe calls after fork: no allocation here.
            let fd = libc::open(c"/proc/self/oom_score_adj".as_ptr(), libc::O_WRONLY);
            if fd >= 0 {
                libc::write(fd, b"0".as_ptr().cast(), 1);
                libc::close(fd);
            }
            Ok(())
        });
    }
    let child = cmd.spawn().context("start login shell")?;
    let pid = child.id() as i32;
    // Reaped by pump through waitpid; the Child handle is not needed.
    std::mem::forget(child);
    if pid <= 1 {
        bail!("bad shell pid");
    }
    Ok(Shell {
        user: user.into(),
        tty,
        pid,
        master,
    })
}

/// util-linux su (2.30+) can keep chosen variables in a login shell.
fn su_keeps_env(su: &str) -> bool {
    static KEEPS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *KEEPS.get_or_init(|| {
        Command::new(su)
            .arg("--help")
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("--whitelist-environment"))
    })
}

/// Forwards terminal output until the shell ends and returns its exit code.
/// Background jobs the shell left behind can keep the terminal open, so the
/// end of the shell process, not of its output, closes the session.
fn pump(s: &Shell, id: &str, out: &Sender<pb::LiveUp>) -> i32 {
    let done = Arc::new(AtomicBool::new(false));
    let code = Arc::new(Mutex::new(0));
    {
        let (done, code, pid) = (done.clone(), code.clone(), s.pid);
        std::thread::spawn(move || {
            let mut status = 0;
            let r = unsafe { libc::waitpid(pid, &mut status, 0) };
            let st = std::process::ExitStatus::from_raw(status);
            *code.lock().unwrap() = if r < 0 {
                -1
            } else {
                st.code().unwrap_or_else(|| 128 + st.signal().unwrap_or(0))
            };
            // Let the last output drain before closing.
            std::thread::sleep(Duration::from_millis(300));
            done.store(true, Ordering::SeqCst);
        });
    }
    let mut buf = vec![0u8; 32 << 10];
    loop {
        let mut pfd = libc::pollfd {
            fd: s.master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, 200) };
        if n > 0 {
            match (&s.master).read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => send(
                    out,
                    live_up::Msg::ShellOutput(pb::ShellData {
                        session_id: id.into(),
                        data: buf[..n].to_vec(),
                    }),
                ),
            }
        } else if done.load(Ordering::SeqCst) {
            break;
        }
    }
    while !done.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(50));
    }
    *code.lock().unwrap()
}

fn resize(master: &File, cols: u32, rows: u32) {
    if cols == 0 || rows == 0 || cols > 1000 || rows > 1000 {
        return;
    }
    let ws = libc::winsize {
        ws_row: rows as u16,
        ws_col: cols as u16,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ as _, &ws) };
}

/// Hangs up the whole session, as closing a terminal window does.
fn hang_up(pid: i32) {
    unsafe {
        libc::kill(-pid, libc::SIGHUP);
        libc::kill(pid, libc::SIGHUP);
    }
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(3));
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_user_names() {
        assert!(valid_user("root"));
        assert!(valid_user("svc_backup-1.x"));
        assert!(!valid_user("Root"));
        assert!(!valid_user("-x"));
        assert!(!valid_user("a;rm"));
        assert!(!valid_user(""));
    }

    #[test]
    fn shell_runs_and_reports_exit() {
        // Needs root (su without a password) and a terminal device.
        if unsafe { libc::geteuid() } != 0 || !std::path::Path::new("/usr/bin/su").exists() {
            return;
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let shells = Shells::default();
        shells.open(
            pb::ShellOpen {
                session_id: "t1".into(),
                user: "root".into(),
                cols: 80,
                rows: 24,
            },
            tx,
        );
        assert_eq!(shells.users().len(), 1);
        shells.input("t1", b"echo xdr-$XDR_CONSOLE_SESSION; exit 7\n");
        let mut output = Vec::new();
        let code = rt.block_on(async {
            loop {
                match tokio::time::timeout(Duration::from_secs(10), rx.recv()).await {
                    Ok(Some(pb::LiveUp {
                        msg: Some(live_up::Msg::ShellOutput(d)),
                    })) => output.extend(d.data),
                    Ok(Some(pb::LiveUp {
                        msg: Some(live_up::Msg::ShellExit(e)),
                    })) => break e.exit_code,
                    other => panic!("unexpected {other:?}"),
                }
            }
        });
        assert_eq!(code, 7);
        assert!(String::from_utf8_lossy(&output).contains("xdr-t1"));
        assert!(shells.users().is_empty());
    }
}
