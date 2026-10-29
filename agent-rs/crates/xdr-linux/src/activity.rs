//! The console's live view: who is logged in on which terminal, what runs
//! there, the busiest processes and host load, from /proc on request.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

use xdr_core::pb;

use crate::procfs;

/// USER_HZ, 100 on every Linux architecture the agent supports.
const CLOCK_TICKS: u64 = 100;
const TOP_PROCS: usize = 12;
const MAX_COMMAND: usize = 300;

#[derive(Debug, Default, Clone, PartialEq)]
struct Proc {
    pid: u32,
    ppid: u32,
    sid: u32,
    tpgid: u32,
    tty: u32,
    uid: u32,
    ticks: u64,
    start: i64,
    rss: u64,
    command: String,
}

/// Reads the fields of /proc/<pid>/stat the view uses. The command name can
/// hold spaces and parentheses, so fields are counted from the last ')'.
fn parse_stat(raw: &str, boot_unix: i64, page: u64) -> Option<Proc> {
    let close = raw.rfind(')')?;
    let comm = &raw[raw.find('(')? + 1..close];
    let f: Vec<&str> = raw[close + 1..].split_whitespace().collect();
    // f[0] is field 3 (state); field n is f[n-3].
    if f.len() < 22 {
        return None;
    }
    let u = |n: usize| f[n - 3].parse::<u64>().unwrap_or(0);
    Some(Proc {
        ppid: u(4) as u32,
        sid: u(6) as u32,
        tty: u(7) as u32,
        tpgid: f[8 - 3].parse::<i64>().ok().filter(|t| *t > 0).unwrap_or(0) as u32,
        ticks: u(14) + u(15),
        start: boot_unix + (u(22) / CLOCK_TICKS) as i64,
        rss: u(24) * page,
        command: format!("[{comm}]"),
        ..Default::default()
    })
}

/// A stat tty_nr as a device name such as pts/3 or tty1.
fn tty_name(nr: u32) -> String {
    let major = (nr >> 8) & 0xfff;
    let minor = (nr & 0xff) | ((nr >> 12) & 0xfff00);
    match major {
        136..=143 => format!("pts/{}", minor + (major - 136) * 256),
        4 if minor < 64 => format!("tty{minor}"),
        4 => format!("ttyS{}", minor - 64),
        _ => format!("tty({major},{minor})"),
    }
}

fn boot_time() -> i64 {
    fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("btime ").and_then(|v| v.trim().parse().ok()))
        })
        .unwrap_or(0)
}

fn read_procs(boot: i64) -> HashMap<u32, Proc> {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
    let mut out = HashMap::new();
    let Ok(rd) = fs::read_dir("/proc") else { return out };
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let base = format!("/proc/{pid}");
        let Some(mut p) = fs::read_to_string(format!("{base}/stat"))
            .ok()
            .and_then(|s| parse_stat(&s, boot, page))
        else {
            continue;
        };
        p.pid = pid;
        p.uid = fs::metadata(&base).map(|m| m.uid()).unwrap_or(0);
        if let Ok(cl) = fs::read(format!("{base}/cmdline")) {
            let cl = String::from_utf8_lossy(&cl).trim_end_matches('\0').replace('\0', " ");
            if !cl.is_empty() {
                p.command = cl;
            }
        }
        truncate(&mut p.command, MAX_COMMAND);
        out.insert(pid, p);
    }
    out
}

fn truncate(s: &mut String, n: usize) {
    if s.len() > n {
        let mut i = n;
        while !s.is_char_boundary(i) {
            i -= 1;
        }
        s.truncate(i);
    }
}

/// The client address of an SSH login, from its environment.
fn ssh_client(pid: u32) -> String {
    let Ok(raw) = fs::read(format!("/proc/{pid}/environ")) else {
        return String::new();
    };
    raw.split(|b| *b == 0)
        .find_map(|kv| kv.strip_prefix(b"SSH_CONNECTION="))
        .and_then(|v| String::from_utf8_lossy(v).split_whitespace().next().map(String::from))
        .unwrap_or_default()
}

fn is_shell(cmd: &str) -> bool {
    let first = cmd.split_whitespace().next().unwrap_or("").trim_start_matches('-');
    let name = first.rsplit('/').next().unwrap_or(first);
    matches!(name, "bash" | "sh" | "zsh" | "dash" | "fish" | "ksh" | "tcsh" | "csh")
}

fn meminfo() -> (u64, u64) {
    let (mut total, mut avail) = (0, 0);
    for line in fs::read_to_string("/proc/meminfo").unwrap_or_default().lines() {
        let (k, v) = line.split_once(':').unwrap_or((line, ""));
        let n: u64 = v.split_whitespace().next().and_then(|n| n.parse().ok()).unwrap_or(0);
        match k {
            "MemTotal" => total = n << 10,
            "MemAvailable" => avail = n << 10,
            _ => {}
        }
    }
    (total, avail)
}

/// Remembers CPU time between snapshots to report CPU use since the last.
#[derive(Default)]
pub struct Sampler {
    prev: HashMap<u32, u64>,
    prev_time: Option<Instant>,
}

impl Sampler {
    /// `console_users` maps the ttys of console remote shells to their user.
    pub fn snapshot(&mut self, console_users: &HashMap<String, String>) -> pb::Activity {
        let now = Instant::now();
        let procs = read_procs(boot_time());
        let elapsed = self.prev_time.map_or(0.0, |t| now.duration_since(t).as_secs_f64());
        let cpu = |p: &Proc| match self.prev.get(&p.pid) {
            Some(&before) if elapsed > 0.0 && elapsed <= 600.0 && p.ticks >= before => {
                100.0 * (p.ticks - before) as f64 / CLOCK_TICKS as f64 / elapsed
            }
            _ => 0.0,
        };
        let lp = |p: &Proc| pb::LiveProcess {
            pid: p.pid,
            ppid: p.ppid,
            user: procfs::username(p.uid),
            tty: if p.tty != 0 { tty_name(p.tty) } else { String::new() },
            command: p.command.clone(),
            cpu_percent: cpu(p),
            rss_bytes: p.rss,
            start_unix: p.start,
        };

        let mut act = pb::Activity::default();
        let mut by_tty: HashMap<u32, Vec<&Proc>> = HashMap::new();
        let mut all: Vec<pb::LiveProcess> = Vec::with_capacity(procs.len());
        for p in procs.values() {
            if p.tty != 0 {
                by_tty.entry(p.tty).or_default().push(p);
            }
            all.push(lp(p));
        }
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        for (nr, mut ps) in by_tty {
            ps.sort_by_key(|p| (p.start, p.pid));
            // The session leader is the login shell (or su for console shells).
            let leader = ps.iter().find(|p| p.pid == p.sid).copied().unwrap_or(ps[0]);
            let mut t = pb::TerminalSession {
                tty: tty_name(nr),
                user: procfs::username(leader.uid),
                from: ssh_client(leader.pid),
                login_unix: leader.start,
                ..Default::default()
            };
            if let Some(u) = console_users.get(&t.tty) {
                t.user = u.clone();
                t.console = true;
            }
            if let Ok(md) = fs::metadata(format!("/dev/{}", t.tty)) {
                t.idle_seconds = (now_unix - md.atime()).max(0) as u64;
            }
            // What runs in the foreground, unless it is the shell at its prompt.
            if let Some(fg) = procs.get(&leader.tpgid)
                && fg.pid != leader.pid
                && !is_shell(&fg.command)
            {
                t.current = fg.command.clone();
            }
            t.processes = ps.iter().map(|p| lp(p)).collect();
            act.terminals.push(t);
        }
        act.terminals.sort_by_key(|t| std::cmp::Reverse(t.login_unix));
        all.sort_by(|a, b| {
            b.cpu_percent
                .total_cmp(&a.cpu_percent)
                .then(b.rss_bytes.cmp(&a.rss_bytes))
        });
        all.truncate(TOP_PROCS);
        act.top = all;

        self.prev = procs.values().map(|p| (p.pid, p.ticks)).collect();
        self.prev_time = Some(now);

        if let Ok(s) = fs::read_to_string("/proc/loadavg") {
            act.load1 = s.split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
        }
        if let Ok(s) = fs::read_to_string("/proc/uptime") {
            act.uptime_seconds = s
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(0.0) as u64;
        }
        (act.mem_total_bytes, act.mem_available_bytes) = meminfo();
        act
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stat_with_odd_command_names() {
        let raw = "1234 (my (odd) cmd) S 1 1234 1234 34816 1300 4194560 100 0 0 0 250 50 0 0 20 0 1 0 500 1000000 300 18446744073709551615";
        let p = parse_stat(raw, 1_000_000, 4096).unwrap();
        assert_eq!((p.ppid, p.sid, p.tty, p.tpgid), (1, 1234, 34816, 1300));
        assert_eq!(p.ticks, 300);
        assert_eq!(p.start, 1_000_005);
        assert_eq!(p.rss, 300 * 4096);
        assert_eq!(p.command, "[my (odd) cmd]");
        assert!(parse_stat("1 (x) S 1", 0, 4096).is_none());
    }

    #[test]
    fn names_ttys() {
        assert_eq!(tty_name(34816), "pts/0");
        assert_eq!(tty_name((136 << 8) | 3), "pts/3");
        assert_eq!(tty_name((4 << 8) | 1), "tty1");
        assert_eq!(tty_name((4 << 8) | 65), "ttyS1");
    }

    #[test]
    fn spots_shells() {
        assert!(is_shell("-bash"));
        assert!(is_shell("/usr/bin/zsh -l"));
        assert!(!is_shell("vim /etc/hosts"));
    }

    #[test]
    fn snapshot_lists_this_process() {
        let mut s = Sampler::default();
        let act = s.snapshot(&HashMap::new());
        assert!(!act.top.is_empty());
        assert!(act.mem_total_bytes > 0);
    }
}
