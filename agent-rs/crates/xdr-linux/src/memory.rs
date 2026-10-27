//! Memory and process-access telemetry from /proc, scanned periodically:
//! one process tracing another (ptrace: debuggers, injectors), writable and
//! executable memory, fileless or deleted executables, and LD_PRELOAD in a
//! process's environment. Each finding is reported once per process.
//!
//! Direct writes through /proc/<pid>/mem and process_vm_writev need the
//! eBPF sensor and are not seen here.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use anyhow::Result;
use xdr_core::bus::{EventSink, new_event};
use xdr_core::pb::{self, EventType};
use xdr_core::platform::Collector;

use crate::procfs;

/// Programs that generate code at run time, where RWX memory is expected.
const JIT: &[&str] = &[
    "java",
    "node",
    "nodejs",
    "chrome",
    "chromium",
    "firefox",
    "firefox-bin",
    "dotnet",
    "pwsh",
    "qemu-system-x86_64",
    "electron",
    "code",
    "slack",
    "mono",
    "luajit",
    "php-fpm",
    "gnome-shell",
    "Xorg",
    "Xwayland",
];

pub struct Memory {
    pub interval: Duration,
}

/// A region with all of r, w and x from a /proc/<pid>/maps line.
#[derive(Debug, PartialEq)]
pub struct Region {
    pub start: u64,
    pub size: u64,
    pub perms: String,
    pub path: String,
}

pub fn rwx_regions(maps: &str) -> Vec<Region> {
    maps.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let range = f.next()?;
            let perms = f.next()?;
            if !perms.starts_with("rwx") {
                return None;
            }
            let path = f.nth(3).unwrap_or("").to_string();
            let (a, b) = range.split_once('-')?;
            let (a, b) = (u64::from_str_radix(a, 16).ok()?, u64::from_str_radix(b, 16).ok()?);
            Some(Region {
                start: a,
                size: b.saturating_sub(a),
                perms: perms.into(),
                path,
            })
        })
        .collect()
}

impl Collector for Memory {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn run(&mut self, sink: &EventSink) -> Result<()> {
        let me = std::process::id();
        // (finding, pid, start ticks) already reported.
        let mut reported: HashSet<(&'static str, u32, u64)> = HashSet::new();
        let mut tracers: HashMap<u32, u32> = HashMap::new();
        loop {
            let mut alive: HashSet<u32> = HashSet::new();
            let Ok(rd) = std::fs::read_dir("/proc") else {
                std::thread::sleep(self.interval);
                continue;
            };
            for ent in rd.flatten() {
                let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                    continue;
                };
                if pid == me {
                    continue;
                }
                let Some(start) = procfs::start_ticks(pid) else {
                    continue;
                };
                alive.insert(pid);
                let mut once = |what: &'static str| reported.insert((what, pid, start));
                let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
                // Kernel threads have no memory to inspect.
                if !status.contains("\nVmSize:") {
                    continue;
                }
                let tracer = status
                    .lines()
                    .find_map(|l| l.strip_prefix("TracerPid:"))
                    .and_then(|v| v.trim().parse::<u32>().ok())
                    .unwrap_or(0);
                if tracer != 0 && tracers.get(&pid) != Some(&tracer) {
                    tracers.insert(pid, tracer);
                    emit(
                        sink,
                        EventType::ProcessAccess,
                        access("ptrace_attach", tracer, pid, "traces"),
                    );
                } else if tracer == 0 {
                    tracers.remove(&pid);
                }

                let exe = procfs::readlink(&format!("/proc/{pid}/exe"));
                if exe.starts_with("/memfd:") && once("memfd") {
                    let mut m = target("memfd_exec", pid, &exe);
                    m.injection = true;
                    m.detail = format!("running from an anonymous memory file {exe}");
                    emit(sink, EventType::ProcessInjection, m);
                } else if exe.ends_with(" (deleted)") && once("deleted") {
                    let mut m = target("deleted_exe", pid, &exe);
                    m.detail = format!(
                        "executable {} was deleted while running",
                        exe.trim_end_matches(" (deleted)")
                    );
                    emit(sink, EventType::ProcessInjection, m);
                }

                if let Some(v) = procfs::environ_var(pid, "LD_PRELOAD")
                    && !v.is_empty()
                    && once("preload")
                {
                    let mut m = target("ld_preload_env", pid, &exe);
                    m.injection = true;
                    m.detail = format!("LD_PRELOAD={v}");
                    emit(sink, EventType::ProcessInjection, m);
                }

                let name = exe.rsplit('/').next().unwrap_or("").trim_end_matches(" (deleted)");
                if !JIT.contains(&name)
                    && let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps"))
                {
                    let rwx = rwx_regions(&maps);
                    if let Some(first) = rwx.first()
                        && once("rwx")
                    {
                        let mut m = target("rwx_mapping", pid, &exe);
                        m.rwx = true;
                        m.address = first.start;
                        m.size = rwx.iter().map(|r| r.size).sum();
                        m.new_protection = first.perms.clone();
                        let anon = rwx
                            .iter()
                            .filter(|r| r.path.is_empty() || r.path.starts_with('['))
                            .count();
                        // Anonymous RWX in a program that is not a JIT is a
                        // classic sign of injected shellcode.
                        m.injection = anon > 0;
                        m.detail = format!(
                            "{} rwx region(s), {} anonymous, first at {:#x} {}",
                            rwx.len(),
                            anon,
                            first.start,
                            first.path
                        )
                        .trim_end()
                        .to_string();
                        emit(sink, EventType::MemoryProtect, m);
                    }
                }
            }
            reported.retain(|(_, pid, _)| alive.contains(pid));
            tracers.retain(|pid, _| alive.contains(pid));
            std::thread::sleep(self.interval);
        }
    }
}

fn guid(pid: u32) -> String {
    procfs::start_ticks(pid)
        .map(|t| procfs::process_guid(pid, t))
        .unwrap_or_default()
}

fn uid_name(pid: u32) -> String {
    procfs::read(pid).map(|i| i.user).unwrap_or_default()
}

/// A finding about one process, which is both source and target.
fn target(op: &str, pid: u32, exe: &str) -> pb::MemoryEvent {
    pb::MemoryEvent {
        operation: op.into(),
        source_pid: pid,
        source_process_guid: guid(pid),
        source_exe: exe.into(),
        source_user: uid_name(pid),
        target_pid: pid,
        target_process_guid: guid(pid),
        target_exe: exe.into(),
        target_user: uid_name(pid),
        ..Default::default()
    }
}

fn access(op: &str, src: u32, dst: u32, verb: &str) -> pb::MemoryEvent {
    let src_exe = procfs::readlink(&format!("/proc/{src}/exe"));
    let dst_exe = procfs::readlink(&format!("/proc/{dst}/exe"));
    let (su, tu) = (uid_name(src), uid_name(dst));
    pb::MemoryEvent {
        operation: op.into(),
        detail: format!("{src_exe} (pid {src}, {su}) {verb} {dst_exe} (pid {dst}, {tu})"),
        source_pid: src,
        source_process_guid: guid(src),
        source_exe: src_exe,
        source_user: su,
        target_pid: dst,
        target_process_guid: guid(dst),
        target_exe: dst_exe,
        target_user: tu,
        ..Default::default()
    }
}

fn emit(sink: &EventSink, t: EventType, m: pb::MemoryEvent) {
    let mut e = new_event(t);
    e.payload = Some(pb::event::Payload::Memory(m));
    sink.emit(e);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_rwx() {
        let maps = "55d0c0000000-55d0c0001000 r-xp 00000000 08:01 123 /usr/bin/x\n\
                    7f0000000000-7f0000002000 rwxp 00000000 00:00 0 \n\
                    7f0000010000-7f0000011000 rw-p 00000000 00:00 0 [heap]\n";
        let r = rwx_regions(maps);
        assert_eq!(r.len(), 1);
        assert_eq!(
            (r[0].start, r[0].size, r[0].path.as_str()),
            (0x7f0000000000, 0x2000, "")
        );
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// cargo test -p xdr-linux --lib live_memory -- --ignored
    #[test]
    #[ignore]
    fn live_memory() {
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .env("LD_PRELOAD", "/nonexistent/evil.so")
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let (sink, mut rx) = EventSink::channel(256);
        std::thread::spawn(move || {
            Memory {
                interval: Duration::from_secs(60),
            }
            .run(&sink)
        });
        std::thread::sleep(Duration::from_secs(2));
        let _ = child.kill();
        let mut found = false;
        while let Ok(e) = rx.try_recv() {
            let t = e.r#type();
            if let Some(pb::event::Payload::Memory(m)) = e.payload {
                println!("{t:?} {} {}", m.operation, m.detail);
                found |= m.operation == "ld_preload_env" && m.source_pid == child.id();
            }
        }
        assert!(found);
    }
}
