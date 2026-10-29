//! eBPF CO-RE collectors: file changes and TCP connections with the process
//! behind them, from the committed objects built from ../../../bpf/xdr.bpf.c.
//! Unlike inotify the file collector has no watch limit and sees every
//! directory under the configured paths; unlike /proc polling the network
//! collector sees connections of any length. Hosts without kernel BTF, or
//! where a hook cannot be attached, keep the inotify and /proc collectors.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use aya::maps::{MapData, RingBuf};
use aya::programs::KProbe;
use aya::{Ebpf, EbpfLoader};
use xdr_core::bus::{EventSink, new_event};
use xdr_core::pb::{self, EventType};
use xdr_core::platform::Collector;

use crate::file::{Actor, emit_file, process_exe};
use crate::procfs::{self, Hasher};
use crate::writers::{Writer, Writers};

#[cfg(target_arch = "x86_64")]
static OBJECT: &[u8] = aya::include_bytes_aligned!("../../../bpf/xdr_x86_bpfel.o");
#[cfg(target_arch = "aarch64")]
static OBJECT: &[u8] = aya::include_bytes_aligned!("../../../bpf/xdr_arm64_bpfel.o");

// Layouts and operations must match xdr.bpf.c.
const FILE_CREATE: u32 = 1;
const FILE_WRITE: u32 = 2;
const FILE_DELETE: u32 = 3;
const FILE_RENAME: u32 = 4;
const FILE_CHMOD: u32 = 5;
const NET_ACCEPT: u16 = 2;

const NAME_SLOT: usize = 128;
const PATH_SLOTS: usize = 32;
const PATH_BUF: usize = NAME_SLOT * PATH_SLOTS;
const PATH_TRUNCATED: u32 = 0x8000_0000;
const FILE_HEADER: usize = 8 * 4 + 16;
const FILE_EVENT_LEN: usize = FILE_HEADER + 2 * PATH_BUF;
const NET_EVENT_LEN: usize = 3 * 4 + 4 * 2 + 4 + 16 + 16 + 16;
const AF_INET: u16 = 2;

/// How long a write-open waits before the file is hashed, so the reported
/// hash is of the new content.
const WRITE_SETTLE: Duration = Duration::from_secs(1);

/// The loaded programs. Each ring buffer is taken by its collector; the
/// programs and their attachments live as long as this.
pub struct Probes {
    _bpf: Ebpf,
    pub files: Option<RingBuf<MapData>>,
    pub net: Option<RingBuf<MapData>>,
}

/// Loads and attaches the programs. A group whose hooks cannot all be
/// attached is left out; it fails only when nothing could be attached.
pub fn load() -> Result<Probes> {
    if !Path::new("/sys/kernel/btf/vmlinux").exists() {
        return Err(anyhow!("kernel BTF not available"));
    }
    // Kernels before 5.11 charge BPF memory to RLIMIT_MEMLOCK.
    let inf = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &inf) };
    let tgid = std::process::id();
    let mut bpf = EbpfLoader::new()
        .set_global("agent_tgid", &tgid, true)
        .load(OBJECT)
        .context("load eBPF objects")?;
    let files = attach(
        &mut bpf,
        &[
            ("file_create", "security_path_mknod"),
            ("file_open", "security_file_open"),
            ("file_delete", "security_path_unlink"),
            ("file_rename", "security_path_rename"),
            ("file_chmod", "security_path_chmod"),
        ],
    )
    .map_err(|e| tracing::warn!("eBPF file hooks unavailable, using inotify: {e:#}"))
    .ok()
    .and_then(|_| ring(&mut bpf, "file_events"));
    let net = attach(
        &mut bpf,
        &[("net_connect", "tcp_connect"), ("net_accept", "inet_csk_accept")],
    )
    .map_err(|e| tracing::warn!("eBPF network hooks unavailable, polling /proc/net: {e:#}"))
    .ok()
    .and_then(|_| ring(&mut bpf, "net_events"));
    if files.is_none() && net.is_none() {
        return Err(anyhow!("no eBPF hooks could be attached"));
    }
    Ok(Probes { _bpf: bpf, files, net })
}

/// Attaches every hook of a group, or none of them.
fn attach(bpf: &mut Ebpf, hooks: &[(&str, &str)]) -> Result<()> {
    let mut done = Vec::new();
    let res = (|| -> Result<()> {
        for (prog, symbol) in hooks {
            let p: &mut KProbe = bpf
                .program_mut(prog)
                .with_context(|| format!("program {prog} missing"))?
                .try_into()?;
            p.load().with_context(|| format!("load {prog}"))?;
            let id = p.attach(symbol, 0).with_context(|| format!("attach {symbol}"))?;
            done.push((*prog, id));
        }
        Ok(())
    })();
    if res.is_err() {
        for (prog, id) in done {
            if let Some(Ok(p)) = bpf.program_mut(prog).map(<&mut KProbe>::try_from) {
                let _ = p.detach(id);
            }
        }
    }
    res
}

fn ring(bpf: &mut Ebpf, name: &str) -> Option<RingBuf<MapData>> {
    let map = bpf.take_map(name)?;
    RingBuf::try_from(map)
        .map_err(|e| tracing::warn!("eBPF ring buffer {name}: {e}"))
        .ok()
}

/// Feeds ring buffer records to `handle`, and `None` about twice a second.
fn read_ring(rb: &mut RingBuf<MapData>, mut handle: impl FnMut(Option<&[u8]>)) -> Result<()> {
    let mut last = Instant::now();
    loop {
        let mut pfd = libc::pollfd {
            fd: rb.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, 500) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                return Err(err).context("poll ring buffer");
            }
        }
        while let Some(item) = rb.next() {
            handle(Some(&item));
        }
        if last.elapsed() >= Duration::from_millis(500) {
            handle(None);
            last = Instant::now();
        }
    }
}

// --- records ---

#[derive(Debug, Default, Clone, PartialEq)]
struct FileRec {
    pid: u32,
    ppid: u32,
    uid: u32,
    op: u32,
    mode: u32,
    comm: String,
    path: String,
    old_path: String,
}

#[derive(Debug, Clone, PartialEq)]
struct NetRec {
    pid: u32,
    ppid: u32,
    uid: u32,
    op: u16,
    v6: bool,
    local: IpAddr,
    local_port: u16,
    remote: IpAddr,
    remote_port: u16,
    comm: String,
}

fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}

fn c_string(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// Name slots, written leaf first, as an absolute path. A path deeper than
/// the slots allow starts with "/...".
fn join_slots(buf: &[u8], n: u32) -> String {
    let truncated = n & PATH_TRUNCATED != 0;
    let n = ((n & !PATH_TRUNCATED) as usize).min(PATH_SLOTS);
    let mut out = String::new();
    if truncated {
        out.push_str("/...");
    }
    for i in (0..n).rev() {
        let name = c_string(&buf[i * NAME_SLOT..(i + 1) * NAME_SLOT]);
        if name.is_empty() || name == "/" {
            continue;
        }
        out.push('/');
        out.push_str(&name);
    }
    if out.is_empty() { "/".into() } else { out }
}

fn parse_file(b: &[u8]) -> Option<FileRec> {
    if b.len() < FILE_EVENT_LEN {
        return None;
    }
    let (path_len, path2_len) = (u32le(b, 20), u32le(b, 24));
    Some(FileRec {
        pid: u32le(b, 0),
        ppid: u32le(b, 4),
        uid: u32le(b, 8),
        op: u32le(b, 12),
        mode: u32le(b, 16),
        comm: c_string(&b[32..48]),
        path: join_slots(&b[FILE_HEADER..FILE_HEADER + PATH_BUF], path_len),
        old_path: if path2_len > 0 {
            join_slots(&b[FILE_HEADER + PATH_BUF..FILE_EVENT_LEN], path2_len)
        } else {
            String::new()
        },
    })
}

fn parse_net(b: &[u8]) -> Option<NetRec> {
    if b.len() < NET_EVENT_LEN {
        return None;
    }
    let v6 = u16le(b, 14) != AF_INET;
    let addr = |at: usize| -> IpAddr {
        if v6 {
            let a: [u8; 16] = b[at..at + 16].try_into().unwrap();
            let a = Ipv6Addr::from(a);
            a.to_ipv4_mapped().map_or(IpAddr::V6(a), IpAddr::V4)
        } else {
            IpAddr::V4(Ipv4Addr::new(b[at], b[at + 1], b[at + 2], b[at + 3]))
        }
    };
    Some(NetRec {
        pid: u32le(b, 0),
        ppid: u32le(b, 4),
        uid: u32le(b, 8),
        op: u16le(b, 12),
        v6,
        local_port: u16le(b, 16),
        remote_port: u16::from_be_bytes([b[18], b[19]]),
        local: addr(24),
        remote: addr(40),
        comm: c_string(&b[56..72]),
    })
}

// --- collectors ---

pub struct EbpfFile {
    pub ring: Option<RingBuf<MapData>>,
    pub paths: Vec<String>,
    pub exclude: Vec<String>,
    pub hasher: Arc<Hasher>,
    /// Who changed persistence paths, for the persistence collector.
    pub writers: Arc<Writers>,
}

impl EbpfFile {
    /// Remembers the writer of a persistence path, whatever the file paths.
    fn note_writer(&self, r: &FileRec) {
        for p in [&r.path, &r.old_path] {
            if !p.is_empty() && crate::persistence::classify(p).is_some() {
                self.writers.record(
                    p,
                    Writer {
                        pid: r.pid,
                        uid: r.uid,
                        comm: r.comm.clone(),
                        exe: process_exe(r.pid, &r.comm),
                    },
                );
            }
        }
    }
}

fn under_any(path: &str, roots: &[String]) -> bool {
    roots.iter().any(|r| {
        let r = r.trim_end_matches('/');
        r.is_empty() || path == r || path.strip_prefix(r).is_some_and(|rest| rest.starts_with('/'))
    })
}

/// Turns raw file records into events: write-opens wait until the writer had
/// time to finish, and are reported before a delete or rename of the file.
struct FileState<'a> {
    paths: &'a [String],
    exclude: &'a [String],
    writes: HashMap<String, (FileRec, Instant)>,
}

impl FileState<'_> {
    fn wanted(&self, p: &str) -> bool {
        !p.is_empty() && under_any(p, self.paths) && !under_any(p, self.exclude)
    }

    fn handle(&mut self, r: FileRec, out: &mut Vec<(EventType, FileRec)>) {
        if !self.wanted(&r.path) && !self.wanted(&r.old_path) {
            return;
        }
        match r.op {
            FILE_WRITE => {
                self.writes.entry(r.path.clone()).or_insert((r, Instant::now()));
            }
            FILE_CREATE => out.push((EventType::FileCreate, r)),
            FILE_DELETE => {
                self.settle(&r.path, out);
                out.push((EventType::FileDelete, r));
            }
            FILE_RENAME => {
                self.settle(&r.old_path, out);
                out.push((EventType::FileRename, r));
            }
            FILE_CHMOD => out.push((EventType::FileAttrib, r)),
            _ => {}
        }
    }

    fn settle(&mut self, path: &str, out: &mut Vec<(EventType, FileRec)>) {
        if let Some((w, _)) = self.writes.remove(path) {
            out.push((EventType::FileModify, w));
        }
    }

    fn flush(&mut self, now: Instant, out: &mut Vec<(EventType, FileRec)>) {
        let due: Vec<String> = self
            .writes
            .iter()
            .filter(|(_, (_, t))| now.duration_since(*t) >= WRITE_SETTLE)
            .map(|(p, _)| p.clone())
            .collect();
        for p in due {
            self.settle(&p, out);
        }
    }
}

impl EbpfFile {
    fn emit(&self, sink: &EventSink, (t, r): (EventType, FileRec)) {
        let actor = Actor {
            pid: r.pid,
            ppid: r.ppid,
            uid: r.uid,
            comm: r.comm,
        };
        let old = (!r.old_path.is_empty()).then(|| Path::new(&r.old_path));
        emit_file(sink, &self.hasher, t, Path::new(&r.path), old, Some(&actor));
    }
}

impl Collector for EbpfFile {
    fn name(&self) -> &'static str {
        "file-ebpf"
    }

    fn run(&mut self, sink: &EventSink) -> Result<()> {
        let mut ring = self.ring.take().context("eBPF file ring buffer already closed")?;
        let mut st = FileState {
            paths: &self.paths,
            exclude: &self.exclude,
            writes: HashMap::new(),
        };
        let mut out = Vec::new();
        tracing::info!(paths = self.paths.len(), "eBPF file collector running");
        let me = &*self;
        // Returns only on error; the core restarts the collector, which then
        // fails until the agent restarts and reloads eBPF.
        read_ring(&mut ring, |raw| {
            match raw {
                Some(raw) => {
                    if let Some(r) = parse_file(raw) {
                        me.note_writer(&r);
                        st.handle(r, &mut out);
                    }
                }
                None => st.flush(Instant::now(), &mut out),
            }
            for ev in out.drain(..) {
                me.emit(sink, ev);
            }
        })
    }
}

pub struct EbpfNetwork {
    pub ring: Option<RingBuf<MapData>>,
}

fn net_event(r: NetRec) -> pb::Event {
    let accept = r.op == NET_ACCEPT;
    let mut e = new_event(if accept {
        EventType::NetAccept
    } else {
        EventType::NetConnect
    });
    e.payload = Some(pb::event::Payload::Network(pb::NetworkEvent {
        protocol: if r.v6 { "tcp6" } else { "tcp" }.into(),
        local_addr: r.local.to_string(),
        local_port: r.local_port.into(),
        remote_addr: r.remote.to_string(),
        remote_port: r.remote_port.into(),
        pid: r.pid,
        exe: process_exe(r.pid, &r.comm),
        uid: r.uid,
        direction: if accept { "inbound" } else { "outbound" }.into(),
        user: procfs::username(r.uid),
        net_namespace: procfs::ns_inode(r.pid, "net"),
    }));
    e
}

impl Collector for EbpfNetwork {
    fn name(&self) -> &'static str {
        "network-ebpf"
    }

    fn run(&mut self, sink: &EventSink) -> Result<()> {
        let mut ring = self.ring.take().context("eBPF network ring buffer already closed")?;
        tracing::info!("eBPF network collector running");
        read_ring(&mut ring, |raw| {
            if let Some(r) = raw.and_then(parse_net) {
                sink.emit(net_event(r));
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slots(names: &[&str]) -> Vec<u8> {
        let mut b = vec![0u8; PATH_BUF];
        for (i, n) in names.iter().enumerate() {
            b[i * NAME_SLOT..i * NAME_SLOT + n.len()].copy_from_slice(n.as_bytes());
        }
        b
    }

    #[test]
    fn joins_path_slots() {
        assert_eq!(join_slots(&slots(&["passwd", "etc", "/"]), 3), "/etc/passwd");
        // A mount crossing leaves an empty slot.
        assert_eq!(join_slots(&slots(&["x", "tmp", "", "/"]), 4), "/tmp/x");
        assert_eq!(join_slots(&slots(&["x", "deep"]), 2 | PATH_TRUNCATED), "/.../deep/x");
        assert_eq!(join_slots(&slots(&[]), 0), "/");
    }

    #[test]
    fn parses_file_record() {
        let mut b = vec![0u8; FILE_EVENT_LEN];
        for (at, v) in [
            (0, 42u32),
            (4, 1),
            (8, 1000),
            (12, FILE_RENAME),
            (16, 0o644),
            (20, 3),
            (24, 3),
        ] {
            b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        b[32..35].copy_from_slice(b"vim");
        b[FILE_HEADER..FILE_HEADER + PATH_BUF].copy_from_slice(&slots(&["new", "etc", "/"]));
        b[FILE_HEADER + PATH_BUF..].copy_from_slice(&slots(&["old", "etc", "/"]));
        let r = parse_file(&b).unwrap();
        assert_eq!((r.pid, r.ppid, r.uid, r.op, r.mode), (42, 1, 1000, FILE_RENAME, 0o644));
        assert_eq!(
            (r.comm.as_str(), r.path.as_str(), r.old_path.as_str()),
            ("vim", "/etc/new", "/etc/old")
        );
        assert!(parse_file(&b[..100]).is_none());
    }

    #[test]
    fn parses_net_records() {
        let mut b = vec![0u8; NET_EVENT_LEN];
        b[0..4].copy_from_slice(&7u32.to_le_bytes());
        b[12..14].copy_from_slice(&1u16.to_le_bytes());
        b[14..16].copy_from_slice(&AF_INET.to_le_bytes());
        b[16..18].copy_from_slice(&40000u16.to_le_bytes());
        b[18..20].copy_from_slice(&443u16.to_be_bytes());
        b[24..28].copy_from_slice(&[10, 0, 0, 5]);
        b[40..44].copy_from_slice(&[93, 184, 216, 34]);
        b[56..60].copy_from_slice(b"curl");
        let r = parse_net(&b).unwrap();
        assert_eq!((r.pid, r.local_port, r.remote_port, r.v6), (7, 40000, 443, false));
        assert_eq!(
            (r.local.to_string(), r.remote.to_string()),
            ("10.0.0.5".into(), "93.184.216.34".into())
        );
        assert_eq!(r.comm, "curl");
        // IPv4-mapped IPv6 addresses are shown as IPv4.
        b[14..16].copy_from_slice(&10u16.to_le_bytes());
        b[40..56].copy_from_slice(&Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped().octets());
        assert_eq!(parse_net(&b).unwrap().remote.to_string(), "1.2.3.4");
    }

    #[test]
    fn file_state_filters_merges_and_settles() {
        let paths = vec!["/etc".to_string()];
        let exclude = vec!["/etc/skip".to_string()];
        let mut st = FileState {
            paths: &paths,
            exclude: &exclude,
            writes: HashMap::new(),
        };
        let mut out = Vec::new();
        let rec = |op, path: &str, old: &str| FileRec {
            op,
            path: path.into(),
            old_path: old.into(),
            ..Default::default()
        };
        st.handle(rec(FILE_WRITE, "/etc/.hosts.swp", ""), &mut out);
        st.handle(rec(FILE_WRITE, "/etc/.hosts.swp", ""), &mut out); // merged
        st.handle(rec(FILE_CREATE, "/elsewhere/x", ""), &mut out);
        st.handle(rec(FILE_CREATE, "/etc/skip/x", ""), &mut out);
        st.handle(rec(FILE_CREATE, "/etcetera/x", ""), &mut out);
        assert!(out.is_empty());
        st.handle(rec(FILE_RENAME, "/etc/hosts", "/etc/.hosts.swp"), &mut out);
        let kinds: Vec<EventType> = out.iter().map(|(t, _)| *t).collect();
        assert_eq!(kinds, vec![EventType::FileModify, EventType::FileRename]);
        out.clear();
        st.handle(rec(FILE_WRITE, "/etc/motd", ""), &mut out);
        st.flush(Instant::now(), &mut out);
        assert!(out.is_empty());
        st.flush(Instant::now() + WRITE_SETTLE, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, EventType::FileModify);
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    /// Loads the real programs; needs root and BTF. `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn loads_and_sees_a_file_write() {
        let mut p = load().expect("load eBPF");
        let mut ring = p.files.take().expect("file hooks attached");
        let path = std::env::temp_dir().join(format!("xdr-ebpf-{}", std::process::id()));
        std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("echo hi > {}", path.display()))
            .status()
            .unwrap();
        let want = path.to_string_lossy().into_owned();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut seen = false;
        while Instant::now() < deadline && !seen {
            while let Some(item) = ring.next() {
                if parse_file(&item).is_some_and(|r| r.path == want) {
                    seen = true;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = std::fs::remove_file(&path);
        assert!(seen, "no eBPF event for {want}");
    }
}
