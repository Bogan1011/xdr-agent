//! DNS telemetry: queries and their answers from a packet socket filtered to
//! UDP port 53, attributed to the asking process through its socket. One
//! event per query, sent when the answer arrives or after a timeout.
//!
//! On hosts with systemd-resolved an application asks the stub at
//! 127.0.0.53 (seen on lo, with the real process) and resolved asks the
//! upstream server; the upstream copy is dropped when the stub query for the
//! same name was just seen.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use xdr_core::bus::{EventSink, new_event};
use xdr_core::pb::{self, EventType};
use xdr_core::platform::Collector;

use crate::procfs;

const ETH_P_ALL: u16 = 0x0003;
const ETH_P_IP: u32 = 0x0800;
const ETH_P_IPV6: u32 = 0x86dd;
const PACKET_OUTGOING: u8 = 4;
/// Unanswered queries are reported after this long.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PENDING: usize = 4096;

pub struct Dns;

struct Fd(i32);
impl Drop for Fd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// A UDP datagram to or from port 53.
#[derive(Debug, PartialEq)]
struct Datagram<'a> {
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
    dport: u16,
    payload: &'a [u8],
}

#[derive(Debug, Default, PartialEq)]
pub struct Message {
    pub id: u16,
    pub response: bool,
    pub rcode: u8,
    pub name: String,
    pub qtype: u16,
    pub answers: Vec<pb::DnsAnswer>,
}

struct Pending {
    at: Instant,
    event: pb::DnsEvent,
    client_loopback: bool,
}

impl Collector for Dns {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn run(&mut self, sink: &EventSink) -> Result<()> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                (ETH_P_ALL.to_be()) as i32,
            )
        };
        if fd < 0 {
            bail!("packet socket: {}", io::Error::last_os_error());
        }
        let fd = Fd(fd);
        attach_filter(fd.0)?;
        let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
        unsafe {
            libc::setsockopt(
                fd.0,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            )
        };
        let lo = unsafe { libc::if_nametoindex(c"lo".as_ptr()) } as i32;
        let me = std::process::id();
        let mut owners = Owners::default();
        let mut pending: HashMap<(u16, u16), Pending> = HashMap::new();
        // Names recently asked through the systemd-resolved stub.
        let mut stub_names: HashMap<String, Instant> = HashMap::new();
        let mut buf = vec![0u8; 65536];
        loop {
            let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut alen = std::mem::size_of::<libc::sockaddr_ll>() as u32;
            let n = unsafe {
                libc::recvfrom(
                    fd.0,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    &mut addr as *mut _ as *mut libc::sockaddr,
                    &mut alen,
                )
            };
            let now = Instant::now();
            if n > 0 && !(addr.sll_ifindex == lo && addr.sll_pkttype == PACKET_OUTGOING) {
                let proto = u16::from_be(addr.sll_protocol) as u32;
                if let Some(d) = parse_ip(proto, &buf[..n as usize])
                    && let Some(m) = parse_message(d.payload)
                {
                    if !m.response && d.dport == 53 {
                        if pending.len() >= MAX_PENDING {
                            pending.clear();
                        }
                        let pid = owners.pid(d.sport);
                        if pid != me {
                            let exe = if pid != 0 {
                                procfs::readlink(&format!("/proc/{pid}/exe"))
                            } else {
                                String::new()
                            };
                            let client_loopback = d.src.is_loopback();
                            if client_loopback {
                                stub_names.insert(m.name.clone(), now);
                            }
                            pending.insert(
                                (m.id, d.sport),
                                Pending {
                                    at: now,
                                    client_loopback,
                                    event: pb::DnsEvent {
                                        query: m.name,
                                        query_type: type_name(m.qtype),
                                        server: d.dst.to_string(),
                                        server_port: 53,
                                        pid,
                                        exe,
                                        protocol: "udp".into(),
                                        ..Default::default()
                                    },
                                },
                            );
                        }
                    } else if m.response
                        && d.sport == 53
                        && let Some(mut p) = pending.remove(&(m.id, d.dport))
                    {
                        p.event.response_code = rcode_name(m.rcode);
                        p.event.answers = m.answers;
                        report(sink, p, &stub_names);
                    }
                }
            }
            // Expire unanswered queries and old stub names.
            if !pending.is_empty() {
                let expired: Vec<(u16, u16)> = pending
                    .iter()
                    .filter(|(_, p)| now.duration_since(p.at) > ANSWER_TIMEOUT)
                    .map(|(k, _)| *k)
                    .collect();
                for k in expired {
                    if let Some(p) = pending.remove(&k) {
                        report(sink, p, &stub_names);
                    }
                }
            }
            stub_names.retain(|_, t| now.duration_since(*t) < Duration::from_secs(10));
            if n < 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EAGAIN) | Some(libc::EINTR) => {}
                    _ => bail!("packet recv: {err}"),
                }
            }
        }
    }
}

fn report(sink: &EventSink, p: Pending, stub_names: &HashMap<String, Instant>) {
    // resolved's upstream copy of a query an application just asked the stub.
    if !p.client_loopback && p.event.exe.ends_with("systemd-resolved") && stub_names.contains_key(&p.event.query) {
        return;
    }
    let mut e = new_event(EventType::DnsQuery);
    e.payload = Some(pb::event::Payload::Dns(p.event));
    sink.emit(e);
}

/// Maps local UDP ports to the owning pid. A lookup reads the UDP socket
/// table and then searches /proc/*/fd newest process first, since the asker
/// is usually short-lived and must be found before it exits.
#[derive(Default)]
struct Owners {
    by_port: HashMap<u16, u32>,
    window: Option<Instant>,
    scans: u32,
}

/// Most /proc searches per second; queries beyond it go unattributed.
const MAX_SCANS: u32 = 50;

impl Owners {
    fn pid(&mut self, port: u16) -> u32 {
        // Ephemeral ports are reused; a hit counts while its process lives.
        if let Some(p) = self.by_port.get(&port)
            && std::path::Path::new(&format!("/proc/{p}")).exists()
        {
            return *p;
        }
        if self.window.is_none_or(|t| t.elapsed() > Duration::from_secs(1)) {
            self.window = Some(Instant::now());
            self.scans = 0;
        }
        if self.scans >= MAX_SCANS {
            return 0;
        }
        self.scans += 1;
        let Some(ino) = udp_inode(port) else { return 0 };
        let pid = socket_pid(ino).unwrap_or(0);
        if pid != 0 {
            if self.by_port.len() > 4096 {
                self.by_port.clear();
            }
            self.by_port.insert(port, pid);
        }
        pid
    }
}

/// The inode of the UDP socket bound to a local port.
fn udp_inode(port: u16) -> Option<u64> {
    let want = format!(":{port:04X}");
    for f in ["/proc/net/udp", "/proc/net/udp6"] {
        let Ok(text) = std::fs::read_to_string(f) else { continue };
        for line in text.lines().skip(1) {
            let c: Vec<&str> = line.split_whitespace().collect();
            if c.len() >= 10
                && c[1].ends_with(&want)
                && let Ok(ino) = c[9].parse::<u64>()
                && ino != 0
            {
                return Some(ino);
            }
        }
    }
    None
}

/// The pid holding a socket inode, searching the newest processes first.
fn socket_pid(ino: u64) -> Option<u32> {
    let target = format!("socket:[{ino}]");
    let mut pids: Vec<u32> = std::fs::read_dir("/proc")
        .ok()?
        .flatten()
        .filter_map(|p| p.file_name().to_str().and_then(|s| s.parse().ok()))
        .collect();
    pids.sort_unstable_by(|a, b| b.cmp(a));
    for pid in pids {
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).is_ok_and(|l| l.as_os_str() == target.as_str()) {
                return Some(pid);
            }
        }
    }
    None
}

/// A classic BPF filter that keeps UDP datagrams to or from port 53 (IPv4
/// with any header length, IPv6 without extension headers).
fn attach_filter(fd: i32) -> Result<()> {
    let prog = filter_program();
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::sock_fprog>() as u32,
        )
    };
    if rc < 0 {
        bail!("attach DNS filter: {}", io::Error::last_os_error());
    }
    Ok(())
}

const LD_PROTO: u32 = 0xffff_f000; // SKF_AD_OFF + SKF_AD_PROTOCOL

fn filter_program() -> [libc::sock_filter; 18] {
    let ins = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
    // Opcodes: ld w abs 0x20, ldb abs 0x30, ldh abs 0x28, ldh ind 0x48,
    // ldx msh 0xb1, jeq 0x15, ret 0x06. Jumps are relative to the next
    // instruction; 16 accepts, 17 drops.
    [
        /* 0 */ ins(0x20, 0, 0, LD_PROTO),
        /* 1 */ ins(0x15, 0, 7, ETH_P_IP),
        /* 2 */ ins(0x30, 0, 0, 9),
        /* 3 */ ins(0x15, 0, 13, 17),
        /* 4 */ ins(0xb1, 0, 0, 0),
        /* 5 */ ins(0x48, 0, 0, 0),
        /* 6 */ ins(0x15, 9, 0, 53),
        /* 7 */ ins(0x48, 0, 0, 2),
        /* 8 */ ins(0x15, 7, 8, 53),
        /* 9 */ ins(0x15, 0, 7, ETH_P_IPV6),
        /* 10 */ ins(0x30, 0, 0, 6),
        /* 11 */ ins(0x15, 0, 5, 17),
        /* 12 */ ins(0x28, 0, 0, 40),
        /* 13 */ ins(0x15, 2, 0, 53),
        /* 14 */ ins(0x28, 0, 0, 42),
        /* 15 */ ins(0x15, 0, 1, 53),
        /* 16 */ ins(0x06, 0, 0, 0xffff),
        /* 17 */ ins(0x06, 0, 0, 0),
    ]
}

fn be16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn parse_ip(proto: u32, pkt: &[u8]) -> Option<Datagram<'_>> {
    let (src, dst, udp) = match proto {
        ETH_P_IP => {
            let ihl = (*pkt.first()? & 0x0f) as usize * 4;
            if pkt.get(9)? != &17 || ihl < 20 {
                return None;
            }
            let s: [u8; 4] = pkt.get(12..16)?.try_into().ok()?;
            let d: [u8; 4] = pkt.get(16..20)?.try_into().ok()?;
            (
                IpAddr::V4(Ipv4Addr::from(s)),
                IpAddr::V4(Ipv4Addr::from(d)),
                pkt.get(ihl..)?,
            )
        }
        ETH_P_IPV6 => {
            if pkt.get(6)? != &17 {
                return None;
            }
            let s: [u8; 16] = pkt.get(8..24)?.try_into().ok()?;
            let d: [u8; 16] = pkt.get(24..40)?.try_into().ok()?;
            (
                IpAddr::V6(Ipv6Addr::from(s)),
                IpAddr::V6(Ipv6Addr::from(d)),
                pkt.get(40..)?,
            )
        }
        _ => return None,
    };
    let len = (be16(udp, 4)? as usize).clamp(8, udp.len());
    Some(Datagram {
        src,
        sport: be16(udp, 0)?,
        dst,
        dport: be16(udp, 2)?,
        payload: udp.get(8..len)?,
    })
}

/// Reads a possibly compressed name at off; returns it and the offset after it.
fn read_name(msg: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let len = *msg.get(off)? as usize;
        if len == 0 {
            return Some((labels.join("."), end.unwrap_or(off + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let ptr = (be16(msg, off)? & 0x3fff) as usize;
            end.get_or_insert(off + 2);
            off = ptr;
            continue;
        }
        let label = msg.get(off + 1..off + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        off += 1 + len;
    }
    None
}

pub fn parse_message(msg: &[u8]) -> Option<Message> {
    let flags = be16(msg, 2)?;
    let qd = be16(msg, 4)?;
    let an = be16(msg, 6)?;
    // Standard queries with exactly one question.
    if qd != 1 || (flags >> 11) & 0xf != 0 {
        return None;
    }
    let (name, off) = read_name(msg, 12)?;
    let mut m = Message {
        id: be16(msg, 0)?,
        response: flags & 0x8000 != 0,
        rcode: (flags & 0xf) as u8,
        name: name.to_lowercase(),
        qtype: be16(msg, off)?,
        answers: Vec::new(),
    };
    let mut off = off + 4;
    for _ in 0..an.min(32) {
        let Some((_, o)) = read_name(msg, off) else { break };
        let (Some(t), Some(ttl_hi), Some(ttl_lo), Some(rdlen)) =
            (be16(msg, o), be16(msg, o + 4), be16(msg, o + 6), be16(msg, o + 8))
        else {
            break;
        };
        let rd = o + 10;
        let Some(data) = msg.get(rd..rd + rdlen as usize) else {
            break;
        };
        let value = match t {
            1 if data.len() == 4 => Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string(),
            28 if data.len() == 16 => Ipv6Addr::from(<[u8; 16]>::try_from(data).unwrap()).to_string(),
            5 | 2 | 12 => read_name(msg, rd).map(|(n, _)| n).unwrap_or_default(),
            15 => read_name(msg, rd + 2).map(|(n, _)| n).unwrap_or_default(),
            16 => data
                .get(1..)
                .map(|t| String::from_utf8_lossy(t).into_owned())
                .unwrap_or_default(),
            _ => String::new(),
        };
        m.answers.push(pb::DnsAnswer {
            r#type: type_name(t),
            data: value,
            ttl: ((ttl_hi as u32) << 16) | ttl_lo as u32,
        });
        off = rd + rdlen as usize;
    }
    Some(m)
}

fn type_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

fn rcode_name(r: u8) -> String {
    match r {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        other => format!("RCODE{other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Response to "example.com A": a CNAME via a compression pointer and an A record.
    pub const RESPONSE: &[u8] = &[
        0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0, //
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1, //
        0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3, b'w', b'w', b'w', 0xc0, 0x0c, //
        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0, 0, 4, 93, 184, 216, 34,
    ];

    #[test]
    fn parses_response() {
        let m = parse_message(RESPONSE).unwrap();
        assert_eq!(
            (m.id, m.response, m.rcode, m.name.as_str(), m.qtype),
            (0x1234, true, 0, "example.com", 1)
        );
        assert_eq!(m.answers.len(), 2);
        assert_eq!(
            (
                m.answers[0].r#type.as_str(),
                m.answers[0].data.as_str(),
                m.answers[0].ttl
            ),
            ("CNAME", "www.example.com", 60)
        );
        assert_eq!((m.answers[1].data.as_str(), m.answers[1].ttl), ("93.184.216.34", 256));
        assert!(parse_message(&RESPONSE[..20]).is_none());
        // A pointer loop ends instead of spinning.
        assert!(read_name(&[0xc0, 0x00], 0).is_none());
    }

    /// Runs the socket filter on a packet: true when it is kept.
    fn filter_keeps(proto: u32, pkt: &[u8]) -> bool {
        let prog = filter_program();
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        loop {
            let i = prog[pc];
            let k = i.k as usize;
            match i.code {
                0x20 => a = if i.k == LD_PROTO { proto } else { unreachable!() },
                0x30 => a = pkt[k] as u32,
                0x28 => a = be16(pkt, k).unwrap() as u32,
                0x48 => a = be16(pkt, x as usize + k).unwrap() as u32,
                0xb1 => x = ((pkt[k] & 0xf) as u32) * 4,
                0x15 => {
                    pc += 1 + if a == i.k { i.jt } else { i.jf } as usize;
                    continue;
                }
                0x06 => return i.k != 0,
                c => panic!("opcode {c:#x}"),
            }
            pc += 1;
        }
    }

    #[test]
    fn filter_keeps_only_dns() {
        let mut v4 = vec![
            0x46, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 8, 8, 8, 8, 0, 0, 0, 0,
        ];
        v4.extend_from_slice(&[0xa0, 0, 0, 53, 0, 8, 0, 0]);
        assert!(filter_keeps(ETH_P_IP, &v4), "query, 24-byte IPv4 header");
        v4[24..28].copy_from_slice(&[0, 53, 0xa0, 0]);
        assert!(filter_keeps(ETH_P_IP, &v4), "response");
        v4[24..28].copy_from_slice(&[0, 80, 0xa0, 0]);
        assert!(!filter_keeps(ETH_P_IP, &v4), "other port");
        v4[9] = 6;
        assert!(!filter_keeps(ETH_P_IP, &v4), "tcp");
        let mut v6 = vec![0u8; 48];
        v6[6] = 17;
        v6[42..44].copy_from_slice(&[0, 53]);
        assert!(filter_keeps(ETH_P_IPV6, &v6));
        v6[42..44].copy_from_slice(&[0, 54]);
        assert!(!filter_keeps(ETH_P_IPV6, &v6));
        assert!(!filter_keeps(0x0806, &v6));
    }

    #[test]
    fn parses_ipv4_udp() {
        let mut pkt = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 8, 8, 8, 8];
        let udp_len = (8 + RESPONSE.len()) as u16;
        pkt.extend_from_slice(&[0, 53, 0xa0, 0x00]);
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&[0, 0]);
        pkt.extend_from_slice(RESPONSE);
        let d = parse_ip(ETH_P_IP, &pkt).unwrap();
        assert_eq!((d.src.to_string().as_str(), d.sport, d.dport), ("10.0.0.2", 53, 0xa000));
        assert_eq!(d.payload, RESPONSE);
        assert!(parse_ip(ETH_P_IP, &pkt[..10]).is_none());
    }
}

#[cfg(test)]
mod live {
    use super::tests::RESPONSE;
    use super::*;

    /// Needs root: cargo test -p xdr-linux -- --ignored live_dns
    #[test]
    #[ignore]
    fn live_dns() {
        let (sink, mut rx) = EventSink::channel(64);
        std::thread::spawn(move || Dns.run(&sink));
        std::thread::sleep(Duration::from_millis(300));
        // A local server answering every query with RESPONSE, and a child
        // process asking it (the agent's own lookups are skipped).
        let srv = std::net::UdpSocket::bind("127.0.0.1:53").unwrap();
        std::thread::spawn(move || {
            let mut b = [0u8; 512];
            while let Ok((_, from)) = srv.recv_from(&mut b) {
                let mut r = RESPONSE.to_vec();
                r[..2].copy_from_slice(&b[..2]);
                let _ = srv.send_to(&r, from);
            }
        });
        let q = "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);\
s.sendto(bytes.fromhex('abcd01000001000000000000076578616d706c6503636f6d0000010001'),('127.0.0.1',53));print(len(s.recv(512)))";
        let child = std::process::Command::new("python3").args(["-c", q]).output().unwrap();
        assert!(child.status.success(), "{child:?}");
        std::thread::sleep(Duration::from_secs(1));
        let mut seen = Vec::new();
        while let Ok(e) = rx.try_recv() {
            if let Some(pb::event::Payload::Dns(d)) = e.payload {
                println!("{d:?}");
                seen.push(d);
            }
        }
        assert!(
            seen.iter()
                .any(|d| d.query == "example.com" && d.response_code == "NOERROR" && d.exe.contains("python"))
        );
    }
}
