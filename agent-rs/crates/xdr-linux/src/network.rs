//! New TCP and UDP connections and listening sockets from /proc/net,
//! attributed to a process through socket inodes. A connection to a local
//! listening port is inbound (accept), anything else outbound (connect). Polling can miss connections shorter than
//! the interval; the eBPF collector (ported later) closes that gap.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use anyhow::Result;
use xdr_core::bus::{EventSink, new_event};
use xdr_core::pb::{self, EventType};
use xdr_core::platform::Collector;

use crate::procfs;

const ESTABLISHED: &str = "01";
const LISTEN: &str = "0A";
/// TCP_CLOSE: how /proc/net/udp shows an unconnected (bound) UDP socket.
const UDP_UNCONNECTED: &str = "07";

pub struct Network {
    pub interval: Duration,
}

#[derive(Debug, Clone, PartialEq)]
struct Sock {
    proto: &'static str,
    state: &'static str,
    local: String,
    local_port: u32,
    remote: String,
    remote_port: u32,
    uid: u32,
    inode: u64,
}

impl Collector for Network {
    fn name(&self) -> &'static str {
        "network"
    }

    fn run(&mut self, sink: &EventSink) -> Result<()> {
        let mut seen: HashSet<u64> = HashSet::new();
        let mut first = true;
        let me = std::process::id();
        loop {
            let mut socks = read_sockets("/proc/net/tcp", "tcp");
            socks.extend(read_sockets("/proc/net/tcp6", "tcp6"));
            socks.extend(read_sockets("/proc/net/udp", "udp"));
            socks.extend(read_sockets("/proc/net/udp6", "udp6"));
            let listening: HashSet<(&str, u32)> = socks
                .iter()
                .filter(|s| s.state == LISTEN)
                .map(|s| (family(s.proto), s.local_port))
                .collect();
            let current: HashSet<u64> = socks.iter().filter(|s| s.inode != 0).map(|s| s.inode).collect();
            let fresh: Vec<&Sock> = socks
                .iter()
                .filter(|s| s.inode != 0 && !seen.contains(&s.inode))
                .collect();
            // Listeners present at startup are reported once so the console
            // knows the exposed services; existing connections are not.
            if !fresh.is_empty() {
                let owners = socket_owners();
                for s in fresh {
                    if first && s.state != LISTEN {
                        continue;
                    }
                    let pid = owners.get(&s.inode).copied().unwrap_or(0);
                    if pid != me {
                        let inbound = s.state != LISTEN && listening.contains(&(family(s.proto), s.local_port));
                        emit(sink, s, pid, inbound);
                    }
                }
            }
            seen = current;
            first = false;
            std::thread::sleep(self.interval);
        }
    }
}

/// "tcp" or "udp", so IPv4 and IPv6 sockets on one port match.
fn family(proto: &str) -> &str {
    proto.trim_end_matches('6')
}

fn emit(sink: &EventSink, s: &Sock, pid: u32, inbound: bool) {
    let (t, direction) = if s.state == LISTEN {
        (EventType::NetListen, "listen")
    } else if inbound {
        (EventType::NetAccept, "inbound")
    } else {
        (EventType::NetConnect, "outbound")
    };
    let mut e = new_event(t);
    e.payload = Some(pb::event::Payload::Network(pb::NetworkEvent {
        protocol: s.proto.into(),
        local_addr: s.local.clone(),
        local_port: s.local_port,
        remote_addr: s.remote.clone(),
        remote_port: s.remote_port,
        pid,
        exe: if pid != 0 {
            procfs::readlink(&format!("/proc/{pid}/exe"))
        } else {
            String::new()
        },
        uid: s.uid,
        direction: direction.into(),
        user: procfs::username(s.uid),
        net_namespace: if pid != 0 { procfs::ns_inode(pid, "net") } else { 0 },
    }));
    sink.emit(e);
}

fn read_sockets(path: &str, proto: &'static str) -> Vec<Sock> {
    fs::read_to_string(path)
        .map(|s| parse_sockets(&s, proto))
        .unwrap_or_default()
}

fn parse_sockets(text: &str, proto: &'static str) -> Vec<Sock> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let (local, local_port) = parse_addr(f[1]);
        let (remote, remote_port) = parse_addr(f[2]);
        let udp = proto.starts_with("udp");
        let state = match f[3] {
            ESTABLISHED => ESTABLISHED,
            LISTEN if !udp => LISTEN,
            // A bound UDP socket serves like a TCP listener.
            UDP_UNCONNECTED if udp && remote_port == 0 && local_port != 0 => LISTEN,
            _ => continue,
        };
        out.push(Sock {
            proto,
            state,
            local,
            local_port,
            remote,
            remote_port,
            uid: f[7].parse().unwrap_or(0),
            inode: f[9].parse().unwrap_or(0),
        });
    }
    out
}

/// Decodes "0100007F:0016"; each 32-bit word is printed in host byte order.
fn parse_addr(s: &str) -> (String, u32) {
    let Some((h, p)) = s.split_once(':') else {
        return (String::new(), 0);
    };
    let port = u32::from_str_radix(p, 16).unwrap_or(0);
    let Ok(raw) = hex::decode(h) else {
        return (String::new(), port);
    };
    let words: Vec<[u8; 4]> = raw
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()).to_be_bytes())
        .collect();
    let ip = match words.len() {
        1 => Ipv4Addr::from(words[0]).to_string(),
        4 => {
            let b: Vec<u8> = words.concat();
            let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(b).unwrap());
            // Match Go's rendering of IPv4-mapped addresses.
            v6.to_ipv4_mapped().map_or(v6.to_string(), |v4| v4.to_string())
        }
        _ => String::new(),
    };
    (ip, port)
}

/// Maps socket inodes to the pid holding them.
fn socket_owners() -> HashMap<u64, u32> {
    let mut out = HashMap::new();
    let Ok(procs) = fs::read_dir("/proc") else {
        return out;
    };
    for p in procs.flatten() {
        let Some(pid) = p.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let link = fs::read_link(fd.path())
                .map(|l| l.to_string_lossy().into_owned())
                .unwrap_or_default();
            if let Some(ino) = link.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']'))
                && let Ok(ino) = ino.parse()
            {
                out.insert(ino, pid);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net_tcp() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n   1: 0100007F:9C40 0101A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 999 1\n   2: 0100007F:9C41 0101A8C0:01BB 06 00000000:00000000 00:00000000 00000000  1000        0 998 1\n";
        let s = parse_sockets(text, "tcp");
        assert_eq!(s.len(), 2);
        assert_eq!(
            (s[0].local.as_str(), s[0].local_port, s[0].state),
            ("127.0.0.1", 22, LISTEN)
        );
        assert_eq!(
            (s[1].remote.as_str(), s[1].remote_port, s[1].uid, s[1].inode),
            ("192.168.1.1", 443, 1000, 999)
        );
        assert_eq!(
            parse_addr("0000000000000000FFFF00000100007F:0050"),
            ("127.0.0.1".into(), 80)
        );
        assert_eq!(parse_addr("00000000000000000000000001000000:0050").0, "::1");
        let u = parse_sockets(
            "  sl local rem st\n  1: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 55 2\n  2: 0100007F:A000 08080808:0035 01 00000000:00000000 00:00000000 00000000 0 0 56 2\n",
            "udp",
        );
        assert_eq!((u[0].state, u[0].local_port), (LISTEN, 53));
        assert_eq!((u[1].state, u[1].remote.as_str()), (ESTABLISHED, "8.8.8.8"));
        assert_eq!(family("tcp6"), "tcp");
    }
}
