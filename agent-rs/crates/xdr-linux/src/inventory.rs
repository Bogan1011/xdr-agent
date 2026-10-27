//! Host inventory: system facts, installed packages, network interfaces and
//! mounted file systems. A full list is sent once (and again only when the
//! saved copy is lost); after that only what was added or removed, checked
//! every few hours. System facts are sent at every start.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use anyhow::Result;
use xdr_core::bus::{EventSink, new_event};
use xdr_core::pb::{self, EventType};
use xdr_core::platform::Collector;

use crate::host;

pub struct Inventory {
    pub interval: Duration,
    /// Where the last sent lists are kept, so a restart sends only changes.
    pub state: PathBuf,
}

type Items = BTreeMap<String, (String, String)>;

fn read(path: &str) -> String {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn os_release(key: &str) -> String {
    read("/etc/os-release")
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_default()
}

pub fn system() -> BTreeMap<String, String> {
    let mut a = BTreeMap::new();
    let h = host::host_info();
    let uptime: f64 = read("/proc/uptime")
        .split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    let btime = read("/proc/stat")
        .lines()
        .find_map(|l| l.strip_prefix("btime ").map(str::to_string))
        .unwrap_or_default();
    let mem_kb: u64 = read("/proc/meminfo")
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
        .unwrap_or(0);
    let cpus = read("/proc/cpuinfo")
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count();
    let model = read("/proc/cpuinfo")
        .lines()
        .find_map(|l| {
            l.strip_prefix("model name")
                .and_then(|r| r.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
        })
        .unwrap_or_default();
    // The root file system's birth time is the closest thing to an install date.
    let install = Command::new("stat")
        .args(["-c", "%W", "/"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|v| v != "0" && v != "-")
        .unwrap_or_default();
    for (k, v) in [
        ("hostname", h.hostname),
        ("machine_id", h.machine_id),
        ("architecture", h.arch),
        ("kernel", h.kernel),
        ("distribution", os_release("NAME")),
        ("version", os_release("VERSION_ID")),
        ("platform", os_release("ID")),
        ("parent_distribution", os_release("ID_LIKE")),
        ("pretty_name", h.os_version),
        ("uptime_seconds", format!("{}", uptime as u64)),
        ("boot_time", btime),
        ("install_time", install),
        ("cpu_cores", cpus.to_string()),
        ("cpu_model", model),
        ("memory_bytes", (mem_kb * 1024).to_string()),
        ("agent_version", h.agent_version),
    ] {
        if !v.is_empty() {
            a.insert(k.to_string(), v);
        }
    }
    a
}

/// Installed packages from dpkg or rpm: name → (version, summary).
pub fn packages() -> Items {
    let dpkg = Command::new("dpkg-query")
        .args([
            "-W",
            "-f",
            "${db:Status-Abbrev}\t${Package}:${Architecture}\t${Version}\t${binary:Summary}\n",
        ])
        .output();
    if let Ok(o) = dpkg
        && o.status.success()
    {
        return parse_dpkg(&String::from_utf8_lossy(&o.stdout));
    }
    let rpm = Command::new("rpm")
        .args(["-qa", "--qf", "%{NAME}.%{ARCH}\t%{VERSION}-%{RELEASE}\t%{SUMMARY}\n"])
        .output();
    if let Ok(o) = rpm
        && o.status.success()
    {
        return String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|l| {
                let mut f = l.splitn(3, '\t');
                Some((
                    f.next()?.to_string(),
                    (f.next()?.to_string(), f.next().unwrap_or("").to_string()),
                ))
            })
            .collect();
    }
    Items::new()
}

pub fn parse_dpkg(text: &str) -> Items {
    text.lines()
        .filter_map(|l| {
            let mut f = l.splitn(4, '\t');
            // Only installed packages ("ii").
            if !f.next()?.starts_with("ii") {
                return None;
            }
            Some((
                f.next()?.to_string(),
                (f.next()?.to_string(), f.next().unwrap_or("").to_string()),
            ))
        })
        .collect()
}

/// name/address → (type, "netmask N"), from getifaddrs.
pub fn interfaces() -> Items {
    let mut out = Items::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let i = &*cur;
            cur = i.ifa_next;
            if i.ifa_addr.is_null() {
                continue;
            }
            let name = std::ffi::CStr::from_ptr(i.ifa_name).to_string_lossy().into_owned();
            let (ip, mask) = match (*i.ifa_addr).sa_family as i32 {
                libc::AF_INET => {
                    let a = &*(i.ifa_addr as *const libc::sockaddr_in);
                    let ip = std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
                    let mask = if i.ifa_netmask.is_null() {
                        0
                    } else {
                        u32::from_be((*(i.ifa_netmask as *const libc::sockaddr_in)).sin_addr.s_addr).count_ones()
                    };
                    (ip.to_string(), mask)
                }
                libc::AF_INET6 => {
                    let a = &*(i.ifa_addr as *const libc::sockaddr_in6);
                    let mask = if i.ifa_netmask.is_null() {
                        0
                    } else {
                        (*(i.ifa_netmask as *const libc::sockaddr_in6))
                            .sin6_addr
                            .s6_addr
                            .iter()
                            .map(|b| b.count_ones())
                            .sum()
                    };
                    (std::net::Ipv6Addr::from(a.sin6_addr.s6_addr).to_string(), mask)
                }
                _ => continue,
            };
            let kind = if name == "lo" {
                "loopback"
            } else if std::path::Path::new(&format!("/sys/class/net/{name}/wireless")).exists() {
                "wireless"
            } else if std::path::Path::new(&format!("/sys/class/net/{name}/device")).exists() {
                "ethernet"
            } else {
                "virtual"
            };
            out.insert(format!("{name} {ip}/{mask}"), (kind.to_string(), String::new()));
        }
        libc::freeifaddrs(ifap);
    }
    out
}

/// Real file systems: mount point → (fstype, "total N free N").
pub fn mounts() -> Items {
    let mut out = Items::new();
    for (point, v) in crate::kernel::parse_mounts(&read("/proc/self/mountinfo")) {
        let fstype = v.split_whitespace().next().unwrap_or("").to_string();
        if matches!(
            fstype.as_str(),
            "proc"
                | "sysfs"
                | "devpts"
                | "cgroup"
                | "cgroup2"
                | "securityfs"
                | "pstore"
                | "bpf"
                | "tracefs"
                | "debugfs"
                | "configfs"
                | "fusectl"
                | "mqueue"
                | "hugetlbfs"
                | "devtmpfs"
                | "efivarfs"
                | "ramfs"
                | "squashfs"
                | "rpc_pipefs"
        ) {
            continue;
        }
        let detail = statvfs(&point)
            .map(|(t, f)| format!("total {t} free {f}"))
            .unwrap_or_default();
        out.insert(point, (fstype, detail));
    }
    out
}

fn statvfs(path: &str) -> Option<(u64, u64)> {
    let c = std::ffi::CString::new(path).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    let bs = s.f_frsize as u64;
    Some((s.f_blocks as u64 * bs, s.f_bavail as u64 * bs))
}

fn items(m: &Items, keys: impl Iterator<Item = String>) -> Vec<pb::InventoryItem> {
    keys.filter_map(|k| {
        let (version, detail) = m.get(&k)?;
        Some(pb::InventoryItem {
            name: k,
            version: version.clone(),
            detail: detail.clone(),
        })
    })
    .collect()
}

/// Added and removed items; a package whose version changed is both.
/// Details (free space, descriptions) are not compared.
pub fn changes(old: &Items, new: &Items) -> (Vec<pb::InventoryItem>, Vec<pb::InventoryItem>) {
    let added = new
        .iter()
        .filter(|(k, v)| old.get(*k).map(|o| &o.0) != Some(&v.0))
        .map(|(k, _)| k.clone());
    let removed = old
        .iter()
        .filter(|(k, v)| new.get(*k).map(|n| &n.0) != Some(&v.0))
        .map(|(k, _)| k.clone());
    (items(new, added), items(old, removed))
}

fn send(sink: &EventSink, kind: &str, action: &str, added: Vec<pb::InventoryItem>, removed: Vec<pb::InventoryItem>) {
    let mut e = new_event(EventType::Inventory);
    e.payload = Some(pb::event::Payload::Inventory(pb::InventoryEvent {
        kind: kind.into(),
        action: action.into(),
        added,
        removed,
        attributes: Default::default(),
    }));
    sink.emit(e);
}

impl Inventory {
    fn load(&self) -> BTreeMap<String, Items> {
        std::fs::read(&self.state)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save(&self, s: &BTreeMap<String, Items>) {
        if let Ok(b) = serde_json::to_vec(s) {
            let tmp = self.state.with_extension("tmp");
            if std::fs::write(&tmp, b).is_ok() {
                let _ = std::fs::rename(tmp, &self.state);
            }
        }
    }
}

impl Collector for Inventory {
    fn name(&self) -> &'static str {
        "inventory"
    }

    fn run(&mut self, sink: &EventSink) -> Result<()> {
        let mut e = new_event(EventType::Inventory);
        e.payload = Some(pb::event::Payload::Inventory(pb::InventoryEvent {
            kind: "system".into(),
            action: "snapshot".into(),
            attributes: system().into_iter().collect(),
            ..Default::default()
        }));
        sink.emit(e);

        let mut saved = self.load();
        loop {
            for (kind, now) in [
                ("packages", packages()),
                ("interfaces", interfaces()),
                ("mounts", mounts()),
            ] {
                if now.is_empty() {
                    continue;
                }
                match saved.get(kind) {
                    None => send(sink, kind, "snapshot", items(&now, now.keys().cloned()), Vec::new()),
                    Some(old) => {
                        let (added, removed) = changes(old, &now);
                        if !added.is_empty() || !removed.is_empty() {
                            send(sink, kind, "changed", added, removed);
                        }
                    }
                }
                saved.insert(kind.to_string(), now);
            }
            self.save(&saved);
            std::thread::sleep(self.interval);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_packages_and_diffs() {
        let p = parse_dpkg(
            "ii \tbash:amd64\t5.2-1\tGNU shell\nrc \told:amd64\t1.0\tremoved\nii \tcurl:amd64\t8.5\tURL tool\n",
        );
        assert_eq!(p.len(), 2);
        assert_eq!(p["bash:amd64"].0, "5.2-1");
        let mut q = p.clone();
        q.insert("curl:amd64".into(), ("8.6".into(), "URL tool".into()));
        q.insert("nmap:amd64".into(), ("7.9".into(), "scanner".into()));
        q.remove("bash:amd64");
        let (added, removed) = changes(&p, &q);
        let names = |v: &[pb::InventoryItem]| {
            v.iter()
                .map(|i| format!("{} {}", i.name, i.version))
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&added), ["curl:amd64 8.6", "nmap:amd64 7.9"]);
        assert_eq!(names(&removed), ["bash:amd64 5.2-1", "curl:amd64 8.5"]);
    }

    #[test]
    fn reads_this_host() {
        let s = system();
        assert!(s.contains_key("cpu_cores") && s.contains_key("memory_bytes"));
        assert!(interfaces().keys().any(|k| k.starts_with("lo ")));
        assert!(mounts().contains_key("/"));
    }
}
