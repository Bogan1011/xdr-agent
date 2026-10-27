//! Host facts for enrollment and heartbeats.

use std::fs;

use xdr_core::pb;

/// Architecture names as the Go agent and the release manifest use them.
pub fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

pub fn host_info() -> pb::HostInfo {
    let mut h = pb::HostInfo {
        os: "linux".into(),
        arch: arch().into(),
        agent_version: format!("{}-rs", xdr_core::VERSION),
        ..Default::default()
    };
    h.hostname = fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    h.kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if let Ok(osr) = fs::read_to_string("/etc/os-release") {
        for line in osr.lines() {
            if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
                h.os_version = v.trim_matches('"').to_string();
            }
        }
    }
    h.machine_id = fs::read_to_string("/etc/machine-id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    h.ip_addresses = ip_addresses();
    h
}

fn ip_addresses() -> Vec<String> {
    let mut out = Vec::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let a = (*cur).ifa_addr;
            if !a.is_null() {
                match (*a).sa_family as i32 {
                    libc::AF_INET => {
                        let sin = &*(a as *const libc::sockaddr_in);
                        let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                        if !ip.is_loopback() && !ip.is_link_local() {
                            out.push(ip.to_string());
                        }
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(a as *const libc::sockaddr_in6);
                        let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                        if !ip.is_loopback() && !ip.is_unicast_link_local() {
                            out.push(ip.to_string());
                        }
                    }
                    _ => {}
                }
            }
            cur = (*cur).ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}

/// CPU seconds and resident set size of this process.
pub fn usage() -> xdr_core::platform::Usage {
    let mut u = xdr_core::platform::Usage::default();
    if let Ok(s) = fs::read_to_string("/proc/self/stat")
        && let Some(rest) = s.rfind(')').map(|i| &s[i + 1..])
    {
        let f: Vec<&str> = rest.split_whitespace().collect();
        // utime and stime are fields 14 and 15, f[11] and f[12].
        if f.len() > 12 {
            let ticks: f64 = f[11].parse::<f64>().unwrap_or(0.0) + f[12].parse::<f64>().unwrap_or(0.0);
            u.cpu_seconds = ticks / 100.0;
        }
    }
    if let Ok(s) = fs::read_to_string("/proc/self/statm")
        && let Some(rss) = s.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok())
    {
        u.rss_bytes = rss * unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    }
    u
}
