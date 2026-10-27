//! Response actions run on the console's request: kill a process,
//! quarantine and restore files, isolate the host with nftables and
//! uninstall the agent.

use std::fmt;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use xdr_core::pb::{self, CommandType};

pub const ISOLATION_TABLE: &str = "xdr_isolation";
/// Left behind by the retired Go agent's firewall module.
pub const FIREWALL_TABLE: &str = "xdr_firewall";

pub struct Responder {
    pub state_dir: PathBuf,
    /// Console addresses (host:port) that stay reachable while isolated.
    pub console: Vec<String>,
}

impl Responder {
    pub fn respond(&self, c: &pb::AgentCommand) -> Result<String> {
        let arg = |k: &str| c.args.get(k).map(String::as_str).unwrap_or("");
        match c.r#type() {
            CommandType::Uninstall => self.uninstall(),
            CommandType::KillProcess => kill_process(arg("pid"), arg("exe")),
            CommandType::QuarantineFile => self.quarantine(arg("path")),
            CommandType::RestoreFile => self.restore(arg("quarantine_id")),
            CommandType::IsolateHost => self.isolate(arg("allow")),
            CommandType::UnisolateHost => self.unisolate(),
            other => bail!(
                "{} is not supported by xdr-agent {} yet",
                other.as_str_name(),
                xdr_core::VERSION
            ),
        }
    }

    fn uninstall(&self) -> Result<String> {
        let dir = self
            .state_dir
            .to_str()
            .filter(|d| !d.contains('\'') && d.len() > 1)
            .context("unsafe state directory")?;
        // Runs outside the agent's own unit, so stopping the unit does not
        // kill it; the pause lets the result reach the console first.
        // Mirrors the console's uninstall.sh.
        let script = format!(
            "sleep 2\nnft delete table inet {ISOLATION_TABLE} 2>/dev/null || true\n\
             nft delete table inet {FIREWALL_TABLE} 2>/dev/null || true\n\
             systemctl disable --now xdr-agent 2>/dev/null || true\n\
             rm -rf /etc/systemd/system/xdr-agent.service /etc/systemd/system/xdr-agent.service.d\n\
             systemctl daemon-reload 2>/dev/null || true\n\
             rm -f /usr/local/bin/xdr-agent /etc/sudoers.d/xdr-jit-* /etc/sudoers.d/xdr-session-recording\n\
             rm -rf /etc/xdr-agent '{dir}' /run/xdr-agent\n"
        );
        let mut cmd = if which("systemd-run") {
            let mut c = Command::new("systemd-run");
            c.args(["--unit=xdr-agent-uninstall", "--collect", "/bin/sh", "-c", &script]);
            c
        } else {
            let mut c = Command::new("setsid");
            c.args(["/bin/sh", "-c", &script]);
            c
        };
        cmd.stdin(Stdio::null()).spawn().context("start uninstall")?;
        tracing::warn!("uninstall requested by the console");
        Ok("uninstalling xdr-agent".into())
    }

    // --- quarantine ---

    fn quarantine_dir(&self) -> PathBuf {
        self.state_dir.join("quarantine")
    }

    pub fn quarantine(&self, path: &str) -> Result<String> {
        let p = clean_abs(path)?;
        protected(&p)?;
        if p.starts_with(&self.state_dir) {
            bail!("refusing to quarantine agent state");
        }
        let st = fs::symlink_metadata(&p).with_context(|| format!("stat {}", p.display()))?;
        if !st.file_type().is_file() {
            bail!("{} is not a regular file", p.display());
        }
        let dir = self.quarantine_dir();
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let id = hex::encode(&uuid::Uuid::new_v4().as_bytes()[..8]);
        let dst = dir.join(format!("{id}.bin"));
        move_file(&p, &dst)?;
        // No permission bits, so the quarantined copy cannot be executed.
        let _ = fs::set_permissions(&dst, fs::Permissions::from_mode(0o000));
        let rec = QuarantineRecord {
            id: id.clone(),
            path: p.to_string_lossy().into_owned(),
            sha256: file_sha256(&dst).unwrap_or_default(),
            size: st.len(),
            mode: st.mode() & 0o7777,
            uid: st.uid(),
            gid: st.gid(),
            time: unix_now().into(),
        };
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(dir.join(format!("{id}.json")))?;
        serde_json::to_writer_pretty(&mut f, &rec)?;
        Ok(id)
    }

    pub fn restore(&self, id: &str) -> Result<String> {
        if id.len() != 16 || !id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            bail!("invalid quarantine id {id:?}");
        }
        let dir = self.quarantine_dir();
        let meta = dir.join(format!("{id}.json"));
        let raw = fs::read(&meta).map_err(|_| anyhow!("no quarantined file {id}"))?;
        let rec: QuarantineRecord = serde_json::from_slice(&raw)?;
        let dst = PathBuf::from(&rec.path);
        if fs::symlink_metadata(&dst).is_ok() {
            bail!("{} already exists; not overwriting it", rec.path);
        }
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        move_file(&dir.join(format!("{id}.bin")), &dst)?;
        let _ = std::os::unix::fs::chown(&dst, Some(rec.uid), Some(rec.gid));
        let _ = fs::set_permissions(&dst, fs::Permissions::from_mode(rec.mode));
        let _ = fs::remove_file(meta);
        Ok(format!("restored {}", rec.path))
    }

    // --- network isolation ---

    fn isolation_file(&self) -> PathBuf {
        self.state_dir.join("isolation.json")
    }

    pub fn isolated(&self) -> bool {
        self.isolation_file().exists()
    }

    fn console_addrs(&self) -> Result<Vec<IpAddr>> {
        let mut out = Vec::new();
        for hp in &self.console {
            if hp.is_empty() {
                continue;
            }
            let addrs: Vec<SocketAddr> = match hp.parse::<SocketAddr>() {
                Ok(a) => vec![a],
                Err(_) => {
                    let host = hp.rsplit_once(':').map_or(hp.as_str(), |(h, _)| h);
                    (host, 0)
                        .to_socket_addrs()
                        .with_context(|| format!("resolve console {host}"))?
                        .collect()
                }
            };
            out.extend(addrs.into_iter().map(|a| unmap(a.ip())));
        }
        if out.is_empty() {
            bail!("no console address to keep reachable");
        }
        Ok(out)
    }

    fn apply_isolation(&self, allow: &[String]) -> Result<String> {
        let mut prefixes: Vec<Prefix> = self.console_addrs()?.into_iter().map(Prefix::host).collect();
        for s in allow.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            prefixes.push(Prefix::parse(s).ok_or_else(|| anyhow!("invalid allow entry {s:?}"))?);
        }
        nft(&isolation_rules(&dedupe(&prefixes)))?;
        let list: Vec<String> = prefixes.iter().map(Prefix::to_string).collect();
        Ok(format!("host isolated; reachable: {}", list.join(", ")))
    }

    pub fn isolate(&self, allow: &str) -> Result<String> {
        let allow: Vec<String> = allow.split(',').map(String::from).collect();
        let msg = self.apply_isolation(&allow)?;
        fs::write(self.isolation_file(), serde_json::to_vec(&IsolationState { allow })?)?;
        Ok(msg)
    }

    pub fn unisolate(&self) -> Result<String> {
        nft(&format!(
            "add table inet {ISOLATION_TABLE}\ndelete table inet {ISOLATION_TABLE}\n"
        ))?;
        match fs::remove_file(self.isolation_file()) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        Ok("network isolation removed".into())
    }

    /// Re-applies isolation after a reboot or agent restart.
    pub fn restore_isolation(&self) {
        let Ok(raw) = fs::read(self.isolation_file()) else {
            return;
        };
        let st: IsolationState = serde_json::from_slice(&raw).unwrap_or_default();
        match self.apply_isolation(&st.allow) {
            Ok(msg) => tracing::warn!(detail = %msg, "network isolation re-applied"),
            Err(err) => tracing::error!("re-applying network isolation failed: {err:#}"),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct QuarantineRecord {
    id: String,
    path: String,
    sha256: String,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    /// RFC 3339 from records the Go agent wrote, Unix seconds from this one.
    time: serde_json::Value,
}

#[derive(Serialize, Deserialize, Default)]
struct IsolationState {
    allow: Vec<String>,
}

// --- kill ---

pub fn kill_process(pid: &str, want_exe: &str) -> Result<String> {
    let pid: i32 = pid
        .parse()
        .ok()
        .filter(|p| *p > 1)
        .ok_or_else(|| anyhow!("invalid pid {pid:?}"))?;
    if pid as u32 == std::process::id() {
        bail!("refusing to kill the agent itself");
    }
    let exe = match fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(p) => Some(p.to_string_lossy().trim_end_matches(" (deleted)").to_string()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => bail!("process {pid} is not running"),
        Err(_) => None, // kernel thread or no permission to read the link
    };
    // The pid may have been reused since the event; only kill the process
    // the console saw.
    if let Some(exe) = &exe
        && !want_exe.is_empty()
        && exe != want_exe
    {
        bail!("pid {pid} is now {exe}, not {want_exe}; not killed");
    }
    if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
        bail!("kill {pid}: {}", io::Error::last_os_error());
    }
    Ok(format!("killed pid {pid} ({})", exe.unwrap_or_default()))
}

// --- helpers ---

/// An absolute path with `.` and duplicate separators removed. `..` is
/// refused rather than resolved.
fn clean_abs(path: &str) -> Result<PathBuf> {
    let p = Path::new(path);
    if !p.is_absolute() {
        bail!("path must be absolute");
    }
    let mut out = PathBuf::from("/");
    for c in p.components() {
        match c {
            Component::Normal(s) => out.push(s),
            Component::ParentDir => bail!("path must not contain .."),
            _ => {}
        }
    }
    Ok(out)
}

fn protected(p: &Path) -> Result<()> {
    for pre in ["/proc", "/sys", "/dev"] {
        if p.starts_with(pre) {
            bail!("refusing to touch {}", p.display());
        }
    }
    if std::env::current_exe().is_ok_and(|e| e == p) {
        bail!("refusing to quarantine the agent binary");
    }
    Ok(())
}

/// Renames, falling back to copy and delete across filesystems.
fn move_file(src: &Path, dst: &Path) -> Result<()> {
    match fs::rename(src, dst) {
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {}
        r => return r.with_context(|| format!("move {} to {}", src.display(), dst.display())),
    }
    let copy = || -> io::Result<()> {
        let mut input = fs::File::open(src)?;
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dst)?;
        io::copy(&mut input, &mut out)?;
        out.sync_all()
    };
    if let Err(e) = copy() {
        let _ = fs::remove_file(dst);
        return Err(e.into());
    }
    Ok(fs::remove_file(src)?)
}

fn file_sha256(p: &Path) -> io::Result<String> {
    let mut h = Sha256::new();
    io::copy(&mut fs::File::open(p)?, &mut h)?;
    Ok(hex::encode(h.finalize()))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| std::env::split_paths(&path).any(|d| d.join(bin).is_file()))
}

fn nft(script: &str) -> Result<()> {
    if !which("nft") {
        bail!("nft not found: install the nftables package to use host isolation");
    }
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    io::Write::write_all(&mut child.stdin.take().expect("stdin"), script.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let mut msg = String::from_utf8_lossy(&out.stderr).into_owned();
        msg.push_str(&String::from_utf8_lossy(&out.stdout));
        bail!("nft: {}: {}", out.status, msg.trim());
    }
    Ok(())
}

fn unmap(a: IpAddr) -> IpAddr {
    match a {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(a, IpAddr::V4),
        v4 => v4,
    }
}

/// An IP network: address with host bits cleared, and prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    addr: IpAddr,
    bits: u8,
}

impl Prefix {
    fn host(a: IpAddr) -> Prefix {
        let a = unmap(a);
        Prefix {
            addr: a,
            bits: if a.is_ipv4() { 32 } else { 128 },
        }
    }

    /// Parses `1.2.3.4`, `10.0.0.0/8` or an IPv6 equivalent.
    pub fn parse(s: &str) -> Option<Prefix> {
        let Some((a, b)) = s.split_once('/') else {
            return s.parse().ok().map(Prefix::host);
        };
        let addr: IpAddr = a.parse().ok()?;
        let bits: u8 = b.parse().ok()?;
        if bits > if addr.is_ipv4() { 32 } else { 128 } {
            return None;
        }
        Some(Prefix {
            addr: mask(addr, bits),
            bits,
        })
    }

    fn contains(&self, a: IpAddr) -> bool {
        a.is_ipv4() == self.addr.is_ipv4() && mask(a, self.bits) == self.addr
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.bits)
    }
}

fn mask(a: IpAddr, bits: u8) -> IpAddr {
    match a {
        IpAddr::V4(v) => {
            let m = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            IpAddr::V4(Ipv4Addr::from(u32::from(v) & m))
        }
        IpAddr::V6(v) => {
            let m = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            IpAddr::V6(Ipv6Addr::from(u128::from(v) & m))
        }
    }
}

/// nft rejects overlapping interval elements, so drop duplicates and
/// prefixes contained in another.
fn dedupe(input: &[Prefix]) -> Vec<Prefix> {
    let mut out = Vec::new();
    for (i, p) in input.iter().enumerate() {
        let covered = input
            .iter()
            .enumerate()
            .any(|(j, q)| i != j && q.bits <= p.bits && q.contains(p.addr) && (q.bits < p.bits || j < i));
        if !covered {
            out.push(*p);
        }
    }
    out
}

/// The nftables ruleset. Matching on the original conntrack tuple keeps the
/// console reachable even when it runs in Docker on the same host, where the
/// packet's address is rewritten by DNAT.
fn isolation_rules(allow: &[Prefix]) -> String {
    let (v4, v6): (Vec<String>, Vec<String>) = {
        let (a, b): (Vec<&Prefix>, Vec<&Prefix>) = allow.iter().partition(|p| p.addr.is_ipv4());
        (
            a.iter().map(|p| p.to_string()).collect(),
            b.iter().map(|p| p.to_string()).collect(),
        )
    };
    let set = |name: &str, typ: &str, elems: &[String]| {
        let mut s = format!("\tset {name} {{\n\t\ttype {typ}\n\t\tflags interval\n");
        if !elems.is_empty() {
            s += &format!("\t\telements = {{ {} }}\n", elems.join(", "));
        }
        s + "\t}\n"
    };
    let t = ISOLATION_TABLE;
    let mut b = format!("add table inet {t}\ndelete table inet {t}\ntable inet {t} {{\n");
    b += &set("allow4", "ipv4_addr", &v4);
    b += &set("allow6", "ipv6_addr", &v6);
    for (name, lo, dhcp, nd) in [
        (
            "input",
            "iif \"lo\"",
            "udp sport 67 udp dport 68",
            "nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert",
        ),
        (
            "output",
            "oif \"lo\"",
            "udp sport 68 udp dport 67",
            "nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit",
        ),
    ] {
        b += &format!("\tchain {name} {{\n\t\ttype filter hook {name} priority -10; policy drop;\n");
        b += &format!("\t\t{lo} accept\n");
        b += "\t\tct original ip saddr @allow4 accept\n\t\tct original ip daddr @allow4 accept\n";
        b += "\t\tct original ip6 saddr @allow6 accept\n\t\tct original ip6 daddr @allow6 accept\n";
        b += &format!("\t\t{dhcp} accept\n\t\ticmpv6 type {{ {nd} }} accept\n\t}}\n");
    }
    b + "}\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn responder(dir: &Path) -> Responder {
        Responder {
            state_dir: dir.join("state"),
            console: vec!["127.0.0.1:8444".into()],
        }
    }

    #[test]
    fn prefixes_parse_mask_and_dedupe() {
        assert_eq!(Prefix::parse("10.1.2.3/8").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(Prefix::parse("::ffff:1.2.3.4").unwrap().to_string(), "1.2.3.4/32");
        assert_eq!(Prefix::parse("fd00::1/64").unwrap().to_string(), "fd00::/64");
        assert!(Prefix::parse("1.2.3.4/33").is_none());
        assert!(Prefix::parse("nope").is_none());
        let p = |s| Prefix::parse(s).unwrap();
        let got = dedupe(&[p("10.0.0.5"), p("10.0.0.0/8"), p("192.168.1.1"), p("192.168.1.1")]);
        assert_eq!(got, vec![p("10.0.0.0/8"), p("192.168.1.1")]);
    }

    #[test]
    fn rules_keep_console_and_split_families() {
        let r = isolation_rules(&[
            Prefix::parse("192.168.1.118").unwrap(),
            Prefix::parse("fd00::/8").unwrap(),
        ]);
        assert!(r.contains("elements = { 192.168.1.118/32 }"));
        assert!(r.contains("elements = { fd00::/8 }"));
        assert!(r.contains("table inet xdr_isolation {"));
        assert_eq!(r.matches("policy drop;").count(), 2);
    }

    #[test]
    fn quarantine_and_restore_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let r = responder(tmp.path());
        let f = tmp.path().join("evil.sh");
        fs::write(&f, b"#!/bin/sh\necho hi\n").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
        let id = r.quarantine(f.to_str().unwrap()).unwrap();
        assert!(!f.exists());
        let bin = r.quarantine_dir().join(format!("{id}.bin"));
        assert_eq!(fs::metadata(&bin).unwrap().mode() & 0o777, 0);
        assert_eq!(r.restore(&id).unwrap(), format!("restored {}", f.display()));
        assert_eq!(fs::read(&f).unwrap(), b"#!/bin/sh\necho hi\n");
        assert_eq!(fs::metadata(&f).unwrap().mode() & 0o777, 0o755);
        assert!(r.restore(&id).is_err());
    }

    #[test]
    fn quarantine_refuses_unsafe_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let r = responder(tmp.path());
        assert!(r.quarantine("relative/file").is_err());
        assert!(r.quarantine("/proc/self/status").is_err());
        assert!(r.quarantine("/tmp/../etc/passwd").is_err());
        assert!(r.quarantine(tmp.path().to_str().unwrap()).is_err()); // directory
        fs::create_dir_all(&r.state_dir).unwrap();
        let own = r.state_dir.join("queue.db");
        fs::write(&own, b"x").unwrap();
        assert!(r.quarantine(own.to_str().unwrap()).is_err());
        assert!(r.restore("../../etc/passwd").is_err());
    }

    #[test]
    fn reads_go_quarantine_records() {
        let go = r#"{"id":"0123456789abcdef","path":"/tmp/x","sha256":"","size":1,"mode":493,"uid":0,"gid":0,"time":"2026-10-27T10:00:00Z"}"#;
        let rec: QuarantineRecord = serde_json::from_str(go).unwrap();
        assert_eq!((rec.mode, rec.path.as_str()), (0o755, "/tmp/x"));
    }

    #[test]
    fn kill_refuses_bad_targets() {
        assert!(kill_process("1", "").is_err());
        assert!(kill_process("abc", "").is_err());
        assert!(kill_process(&std::process::id().to_string(), "").is_err());
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id().to_string();
        assert!(
            kill_process(&pid, "/not/sleep")
                .unwrap_err()
                .to_string()
                .contains("not killed")
        );
        assert!(kill_process(&pid, "").unwrap().starts_with("killed pid"));
        assert!(!child.wait().unwrap().success());
    }
}
