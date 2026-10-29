//! Prevention policy rules shared by the modules: defaults for missing
//! sections, path and glob matching, application control and script rules,
//! and the nftables tables the agent owns. Ported from internal/policy, which
//! the console still uses to validate policies; keep the two in step.

use std::net::IpAddr;

use xdr_core::pb;

use crate::response::Prefix;

pub const FIREWALL_TABLE: &str = "xdr_firewall";
pub const WEB_REPUTATION_TABLE: &str = "xdr_webrep";
pub const INTRUSION_TABLE: &str = "xdr_ips";

pub const USB_ALLOW: &str = "allow";
pub const USB_READ_ONLY: &str = "read_only";
pub const USB_BLOCK: &str = "block";

/// What lockdown allows when the policy names nothing: system and
/// package-managed locations, including container images.
pub const DEFAULT_ALLOWED_PATHS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/opt",
    "/snap",
    "/etc",
    "/var/lib/docker",
    "/var/lib/containerd",
    "/var/lib/snapd",
];

/// The world-writable places droppers use.
pub const DEFAULT_SCRIPT_PATHS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm"];

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// Fills missing sections and defaults so modules never deal with None.
/// A policy saved before modules existed keeps its behaviour.
pub fn normalize(mut p: pb::PreventionPolicy) -> pb::PreventionPolicy {
    let fim = p.fim.get_or_insert_default();
    if fim.interval_minutes == 0 {
        fim.interval_minutes = 60;
    }
    p.firewall.get_or_insert_default();
    if p.anti_malware.is_none() {
        p.anti_malware = Some(pb::AntiMalwarePolicy {
            enabled: true,
            block_known_bad: p.block_exec,
            ..Default::default()
        });
    }
    p.block_exec = false;
    let wr = p.web_reputation.get_or_insert(pb::WebReputationPolicy {
        use_threat_intel: true,
        ..Default::default()
    });
    for d in wr.blocked_domains.iter_mut().chain(wr.allowed_domains.iter_mut()) {
        *d = d.trim().to_lowercase().trim_end_matches('.').to_string();
    }
    let ips = p.intrusion_prevention.get_or_insert_default();
    if ips.max_failures == 0 {
        ips.max_failures = 5;
    }
    if ips.window_seconds == 0 {
        ips.window_seconds = 300;
    }
    if ips.ban_minutes == 0 {
        ips.ban_minutes = 30;
    }
    let dc = p.device_control.get_or_insert_default();
    if dc.usb_storage.is_empty() {
        dc.usb_storage = USB_ALLOW.into();
    }
    for d in &mut dc.allowed_devices {
        *d = d.trim().to_lowercase();
    }
    p.activity_monitoring.get_or_insert(pb::ActivityMonitoringPolicy {
        process: true,
        file: true,
        network: true,
    });
    p.self_protection.get_or_insert_default();
    let ac = p.application_control.get_or_insert_default();
    for h in ac.blocked_sha256.iter_mut().chain(ac.allowed_sha256.iter_mut()) {
        *h = h.trim().to_lowercase();
    }
    if ac.lockdown && ac.allowed_paths.is_empty() {
        ac.allowed_paths = strings(DEFAULT_ALLOWED_PATHS);
    }
    if ac.block_scripts && ac.script_paths.is_empty() {
        ac.script_paths = strings(DEFAULT_SCRIPT_PATHS);
    }
    p
}

/// Whether path is one of the patterns: a path prefix, or a glob when the
/// pattern contains a glob character.
pub fn matches<S: AsRef<str>>(path: &str, patterns: &[S]) -> bool {
    patterns.iter().any(|p| {
        let p = p.as_ref();
        if p.contains(['*', '?', '[']) {
            return glob(p.as_bytes(), path.as_bytes());
        }
        let base = p.trim_end_matches('/');
        path == p || (path.len() > base.len() && path.starts_with(base) && path.as_bytes()[base.len()] == b'/')
    })
}

/// Go's filepath.Match: `*` and `?` stop at `/`, `[a-z]` and `[^a-z]` are
/// classes and `\` escapes.
pub fn glob(pat: &[u8], name: &[u8]) -> bool {
    match pat.first() {
        None => name.is_empty(),
        Some(b'*') => {
            let rest = &pat[1..];
            for i in 0..=name.len() {
                if glob(rest, &name[i..]) {
                    return true;
                }
                if i < name.len() && name[i] == b'/' {
                    return false;
                }
            }
            false
        }
        Some(b'?') => !name.is_empty() && name[0] != b'/' && glob(&pat[1..], &name[1..]),
        Some(b'[') => {
            let Some((&c, rest_name)) = name.split_first() else {
                return false;
            };
            let mut i = 1;
            let negate = pat.get(1) == Some(&b'^');
            if negate {
                i += 1;
            }
            let mut hit = false;
            let mut first = true;
            loop {
                let Some(&b) = pat.get(i) else { return false };
                if b == b']' && !first {
                    i += 1;
                    break;
                }
                first = false;
                let lo = if b == b'\\' {
                    i += 1;
                    *pat.get(i).unwrap_or(&0)
                } else {
                    b
                };
                i += 1;
                let mut hi = lo;
                if pat.get(i) == Some(&b'-') && pat.get(i + 1).is_some_and(|&x| x != b']') {
                    hi = pat[i + 1];
                    i += 2;
                }
                if lo <= c && c <= hi {
                    hit = true;
                }
            }
            hit != negate && c != b'/' && glob(&pat[i..], rest_name)
        }
        Some(b'\\') if pat.len() > 1 => name.first() == Some(&pat[1]) && glob(&pat[2..], &name[1..]),
        Some(&b) => name.first() == Some(&b) && glob(&pat[1..], &name[1..]),
    }
}

/// Which application control rule stops a file, if any. The block lists
/// come first; in lockdown anything not on the allow-list is stopped too.
/// sha is empty when the file could not be hashed.
pub fn app_rule(ac: &pb::ApplicationControlPolicy, path: &str, sha: &str) -> Option<String> {
    if !sha.is_empty()
        && let Some(h) = ac.blocked_sha256.iter().find(|h| *h == sha)
    {
        return Some(format!("sha256 {h}"));
    }
    if !path.is_empty()
        && let Some(p) = ac
            .blocked_paths
            .iter()
            .find(|p| matches(path, std::slice::from_ref(*p)))
    {
        return Some(format!("path {p}"));
    }
    if ac.lockdown && !app_allowed(ac, path, sha) {
        return Some("lockdown (not on the allow-list)".into());
    }
    None
}

/// Whether lockdown lets the file run.
pub fn app_allowed(ac: &pb::ApplicationControlPolicy, path: &str, sha: &str) -> bool {
    (!path.is_empty() && matches(path, &ac.allowed_paths))
        || (!sha.is_empty() && ac.allowed_sha256.iter().any(|h| h == sha))
}

/// Whether app_rule may need the file's hash to decide on path.
pub fn app_needs_hash(ac: &pb::ApplicationControlPolicy, path: &str) -> bool {
    !ac.blocked_sha256.is_empty() || (ac.lockdown && !ac.allowed_sha256.is_empty() && !matches(path, &ac.allowed_paths))
}

fn base_name(exe: &str) -> &str {
    exe.trim_end_matches(" (deleted)").rsplit('/').next().unwrap_or("")
}

/// Whether exe is a shell or script interpreter.
pub fn is_interpreter(exe: &str) -> bool {
    let b = base_name(exe);
    if matches!(
        b,
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "mksh" | "fish" | "busybox" | "node" | "nodejs" | "pwsh" | "osascript"
    ) {
        return true;
    }
    ["python", "perl", "ruby", "php", "lua", "tclsh"].iter().any(|f| {
        b.strip_prefix(f)
            .is_some_and(|v| v.bytes().all(|c| c.is_ascii_digit() || c == b'.'))
    })
}

fn family(exe: &str) -> &'static str {
    let b = base_name(exe);
    ["python", "perl", "ruby", "node"]
        .into_iter()
        .find(|f| b.starts_with(f))
        .unwrap_or("sh")
}

/// Options that take the next argument as their value.
fn value_opts(fam: &str) -> &'static [&'static str] {
    match fam {
        "python" => &["-W", "-X", "-Q"],
        "perl" => &["-I", "-M", "-m"],
        "ruby" => &["-I", "-r"],
        "node" => &["-r", "--require", "--import"],
        _ => &["-o", "-O", "--rcfile", "--init-file"],
    }
}

/// Options after which the program is inline code or a module, not a file.
fn code_opts(fam: &str) -> &'static [&'static str] {
    match fam {
        "python" => &["-c", "-m"],
        "perl" => &["-e", "-E"],
        "ruby" => &["-e"],
        "node" => &["-e", "--eval", "-p", "--print"],
        _ => &["-c"],
    }
}

/// The script file an interpreter was started with, as an absolute path:
/// the first argument after argv[0] that is not an option. Inline code
/// (bash -c, python -c) has none.
pub fn script_arg(exe: &str, args: &[String], cwd: &str) -> Option<String> {
    let fam = family(exe);
    let mut i = 1;
    while i < args.len() {
        let mut a = args[i].as_str();
        if a == "--" {
            a = args.get(i + 1)?;
        } else if a.starts_with('-') || a.starts_with('+') {
            if code_opts(fam).contains(&a) {
                return None;
            }
            if value_opts(fam).contains(&a) {
                i += 1;
            }
            i += 1;
            continue;
        }
        return abs_path(a, cwd);
    }
    None
}

/// Joins a relative path to cwd and removes `.`, `..` and duplicate slashes.
pub fn abs_path(a: &str, cwd: &str) -> Option<String> {
    if a.is_empty() {
        return None;
    }
    let joined = if a.starts_with('/') {
        a.to_string()
    } else if cwd.is_empty() {
        return None;
    } else {
        format!("{cwd}/{a}")
    };
    let mut out: Vec<&str> = Vec::new();
    for c in joined.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    Some(format!("/{}", out.join("/")))
}

/// The script and the script folder rule an interpreter run breaks, if
/// script blocking is on and exe runs a script from one of the folders.
pub fn script_rule(
    ac: &pb::ApplicationControlPolicy,
    exe: &str,
    args: &[String],
    cwd: &str,
) -> Option<(String, String)> {
    if !ac.block_scripts || !is_interpreter(exe) {
        return None;
    }
    let script = script_arg(exe, args, cwd)?;
    let p = ac
        .script_paths
        .iter()
        .find(|p| matches(&script, std::slice::from_ref(*p)))?;
    Some((script, format!("script in {p}")))
}

/// Whether host is one of the domains or a subdomain of one.
pub fn domain_listed(host: &str, domains: &std::collections::HashSet<String>) -> bool {
    let host = host.to_lowercase();
    let mut h = host.trim_end_matches('.');
    while !h.is_empty() {
        if domains.contains(h) {
            return true;
        }
        match h.split_once('.') {
            Some((_, rest)) => h = rest,
            None => return false,
        }
    }
    false
}

/// An IP address or CIDR; addresses become host prefixes.
pub fn parse_prefix(s: &str) -> Option<Prefix> {
    Prefix::parse(s.trim())
}

/// Parses "22, 80-90" into the nftables set "22, 80-90".
fn parse_ports(s: &str) -> Result<String, String> {
    let port = |s: &str| -> Result<u32, String> {
        s.trim()
            .parse::<u32>()
            .ok()
            .filter(|n| (1..=65535).contains(n))
            .ok_or_else(|| format!("{s:?} is not a port"))
    };
    let mut out = Vec::new();
    for f in s.split(',').map(str::trim).filter(|f| !f.is_empty()) {
        match f.split_once('-') {
            None => out.push(port(f)?.to_string()),
            Some((lo, hi)) => {
                let (a, b) = (port(lo)?, port(hi)?);
                if b <= a {
                    return Err(format!("port range {f:?} is empty"));
                }
                out.push(format!("{a}-{b}"));
            }
        }
    }
    Ok(out.join(", "))
}

/// One firewall rule as an nftables statement.
pub fn rule_expr(r: &pb::FirewallRule) -> Result<String, String> {
    let dir = match r.direction.as_str() {
        "in" => "saddr",
        "out" => "daddr",
        _ => return Err("direction must be in or out".into()),
    };
    let mut verdict = match r.action.as_str() {
        "allow" => "accept".to_string(),
        "deny" => "drop".to_string(),
        _ => return Err("action must be allow or deny".into()),
    };
    let mut parts = Vec::new();
    let cidr = r.cidr.trim();
    if !cidr.is_empty() {
        let p = parse_prefix(cidr).ok_or_else(|| format!("{cidr:?} is not an IP address or CIDR"))?;
        let fam = if p.is_ipv4() { "ip" } else { "ip6" };
        parts.push(format!("{fam} {dir} {p}"));
    }
    let ports = parse_ports(&r.ports)?;
    match r.protocol.as_str() {
        "tcp" | "udp" if !ports.is_empty() => parts.push(format!("{} dport {{ {ports} }}", r.protocol)),
        "tcp" | "udp" => parts.push(format!("meta l4proto {}", r.protocol)),
        "icmp" | "any" | "" if !ports.is_empty() => return Err("ports need protocol tcp or udp".into()),
        "icmp" => parts.push("meta l4proto { icmp, ipv6-icmp }".into()),
        "any" | "" => {}
        _ => return Err("protocol must be tcp, udp, icmp or any".into()),
    }
    if r.comment.contains(['"', '\n', '\\']) || r.comment.len() > 120 {
        return Err("comment must be under 120 characters without quotes or backslashes".into());
    }
    if !r.comment.is_empty() {
        verdict += &format!(" comment \"{}\"", r.comment);
    }
    parts.push(verdict);
    Ok(parts.join(" "))
}

fn nft_set(name: &str, typ: &str, interval: bool, elems: &[String]) -> String {
    let mut s = format!("\tset {name} {{\n\t\ttype {typ}\n");
    if interval {
        s += "\t\tflags interval\n\t\tauto-merge\n";
    }
    if !elems.is_empty() {
        s += &format!("\t\telements = {{ {} }}\n", elems.join(", "));
    }
    s + "\t}\n"
}

fn split_families(addrs: impl IntoIterator<Item = String>) -> (Vec<String>, Vec<String>) {
    addrs.into_iter().partition(|a| !a.contains(':'))
}

/// The nftables script for the host firewall. Loopback, established
/// connections, DHCP, IPv6 neighbour discovery and the console are always
/// allowed, so a bad policy cannot cut the agent off. The script replaces the
/// table atomically.
pub fn firewall_rules(fw: &pb::FirewallPolicy, console: &[IpAddr]) -> Result<String, String> {
    let mut seen = std::collections::BTreeSet::new();
    let (v4, v6) = split_families(console.iter().filter(|a| seen.insert(**a)).map(|a| a.to_string()));
    let (mut input, mut output) = (Vec::new(), Vec::new());
    for (i, r) in fw.rules.iter().enumerate() {
        let e = rule_expr(r).map_err(|e| format!("rule {}: {e}", i + 1))?;
        if r.direction == "in" {
            input.push(e)
        } else {
            output.push(e)
        }
    }
    let t = FIREWALL_TABLE;
    let mut b = format!("add table inet {t}\ndelete table inet {t}\ntable inet {t} {{\n");
    b += &nft_set("console4", "ipv4_addr", false, &v4);
    b += &nft_set("console6", "ipv6_addr", false, &v6);
    let in_policy = if fw.default_deny_inbound { "drop" } else { "accept" };
    for (name, policy, lo, dir, dhcp, nd, rules) in [
        (
            "input",
            in_policy,
            "iif \"lo\"",
            "saddr",
            "udp sport 67 udp dport 68",
            "nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert",
            &input,
        ),
        (
            "output",
            "accept",
            "oif \"lo\"",
            "daddr",
            "udp sport 68 udp dport 67",
            "nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit",
            &output,
        ),
    ] {
        b += &format!("\tchain {name} {{\n\t\ttype filter hook {name} priority 0; policy {policy};\n");
        b += &format!("\t\t{lo} accept\n\t\tct state established,related accept\n");
        b += &format!("\t\tip {dir} @console4 accept\n\t\tip6 {dir} @console6 accept\n");
        b += &format!("\t\t{dhcp} accept\n\t\ticmpv6 type {{ {nd} }} accept\n");
        for r in rules {
            b += &format!("\t\t{r}\n");
        }
        b += "\t}\n";
    }
    Ok(b + "}\n")
}

/// The table that rejects outbound connections, including from containers,
/// to the listed addresses.
pub fn web_reputation_rules(addrs: &[Prefix]) -> String {
    let (v4, v6) = split_families(addrs.iter().map(|p| p.to_string()));
    let t = WEB_REPUTATION_TABLE;
    let mut b = format!("add table inet {t}\ndelete table inet {t}\ntable inet {t} {{\n");
    b += &nft_set("bad4", "ipv4_addr", true, &v4);
    b += &nft_set("bad6", "ipv6_addr", true, &v6);
    for hook in ["output", "forward"] {
        b += &format!("\tchain {hook} {{\n\t\ttype filter hook {hook} priority -5; policy accept;\n");
        b += "\t\tip daddr @bad4 counter reject\n\t\tip6 daddr @bad6 counter reject\n\t}\n";
    }
    b + "}\n"
}

/// Creates the ban table, keeping bans already in it.
pub fn intrusion_rules() -> String {
    let t = INTRUSION_TABLE;
    format!(
        "add table inet {t}\n\
         add set inet {t} banned4 {{ type ipv4_addr; flags timeout; }}\n\
         add set inet {t} banned6 {{ type ipv6_addr; flags timeout; }}\n\
         add chain inet {t} input {{ type filter hook input priority -5; policy accept; }}\n\
         flush chain inet {t} input\n\
         add rule inet {t} input ip saddr @banned4 counter drop\n\
         add rule inet {t} input ip6 saddr @banned6 counter drop\n"
    )
}

/// Adds an address to the ban table for the given minutes.
pub fn ban(a: IpAddr, minutes: u32) -> String {
    let set = if a.is_ipv4() { "banned4" } else { "banned6" };
    format!("add element inet {INTRUSION_TABLE} {set} {{ {a} timeout {minutes}m }}\n")
}

/// Removes a table whether or not it exists.
pub fn delete_table(name: &str) -> String {
    format!("add table inet {name}\ndelete table inet {name}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        strings(s)
    }

    #[test]
    fn globs_follow_go_filepath_match() {
        assert!(glob(b"/tmp/*.sh", b"/tmp/x.sh"));
        assert!(!glob(b"/tmp/*.sh", b"/tmp/a/x.sh"));
        assert!(glob(b"/home/*/bin/?", b"/home/bob/bin/x"));
        assert!(glob(b"/x/[a-c]*", b"/x/beta"));
        assert!(!glob(b"/x/[^a-c]*", b"/x/beta"));
        assert!(glob(b"/etc/sudoers.d/xdr-*", b"/etc/sudoers.d/xdr-jit-bob"));
        assert!(matches("/usr/bin/ls", &["/usr"]));
        assert!(matches("/usr/bin", &["/usr/"]));
        assert!(!matches("/usrlocal/x", &["/usr"]));
        assert!(matches("/opt/app/run", &["/opt/*/run"]));
    }

    #[test]
    fn normalize_fills_defaults() {
        let p = normalize(pb::PreventionPolicy {
            block_exec: true,
            application_control: Some(pb::ApplicationControlPolicy {
                lockdown: true,
                block_scripts: true,
                blocked_sha256: v(&[" ABC "]),
                ..Default::default()
            }),
            ..Default::default()
        });
        let am = p.anti_malware.unwrap();
        assert!(am.enabled && am.block_known_bad);
        let ac = p.application_control.unwrap();
        assert_eq!(ac.allowed_paths.len(), DEFAULT_ALLOWED_PATHS.len());
        assert_eq!(ac.script_paths, v(&["/tmp", "/var/tmp", "/dev/shm"]));
        assert_eq!(ac.blocked_sha256, v(&["abc"]));
        assert_eq!(p.intrusion_prevention.unwrap().max_failures, 5);
        assert_eq!(p.device_control.unwrap().usb_storage, "allow");
        assert!(p.activity_monitoring.unwrap().network);
    }

    #[test]
    fn app_rules_block_then_lockdown() {
        let ac = pb::ApplicationControlPolicy {
            enabled: true,
            block: true,
            lockdown: true,
            blocked_paths: v(&["/usr/bin/nc"]),
            allowed_paths: v(&["/usr", "/opt/app/*"]),
            allowed_sha256: v(&["aa"]),
            ..Default::default()
        };
        assert_eq!(app_rule(&ac, "/usr/bin/nc", "").unwrap(), "path /usr/bin/nc");
        assert_eq!(app_rule(&ac, "/usr/bin/ls", ""), None);
        assert_eq!(app_rule(&ac, "/opt/app/run", ""), None);
        assert!(app_rule(&ac, "/tmp/x", "").unwrap().starts_with("lockdown"));
        assert_eq!(app_rule(&ac, "/tmp/x", "aa"), None);
        assert!(app_needs_hash(&ac, "/tmp/x"));
        assert!(!app_needs_hash(&ac, "/usr/bin/ls"));
    }

    #[test]
    fn scripts_are_found_in_interpreter_args() {
        let a = |s: &[&str]| v(s);
        assert!(is_interpreter("/usr/bin/python3.12"));
        assert!(is_interpreter("/bin/bash"));
        assert!(!is_interpreter("/usr/bin/pythonista"));
        assert!(!is_interpreter("/usr/bin/ls"));
        assert_eq!(
            script_arg("/bin/bash", &a(&["bash", "-x", "run.sh"]), "/tmp").unwrap(),
            "/tmp/run.sh"
        );
        assert_eq!(script_arg("/bin/bash", &a(&["bash", "-c", "/tmp/x.sh"]), "/"), None);
        assert_eq!(
            script_arg("/usr/bin/python3", &a(&["python3", "-W", "ignore", "/tmp/./a.py"]), "/"),
            Some("/tmp/a.py".into())
        );
        assert_eq!(
            script_arg("/usr/bin/python3", &a(&["python3", "-m", "http.server"]), "/"),
            None
        );
        assert_eq!(
            script_arg("/bin/sh", &a(&["sh", "--", "../tmp/x"]), "/home"),
            Some("/tmp/x".into())
        );
        let ac = normalize(pb::PreventionPolicy {
            application_control: Some(pb::ApplicationControlPolicy {
                block_scripts: true,
                ..Default::default()
            }),
            ..Default::default()
        })
        .application_control
        .unwrap();
        let (s, r) = script_rule(&ac, "/usr/bin/bash", &a(&["bash", "/dev/shm/x.sh"]), "/").unwrap();
        assert_eq!((s.as_str(), r.as_str()), ("/dev/shm/x.sh", "script in /dev/shm"));
        assert!(script_rule(&ac, "/usr/bin/bash", &a(&["bash", "/home/x.sh"]), "/").is_none());
        assert!(script_rule(&ac, "/usr/bin/cat", &a(&["cat", "/tmp/x.sh"]), "/").is_none());
    }

    #[test]
    fn domains_match_subdomains() {
        let set: std::collections::HashSet<String> = ["evil.com".to_string()].into();
        assert!(domain_listed("evil.com", &set));
        assert!(domain_listed("A.Evil.com.", &set));
        assert!(!domain_listed("notevil.com", &set));
    }

    #[test]
    fn firewall_script_keeps_console_and_renders_rules() {
        let fw = pb::FirewallPolicy {
            enabled: true,
            default_deny_inbound: true,
            rules: vec![
                pb::FirewallRule {
                    direction: "in".into(),
                    action: "allow".into(),
                    protocol: "tcp".into(),
                    ports: "22, 8000-8100".into(),
                    cidr: "10.1.2.3/8".into(),
                    comment: "ssh".into(),
                },
                pb::FirewallRule {
                    direction: "out".into(),
                    action: "deny".into(),
                    protocol: "icmp".into(),
                    ..Default::default()
                },
            ],
        };
        let s = firewall_rules(&fw, &["192.168.1.118".parse().unwrap()]).unwrap();
        assert!(s.contains("elements = { 192.168.1.118 }"));
        assert!(s.contains("policy drop;"));
        assert!(s.contains("ip saddr 10.0.0.0/8 tcp dport { 22, 8000-8100 } accept comment \"ssh\""));
        assert!(s.contains("meta l4proto { icmp, ipv6-icmp } drop"));
        let bad = |f: fn(&mut pb::FirewallRule)| {
            let mut r = fw.rules[0].clone();
            f(&mut r);
            rule_expr(&r).is_err()
        };
        assert!(bad(|r| r.ports = "0".into()));
        assert!(bad(|r| r.ports = "90-80".into()));
        assert!(bad(|r| r.direction = "up".into()));
        assert!(bad(|r| r.comment = "a\"b".into()));
        assert!(bad(|r| r.protocol = "any".into()));
    }

    #[test]
    fn nft_tables_render() {
        let w = web_reputation_rules(&[parse_prefix("1.2.3.4").unwrap(), parse_prefix("2001:db8::/32").unwrap()]);
        assert!(w.contains("elements = { 1.2.3.4/32 }") && w.contains("elements = { 2001:db8::/32 }"));
        assert!(intrusion_rules().contains("flags timeout"));
        assert_eq!(
            ban("203.0.113.5".parse().unwrap(), 30),
            "add element inet xdr_ips banned4 { 203.0.113.5 timeout 30m }\n"
        );
    }
}
