//! Authentication telemetry: SSH and console logins, failures, logouts, sudo,
//! su and local account changes, parsed from the messages sshd, sudo, su,
//! login and the shadow-utils tools log. Reads the journal (journalctl -f -o
//! json) and falls back to /var/log/auth.log or /var/log/secure.

use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Result, bail};
use xdr_core::bus::{EventSink, new_event};
use xdr_core::pb::{self, EventType};
use xdr_core::platform::Collector;

use crate::procfs;

/// Programs whose messages are parsed; everything else is skipped.
const IDENTS: &[&str] = &[
    "sshd",
    "sshd-session",
    "sudo",
    "su",
    "login",
    "useradd",
    "userdel",
    "usermod",
    "groupadd",
    "groupdel",
    "groupmod",
    "passwd",
    "chpasswd",
    "gdm-password",
    "lightdm",
];

pub struct Auth;

impl Collector for Auth {
    fn name(&self) -> &'static str {
        "auth"
    }

    fn run(&mut self, sink: &EventSink) -> Result<()> {
        if Command::new("journalctl")
            .arg("--version")
            .stdout(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
        {
            return follow_journal(sink);
        }
        follow_file(sink)
    }
}

fn follow_journal(sink: &EventSink) -> Result<()> {
    let mut cmd = Command::new("journalctl");
    cmd.args([
        "-f",
        "-n",
        "0",
        "-o",
        "json",
        "--output-fields=SYSLOG_IDENTIFIER,_PID,MESSAGE,_COMM",
    ]);
    for id in IDENTS {
        cmd.arg(format!("SYSLOG_IDENTIFIER={id}"));
    }
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;
    let out = child.stdout.take().expect("piped stdout");
    for line in BufReader::new(out).lines() {
        let Ok(line) = line else { break };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let field = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        let pid = field("_PID").parse().unwrap_or(0);
        if let Some(e) = parse(&field("SYSLOG_IDENTIFIER"), pid, &field("MESSAGE")) {
            sink.emit(e);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    bail!("journalctl exited")
}

/// Tails the syslog auth file, reopening it after rotation.
fn follow_file(sink: &EventSink) -> Result<()> {
    let Some(path) = ["/var/log/auth.log", "/var/log/secure"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
    else {
        bail!("no journalctl, /var/log/auth.log or /var/log/secure");
    };
    let mut f = std::fs::File::open(path)?;
    let mut pos = f.seek(SeekFrom::End(0))?;
    let mut buf = String::new();
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if len < pos {
            f = std::fs::File::open(path)?;
            pos = 0;
        }
        f.seek(SeekFrom::Start(pos))?;
        let mut r = BufReader::new(&f);
        loop {
            buf.clear();
            let n = r.read_line(&mut buf)?;
            if n == 0 || !buf.ends_with('\n') {
                break;
            }
            pos += n as u64;
            if let Some((ident, pid, msg)) = split_syslog(buf.trim_end())
                && let Some(e) = parse(ident, pid, msg)
            {
                sink.emit(e);
            }
        }
    }
}

/// "Oct 27 12:00:01 host sshd[812]: Accepted ..." or the RFC 3339 form →
/// ("sshd", 812, "Accepted ...").
fn split_syslog(line: &str) -> Option<(&str, u32, &str)> {
    let (head, msg) = line.split_once(": ")?;
    let tag = head.rsplit(' ').next()?;
    let (ident, pid) = match tag.split_once('[') {
        Some((i, p)) => (i, p.trim_end_matches(']').parse().unwrap_or(0)),
        None => (tag, 0),
    };
    Some((ident, pid, msg))
}

fn auth(t: EventType, a: pb::AuthEvent) -> pb::Event {
    let mut e = new_event(t);
    e.payload = Some(pb::event::Payload::Auth(a));
    e
}

/// The word after `key` in s, e.g. word_after("for root from", "for ") = "root".
fn word_after<'a>(s: &'a str, key: &str) -> &'a str {
    s.split_once(key)
        .and_then(|(_, r)| r.split_whitespace().next())
        .unwrap_or("")
}

/// The value of "KEY=value" in sudo's "A=1 ; B=2" lists.
fn sudo_field<'a>(s: &'a str, key: &str) -> &'a str {
    s.split(" ; ")
        .find_map(|p| p.trim().strip_prefix(key).and_then(|r| r.strip_prefix('=')))
        .unwrap_or("")
}

/// "name=bob, UID=1001" → "bob".
fn kv<'a>(s: &'a str, key: &str) -> &'a str {
    s.split(", ")
        .find_map(|p| p.trim().strip_prefix(key).and_then(|r| r.strip_prefix('=')))
        .unwrap_or("")
}

/// Text between the first pair of single quotes.
fn quoted(s: &str) -> &str {
    s.split('\'').nth(1).unwrap_or("")
}

fn uid_of(user: &str) -> u32 {
    std::fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|p| {
            p.lines().find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.len() > 2 && f[0] == user).then(|| f[2].parse().ok()).flatten()
            })
        })
        .unwrap_or(0)
}

/// Turns one log message into an event, or None when it isn't one we track.
pub fn parse(ident: &str, pid: u32, msg: &str) -> Option<pb::Event> {
    let base = |action: &str, service: &str| pb::AuthEvent {
        action: action.into(),
        service: service.into(),
        pid,
        ..Default::default()
    };
    let msg = msg.trim();
    match ident {
        // OpenSSH 9.8+ logs sessions as sshd-session.
        "sshd" | "sshd-session" => {
            if let Some(rest) = msg.strip_prefix("Accepted ") {
                // "publickey for root from 10.0.0.1 port 5022 ssh2: RSA SHA256:..."
                let mut a = base("login", "sshd");
                a.method = rest.split_whitespace().next()?.into();
                a.user = word_after(rest, " for ").into();
                a.source_ip = word_after(rest, " from ").into();
                a.source_port = word_after(rest, " port ").parse().unwrap_or(0);
                a.success = true;
                a.uid = uid_of(&a.user);
                a.detail = rest.split_once(": ").map(|(_, k)| k.to_string()).unwrap_or_default();
                return Some(auth(EventType::AuthLogin, a));
            }
            if let Some(rest) = msg.strip_prefix("Failed ") {
                // "password for invalid user x from ..." is preceded by "Invalid user x from ...".
                if rest.contains(" for invalid user ") {
                    return None;
                }
                let mut a = base("failed", "sshd");
                a.method = rest.split_whitespace().next()?.into();
                a.user = word_after(rest, " for ").into();
                a.source_ip = word_after(rest, " from ").into();
                a.source_port = word_after(rest, " port ").parse().unwrap_or(0);
                a.failure_reason = format!("wrong {}", a.method);
                return Some(auth(EventType::AuthFailed, a));
            }
            if let Some(rest) = msg.strip_prefix("Invalid user ") {
                let mut a = base("failed", "sshd");
                a.user = rest.split_whitespace().next()?.into();
                a.source_ip = word_after(rest, " from ").into();
                a.source_port = word_after(rest, " port ").parse().unwrap_or(0);
                a.failure_reason = "invalid user".into();
                return Some(auth(EventType::AuthFailed, a));
            }
            if let Some(rest) = msg.strip_prefix("Disconnected from user ") {
                let mut a = base("logout", "sshd");
                a.user = rest.split_whitespace().next()?.into();
                a.source_ip = rest.split_whitespace().nth(1).unwrap_or("").into();
                a.source_port = word_after(rest, " port ").parse().unwrap_or(0);
                a.success = true;
                a.uid = uid_of(&a.user);
                return Some(auth(EventType::AuthLogout, a));
            }
            None
        }
        "sudo" => {
            // "  rutav : TTY=pts/0 ; PWD=/home/rutav ; USER=root ; COMMAND=/usr/bin/id"
            let (user, rest) = msg.split_once(" : ")?;
            let command = sudo_field(rest, "COMMAND");
            if command.is_empty() {
                return None;
            }
            let mut a = base("sudo", "sudo");
            a.user = user.trim().into();
            a.uid = uid_of(&a.user);
            a.tty = sudo_field(rest, "TTY").into();
            a.target_user = sudo_field(rest, "USER").into();
            a.command = command.into();
            a.detail = format!("cwd {}", sudo_field(rest, "PWD"));
            // Failures put the reason first: "3 incorrect password attempts ; TTY=...".
            let first = rest.split(" ; ").next().unwrap_or("");
            a.success = first.contains('=');
            if !a.success {
                a.failure_reason = first.trim().into();
            }
            Some(auth(EventType::Sudo, a))
        }
        "su" => {
            // "(to root) rutav on pts/0" or "FAILED SU (to root) rutav on pts/0"
            let failed = msg.starts_with("FAILED SU ");
            let rest = msg.strip_prefix("FAILED SU ").unwrap_or(msg).strip_prefix("(to ")?;
            let (target, rest) = rest.split_once(") ")?;
            let mut a = base("su", "su");
            a.target_user = target.into();
            a.user = rest.split_whitespace().next()?.into();
            a.uid = uid_of(&a.user);
            a.tty = word_after(rest, " on ").into();
            a.success = !failed;
            if failed {
                a.failure_reason = "authentication failure".into();
            }
            Some(auth(EventType::Su, a))
        }
        "login" | "gdm-password" | "lightdm" => {
            if msg.contains("session opened for user ") {
                let mut a = base("login", ident);
                a.user = word_after(msg, "session opened for user ").split('(').next()?.into();
                a.uid = uid_of(&a.user);
                a.method = "password".into();
                a.success = true;
                return Some(auth(EventType::AuthLogin, a));
            }
            if msg.contains("session closed for user ") {
                let mut a = base("logout", ident);
                a.user = word_after(msg, "session closed for user ").into();
                a.success = true;
                return Some(auth(EventType::AuthLogout, a));
            }
            // "FAILED LOGIN (1) on '/dev/tty1' FOR 'rutav', Authentication failure"
            if msg.starts_with("FAILED LOGIN") {
                let mut a = base("failed", ident);
                a.tty = quoted(msg).trim_start_matches("/dev/").into();
                a.user = msg
                    .split_once(" FOR ")
                    .map(|(_, r)| quoted(&format!(" {r}")).to_string())?;
                a.failure_reason = msg.rsplit_once(", ").map(|(_, r)| r.to_string()).unwrap_or_default();
                return Some(auth(EventType::AuthFailed, a));
            }
            None
        }
        "useradd" | "userdel" | "usermod" | "groupadd" | "groupdel" | "groupmod" | "passwd" | "chpasswd" => {
            account_change(ident, pid, msg)
        }
        _ => None,
    }
}

fn account_change(ident: &str, pid: u32, msg: &str) -> Option<pb::Event> {
    let (action, target) = if let Some(r) = msg.strip_prefix("new user: ") {
        ("user_created", kv(r, "name"))
    } else if let Some(r) = msg.strip_prefix("new group: ") {
        ("group_created", kv(r, "name"))
    } else if msg.starts_with("delete user ") {
        ("user_deleted", quoted(msg))
    } else if msg.starts_with("group '") && msg.ends_with(" removed") {
        ("group_deleted", quoted(msg))
    } else if msg.starts_with("removed group ") {
        // userdel removing the user's own group.
        ("group_deleted", quoted(msg))
    } else if ident == "usermod" {
        // "add 'bob' to group 'sudo'", "change user 'bob' shell from ..."
        ("user_modified", quoted(msg))
    } else if ident == "groupmod" {
        ("group_modified", quoted(msg))
    } else if msg.contains("password changed for ") {
        ("password_changed", word_after(msg, "password changed for "))
    } else {
        return None;
    };
    if target.is_empty() {
        return None;
    }
    // Who ran the tool: the login behind it survives sudo.
    let actor = procfs::read(pid).map(|i| procfs::username(i.uid)).unwrap_or_default();
    Some(auth(
        EventType::AccountChange,
        pb::AuthEvent {
            action: action.into(),
            target_user: target.into(),
            user: actor,
            service: ident.into(),
            pid,
            success: true,
            detail: msg.into(),
            ..Default::default()
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(e: &pb::Event) -> &pb::AuthEvent {
        match &e.payload {
            Some(pb::event::Payload::Auth(a)) => a,
            _ => panic!("no auth payload"),
        }
    }

    #[test]
    fn parses_ssh() {
        let e = parse(
            "sshd",
            9,
            "Accepted publickey for root from 10.0.0.5 port 50022 ssh2: ED25519 SHA256:abc",
        )
        .unwrap();
        assert_eq!(e.r#type(), EventType::AuthLogin);
        let x = a(&e);
        assert_eq!(
            (x.user.as_str(), x.source_ip.as_str(), x.source_port, x.method.as_str()),
            ("root", "10.0.0.5", 50022, "publickey")
        );
        assert_eq!(x.detail, "ED25519 SHA256:abc");

        let e = parse("sshd", 9, "Failed password for rutav from 10.0.0.6 port 1 ssh2").unwrap();
        assert_eq!(
            (e.r#type(), a(&e).user.as_str(), a(&e).failure_reason.as_str()),
            (EventType::AuthFailed, "rutav", "wrong password")
        );
        assert!(
            parse(
                "sshd",
                9,
                "Failed password for invalid user bob from 10.0.0.6 port 1 ssh2"
            )
            .is_none()
        );
        let e = parse("sshd", 9, "Invalid user bob from 10.0.0.6 port 2").unwrap();
        assert_eq!((a(&e).user.as_str(), a(&e).source_ip.as_str()), ("bob", "10.0.0.6"));
        let e = parse("sshd", 9, "Disconnected from user rutav 10.0.0.5 port 50022").unwrap();
        assert_eq!(
            (e.r#type(), a(&e).source_ip.as_str()),
            (EventType::AuthLogout, "10.0.0.5")
        );
        assert!(parse("sshd", 9, "Server listening on 0.0.0.0 port 22.").is_none());
    }

    #[test]
    fn parses_sudo_and_su() {
        let e = parse(
            "sudo",
            3,
            "   rutav : TTY=pts/0 ; PWD=/home/rutav ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
        )
        .unwrap();
        let x = a(&e);
        assert!(x.success);
        assert_eq!(
            (
                x.user.as_str(),
                x.target_user.as_str(),
                x.command.as_str(),
                x.tty.as_str()
            ),
            ("rutav", "root", "/usr/bin/cat /etc/shadow", "pts/0")
        );
        let e = parse(
            "sudo",
            3,
            "rutav : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
        )
        .unwrap();
        assert!(!a(&e).success);
        assert_eq!(a(&e).failure_reason, "3 incorrect password attempts");
        assert!(parse("sudo", 3, "pam_unix(sudo:session): session opened for user root").is_none());

        let e = parse("su", 4, "(to root) rutav on pts/1").unwrap();
        assert_eq!(
            (
                a(&e).target_user.as_str(),
                a(&e).user.as_str(),
                a(&e).tty.as_str(),
                a(&e).success
            ),
            ("root", "rutav", "pts/1", true)
        );
        let e = parse("su", 4, "FAILED SU (to root) rutav on pts/1").unwrap();
        assert!(!a(&e).success);
    }

    #[test]
    fn parses_console_and_accounts() {
        let e = parse(
            "login",
            5,
            "pam_unix(login:session): session opened for user rutav(uid=1000) by LOGIN(uid=0)",
        )
        .unwrap();
        assert_eq!((e.r#type(), a(&e).user.as_str()), (EventType::AuthLogin, "rutav"));
        let e = parse(
            "login",
            5,
            "FAILED LOGIN (1) on '/dev/tty1' FOR 'rutav', Authentication failure",
        )
        .unwrap();
        assert_eq!(
            (a(&e).user.as_str(), a(&e).tty.as_str(), a(&e).failure_reason.as_str()),
            ("rutav", "tty1", "Authentication failure")
        );

        let cases = [
            (
                "useradd",
                "new user: name=bob, UID=1001, GID=1001, home=/home/bob, shell=/bin/bash, from=/dev/pts/0",
                "user_created",
                "bob",
            ),
            ("useradd", "new group: name=bob, GID=1001", "group_created", "bob"),
            ("userdel", "delete user 'bob'", "user_deleted", "bob"),
            ("usermod", "add 'bob' to group 'sudo'", "user_modified", "bob"),
            ("groupdel", "group 'dev' removed", "group_deleted", "dev"),
            (
                "passwd",
                "pam_unix(passwd:chauthtok): password changed for bob",
                "password_changed",
                "bob",
            ),
        ];
        for (ident, msg, action, target) in cases {
            let e = parse(ident, 0, msg).unwrap_or_else(|| panic!("{msg}"));
            assert_eq!(
                (a(&e).action.as_str(), a(&e).target_user.as_str()),
                (action, target),
                "{msg}"
            );
        }
        assert!(parse("groupadd", 0, "group added to /etc/group: name=dev, GID=1002").is_none());
    }

    #[test]
    fn splits_syslog_lines() {
        assert_eq!(
            split_syslog("Oct 27 12:00:01 web sshd[812]: Accepted password for a from b port 1 ssh2"),
            Some(("sshd", 812, "Accepted password for a from b port 1 ssh2"))
        );
        assert_eq!(
            split_syslog("2026-10-27T12:00:01.1+00:00 web sudo: rutav : TTY=pts/0 ; USER=root ; COMMAND=/bin/id"),
            Some(("sudo", 0, "rutav : TTY=pts/0 ; USER=root ; COMMAND=/bin/id"))
        );
    }
}
