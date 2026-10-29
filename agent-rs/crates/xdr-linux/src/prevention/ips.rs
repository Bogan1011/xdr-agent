//! Intrusion prevention: SSH brute force. An address that fails to log in
//! max_failures times within the window is reported and, with prevention on,
//! banned with nftables for ban_minutes. Failed logins come from the auth
//! collector's events, so sshd's log is read once.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use xdr_core::bus::new_event;
use xdr_core::pb::{self, EventType};

use super::{Emitter, policy, table_present};
use crate::response::{Prefix, nft, unmap};

#[derive(Default)]
struct Inner {
    pol: Option<pb::IntrusionPreventionPolicy>,
    allow: Vec<Prefix>,
    fails: HashMap<IpAddr, Vec<Instant>>,
    bans: HashMap<IpAddr, Instant>,
    table_on: bool,
    error: String,
}

pub struct Intrusion {
    emit: Emitter,
    console: Vec<String>,
    inner: Mutex<Inner>,
}

impl Intrusion {
    pub fn new(emit: Emitter, console: Vec<String>) -> Self {
        Intrusion {
            emit,
            console,
            inner: Mutex::default(),
        }
    }

    pub fn set_policy(&self, p: &pb::IntrusionPreventionPolicy) {
        let mut i = self.inner.lock().unwrap();
        if i.pol.as_ref() == Some(p) {
            return;
        }
        i.pol = Some(p.clone());
        i.allow = p.allow.iter().filter_map(|a| policy::parse_prefix(a)).collect();
        // The console is resolved here, not per failed login.
        if let Ok(cs) = crate::response::console_addrs(&self.console) {
            i.allow.extend(cs.into_iter().map(Prefix::host));
        }
        i.fails.clear();
        let want_table = p.enabled && p.prevent;
        if want_table && !i.table_on {
            match nft(&policy::intrusion_rules()) {
                Ok(()) => {
                    i.table_on = true;
                    i.error.clear();
                }
                Err(err) => {
                    tracing::error!("intrusion prevention table not applied: {err:#}");
                    i.error = format!("{err:#}");
                }
            }
        } else if !want_table && (i.table_on || table_present(policy::INTRUSION_TABLE)) {
            match nft(&policy::delete_table(policy::INTRUSION_TABLE)) {
                Ok(()) => {
                    i.table_on = false;
                    i.error.clear();
                    i.bans.clear();
                }
                Err(err) => i.error = format!("{err:#}"),
            }
        }
        if p.enabled {
            tracing::info!(
                prevent = p.prevent,
                max_failures = p.max_failures,
                window_seconds = p.window_seconds,
                "intrusion prevention on"
            );
        }
    }

    /// Counts failed SSH logins from the auth collector.
    pub fn observe(&self, e: &pb::Event) {
        let Some(pb::event::Payload::Auth(a)) = &e.payload else {
            return;
        };
        if e.r#type() != EventType::AuthFailed || a.service != "sshd" {
            return;
        }
        if let Ok(ip) = a.source_ip.parse::<IpAddr>() {
            self.failed(unmap(ip), Instant::now());
        }
    }

    fn failed(&self, a: IpAddr, now: Instant) {
        let mut i = self.inner.lock().unwrap();
        let Some(pol) = i.pol.clone().filter(|p| p.enabled) else {
            return;
        };
        if a.is_loopback() || a.is_unspecified() || i.allow.iter().any(|p| p.contains(a)) {
            return;
        }
        let window = Duration::from_secs(pol.window_seconds as u64);
        let mut ts: Vec<Instant> = i
            .fails
            .remove(&a)
            .unwrap_or_default()
            .into_iter()
            .filter(|t| now.duration_since(*t) < window)
            .collect();
        ts.push(now);
        if ts.len() < pol.max_failures as usize {
            if i.fails.len() > 50_000 {
                i.fails.clear();
            }
            i.fails.insert(a, ts);
            return;
        }
        let mut action = "detected";
        let mut detail = format!("{} failed SSH logins in {}s", ts.len(), pol.window_seconds);
        if pol.prevent {
            match nft(&policy::ban(a, pol.ban_minutes)) {
                Ok(()) => {
                    action = "banned";
                    detail += &format!(", banned for {} minutes", pol.ban_minutes);
                    i.bans.insert(a, now + Duration::from_secs(pol.ban_minutes as u64 * 60));
                }
                Err(err) => {
                    tracing::error!(addr = %a, "ban failed: {err:#}");
                    i.error = format!("{err:#}");
                }
            }
        }
        drop(i);
        tracing::warn!(addr = %a, action, failures = ts.len(), "SSH brute force");
        let mut e = new_event(EventType::Intrusion);
        e.payload = Some(pb::event::Payload::Policy(pb::PolicyEvent {
            action: action.into(),
            detail,
            remote_addr: a.to_string(),
            ..Default::default()
        }));
        self.emit.emit(e);
    }

    /// Whether the module is on, how many addresses are banned, last error.
    pub fn status(&self) -> (bool, usize, String) {
        let mut i = self.inner.lock().unwrap();
        let now = Instant::now();
        i.bans.retain(|_, until| *until > now);
        (i.pol.as_ref().is_some_and(|p| p.enabled), i.bans.len(), i.error.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_failures_in_window_and_skips_allowed() {
        let (sink, mut rx) = xdr_core::bus::EventSink::channel(8);
        let emit = Emitter::default();
        emit.set(sink);
        let ips = Intrusion::new(emit, vec![]);
        ips.set_policy(&pb::IntrusionPreventionPolicy {
            enabled: true,
            max_failures: 3,
            window_seconds: 60,
            ban_minutes: 30,
            allow: vec!["10.0.0.0/8".into()],
            ..Default::default()
        });
        let t0 = Instant::now();
        let bad: IpAddr = "203.0.113.5".parse().unwrap();
        ips.failed(bad, t0);
        ips.failed(bad, t0 + Duration::from_secs(61)); // first one aged out
        ips.failed(bad, t0 + Duration::from_secs(62));
        assert!(rx.try_recv().is_err());
        ips.failed(bad, t0 + Duration::from_secs(63));
        let e = rx.try_recv().unwrap();
        let Some(pb::event::Payload::Policy(p)) = e.payload else {
            panic!()
        };
        assert_eq!((p.action.as_str(), p.remote_addr.as_str()), ("detected", "203.0.113.5"));
        for _ in 0..5 {
            ips.failed("10.1.1.1".parse().unwrap(), t0);
        }
        assert!(rx.try_recv().is_err());
    }
}
