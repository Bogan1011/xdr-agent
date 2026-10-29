//! Web reputation: rejects outbound connections to known-bad addresses (IP
//! IOCs and the addresses of listed domains, resolved every few minutes) with
//! an nftables table, and reports connections to them seen by the network
//! collectors.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use xdr_core::bus::new_event;
use xdr_core::pb::{self, EventType};

use super::{Emitter, policy, table_present};
use crate::response::{Prefix, nft, unmap};

const REFRESH: Duration = Duration::from_secs(600);
/// Domains resolved per refresh; the policy's own come first.
const MAX_RESOLVE: usize = 2000;
const DEDUPE: Duration = Duration::from_secs(60);
const RESOLVERS: usize = 16;

#[derive(Default)]
struct Inner {
    pol: Option<pb::WebReputationPolicy>,
    intel_ips: Vec<String>,
    intel_domains: Vec<String>,
    /// Address to why it is listed.
    exact: HashMap<IpAddr, String>,
    nets: Vec<(Prefix, String)>,
    script: String,
    error: String,
    last_report: HashMap<String, Instant>,
}

pub struct WebReputation {
    emit: Emitter,
    console: Vec<String>,
    inner: Mutex<Inner>,
    tx: mpsc::SyncSender<()>,
    rx: Mutex<Option<mpsc::Receiver<()>>>,
}

impl WebReputation {
    pub fn new(emit: Emitter, console: Vec<String>) -> Self {
        let (tx, rx) = mpsc::sync_channel(1);
        WebReputation {
            emit,
            console,
            inner: Mutex::default(),
            tx,
            rx: Mutex::new(Some(rx)),
        }
    }

    pub fn set_policy(&self, p: &pb::WebReputationPolicy) {
        let mut i = self.inner.lock().unwrap();
        if i.pol.as_ref() != Some(p) {
            i.pol = Some(p.clone());
            let _ = self.tx.try_send(());
        }
    }

    /// Takes the IP and domain IOCs from the detection content.
    pub fn set_intel(&self, ips: &[String], domains: &[String]) {
        let mut i = self.inner.lock().unwrap();
        if i.intel_ips != ips || i.intel_domains != domains {
            (i.intel_ips, i.intel_domains) = (ips.to_vec(), domains.to_vec());
            let _ = self.tx.try_send(());
        }
    }

    pub fn run(&self) {
        let rx = self.rx.lock().unwrap().take().expect("web reputation runs once");
        loop {
            match rx.recv_timeout(REFRESH) {
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
                _ => self.rebuild(),
            }
        }
    }

    fn rebuild(&self) {
        let (pol, ips, doms) = {
            let i = self.inner.lock().unwrap();
            (i.pol.clone(), i.intel_ips.clone(), i.intel_domains.clone())
        };
        let Some(pol) = pol.filter(|p| p.enabled) else {
            let mut i = self.inner.lock().unwrap();
            i.exact.clear();
            i.nets.clear();
            drop(i);
            self.apply(&[], false);
            return;
        };
        let allowed: HashSet<String> = pol.allowed_domains.iter().cloned().collect();
        let mut exact: HashMap<IpAddr, String> = HashMap::new();
        let mut nets = Vec::new();
        let mut resolve: Vec<String> = Vec::new();
        let mut seen = HashSet::new();
        let mut add = |d: &str| {
            if resolve.len() < MAX_RESOLVE && !policy::domain_listed(d, &allowed) && seen.insert(d.to_string()) {
                resolve.push(d.to_string());
            }
        };
        pol.blocked_domains.iter().for_each(|d| add(d));
        if pol.use_threat_intel {
            doms.iter().for_each(|d| add(d));
            for s in &ips {
                match policy::parse_prefix(s) {
                    Some(p) if p.is_host() => {
                        exact.insert(p.addr(), "threat intel".into());
                    }
                    Some(p) => nets.push((p, "threat intel".to_string())),
                    None => {}
                }
            }
        }
        for (d, addrs) in resolve_all(&resolve) {
            for a in addrs {
                exact.insert(a, d.clone());
            }
        }
        // Never cut the agent off from the console, or the host from itself.
        let console = crate::response::console_addrs(&self.console).unwrap_or_default();
        exact.retain(|a, _| !console.contains(a) && !a.is_loopback() && !a.is_unspecified());
        nets.retain(|(p, _)| {
            !p.contains(IpAddr::from([0u8; 4]))
                && !p.contains(IpAddr::from([0u16; 8]))
                && !console.iter().any(|c| p.contains(*c))
        });
        let mut prefixes: Vec<Prefix> = exact.keys().map(|a| Prefix::host(*a)).collect();
        prefixes.extend(nets.iter().map(|(p, _)| *p));
        prefixes.sort_by_key(|p| p.addr());
        {
            let mut i = self.inner.lock().unwrap();
            i.exact = exact;
            i.nets = nets;
        }
        self.apply(&prefixes, pol.block);
    }

    /// Installs or removes the nftables table.
    fn apply(&self, prefixes: &[Prefix], block: bool) {
        let mut i = self.inner.lock().unwrap();
        if !block {
            if !i.script.is_empty() || table_present(policy::WEB_REPUTATION_TABLE) {
                if let Err(err) = nft(&policy::delete_table(policy::WEB_REPUTATION_TABLE)) {
                    i.error = format!("{err:#}");
                    return;
                }
                tracing::info!("web reputation blocking stopped");
            }
            i.script.clear();
            i.error.clear();
            return;
        }
        let script = policy::web_reputation_rules(prefixes);
        if script == i.script && table_present(policy::WEB_REPUTATION_TABLE) {
            return;
        }
        match nft(&script) {
            Ok(()) => {
                i.script = script;
                i.error.clear();
                tracing::info!(addresses = prefixes.len(), "web reputation block list applied");
            }
            Err(err) => {
                i.error = format!("{err:#}");
                tracing::error!("web reputation block list not applied: {err:#}");
            }
        }
    }

    /// Reports connections to listed addresses.
    pub fn observe(&self, e: &pb::Event) {
        let Some(pb::event::Payload::Network(ne)) = &e.payload else {
            return;
        };
        if e.r#type() != EventType::NetConnect {
            return;
        }
        let Ok(a) = ne.remote_addr.parse::<IpAddr>() else {
            return;
        };
        let a = unmap(a);
        let mut i = self.inner.lock().unwrap();
        if !i.pol.as_ref().is_some_and(|p| p.enabled) {
            return;
        }
        let Some(reason) = i
            .exact
            .get(&a)
            .cloned()
            .or_else(|| i.nets.iter().find(|(p, _)| p.contains(a)).map(|(_, r)| r.clone()))
        else {
            return;
        };
        let key = format!("{a}|{}", ne.exe);
        if i.last_report.get(&key).is_some_and(|t| t.elapsed() < DEDUPE) {
            return;
        }
        if i.last_report.len() > 10_000 {
            i.last_report.clear();
        }
        i.last_report.insert(key, Instant::now());
        let action = if i.script.is_empty() { "detected" } else { "blocked" };
        drop(i);
        let detail = if reason == "threat intel" {
            "listed by threat intel".to_string()
        } else {
            format!("domain {reason}")
        };
        let mut ev = new_event(EventType::WebReputation);
        ev.payload = Some(pb::event::Payload::Policy(pb::PolicyEvent {
            action: action.into(),
            detail,
            remote_addr: a.to_string(),
            pid: ne.pid,
            exe: ne.exe.clone(),
            ..Default::default()
        }));
        self.emit.emit(ev);
    }

    /// Listed addresses, whether they are blocked, and the last error.
    pub fn status(&self) -> (usize, bool, String) {
        let i = self.inner.lock().unwrap();
        (i.exact.len() + i.nets.len(), !i.script.is_empty(), i.error.clone())
    }
}

/// Looks up the domains on a few threads.
fn resolve_all(domains: &[String]) -> HashMap<String, Vec<IpAddr>> {
    let out = Mutex::new(HashMap::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..RESOLVERS.min(domains.len()) {
            s.spawn(|| {
                loop {
                    let n = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(d) = domains.get(n) else { return };
                    if let Ok(addrs) = (d.as_str(), 0).to_socket_addrs() {
                        let ips: Vec<IpAddr> = addrs.map(|a| unmap(a.ip())).collect();
                        out.lock().unwrap().insert(d.clone(), ips);
                    }
                }
            });
        }
    });
    out.into_inner().unwrap()
}
