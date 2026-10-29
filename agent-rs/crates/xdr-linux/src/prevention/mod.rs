//! Prevention: enforces the endpoint's policy module by module. Exec
//! blocking (hash IOCs and application control incl. lockdown), script
//! blocking, file integrity, the host firewall, web reputation, intrusion
//! prevention, device control (incl. read-only USB), activity monitoring and
//! tamper protection with the self-protection password. Anti-malware YARA
//! scanning lives in the core scanner. The heartbeat caches the policy, so it
//! applies at start before the console answers.

pub mod devctl;
pub mod execblock;
pub mod fanotify;
pub mod fim;
pub mod ips;
pub mod policy;
pub mod scriptblock;
pub mod tamper;
pub mod webrep;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock, mpsc};
use std::time::Duration;

use xdr_core::bus::{EventSink, new_event};
use xdr_core::pb::{self, EventType};

use crate::procfs;
use crate::response::nft;

const FIREWALL_CHECK: Duration = Duration::from_secs(120);

/// Where modules send their events; set once the bus exists.
#[derive(Clone, Default)]
pub struct Emitter(Arc<OnceLock<EventSink>>);

impl Emitter {
    pub fn set(&self, sink: EventSink) {
        let _ = self.0.set(sink);
    }

    pub fn emit(&self, e: pb::Event) {
        if let Some(s) = self.0.get() {
            s.emit(e);
        }
    }
}

/// An event for a file an application control rule matched; pid is the
/// process that ran, or tried to run, it.
pub fn app_control_event(action: &str, path: &str, sha: &str, rule: &str, pid: u32) -> pb::Event {
    let mut pe = pb::PolicyEvent {
        action: action.into(),
        exe: path.into(),
        sha256: sha.into(),
        pid,
        detail: format!("matched {rule}"),
        ..Default::default()
    };
    if let Some(i) = procfs::read(pid) {
        pe.user = i.user;
        if action == "blocked" {
            pe.detail += &format!(", run by {}", i.exe);
        }
    }
    let mut e = new_event(EventType::AppControl);
    e.payload = Some(pb::event::Payload::Policy(pe));
    e
}

/// Whether one of the agent's nftables tables exists.
pub fn table_present(name: &str) -> bool {
    crate::response::which("nft")
        && std::process::Command::new("nft")
            .args(["list", "table", "inet", name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
}

#[derive(Default)]
struct Firewall {
    script: String,
    error: String,
}

pub struct Prevention {
    emit: Emitter,
    console: Vec<String>,
    /// The policy as received, and normalized.
    raw: Mutex<Option<pb::PreventionPolicy>>,
    pol: RwLock<pb::PreventionPolicy>,
    /// Read per event, so kept as flags.
    send_process: AtomicBool,
    send_file: AtomicBool,
    send_network: AtomicBool,
    pub exec: Arc<execblock::ExecBlocker>,
    pub scripts: Arc<scriptblock::ScriptBlocker>,
    pub fim: Arc<fim::Fim>,
    pub web: Arc<webrep::WebReputation>,
    pub ips: Arc<ips::Intrusion>,
    pub dev: Arc<devctl::DeviceControl>,
    pub tamper: Arc<tamper::Tamper>,
    firewall: Mutex<Firewall>,
    kick: mpsc::SyncSender<()>,
    kick_rx: Mutex<Option<mpsc::Receiver<()>>>,
}

impl Prevention {
    /// protected are the agent's config and CA, which tamper protection locks.
    pub fn new(state_dir: PathBuf, console: Vec<String>, scan_max_bytes: u64, protected: &[PathBuf]) -> Self {
        let emit = Emitter::default();
        let (kick, kick_rx) = mpsc::sync_channel(1);
        let pol = policy::normalize(Default::default());
        Prevention {
            exec: Arc::new(execblock::ExecBlocker::new(
                emit.clone(),
                scan_max_bytes,
                state_dir.to_string_lossy().into_owned(),
            )),
            scripts: Arc::new(scriptblock::ScriptBlocker::new(emit.clone())),
            fim: Arc::new(fim::Fim::new(emit.clone(), state_dir.join("fim.json"))),
            web: Arc::new(webrep::WebReputation::new(emit.clone(), console.clone())),
            ips: Arc::new(ips::Intrusion::new(emit.clone(), console.clone())),
            dev: Arc::new(devctl::DeviceControl::new(emit.clone(), state_dir.join("devctl.json"))),
            tamper: Arc::new(tamper::Tamper::new(emit.clone(), state_dir, protected)),
            send_process: AtomicBool::new(true),
            send_file: AtomicBool::new(true),
            send_network: AtomicBool::new(true),
            raw: Mutex::new(None),
            pol: RwLock::new(pol),
            emit,
            console,
            firewall: Mutex::default(),
            kick,
            kick_rx: Mutex::new(Some(kick_rx)),
        }
    }

    /// Starts the module threads; events go to sink from now on.
    pub fn start(self: &Arc<Self>, sink: EventSink) {
        self.emit.set(sink);
        self.tamper.check_unclean_exit();
        let spawn = |name: &str, f: Box<dyn FnOnce() + Send>| {
            std::thread::Builder::new()
                .name(name.into())
                .spawn(f)
                .expect("spawn prevention thread");
        };
        let (fim, web, dev, tamper, this) = (
            self.fim.clone(),
            self.web.clone(),
            self.dev.clone(),
            self.tamper.clone(),
            self.clone(),
        );
        spawn("fim", Box::new(move || fim.run()));
        spawn("web-reputation", Box::new(move || web.run()));
        spawn("device-control", Box::new(move || dev.run()));
        spawn("tamper", Box::new(move || tamper.run()));
        spawn("prevention", Box::new(move || this.run()));
    }

    /// Takes the policy from a heartbeat or the cache.
    pub fn set_policy(&self, p: &pb::PreventionPolicy) {
        {
            let mut raw = self.raw.lock().unwrap();
            if raw.as_ref() == Some(p) {
                return;
            }
            *raw = Some(p.clone());
        }
        let n = policy::normalize(p.clone());
        let act = n.activity_monitoring.unwrap_or_default();
        self.send_process.store(act.process, Ordering::Relaxed);
        self.send_file.store(act.file, Ordering::Relaxed);
        self.send_network.store(act.network, Ordering::Relaxed);
        tracing::info!(policy = %p.name, modules = ?modules_on(&n), "prevention policy applied");
        self.fim.set_policy(n.fim.as_ref().unwrap());
        *self.pol.write().unwrap() = n;
        let _ = self.kick.try_send(());
    }

    /// Takes hash, IP and domain IOCs from the detection content.
    pub fn set_content(&self, c: &pb::DetectionContent) {
        let n = self.exec.set_hashes(&c.blocked_sha256);
        tracing::info!(
            hashes = n,
            ips = c.bad_ips.len(),
            domains = c.bad_domains.len(),
            "prevention intel loaded"
        );
        self.web.set_intel(&c.bad_ips, &c.bad_domains);
        let _ = self.kick.try_send(());
    }

    /// Whether activity monitoring sends this event type to the console.
    /// Prevention and detection events are always sent.
    pub fn telemetry(&self, t: EventType) -> bool {
        use EventType::*;
        match t {
            ProcessExec | ProcessExit => self.send_process.load(Ordering::Relaxed),
            FileCreate | FileModify | FileDelete | FileRename | FileAttrib => self.send_file.load(Ordering::Relaxed),
            NetConnect | NetListen | NetAccept => self.send_network.load(Ordering::Relaxed),
            _ => true,
        }
    }

    /// Feeds file events to FIM, connections to web reputation, failed logins
    /// to intrusion prevention and new processes to application control.
    pub fn observe(&self, e: &pb::Event) {
        match &e.payload {
            Some(pb::event::Payload::File(f)) if e.r#type() != EventType::FimChange => {
                self.fim.notify(&f.path);
                self.fim.notify(&f.old_path);
            }
            Some(pb::event::Payload::Network(_)) => self.web.observe(e),
            Some(pb::event::Payload::Auth(_)) => self.ips.observe(e),
            Some(pb::event::Payload::Process(p)) if e.r#type() == EventType::ProcessExec => self.observe_exec(p),
            _ => {}
        }
    }

    /// Reports executions application control lists but does not block
    /// (monitor mode, or blocking that could not start), and stops
    /// interpreters started on a script the script blocker cannot see yet.
    fn observe_exec(&self, pe: &pb::ProcessEvent) {
        let ac = {
            let pol = self.pol.read().unwrap();
            match pol.application_control.as_ref() {
                Some(ac) if ac.enabled => ac.clone(),
                _ => return,
            }
        };
        if let Some((script, rule)) = policy::script_rule(&ac, &pe.exe, &pe.args, &pe.cwd) {
            let dir = script
                .rsplit_once('/')
                .map_or("/", |(d, _)| if d.is_empty() { "/" } else { d });
            if !ac.block {
                tracing::warn!(path = %script, rule, pid = pe.pid, "script from a script folder");
                self.emit
                    .emit(app_control_event("detected", &script, "", &rule, pe.pid));
            } else if !self.scripts.covers(dir) {
                let res = crate::response::kill_process(&pe.pid.to_string(), &pe.exe);
                tracing::warn!(path = %script, rule, pid = pe.pid, ok = res.is_ok(), "script stopped after start");
                if res.is_ok() {
                    self.emit.emit(app_control_event(
                        "blocked",
                        &script,
                        "",
                        &format!("{rule}, stopped after start"),
                        pe.pid,
                    ));
                }
            }
        }
        if ac.block && self.exec.active.load(Ordering::Relaxed) {
            return;
        }
        if let Some(rule) = policy::app_rule(&ac, &pe.exe, &pe.sha256) {
            tracing::warn!(path = %pe.exe, rule, pid = pe.pid, "application control match");
            self.emit
                .emit(app_control_event("detected", &pe.exe, &pe.sha256, &rule, pe.pid));
        }
    }

    fn run(&self) {
        let rx = self.kick_rx.lock().unwrap().take().expect("prevention runs once");
        loop {
            match rx.recv_timeout(FIREWALL_CHECK) {
                Ok(()) => self.apply(),
                Err(mpsc::RecvTimeoutError::Timeout) => self.check_firewall(),
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    }

    fn apply(&self) {
        let pol = self.pol.read().unwrap().clone();
        let ac = pol.application_control.clone().unwrap_or_default();
        let am = pol.anti_malware.unwrap_or_default();
        self.exec
            .set_rules(am.block_known_bad, (ac.enabled && ac.block).then(|| ac.clone()));
        self.exec.reconcile();
        self.scripts.set_policy(&ac);
        self.apply_firewall(pol.firewall.as_ref().unwrap());
        self.web.set_policy(pol.web_reputation.as_ref().unwrap());
        self.ips.set_policy(pol.intrusion_prevention.as_ref().unwrap());
        self.dev.set_policy(pol.device_control.as_ref().unwrap());
    }

    fn apply_firewall(&self, fw: &pb::FirewallPolicy) {
        let mut st = self.firewall.lock().unwrap();
        if !fw.enabled {
            if !st.script.is_empty() || table_present(policy::FIREWALL_TABLE) {
                if let Err(err) = nft(&policy::delete_table(policy::FIREWALL_TABLE)) {
                    st.error = format!("{err:#}");
                    return;
                }
                tracing::info!("host firewall removed");
            }
            *st = Firewall::default();
            return;
        }
        let res = crate::response::console_addrs(&self.console)
            .map_err(|e| format!("{e:#}"))
            .and_then(|addrs| policy::firewall_rules(fw, &addrs));
        let script = match res {
            Ok(s) => s,
            Err(err) => {
                tracing::error!("host firewall not applied: {err}");
                st.error = err;
                return;
            }
        };
        if script == st.script && table_present(policy::FIREWALL_TABLE) {
            return;
        }
        match nft(&script) {
            Ok(()) => {
                *st = Firewall {
                    script,
                    error: String::new(),
                };
                tracing::info!(
                    rules = fw.rules.len(),
                    default_deny_inbound = fw.default_deny_inbound,
                    "host firewall applied"
                );
            }
            Err(err) => {
                tracing::error!("host firewall not applied: {err:#}");
                st.error = format!("{err:#}");
            }
        }
    }

    /// Puts the firewall table back when someone deletes it.
    fn check_firewall(&self) {
        let script = self.firewall.lock().unwrap().script.clone();
        if script.is_empty() || table_present(policy::FIREWALL_TABLE) {
            return;
        }
        if let Err(err) = nft(&script) {
            tracing::error!("restoring host firewall failed: {err:#}");
            return;
        }
        tracing::warn!("host firewall table was removed outside the agent, restored");
        let mut e = new_event(EventType::AgentTamper);
        e.payload = Some(pb::event::Payload::Tamper(pb::TamperEvent {
            action: "firewall_restored".into(),
            detail: format!(
                "nftables table inet {} was deleted and has been re-applied",
                policy::FIREWALL_TABLE
            ),
            pid: std::process::id(),
            ..Default::default()
        }));
        self.emit.emit(e);
    }

    /// What the agent reports in its heartbeat.
    pub fn state(&self) -> pb::PreventionState {
        let (fim_on, fim_files) = self.fim.status();
        let (web_addrs, web_blocking, web_err) = self.web.status();
        let (ips_on, banned, ips_err) = self.ips.status();
        let (dev_on, dev_blocked) = self.dev.status();
        let pol = self.pol.read().unwrap();
        let fw = self.firewall.lock().unwrap();
        let exec_err = self.exec.error.lock().unwrap().clone();
        let script_err = self.scripts.error.lock().unwrap().clone();
        let scripts_on = self.scripts.active.load(Ordering::Relaxed);
        let error = [
            ("exec blocking", exec_err.as_str()),
            ("firewall", fw.error.as_str()),
            ("web reputation", web_err.as_str()),
            ("intrusion prevention", ips_err.as_str()),
            ("script blocking", if scripts_on { "" } else { script_err.as_str() }),
        ]
        .into_iter()
        .find(|(_, e)| !e.is_empty())
        .map(|(m, e)| format!("{m}: {e}"))
        .unwrap_or_default();
        pb::PreventionState {
            exec_blocking: self.exec.active.load(Ordering::Relaxed),
            blocked_hashes: self.exec.len() as u32,
            fim_active: fim_on,
            fim_files: fim_files as u32,
            firewall_applied: !fw.script.is_empty(),
            error,
            policy_name: self
                .raw
                .lock()
                .unwrap()
                .as_ref()
                .map(|p| p.name.clone())
                .unwrap_or_default(),
            realtime_scan: pol.anti_malware.as_ref().is_some_and(|a| a.enabled),
            web_reputation_addrs: web_addrs as u32,
            web_reputation_blocking: web_blocking,
            intrusion_prevention: ips_on,
            banned_addrs: banned as u32,
            device_control: dev_on,
            blocked_devices: dev_blocked as u32,
            app_control: pol.application_control.as_ref().is_some_and(|a| a.enabled),
            script_blocking: scripts_on,
        }
    }
}

/// The modules a policy switches on, for the log.
fn modules_on(p: &pb::PreventionPolicy) -> Vec<&'static str> {
    let am = p.anti_malware.as_ref().unwrap();
    [
        ("anti-malware", am.enabled || am.block_known_bad),
        ("web-reputation", p.web_reputation.as_ref().unwrap().enabled),
        ("file-integrity", p.fim.as_ref().unwrap().enabled),
        ("firewall", p.firewall.as_ref().unwrap().enabled),
        ("intrusion-prevention", p.intrusion_prevention.as_ref().unwrap().enabled),
        ("device-control", p.device_control.as_ref().unwrap().enabled),
        ("application-control", p.application_control.as_ref().unwrap().enabled),
        ("self-protection", p.self_protection.as_ref().unwrap().enabled),
    ]
    .into_iter()
    .filter_map(|(n, on)| on.then_some(n))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_monitoring_filters_telemetry_only() {
        let p = Prevention::new(std::env::temp_dir(), vec![], 0, &[]);
        assert!(p.telemetry(EventType::ProcessExec));
        p.set_policy(&pb::PreventionPolicy {
            activity_monitoring: Some(pb::ActivityMonitoringPolicy {
                process: false,
                file: true,
                network: false,
            }),
            ..Default::default()
        });
        assert!(!p.telemetry(EventType::ProcessExec));
        assert!(!p.telemetry(EventType::NetConnect));
        assert!(p.telemetry(EventType::FileModify));
        assert!(p.telemetry(EventType::ExecBlocked));
        assert!(p.telemetry(EventType::DnsQuery));
    }
}
