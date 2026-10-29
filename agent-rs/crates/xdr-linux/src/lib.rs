//! Linux adapters for the XDR agent core: netlink process events, eBPF or
//! inotify file events, /proc/net connections and procfs process identity.
//! Response actions live in [`response`], policy enforcement in
//! [`prevention`].

pub mod activity;
pub mod auth;
pub mod container;
pub mod credaccess;
pub mod dns;
pub mod ebpf;
pub mod file;
pub mod host;
pub mod inventory;
pub mod kernel;
pub mod memory;
pub mod migrate;
pub mod network;
pub mod persistence;
pub mod prevention;
pub mod process;
pub mod procfs;
pub mod resolver;
pub mod response;
pub mod shell;

use std::sync::Arc;

use xdr_core::config::Config;
use xdr_core::pb;
use xdr_core::platform::{Collector, Platform, ProcessResolver, Usage};

pub struct Linux {
    hasher: Arc<procfs::Hasher>,
    resolver: Arc<resolver::Resolver>,
    responder: response::Responder,
    sampler: std::sync::Mutex<activity::Sampler>,
    shells: shell::Shells,
    /// Loaded eBPF programs; collectors() takes their ring buffers.
    probes: std::sync::Mutex<Option<ebpf::Probes>>,
    prevention: Arc<prevention::Prevention>,
}

impl Linux {
    pub fn new(cfg: &Config) -> Self {
        let hasher = Arc::new(procfs::Hasher::new(50_000));
        let console = vec![cfg.server.clone(), cfg.enroll_server.clone()];
        Linux {
            prevention: Arc::new(prevention::Prevention::new(
                cfg.state_dir.clone(),
                console.clone(),
                cfg.scan_max_bytes,
                &protected_files(cfg),
            )),
            resolver: Arc::new(resolver::Resolver::new(hasher.clone())),
            hasher,
            responder: response::Responder {
                state_dir: cfg.state_dir.clone(),
                console,
            },
            sampler: Default::default(),
            shells: shell::Shells::new(cfg.disable_remote_shell),
            probes: std::sync::Mutex::new(if cfg.ebpf == "off" {
                tracing::info!("eBPF turned off in the agent config");
                None
            } else {
                ebpf::load()
                    .map_err(|e| tracing::warn!("eBPF unavailable, using inotify and /proc collectors: {e:#}"))
                    .ok()
            }),
        }
    }
}

impl Platform for Linux {
    fn host_info(&self) -> pb::HostInfo {
        host::host_info()
    }

    fn resolver(&self) -> Arc<dyn ProcessResolver> {
        self.resolver.clone()
    }

    fn collectors(&self, cfg: &Config) -> Vec<Box<dyn Collector>> {
        let (files_ebpf, net_ebpf) = match self.probes.lock().unwrap().as_mut() {
            Some(p) => (p.files.take(), p.net.take()),
            None => (None, None),
        };
        let file: Box<dyn Collector> = match files_ebpf {
            Some(ring) => Box::new(ebpf::EbpfFile {
                ring: Some(ring),
                paths: cfg.file_paths.clone(),
                exclude: cfg.file_exclude.clone(),
                hasher: self.hasher.clone(),
            }),
            None => Box::new(file::File {
                paths: cfg.file_paths.clone(),
                exclude: cfg.file_exclude.clone(),
                max_watches: cfg.max_file_watches,
                hasher: self.hasher.clone(),
            }),
        };
        let tcp_ebpf = net_ebpf.is_some();
        let mut out: Vec<Box<dyn Collector>> = Vec::new();
        if tcp_ebpf {
            out.push(Box::new(ebpf::EbpfNetwork { ring: net_ebpf }));
        }
        let rest: Vec<Box<dyn Collector>> = vec![
            Box::new(process::Process::new(self.hasher.clone())),
            file,
            Box::new(network::Network {
                interval: cfg.network_interval,
                skip_tcp_connections: tcp_ebpf,
            }),
            Box::new(auth::Auth),
            Box::new(dns::Dns),
            Box::new(memory::Memory {
                interval: std::time::Duration::from_secs(30),
            }),
            Box::new(credaccess::CredentialAccess),
            Box::new(kernel::Kernel {
                interval: std::time::Duration::from_secs(15),
            }),
            Box::new(inventory::Inventory {
                interval: std::time::Duration::from_secs(6 * 3600),
                state: cfg.state_path("inventory.json"),
            }),
            Box::new(container::Containers {
                interval: std::time::Duration::from_secs(10),
            }),
            Box::new(persistence::Persistence {
                hasher: self.hasher.clone(),
            }),
        ];
        out.extend(rest);
        out
    }

    fn usage(&self) -> Usage {
        host::usage()
    }

    fn respond(&self, c: &pb::AgentCommand) -> anyhow::Result<String> {
        match c.r#type() {
            pb::CommandType::FimRebaseline => self.prevention.fim.rebaseline(),
            pb::CommandType::Uninstall => {
                self.prevention.tamper.release();
                self.responder.respond(c)
            }
            _ => self.responder.respond(c),
        }
    }

    fn isolated(&self) -> bool {
        self.responder.isolated()
    }

    fn activity(&self) -> pb::Activity {
        let users = self.shells.users();
        self.sampler.lock().unwrap().snapshot(&users)
    }

    fn shell_open(&self, req: pb::ShellOpen, out: tokio::sync::mpsc::Sender<pb::LiveUp>) {
        self.shells.open(req, out);
    }

    fn shell_input(&self, id: &str, data: &[u8]) {
        self.shells.input(id, data);
    }

    fn shell_resize(&self, id: &str, cols: u32, rows: u32) {
        self.shells.resize(id, cols, rows);
    }

    fn shell_close(&self, id: &str) {
        self.shells.close(id);
    }

    fn shell_close_all(&self) {
        self.shells.close_all();
    }

    fn restore(&self) {
        migrate::cleanup_go_agent();
        self.responder.restore_isolation();
    }

    fn start_prevention(&self, sink: xdr_core::bus::EventSink) {
        self.prevention.start(sink);
    }

    fn set_policy(&self, p: &pb::PreventionPolicy) {
        self.prevention.set_policy(p);
    }

    fn set_content(&self, c: &pb::DetectionContent) {
        self.prevention.set_content(c);
    }

    fn set_tamper(&self, t: &pb::TamperPolicy) {
        self.prevention.tamper.set_policy(t);
    }

    fn prevention_state(&self) -> Option<pb::PreventionState> {
        Some(self.prevention.state())
    }

    fn tamper_protected(&self) -> bool {
        self.prevention.tamper.applied()
    }

    fn observe(&self, e: &pb::Event) {
        self.prevention.observe(e);
    }

    fn telemetry(&self, t: pb::EventType) -> bool {
        self.prevention.telemetry(t)
    }

    fn stop_allowed(&self) -> bool {
        self.prevention.tamper.stop_allowed()
    }

    fn stopping(&self) {
        self.prevention.tamper.clear_running_marker();
    }
}

/// The agent's config and CA, which tamper protection makes immutable.
pub fn protected_files(cfg: &Config) -> Vec<std::path::PathBuf> {
    let mut out = vec![cfg.ca_file.clone()];
    if !cfg.config_path.as_os_str().is_empty() {
        out.push(cfg.config_path.clone());
    }
    out
}
