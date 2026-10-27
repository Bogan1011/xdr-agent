//! Linux adapters for the XDR agent core: netlink process events, inotify
//! file events, /proc/net connections and procfs process identity. eBPF CO-RE
//! and fanotify prevention are ported next.

pub mod auth;
pub mod container;
pub mod credaccess;
pub mod dns;
pub mod file;
pub mod host;
pub mod inventory;
pub mod kernel;
pub mod memory;
pub mod network;
pub mod persistence;
pub mod process;
pub mod procfs;
pub mod resolver;

use std::sync::Arc;

use xdr_core::config::Config;
use xdr_core::pb;
use xdr_core::platform::{Collector, Platform, ProcessResolver, Usage};

pub struct Linux {
    hasher: Arc<procfs::Hasher>,
    resolver: Arc<resolver::Resolver>,
}

impl Default for Linux {
    fn default() -> Self {
        let hasher = Arc::new(procfs::Hasher::new(50_000));
        Linux {
            resolver: Arc::new(resolver::Resolver::new(hasher.clone())),
            hasher,
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
        vec![
            Box::new(process::Process::new(self.hasher.clone())),
            Box::new(file::File {
                paths: cfg.file_paths.clone(),
                exclude: cfg.file_exclude.clone(),
                max_watches: cfg.max_file_watches,
                hasher: self.hasher.clone(),
            }),
            Box::new(network::Network {
                interval: cfg.network_interval,
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
        ]
    }

    fn usage(&self) -> Usage {
        host::usage()
    }
}
