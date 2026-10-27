//! Linux adapters for the XDR agent core: netlink process events, inotify
//! file events, /proc/net connections and procfs process identity. eBPF CO-RE
//! and fanotify prevention are ported next.

pub mod file;
pub mod host;
pub mod network;
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
        ]
    }

    fn usage(&self) -> Usage {
        host::usage()
    }
}
