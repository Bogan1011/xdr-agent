//! The boundary between the shared core and an operating system. Linux
//! implements it with procfs, netlink and inotify (later eBPF and fanotify);
//! Windows will implement it with ETW, WFP and a minifilter.

use std::sync::Arc;

use crate::bus::EventSink;
use crate::config::Config;
use crate::pb;

/// A telemetry source. `run` blocks on its own thread and returns only on
/// error; the core restarts it after a pause.
pub trait Collector: Send {
    fn name(&self) -> &'static str;
    fn run(&mut self, sink: &EventSink) -> anyhow::Result<()>;
}

/// Resolves the process behind an event to a [`pb::ProcessContext`] with a
/// stable process_guid and its parent.
pub trait ProcessResolver: Send + Sync {
    fn context(&self, event: &pb::Event) -> Option<pb::ProcessContext>;
}

/// CPU seconds used and resident memory of the agent itself.
#[derive(Debug, Default, Clone, Copy)]
pub struct Usage {
    pub cpu_seconds: f64,
    pub rss_bytes: u64,
}

pub trait Platform: Send + Sync + 'static {
    fn host_info(&self) -> pb::HostInfo;
    fn resolver(&self) -> Arc<dyn ProcessResolver>;
    fn collectors(&self, cfg: &Config) -> Vec<Box<dyn Collector>>;
    fn usage(&self) -> Usage;
}
