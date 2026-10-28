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

    /// The container the event's process runs in; None on the host.
    fn container(&self, _event: &pb::Event) -> Option<pb::ContainerContext> {
        None
    }
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
    /// Runs a response command from the console and returns the result
    /// message. It blocks, so the core calls it off the async runtime.
    fn respond(&self, c: &pb::AgentCommand) -> anyhow::Result<String>;
    /// True while the host's network is isolated by the agent.
    fn isolated(&self) -> bool;
    /// Re-applies enforcement that must survive a restart, such as isolation.
    fn restore(&self);
    /// The console's live view of the host. Blocks briefly.
    fn activity(&self) -> pb::Activity;
    /// Starts a remote shell; its output and end go to `out`. Blocks briefly.
    fn shell_open(&self, req: pb::ShellOpen, out: tokio::sync::mpsc::Sender<pb::LiveUp>);
    fn shell_input(&self, id: &str, data: &[u8]);
    fn shell_resize(&self, id: &str, cols: u32, rows: u32);
    fn shell_close(&self, id: &str);
    fn shell_close_all(&self);
}
