//! Periodic heartbeat: reports host and agent health and isolation,
//! receives policy and commands. The last policy is cached so a restart without the console
//! still knows it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use prost::Message;
use tokio::sync::Notify;
use tonic::transport::Channel;

use crate::commands::Commands;
use crate::pb::{self, agent_service_client::AgentServiceClient};
use crate::platform::Platform;
use crate::queue::Queue;

pub const INTERVAL: Duration = Duration::from_secs(15);
const POLICY_KEY: &str = "policy.prevention";
const TAMPER_KEY: &str = "policy.tamper";

pub struct Heartbeat<P: Platform> {
    pub client: AgentServiceClient<Channel>,
    pub platform: Arc<P>,
    pub queue: Arc<Queue>,
    pub sent: Arc<AtomicU64>,
    pub bus_dropped: Arc<AtomicU64>,
    pub started: Instant,
    pub commands: Arc<Commands<P>>,
    /// Sends a heartbeat now instead of at the next tick.
    pub wake: Arc<Notify>,
}

/// The last prevention policy received from the console, if any.
pub fn cached_policy(q: &Queue) -> Option<pb::PreventionPolicy> {
    let raw = q.get(POLICY_KEY).ok()??;
    pb::PreventionPolicy::decode(raw.as_slice()).ok()
}

impl<P: Platform> Heartbeat<P> {
    pub async fn run(mut self) {
        let mut tick = tokio::time::interval(INTERVAL);
        let mut last_version = cached_policy(&self.queue).map(|p| p.version);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = self.wake.notified() => {}
            }
            let mut req = tonic::Request::new(pb::HeartbeatRequest {
                host: Some(self.platform.host_info()),
                stats: Some(self.stats()),
                isolated: self.platform.isolated(),
                ..Default::default()
            });
            req.set_timeout(Duration::from_secs(10));
            let resp = match self.client.heartbeat(req).await {
                Ok(r) => r.into_inner(),
                Err(status) => {
                    tracing::warn!(code = ?status.code(), msg = status.message(), "heartbeat failed");
                    continue;
                }
            };
            if let Some(p) = &resp.prevention {
                if last_version != Some(p.version) {
                    tracing::info!(name = %p.name, version = p.version, "policy received");
                    last_version = Some(p.version);
                }
                let _ = self.queue.put(POLICY_KEY, &p.encode_to_vec());
            }
            if let Some(t) = &resp.tamper {
                let _ = self.queue.put(TAMPER_KEY, &t.encode_to_vec());
            }
            for c in resp.commands {
                self.commands.dispatch(c);
            }
        }
    }

    fn stats(&self) -> pb::AgentStats {
        let u = self.platform.usage();
        let up = self.started.elapsed().as_secs_f64();
        pb::AgentStats {
            events_sent: self.sent.load(Ordering::Relaxed),
            events_dropped: self.queue.dropped() + self.bus_dropped.load(Ordering::Relaxed),
            uptime_seconds: up as u64,
            cpu_percent: if up > 0.0 { 100.0 * u.cpu_seconds / up } else { 0.0 },
            rss_bytes: u.rss_bytes,
        }
    }
}
