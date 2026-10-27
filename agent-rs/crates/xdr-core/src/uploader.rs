//! Drains the durable queue to the console. A batch is deleted only after
//! SendEvents succeeds; failures back off from 1 s to 60 s with jitter.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use prost::Message;
use tokio::sync::Notify;
use tonic::transport::Channel;

use crate::pb::{self, agent_service_client::AgentServiceClient};
use crate::queue::Queue;

pub struct Uploader {
    pub client: AgentServiceClient<Channel>,
    pub queue: Arc<Queue>,
    pub batch_size: usize,
    pub wake: Arc<Notify>,
    pub sent: Arc<AtomicU64>,
}

impl Uploader {
    pub async fn run(mut self) {
        let mut backoff = Duration::from_secs(1);
        loop {
            let q = self.queue.clone();
            let n = self.batch_size;
            let items = match tokio::task::spawn_blocking(move || q.peek(n)).await {
                Ok(Ok(items)) => items,
                Ok(Err(err)) => {
                    tracing::error!(%err, "reading the local queue failed");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                Err(_) => continue,
            };
            if items.is_empty() {
                // Woken by new events, or poll in case a notification was missed.
                let _ = tokio::time::timeout(Duration::from_secs(1), self.wake.notified()).await;
                continue;
            }
            let ids: Vec<i64> = items.iter().map(|i| i.id).collect();
            let events = items
                .iter()
                .filter_map(|i| pb::Event::decode(i.data.as_slice()).ok())
                .collect();
            let mut req = tonic::Request::new(pb::EventBatch { events });
            req.set_timeout(Duration::from_secs(20));
            match self.client.send_events(req).await {
                Ok(_) => {
                    self.sent.fetch_add(ids.len() as u64, Ordering::Relaxed);
                    let q = self.queue.clone();
                    if let Ok(Err(err)) = tokio::task::spawn_blocking(move || q.ack(&ids)).await {
                        tracing::error!(%err, "removing sent events from the local queue failed");
                    }
                    backoff = Duration::from_secs(1);
                }
                Err(status) => {
                    let wait = jitter(backoff);
                    tracing::warn!(code = ?status.code(), msg = status.message(), batch = ids.len(),
                        retry_in = ?wait, "sending events failed");
                    tokio::time::sleep(wait).await;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            }
        }
    }
}

/// Spreads retries of many agents over 75 % to 125 % of the backoff.
fn jitter(d: Duration) -> Duration {
    let r = (crate::bus::now_nanos() as u64 % 500) as f64 / 1000.0;
    d.mul_f64(0.75 + r)
}
