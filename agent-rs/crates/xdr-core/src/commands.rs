//! Runs response commands from the console, whether they arrive with a
//! heartbeat or are pushed on the live stream, and reports each result.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;
use tonic::transport::Channel;

use crate::pb::{self, CommandType, agent_service_client::AgentServiceClient};
use crate::platform::Platform;

/// How many command IDs are remembered, so a command delivered on both the
/// live stream and a heartbeat runs once.
const RECENT: usize = 256;

pub struct Commands<P: Platform> {
    pub client: AgentServiceClient<Channel>,
    pub platform: Arc<P>,
    /// Wakes the heartbeat, so the console sees isolation change at once.
    pub heartbeat: Arc<Notify>,
    seen: Mutex<Recent>,
}

impl<P: Platform> Commands<P> {
    pub fn new(client: AgentServiceClient<Channel>, platform: Arc<P>, heartbeat: Arc<Notify>) -> Self {
        Commands {
            client,
            platform,
            heartbeat,
            seen: Mutex::new(Recent::default()),
        }
    }

    /// Starts a command in the background unless it already ran.
    pub fn dispatch(self: &Arc<Self>, c: pb::AgentCommand) {
        if !c.id.is_empty() && !self.seen.lock().unwrap().first(&c.id) {
            tracing::info!(command_id = %c.id, "ignoring a command that already ran");
            return;
        }
        let this = self.clone();
        tokio::spawn(async move { this.run(c).await });
    }

    async fn run(&self, c: pb::AgentCommand) {
        let ty = c.r#type();
        tracing::warn!(command_id = %c.id, r#type = ty.as_str_name(), args = ?c.args, "response action requested by the console");
        let platform = self.platform.clone();
        let cmd = c.clone();
        let res = tokio::task::spawn_blocking(move || platform.respond(&cmd))
            .await
            .unwrap_or_else(|e| Err(anyhow::anyhow!("response action panicked: {e}")));
        let result = match res {
            Ok(message) => {
                tracing::info!(command_id = %c.id, result = %message, "response action done");
                pb::CommandResult {
                    command_id: c.id,
                    success: true,
                    message,
                }
            }
            Err(err) => {
                tracing::error!(command_id = %c.id, "response action failed: {err:#}");
                pb::CommandResult {
                    command_id: c.id,
                    success: false,
                    message: format!("{err:#}"),
                }
            }
        };
        if matches!(ty, CommandType::IsolateHost | CommandType::UnisolateHost) {
            self.heartbeat.notify_one();
        }
        let mut client = self.client.clone();
        for i in 1..=5u64 {
            match client.report_command_result(result.clone()).await {
                Ok(_) => return,
                Err(status) if status.code() == tonic::Code::NotFound => return,
                Err(status) => tracing::warn!(msg = status.message(), "reporting command result failed"),
            }
            tokio::time::sleep(Duration::from_secs(5 * i)).await;
        }
    }
}

#[derive(Default)]
struct Recent {
    order: VecDeque<String>,
    set: HashSet<String>,
}

impl Recent {
    /// Records an ID and reports whether it is new.
    fn first(&mut self, id: &str) -> bool {
        if !self.set.insert(id.to_string()) {
            return false;
        }
        self.order.push_back(id.to_string());
        if self.order.len() > RECENT
            && let Some(old) = self.order.pop_front()
        {
            self.set.remove(&old);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_ids_run_once_and_age_out() {
        let mut r = Recent::default();
        assert!(r.first("a"));
        assert!(!r.first("a"));
        for i in 0..RECENT {
            assert!(r.first(&i.to_string()));
        }
        assert!(r.first("a"), "oldest id is forgotten after RECENT others");
        assert_eq!(r.order.len(), RECENT);
    }
}
