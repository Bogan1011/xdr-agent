//! Runs response commands from the console, whether they arrive with a
//! heartbeat or are pushed on the live stream, and reports each result.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;
use tonic::transport::Channel;

use crate::pb::{self, CommandType, agent_service_client::AgentServiceClient};
use crate::platform::Platform;
use crate::scanner::Scanner;
use crate::update::Updater;

/// How many command IDs are remembered, so a command delivered on both the
/// live stream and a heartbeat runs once.
const RECENT: usize = 256;

pub struct Commands<P: Platform> {
    pub client: AgentServiceClient<Channel>,
    pub platform: Arc<P>,
    /// Wakes the heartbeat, so the console sees isolation change at once.
    pub heartbeat: Arc<Notify>,
    pub updater: Arc<Updater>,
    /// Ends the agent so systemd starts the updated binary.
    pub restart: Arc<Notify>,
    pub scanner: Arc<Scanner>,
    seen: Mutex<Recent>,
}

impl<P: Platform> Commands<P> {
    pub fn new(
        client: AgentServiceClient<Channel>,
        platform: Arc<P>,
        heartbeat: Arc<Notify>,
        updater: Arc<Updater>,
        restart: Arc<Notify>,
        scanner: Arc<Scanner>,
    ) -> Self {
        Commands {
            client,
            platform,
            heartbeat,
            updater,
            restart,
            scanner,
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
        let res = if ty == CommandType::UpdateAgent {
            let arg = |k: &str| c.args.get(k).map(String::as_str).unwrap_or("");
            let arch = self.platform.host_info().arch;
            self.updater
                .update(&self.client, &arch, arg("version"), arg("sha256"))
                .await
        } else if ty == CommandType::ScanPath {
            let (s, path) = (self.scanner.clone(), c.args.get("path").cloned().unwrap_or_default());
            match tokio::time::timeout(
                Duration::from_secs(3600),
                tokio::task::spawn_blocking(move || s.scan_path(&path)),
            )
            .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => Err(anyhow::anyhow!("scan panicked: {e}")),
                Err(_) => Err(anyhow::anyhow!("scan did not finish within an hour")),
            }
        } else {
            let platform = self.platform.clone();
            let cmd = c.clone();
            tokio::task::spawn_blocking(move || platform.respond(&cmd))
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("response action panicked: {e}")))
        };
        let restart = ty == CommandType::UpdateAgent && res.as_ref().is_ok_and(|m| !m.starts_with("already running"));
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
        self.report(result).await;
        if restart {
            tracing::info!("restarting into the updated agent");
            self.restart.notify_one();
        }
    }

    async fn report(&self, result: pb::CommandResult) {
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
