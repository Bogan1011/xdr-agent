//! The live stream the console uses to reach the agent at once. The agent
//! announces in its first message that it takes response commands here, so
//! the console pushes them the moment they are queued instead of waiting for
//! the next heartbeat. Remote shells and the activity view are not ported
//! yet; a shell request is answered with an error so the console does not
//! hang.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;

use crate::commands::Commands;
use crate::pb::{self, agent_service_client::AgentServiceClient, live_down, live_up};
use crate::platform::Platform;

pub struct Live<P: Platform> {
    pub client: AgentServiceClient<Channel>,
    pub commands: Arc<Commands<P>>,
}

impl<P: Platform> Live<P> {
    /// Keeps the stream open, reconnecting with backoff.
    pub async fn run(mut self) {
        let mut backoff = Duration::from_secs(1);
        loop {
            let start = Instant::now();
            let err = self.serve().await;
            if start.elapsed() > Duration::from_secs(60) {
                backoff = Duration::from_secs(1);
            }
            tracing::debug!(err = ?err, retry_in = ?backoff, "live stream closed, reconnecting");
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    }

    async fn serve(&mut self) -> Result<(), tonic::Status> {
        let (tx, rx) = mpsc::channel(32);
        let hello = pb::LiveUp {
            msg: Some(live_up::Msg::Hello(pb::LiveHello { commands: true })),
        };
        tx.send(hello).await.expect("receiver alive");
        let mut down = self.client.live(ReceiverStream::new(rx)).await?.into_inner();
        tracing::info!("live stream connected");
        while let Some(m) = down.message().await? {
            match m.msg {
                Some(live_down::Msg::Command(c)) => self.commands.dispatch(c),
                Some(live_down::Msg::ShellOpen(o)) => {
                    let exit = pb::ShellExit {
                        session_id: o.session_id,
                        exit_code: -1,
                        error: format!("remote shell is not supported by xdr-agent-rs {} yet", crate::VERSION),
                    };
                    let _ = tx
                        .send(pb::LiveUp {
                            msg: Some(live_up::Msg::ShellExit(exit)),
                        })
                        .await;
                }
                _ => {}
            }
        }
        Ok(())
    }
}
