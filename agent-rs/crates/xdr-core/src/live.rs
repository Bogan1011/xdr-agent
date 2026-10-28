//! The live stream the console uses to reach the agent at once. The agent
//! announces in its first message that it takes response commands here, so
//! the console pushes them the moment they are queued instead of waiting for
//! the next heartbeat. It also carries remote shells and the live view,
//! which the platform implements.

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
        let (tx, rx) = mpsc::channel(256);
        let hello = pb::LiveUp {
            msg: Some(live_up::Msg::Hello(pb::LiveHello { commands: true })),
        };
        tx.send(hello).await.expect("receiver alive");
        let mut down = self.client.live(ReceiverStream::new(rx)).await?.into_inner();
        tracing::info!("live stream connected");
        let res = self.handle(&mut down, &tx).await;
        // The console forgets its shells when the stream drops, so end them too.
        self.commands.platform.shell_close_all();
        res
    }

    async fn handle(
        &self,
        down: &mut tonic::Streaming<pb::LiveDown>,
        tx: &mpsc::Sender<pb::LiveUp>,
    ) -> Result<(), tonic::Status> {
        let platform = &self.commands.platform;
        while let Some(m) = down.message().await? {
            match m.msg {
                Some(live_down::Msg::Command(c)) => self.commands.dispatch(c),
                Some(live_down::Msg::ShellOpen(o)) => {
                    let (p, tx) = (platform.clone(), tx.clone());
                    tokio::task::spawn_blocking(move || p.shell_open(o, tx));
                }
                Some(live_down::Msg::ShellInput(d)) => platform.shell_input(&d.session_id, &d.data),
                Some(live_down::Msg::ShellResize(r)) => platform.shell_resize(&r.session_id, r.cols, r.rows),
                Some(live_down::Msg::ShellClose(c)) => platform.shell_close(&c.session_id),
                Some(live_down::Msg::Activity(req)) => {
                    let (p, tx) = (platform.clone(), tx.clone());
                    tokio::spawn(async move {
                        let Ok(mut act) = tokio::task::spawn_blocking(move || p.activity()).await else {
                            return;
                        };
                        act.request_id = req.request_id;
                        let _ = tx
                            .send(pb::LiveUp {
                                msg: Some(live_up::Msg::Activity(act)),
                            })
                            .await;
                    });
                }
                None => {}
            }
        }
        Ok(())
    }
}
