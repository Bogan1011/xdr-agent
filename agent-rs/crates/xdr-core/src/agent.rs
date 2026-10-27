//! Wires the core together: identity, bus, queue, uploader, heartbeat, the
//! live stream, response commands and the platform's collectors.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::Notify;

use crate::bus::{Bus, EventSink};
use crate::commands::Commands;
use crate::config::Config;
use crate::heartbeat::{self, Heartbeat};
use crate::live::Live;
use crate::platform::{Collector, Platform};
use crate::queue::Queue;
use crate::uploader::Uploader;
use crate::{identity, transport};

pub async fn run<P: Platform>(cfg: Config, platform: P) -> Result<()> {
    let started = Instant::now();
    let platform = Arc::new(platform);
    std::fs::create_dir_all(&cfg.state_dir)?;
    let queue = Arc::new(Queue::open(&cfg.state_path("queue.db"), cfg.queue_bytes)?);
    tracing::info!(queued = queue.len()?, bytes = queue.bytes(), "local queue opened");
    if let Some(p) = heartbeat::cached_policy(&queue) {
        tracing::info!(name = %p.name, version = p.version, "last known policy loaded from cache");
    }
    platform.restore();

    let id = loop {
        match identity::load_or_enroll(&cfg, platform.host_info()).await {
            Ok(id) => break id,
            Err(err) => {
                tracing::error!("enrollment failed, retrying in 30s: {err:#}");
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    };
    tracing::info!(agent_id = %id.agent_id, "agent identity loaded");
    let client = transport::agent_client(&cfg, &id)?;
    let hb_wake = Arc::new(Notify::new());
    let commands = Arc::new(Commands::new(client.clone(), platform.clone(), hb_wake.clone()));

    let bus = Bus::new(20_000);
    let wake = Arc::new(Notify::new());
    let sent = Arc::new(AtomicU64::new(0));
    let bus_dropped = bus.dropped();
    for c in platform.collectors(&cfg) {
        spawn_collector(c, bus.sink());
    }
    tokio::spawn(bus.run(id.agent_id.clone(), platform.resolver(), queue.clone(), wake.clone()));
    tokio::spawn(
        Uploader {
            client: client.clone(),
            queue: queue.clone(),
            batch_size: cfg.batch_size,
            wake,
            sent: sent.clone(),
        }
        .run(),
    );
    tokio::spawn(
        Heartbeat {
            client,
            platform,
            queue,
            sent,
            bus_dropped,
            started,
            commands: commands.clone(),
            wake: hb_wake,
        }
        .run(),
    );
    tokio::spawn(
        Live {
            client: transport::live_client(&cfg, &id)?,
            commands,
        }
        .run(),
    );

    shutdown_signal().await;
    tracing::info!("stopping");
    Ok(())
}

/// Runs a blocking collector on its own thread and restarts it when it fails,
/// so one broken source does not take the agent down.
fn spawn_collector(mut c: Box<dyn Collector>, sink: EventSink) {
    std::thread::Builder::new()
        .name(format!("collector-{}", c.name()))
        .spawn(move || {
            loop {
                tracing::info!(collector = c.name(), "collector starting");
                if let Err(err) = c.run(&sink) {
                    tracing::error!(collector = c.name(), "collector stopped, restarting in 10s: {err:#}");
                }
                std::thread::sleep(Duration::from_secs(10));
            }
        })
        .expect("spawn collector thread");
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
