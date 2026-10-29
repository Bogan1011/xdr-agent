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
use crate::scanner::Scanner;
use crate::update::Updater;
use crate::uploader::Uploader;
use crate::{identity, pb, transport};

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
    let updater = Arc::new(Updater::new(&cfg.state_dir));
    updater.check();

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
    let restart = Arc::new(Notify::new());
    let bus = Bus::new(20_000);
    let quarantine = platform.clone();
    let (scanner, scan_queue) = Scanner::new(
        bus.sink().named("yara"),
        cfg.scan_max_bytes,
        vec![cfg.state_dir.to_string_lossy().into_owned()],
        Box::new(move |path| {
            let c = pb::AgentCommand {
                r#type: pb::CommandType::QuarantineFile as i32,
                args: [("path".to_string(), path.to_string())].into(),
                ..Default::default()
            };
            match quarantine.respond(&c) {
                Ok(_) => Some("quarantined".into()),
                Err(err) => {
                    tracing::warn!(path, "auto-quarantine failed: {err:#}");
                    None
                }
            }
        }),
    );
    if let Some(c) = heartbeat::cached_content(&queue)
        && let Err(err) = scanner.update(&c.version, &c.yara_rules)
    {
        tracing::warn!("cached detection content rejected: {err:#}");
    }
    scanner.set_policy(
        heartbeat::cached_policy(&queue)
            .as_ref()
            .and_then(|p| p.anti_malware.as_ref()),
    );
    let mut local = bus.subscribe();
    let observer = scanner.clone();
    tokio::spawn(async move {
        use tokio::sync::broadcast::error::RecvError;
        loop {
            match local.recv().await {
                Ok(e) => observer.observe(&e),
                Err(RecvError::Lagged(n)) => tracing::debug!(skipped = n, "scanner lagged behind the bus"),
                Err(RecvError::Closed) => break,
            }
        }
    });
    tokio::spawn(scan_queue.run(scanner.clone()));
    let commands = Arc::new(Commands::new(
        client.clone(),
        platform.clone(),
        hb_wake.clone(),
        updater,
        restart.clone(),
        scanner,
    ));

    let wake = Arc::new(Notify::new());
    let sent = Arc::new(AtomicU64::new(0));
    let bus_dropped = bus.dropped();
    for c in platform.collectors(&cfg) {
        let sink = bus.sink().named(c.name());
        spawn_collector(c, sink);
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

    tokio::select! {
        _ = shutdown_signal() => tracing::info!("stopping"),
        // Exit non-zero so systemd restarts the unit into the new binary
        // whatever its Restart= setting.
        _ = restart.notified() => std::process::exit(3),
    }
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
