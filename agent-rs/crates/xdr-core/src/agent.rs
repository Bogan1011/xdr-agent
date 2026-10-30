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
    let queue = Arc::new(Queue::open(&cfg.state_path("queue.db"), cfg.queue_bytes, cfg.queue_disk_reserve_bytes)?);
    tracing::info!(queued = queue.len()?, bytes = queue.bytes(), "local queue opened");
    if let Some(p) = heartbeat::cached_policy(&queue) {
        tracing::info!(name = %p.name, version = p.version, "last known policy loaded from cache");
    }
    platform.restore();
    // Prevention starts before enrollment, from the cached policy, so it
    // applies at boot even when the console is unreachable.
    let bus = Bus::new(20_000);
    platform.start_prevention(bus.sink().named("prevention"));
    if let Some(p) = heartbeat::cached_policy(&queue) {
        platform.set_policy(&p);
    }
    if let Some(c) = heartbeat::cached_content(&queue) {
        platform.set_content(&c);
    }
    // Prevention reads /proc and may kill, so it observes on its own thread.
    let mut prevention = bus.subscribe();
    let observer = platform.clone();
    std::thread::Builder::new()
        .name("prevention-observer".into())
        .spawn(move || {
            use tokio::sync::broadcast::error::RecvError;
            loop {
                match prevention.blocking_recv() {
                    Ok(e) => {
                        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| observer.observe(&e))).is_err() {
                            tracing::error!(event = e.id, "prevention panicked on an event, skipped it");
                        }
                    }
                    Err(RecvError::Lagged(n)) => tracing::debug!(skipped = n, "prevention lagged behind the bus"),
                    Err(RecvError::Closed) => break,
                }
            }
        })?;
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
    supervise("scanner-observer", async move {
        use tokio::sync::broadcast::error::RecvError;
        loop {
            match local.recv().await {
                Ok(e) => observer.observe(&e),
                Err(RecvError::Lagged(n)) => tracing::debug!(skipped = n, "scanner lagged behind the bus"),
                Err(RecvError::Closed) => break,
            }
        }
    });
    supervise("yara-scan-queue", scan_queue.run(scanner.clone()));
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
    let filter = platform.clone();
    supervise(
        "bus",
        bus.run(
            id.agent_id.clone(),
            platform.resolver(),
            queue.clone(),
            wake.clone(),
            Arc::new(move |t| filter.telemetry(t)),
        ),
    );
    supervise(
        "uploader",
        Uploader {
            client: client.clone(),
            queue: queue.clone(),
            batch_size: cfg.batch_size,
            wake,
            sent: sent.clone(),
        }
        .run(),
    );
    supervise(
        "heartbeat",
        Heartbeat {
            client,
            platform: platform.clone(),
            queue,
            sent,
            bus_dropped,
            started,
            commands: commands.clone(),
            wake: hb_wake,
        }
        .run(),
    );
    supervise(
        "live",
        Live {
            client: transport::live_client(&cfg, &id)?,
            commands,
        }
        .run(),
    );
    if cfg.max_memory_bytes > 0 {
        tokio::spawn(memory_watchdog(platform.clone(), cfg.max_memory_bytes));
    }

    tokio::select! {
        _ = shutdown_signal(platform.clone()) => {
            tracing::info!("stopping");
            platform.stopping();
        }
        // Exit non-zero so systemd restarts the unit into the new binary
        // whatever its Restart= setting.
        _ = restart.notified() => std::process::exit(3),
    }
    Ok(())
}

/// Exit code when a core task died: systemd restarts the agent, which is
/// better than running on without uploads, heartbeats or the live stream.
const EXIT_CORE_TASK: i32 = 70;
/// Exit code when the memory watchdog fired.
const EXIT_MEMORY: i32 = 71;

/// Runs a task the agent cannot work without. These loop forever, so if one
/// ever ends, by a panic or a bug, the agent exits for systemd to restart it.
fn supervise<F>(name: &'static str, task: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let handle = tokio::spawn(task);
    tokio::spawn(async move {
        match handle.await {
            Err(err) if err.is_panic() => tracing::error!(task = name, "core task panicked, restarting the agent"),
            _ => tracing::error!(task = name, "core task ended, restarting the agent"),
        }
        std::process::exit(EXIT_CORE_TASK);
    });
}

/// Restarts the agent when its resident memory stays above max for
/// LIMIT_CHECKS samples in a row. Child processes such as remote shells are
/// not counted.
async fn memory_watchdog<P: Platform>(platform: Arc<P>, max: u64) {
    const EVERY: Duration = Duration::from_secs(20);
    const LIMIT_CHECKS: u32 = 3;
    let mut over = 0;
    loop {
        tokio::time::sleep(EVERY).await;
        let rss = platform.usage().rss_bytes;
        over = if rss > max { over + 1 } else { 0 };
        if over == 1 {
            tracing::warn!(rss_mb = rss >> 20, max_mb = max >> 20, "agent memory above its limit");
        }
        if over >= LIMIT_CHECKS {
            tracing::error!(
                rss_mb = rss >> 20,
                max_mb = max >> 20,
                "agent memory stayed above its limit, restarting"
            );
            std::process::exit(EXIT_MEMORY);
        }
    }
}

/// Runs a blocking collector on its own thread and restarts it when it fails
/// or panics, so one broken source does not take the agent down.
fn spawn_collector(mut c: Box<dyn Collector>, sink: EventSink) {
    std::thread::Builder::new()
        .name(format!("collector-{}", c.name()))
        .spawn(move || {
            loop {
                tracing::info!(collector = c.name(), "collector starting");
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.run(&sink))) {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        tracing::error!(collector = c.name(), "collector stopped, restarting in 10s: {err:#}")
                    }
                    Err(_) => tracing::error!(collector = c.name(), "collector panicked, restarting in 10s"),
                }
                std::thread::sleep(Duration::from_secs(10));
            }
        })
        .expect("spawn collector thread");
}

/// Returns on SIGINT, or on SIGTERM unless tamper protection refuses it.
async fn shutdown_signal<P: Platform>(platform: Arc<P>) {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return,
            _ = term.recv() => {}
        }
        let p = platform.clone();
        if tokio::task::spawn_blocking(move || p.stop_allowed())
            .await
            .unwrap_or(true)
        {
            return;
        }
    }
}
