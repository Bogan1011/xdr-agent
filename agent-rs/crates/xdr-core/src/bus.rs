//! Local event bus: collectors → normalizer → (local consumers, durable queue).
//!
//! Local detection and prevention subscribe to the bus, not the queue, so they
//! keep working while the console is unreachable.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prost::Message;
use tokio::sync::{Notify, broadcast, mpsc};

use crate::pb::{self, EventType, Priority};
use crate::platform::ProcessResolver;
use crate::queue::Queue;

/// Handed to collectors. Emitting never blocks: when the in-memory channel
/// is full the event is dropped and counted.
#[derive(Clone)]
pub struct EventSink {
    tx: mpsc::Sender<pb::Event>,
    dropped: Arc<AtomicU64>,
}

impl EventSink {
    pub fn emit(&self, e: pb::Event) {
        if self.tx.try_send(e).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A new event with a random id and the current time.
pub fn new_event(t: EventType) -> pb::Event {
    pb::Event {
        id: uuid::Uuid::new_v4().simple().to_string(),
        timestamp_unix_nano: now_nanos(),
        r#type: t as i32,
        ..Default::default()
    }
}

pub fn now_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i64)
}

pub struct Bus {
    sink: EventSink,
    rx: Option<mpsc::Receiver<pb::Event>>,
    local: broadcast::Sender<Arc<pb::Event>>,
}

impl Bus {
    pub fn new(capacity: usize) -> Bus {
        let (tx, rx) = mpsc::channel(capacity);
        let (local, _) = broadcast::channel(capacity);
        Bus {
            sink: EventSink {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            rx: Some(rx),
            local,
        }
    }

    pub fn sink(&self) -> EventSink {
        self.sink.clone()
    }

    /// Events dropped before reaching the queue.
    pub fn dropped(&self) -> Arc<AtomicU64> {
        self.sink.dropped.clone()
    }

    /// Normalized events for local consumers (detection, prevention).
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<pb::Event>> {
        self.local.subscribe()
    }

    /// Normalizes events and writes them to the queue in small transactions.
    pub async fn run(
        mut self,
        agent_id: String,
        resolver: Arc<dyn ProcessResolver>,
        queue: Arc<Queue>,
        uploaded: Arc<Notify>,
    ) {
        let mut rx = self.rx.take().expect("bus runs once");
        let mut batch: Vec<pb::Event> = Vec::with_capacity(256);
        loop {
            let Some(first) = rx.recv().await else { return };
            batch.push(first);
            // Collect what arrives within a short window into one transaction.
            let deadline = tokio::time::sleep(Duration::from_millis(200));
            tokio::pin!(deadline);
            while batch.len() < 1000 {
                tokio::select! {
                    e = rx.recv() => match e { Some(e) => batch.push(e), None => break },
                    _ = &mut deadline => break,
                }
            }
            let res = resolver.clone();
            let id = agent_id.clone();
            let mut events = std::mem::take(&mut batch);
            // Resolving reads /proc and hashes files: keep it off the reactor.
            let encoded = tokio::task::spawn_blocking(move || {
                for e in &mut events {
                    envelope(e, &id, res.as_ref());
                }
                let enc: Vec<(i32, Vec<u8>)> = events.iter().map(|e| (e.priority, e.encode_to_vec())).collect();
                (events, enc)
            })
            .await;
            let Ok((events, enc)) = encoded else { continue };
            for e in events {
                let _ = self.local.send(Arc::new(e));
            }
            let q = queue.clone();
            match tokio::task::spawn_blocking(move || q.push(&enc)).await {
                Ok(Ok(_)) => uploaded.notify_one(),
                Ok(Err(err)) => tracing::error!(%err, "writing events to the local queue failed"),
                Err(_) => {}
            }
        }
    }
}

/// Fills the schema_version 1 envelope.
pub fn envelope(e: &mut pb::Event, agent_id: &str, resolver: &dyn ProcessResolver) {
    if e.schema_version != 0 {
        return;
    }
    e.schema_version = crate::SCHEMA_VERSION;
    e.agent_id = agent_id.to_string();
    if e.priority == 0 {
        e.priority = priority_for(e.r#type()) as i32;
    }
    if e.process_context.is_none() {
        e.process_context = resolver.context(e);
    }
}

/// Same ranking as the Go agent (docs/architecture.md, "Priority").
pub fn priority_for(t: EventType) -> Priority {
    use EventType::*;
    match t {
        ExecBlocked | YaraMatch | AgentTamper => Priority::Critical,
        FimChange | WebReputation | Intrusion | DeviceControl | AppControl => Priority::High,
        FileCreate | FileModify | FileDelete | FileRename | FileAttrib | NetListen => Priority::Low,
        _ => Priority::Normal,
    }
}

/// The process that caused an event, from its payload.
pub fn actor_pid(e: &pb::Event) -> u32 {
    use pb::event::Payload;
    match &e.payload {
        Some(Payload::Process(p)) => p.pid,
        Some(Payload::File(f)) => f.pid,
        Some(Payload::Network(n)) => n.pid,
        Some(Payload::Yara(y)) => y.pid,
        Some(Payload::Tamper(t)) => t.pid,
        Some(Payload::Policy(p)) => p.pid,
        Some(Payload::Shell(s)) => s.pid,
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed;
    impl ProcessResolver for Fixed {
        fn context(&self, e: &pb::Event) -> Option<pb::ProcessContext> {
            Some(pb::ProcessContext {
                pid: actor_pid(e),
                process_guid: "g".into(),
                ..Default::default()
            })
        }
    }

    #[test]
    fn fills_envelope() {
        let mut e = new_event(EventType::FileModify);
        e.payload = Some(pb::event::Payload::File(pb::FileEvent {
            pid: 42,
            ..Default::default()
        }));
        envelope(&mut e, "a1", &Fixed);
        assert_eq!(e.schema_version, 1);
        assert_eq!(e.agent_id, "a1");
        assert_eq!(e.priority(), Priority::Low);
        assert_eq!(e.process_context.unwrap().pid, 42);
        assert_eq!(priority_for(EventType::ExecBlocked), Priority::Critical);
        assert_eq!(priority_for(EventType::ProcessExec), Priority::Normal);
    }
}
