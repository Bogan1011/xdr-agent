//! Durable, priority-aware event queue and key/value cache on SQLite.
//!
//! Contract (docs/architecture.md): events are persisted before they count as
//! accepted; the uploader drains highest priority first and oldest first
//! within a priority; under the byte budget the oldest events of the lowest
//! priority go first, and an event never evicts a higher-priority one.

use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};

pub struct Queue {
    db: Mutex<Inner>,
}

struct Inner {
    conn: Connection,
    bytes: u64,
    budget: u64,
    dropped: u64,
}

/// One queued event: its row id, for [`Queue::ack`], and the encoded protobuf.
pub struct Item {
    pub id: i64,
    pub data: Vec<u8>,
}

impl Queue {
    pub fn open(path: &Path, budget: u64) -> Result<Queue> {
        let conn = Connection::open(path)?;
        Self::init(conn, budget)
    }

    pub fn in_memory(budget: u64) -> Result<Queue> {
        Self::init(Connection::open_in_memory()?, budget)
    }

    fn init(conn: Connection, budget: u64) -> Result<Queue> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS events (
                 id       INTEGER PRIMARY KEY AUTOINCREMENT,
                 priority INTEGER NOT NULL,
                 size     INTEGER NOT NULL,
                 data     BLOB NOT NULL
             );
             CREATE INDEX IF NOT EXISTS events_drain ON events (priority DESC, id);
             CREATE TABLE IF NOT EXISTS kv (
                 key   TEXT PRIMARY KEY,
                 value BLOB NOT NULL
             );",
        )?;
        let bytes: i64 = conn.query_row("SELECT COALESCE(SUM(size), 0) FROM events", [], |r| r.get(0))?;
        Ok(Queue {
            db: Mutex::new(Inner {
                conn,
                bytes: bytes as u64,
                budget,
                dropped: 0,
            }),
        })
    }

    /// Persists events, given as (priority, encoded event), in one transaction.
    /// Returns how many were stored; the rest were dropped for lack of room.
    pub fn push(&self, events: &[(i32, Vec<u8>)]) -> Result<usize> {
        let mut g = self.db.lock().unwrap();
        let inner = &mut *g;
        let tx = inner.conn.transaction()?;
        let mut stored = 0;
        for (prio, data) in events {
            let size = data.len() as u64;
            while inner.bytes + size > inner.budget {
                // Oldest row of the lowest priority not above this event's.
                let victim: Option<(i64, i64)> = tx
                    .query_row(
                        "SELECT id, size FROM events WHERE priority <= ?1 ORDER BY priority, id LIMIT 1",
                        [prio],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                let Some((id, vsize)) = victim else { break };
                tx.execute("DELETE FROM events WHERE id = ?1", [id])?;
                inner.bytes -= vsize as u64;
                inner.dropped += 1;
            }
            if inner.bytes + size > inner.budget {
                inner.dropped += 1;
                continue;
            }
            tx.execute(
                "INSERT INTO events (priority, size, data) VALUES (?1, ?2, ?3)",
                params![prio, size as i64, data],
            )?;
            inner.bytes += size;
            stored += 1;
        }
        tx.commit()?;
        Ok(stored)
    }

    /// The next events to upload, highest priority first.
    pub fn peek(&self, max: usize) -> Result<Vec<Item>> {
        let g = self.db.lock().unwrap();
        let mut st = g
            .conn
            .prepare_cached("SELECT id, data FROM events ORDER BY priority DESC, id LIMIT ?1")?;
        let rows = st.query_map([max as i64], |r| {
            Ok(Item {
                id: r.get(0)?,
                data: r.get(1)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Removes events the server acknowledged.
    pub fn ack(&self, ids: &[i64]) -> Result<()> {
        let mut g = self.db.lock().unwrap();
        let inner = &mut *g;
        let tx = inner.conn.transaction()?;
        for id in ids {
            let size: Option<i64> = tx
                .query_row("DELETE FROM events WHERE id = ?1 RETURNING size", [id], |r| r.get(0))
                .optional()?;
            inner.bytes -= size.unwrap_or(0) as u64;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn len(&self) -> Result<u64> {
        let g = self.db.lock().unwrap();
        let n: i64 = g.conn.query_row("SELECT count(*) FROM events", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    pub fn bytes(&self) -> u64 {
        self.db.lock().unwrap().bytes
    }

    /// Events evicted or refused since start.
    pub fn dropped(&self) -> u64 {
        self.db.lock().unwrap().dropped
    }

    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let g = self.db.lock().unwrap();
        Ok(g.conn
            .query_row("SELECT value FROM kv WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let g = self.db.lock().unwrap();
        g.conn.execute(
            "INSERT INTO kv (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOW: i32 = 1;
    const NORMAL: i32 = 2;
    const CRITICAL: i32 = 4;

    fn ev(tag: u8) -> Vec<u8> {
        vec![tag; 10]
    }

    #[test]
    fn drains_by_priority_then_age() {
        let q = Queue::in_memory(1 << 20).unwrap();
        q.push(&[(LOW, ev(1)), (CRITICAL, ev(2)), (NORMAL, ev(3)), (CRITICAL, ev(4))])
            .unwrap();
        let order: Vec<u8> = q.peek(10).unwrap().iter().map(|i| i.data[0]).collect();
        assert_eq!(order, vec![2, 4, 3, 1]);
        let ids: Vec<i64> = q.peek(2).unwrap().iter().map(|i| i.id).collect();
        q.ack(&ids).unwrap();
        assert_eq!(q.len().unwrap(), 2);
        assert_eq!(q.bytes(), 20);
    }

    #[test]
    fn evicts_low_before_critical() {
        let q = Queue::in_memory(30).unwrap();
        q.push(&[(LOW, ev(1)), (CRITICAL, ev(2)), (LOW, ev(3))]).unwrap();
        // Full: a critical event evicts the oldest low one.
        q.push(&[(CRITICAL, ev(4))]).unwrap();
        let tags: Vec<u8> = q.peek(10).unwrap().iter().map(|i| i.data[0]).collect();
        assert_eq!(tags, vec![2, 4, 3]);
        // A low event may only replace another low one.
        q.push(&[(LOW, ev(5))]).unwrap();
        let tags: Vec<u8> = q.peek(10).unwrap().iter().map(|i| i.data[0]).collect();
        assert_eq!(tags, vec![2, 4, 5]);
        q.push(&[(CRITICAL, ev(6))]).unwrap();
        // Only critical events left: a new low event is refused.
        assert_eq!(q.push(&[(LOW, ev(7))]).unwrap(), 0);
        let tags: Vec<u8> = q.peek(10).unwrap().iter().map(|i| i.data[0]).collect();
        assert_eq!(tags, vec![2, 4, 6]);
        assert_eq!(q.dropped(), 4);
    }

    #[test]
    fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("queue.db");
        {
            let q = Queue::open(&p, 1 << 20).unwrap();
            q.push(&[(NORMAL, ev(9))]).unwrap();
            q.put("policy", b"v1").unwrap();
        }
        let q = Queue::open(&p, 1 << 20).unwrap();
        assert_eq!(q.peek(1).unwrap()[0].data, ev(9));
        assert_eq!(q.bytes(), 10);
        assert_eq!(q.get("policy").unwrap().as_deref(), Some(&b"v1"[..]));
    }
}
