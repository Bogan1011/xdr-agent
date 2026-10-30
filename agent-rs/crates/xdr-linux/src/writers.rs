//! The last process seen changing each persistence path, from the eBPF file
//! hooks, so persistence events (found with inotify, which does not know the
//! writer) can name the process that made the change.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a writer stays attributable to its path.
const KEEP: Duration = Duration::from_secs(30);
/// Entries kept before old ones are pruned.
const MAX: usize = 4096;
/// The eBPF ring is read as soon as it has data, but its reader runs on
/// another thread: a lookup waits this long for the record to arrive.
const WAIT: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, PartialEq)]
pub struct Writer {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe: String,
}

#[derive(Default)]
pub struct Writers {
    m: Mutex<HashMap<String, (Writer, Instant)>>,
}

impl Writers {
    pub fn record(&self, path: &str, w: Writer) {
        let mut m = self.m.lock().unwrap();
        if m.len() >= MAX {
            let now = Instant::now();
            m.retain(|_, (_, t)| now.duration_since(*t) < KEEP);
            if m.len() >= MAX {
                m.clear();
            }
        }
        m.insert(path.to_string(), (w, Instant::now()));
    }

    /// The process that last changed path within KEEP, waiting briefly for
    /// a record still on its way.
    pub fn lookup(&self, path: &str) -> Option<Writer> {
        self.lookup_within(path, WAIT)
    }

    fn lookup_within(&self, path: &str, wait: Duration) -> Option<Writer> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some((w, t)) = self.m.lock().unwrap().get(path)
                && t.elapsed() < KEEP
            {
                return Some(w.clone());
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembers_last_writer() {
        let w = Writers::default();
        let wr = |pid| Writer {
            pid,
            uid: 0,
            comm: "bash".into(),
            exe: "/usr/bin/bash".into(),
        };
        w.record("/etc/cron.d/x", wr(1));
        w.record("/etc/cron.d/x", wr(2));
        assert_eq!(w.lookup_within("/etc/cron.d/x", Duration::ZERO).unwrap().pid, 2);
        assert!(w.lookup_within("/etc/cron.d/y", Duration::ZERO).is_none());
        for i in 0..MAX + 1 {
            w.record(&format!("/p{i}"), wr(3));
        }
        assert!(w.m.lock().unwrap().len() <= MAX);
    }
}
