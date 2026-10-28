//! YARA scanning with the console's detection content. New and changed
//! files and the binaries of new processes are scanned in the background when
//! the anti-malware module is on; the console can also ask for a path to be
//! scanned. Work is queued and dropped when the queue is full, so scanning
//! never slows the collectors down. The engine is boreal, a pure Rust YARA
//! implementation, so the agent stays one static binary.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::bus::{EventSink, new_event};
use crate::pb::{self, EventType};

const MAX_SEEN: usize = 50_000;
const MAX_PATH_FILES: usize = 200_000;
const QUEUE: usize = 512;

/// Moves a matched file away and returns what was done, e.g. "quarantined".
pub type OnMatch = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

struct Req {
    path: String,
    sha256: String,
    pid: u32,
}

pub struct Scanner {
    rules: RwLock<Option<Arc<boreal::Scanner>>>,
    version: RwLock<String>,
    realtime: AtomicBool,
    auto_quarantine: AtomicBool,
    max_bytes: u64,
    skip: Vec<String>,
    sink: EventSink,
    on_match: OnMatch,
    queue: mpsc::Sender<Req>,
    /// File identity → content version it was last scanned with.
    seen: Mutex<HashMap<String, String>>,
}

impl Scanner {
    /// Returns the scanner and the receiver to pass to `run`.
    pub fn new(sink: EventSink, max_bytes: u64, skip: Vec<String>, on_match: OnMatch) -> (Arc<Self>, ScanQueue) {
        let (tx, rx) = mpsc::channel(QUEUE);
        let s = Scanner {
            rules: RwLock::new(None),
            version: RwLock::new(String::new()),
            realtime: AtomicBool::new(false),
            auto_quarantine: AtomicBool::new(false),
            max_bytes,
            skip,
            sink,
            on_match,
            queue: tx,
            seen: Mutex::new(HashMap::new()),
        };
        (Arc::new(s), ScanQueue(rx))
    }

    /// Content version of the loaded rules; empty when there are none.
    pub fn version(&self) -> String {
        self.version.read().unwrap().clone()
    }

    /// Compiles and swaps in a new rule set.
    pub fn update(&self, version: &str, src: &str) -> Result<()> {
        let rules = if src.trim().is_empty() {
            None
        } else {
            let mut c = boreal::Compiler::new();
            c.add_rules_str(src).map_err(|e| anyhow!("compile YARA rules: {e}"))?;
            Some(Arc::new(c.finalize()))
        };
        let n = src.matches("rule ").count();
        *self.rules.write().unwrap() = rules;
        *self.version.write().unwrap() = version.to_string();
        tracing::info!(version, rules = n, "YARA rules loaded");
        Ok(())
    }

    /// Applies the anti-malware module of the prevention policy.
    pub fn set_policy(&self, p: Option<&pb::AntiMalwarePolicy>) {
        self.realtime.store(p.is_some_and(|p| p.enabled), Ordering::Relaxed);
        self.auto_quarantine
            .store(p.is_some_and(|p| p.auto_quarantine), Ordering::Relaxed);
    }

    fn submit(&self, path: &str, sha256: &str, pid: u32) {
        if path.is_empty() || self.rules.read().unwrap().is_none() {
            return;
        }
        let _ = self.queue.try_send(Req {
            path: path.into(),
            sha256: sha256.into(),
            pid,
        });
    }

    /// Queues the file an event introduces, when real-time scanning is on.
    pub fn observe(&self, e: &pb::Event) {
        if !self.realtime.load(Ordering::Relaxed) {
            return;
        }
        let t = e.r#type();
        match &e.payload {
            Some(pb::event::Payload::Process(p)) if t == EventType::ProcessExec => {
                self.submit(&p.exe, &p.sha256, p.pid)
            }
            Some(pb::event::Payload::File(f))
                if matches!(
                    t,
                    EventType::FileModify | EventType::FileRename | EventType::FileCreate | EventType::FileAttrib
                ) =>
            {
                self.submit(&f.path, &f.sha256, 0)
            }
            _ => {}
        }
    }

    fn skipped(&self, path: &str) -> bool {
        let under = |p: &str, root: &str| {
            let root = root.trim_end_matches('/');
            p == root || p.strip_prefix(root).is_some_and(|r| r.starts_with('/'))
        };
        self.skip.iter().any(|s| under(path, s))
            || under(path, "/proc")
            || under(path, "/sys")
            || (under(path, "/dev") && !under(path, "/dev/shm"))
    }

    /// Scans one regular file and emits a match event. With `force` files
    /// already scanned with the current rules are scanned again.
    fn scan_file(&self, path: &str, sha256: &str, pid: u32, force: bool) -> Result<bool> {
        let rules = self.rules.read().unwrap().clone().context("no rules loaded")?;
        if self.skipped(path) {
            bail!("excluded path");
        }
        let mut f = fs::File::open(path)?;
        let md = f.metadata()?;
        if !md.is_file() || md.len() == 0 {
            bail!("not a regular non-empty file");
        }
        if md.len() > self.max_bytes {
            bail!("larger than {} bytes", self.max_bytes);
        }
        let version = self.version();
        let key = if sha256.is_empty() {
            format!("{path}|{}|{}", md.len(), md.mtime_nsec() + md.mtime() * 1_000_000_000)
        } else {
            sha256.to_string()
        };
        if !force && self.seen.lock().unwrap().get(&key) == Some(&version) {
            return Ok(false);
        }
        let mut data = Vec::with_capacity(md.len() as usize);
        (&mut f).take(self.max_bytes).read_to_end(&mut data)?;
        drop(f);
        let hash = hex::encode(Sha256::digest(&data));
        {
            let mut seen = self.seen.lock().unwrap();
            if seen.len() >= MAX_SEEN {
                seen.clear();
            }
            seen.insert(key, version.clone());
            seen.insert(hash.clone(), version);
        }
        let names: Vec<String> = match rules.scan_mem(&data) {
            Ok(r) => r.rules.iter().map(|r| r.name.to_string()).collect(),
            // A timeout or module error still reports what matched so far.
            Err((_, r)) => r.rules.iter().map(|r| r.name.to_string()).collect(),
        };
        if names.is_empty() {
            return Ok(false);
        }
        tracing::warn!(path, rules = ?names, sha256 = %hash, "YARA match");
        let action = if self.auto_quarantine.load(Ordering::Relaxed) {
            (self.on_match)(path).unwrap_or_default()
        } else {
            String::new()
        };
        let mut e = new_event(EventType::YaraMatch);
        e.payload = Some(pb::event::Payload::Yara(pb::YaraMatch {
            path: path.into(),
            sha256: hash,
            rules: names,
            pid,
            size: data.len() as u64,
            action,
        }));
        self.sink.emit(e);
        Ok(true)
    }

    /// Scans a file or a directory tree on request from the console. Blocks.
    pub fn scan_path(&self, root: &str) -> Result<String> {
        if self.rules.read().unwrap().is_none() {
            bail!("no YARA rules loaded yet");
        }
        let root_path = Path::new(root);
        let md = fs::symlink_metadata(root_path).with_context(|| format!("stat {root}"))?;
        let (mut files, mut matches) = (0usize, 0usize);
        let mut stack: Vec<PathBuf> = vec![root_path.to_path_buf()];
        let scan = |p: &Path, files: &mut usize, matches: &mut usize| {
            *files += 1;
            if self.scan_file(&p.to_string_lossy(), "", 0, true).unwrap_or(false) {
                *matches += 1;
            }
        };
        if md.is_file() {
            scan(root_path, &mut files, &mut matches);
        } else {
            while let Some(dir) = stack.pop() {
                let Ok(rd) = fs::read_dir(&dir) else { continue };
                for e in rd.flatten() {
                    let Ok(ft) = e.file_type() else { continue };
                    let p = e.path();
                    if ft.is_dir() {
                        if !self.skipped(&p.to_string_lossy()) {
                            stack.push(p);
                        }
                    } else if ft.is_file() {
                        if files >= MAX_PATH_FILES {
                            stack.clear();
                            break;
                        }
                        scan(&p, &mut files, &mut matches);
                    }
                }
            }
        }
        Ok(format!("scanned {files} files under {root}, {matches} matched"))
    }
}

/// The receiving end of the scan queue; `run` drains it.
pub struct ScanQueue(mpsc::Receiver<Req>);

impl ScanQueue {
    pub async fn run(mut self, scanner: Arc<Scanner>) {
        while let Some(r) = self.0.recv().await {
            let s = scanner.clone();
            let res = tokio::task::spawn_blocking(move || s.scan_file(&r.path, &r.sha256, r.pid, false)).await;
            if let Ok(Err(err)) = res {
                tracing::debug!("scan skipped: {err:#}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
rule Eicar : test {
  strings:
    $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" nocase
  condition:
    $e and filesize < 1KB
}
rule Miner {
  strings:
    $a = "stratum+tcp://"
    $b = /donate-level\s*=\s*\d+/i
  condition:
    all of them
}
"#;

    fn scanner(quarantine: bool) -> (Arc<Scanner>, mpsc::Receiver<pb::Event>) {
        let (sink, rx) = EventSink::channel(16);
        let (s, _q) = Scanner::new(
            sink,
            1 << 20,
            vec!["/skipme".into()],
            Box::new(|_| Some("quarantined".into())),
        );
        s.update("v1", RULES).unwrap();
        s.set_policy(Some(&pb::AntiMalwarePolicy {
            enabled: true,
            auto_quarantine: quarantine,
            ..Default::default()
        }));
        (s, rx)
    }

    #[test]
    fn matches_and_reports() {
        let (s, mut rx) = scanner(true);
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("eicar.txt");
        fs::write(
            &bad,
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .unwrap();
        let good = dir.path().join("ok.txt");
        fs::write(&good, "hello").unwrap();
        assert!(s.scan_file(bad.to_str().unwrap(), "", 0, false).unwrap());
        assert!(!s.scan_file(good.to_str().unwrap(), "", 0, false).unwrap());
        // Already scanned with this version: not again unless forced.
        assert!(!s.scan_file(bad.to_str().unwrap(), "", 0, false).unwrap());
        let e = rx.try_recv().unwrap();
        let Some(pb::event::Payload::Yara(y)) = e.payload else {
            panic!()
        };
        assert_eq!(y.rules, vec!["Eicar".to_string()]);
        assert_eq!(y.action, "quarantined");
        assert_eq!(
            s.scan_path(dir.path().to_str().unwrap()).unwrap(),
            format!("scanned 2 files under {}, 1 matched", dir.path().display())
        );
    }

    #[test]
    fn bad_rules_keep_the_old_set() {
        let (s, _rx) = scanner(false);
        assert!(s.update("v2", "rule broken { condition: nope( }").is_err());
        assert_eq!(s.version(), "v1");
        s.update("v3", "").unwrap();
        assert!(s.scan_path("/tmp").is_err());
    }

    #[test]
    fn skips_pseudo_and_excluded_paths() {
        let (s, _rx) = scanner(false);
        assert!(s.skipped("/proc/1/mem"));
        assert!(s.skipped("/dev/sda"));
        assert!(!s.skipped("/dev/shm/x"));
        assert!(s.skipped("/skipme/a"));
        assert!(!s.skipped("/skipmenot"));
    }
}
