//! Container and Kubernetes context: which container a process runs in, from
//! its cgroup, with the name, image and pod read from the runtime's state
//! (Docker, containerd/CRI, CRI-O, Podman). Also a collector that reports
//! containers starting and stopping.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::Result;
use xdr_core::bus::{EventSink, new_event};
use xdr_core::pb::{self, EventType};
use xdr_core::platform::Collector;

/// (runtime, container id, pod uid) from /proc/<pid>/cgroup text.
pub fn parse_cgroup(text: &str) -> Option<(&'static str, String, String)> {
    for line in text.lines() {
        let path = line.splitn(3, ':').nth(2).unwrap_or("");
        let pod = path
            .split('/')
            .find_map(|seg| {
                let s = seg.strip_suffix(".slice").unwrap_or(seg);
                let i = s.rfind("pod")?;
                let uid = &s[i + 3..];
                (uid.len() >= 32).then(|| uid.replace('_', "-"))
            })
            .unwrap_or_default();
        for seg in path.rsplit('/') {
            let s = seg.strip_suffix(".scope").unwrap_or(seg);
            let (runtime, id) = if let Some(id) = s.strip_prefix("docker-") {
                ("docker", id)
            } else if let Some(id) = s.strip_prefix("cri-containerd-") {
                ("containerd", id)
            } else if let Some(id) = s.strip_prefix("crio-") {
                ("cri-o", id)
            } else if let Some(id) = s.strip_prefix("libpod-") {
                ("podman", id)
            } else if s.len() == 64 && path.contains("/docker/") {
                ("docker", s)
            } else if s.len() == 64 && path.contains("kubepods") {
                ("containerd", s)
            } else {
                continue;
            };
            if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Some((runtime, id.to_string(), pod));
            }
        }
    }
    None
}

/// The container pid runs in, or None on the host.
pub fn of_pid(pid: u32) -> Option<pb::ContainerContext> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let (runtime, id, pod_uid) = parse_cgroup(&text)?;
    static CACHE: OnceLock<Mutex<HashMap<String, pb::ContainerContext>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(c) = cache.lock().unwrap().get(&id) {
        return Some(c.clone());
    }
    let mut c = pb::ContainerContext {
        container_id: id.clone(),
        runtime: runtime.into(),
        pod_uid,
        ..Default::default()
    };
    describe(&mut c);
    let mut m = cache.lock().unwrap();
    if m.len() > 2048 {
        m.clear();
    }
    // Keep retrying until the runtime has written its state.
    if !c.name.is_empty() || !c.image.is_empty() {
        m.insert(id, c.clone());
    }
    Some(c)
}

/// Fills name, image and pod from the runtime's state files.
fn describe(c: &mut pb::ContainerContext) {
    let id = c.container_id.clone();
    let read = |p: String| -> Option<serde_json::Value> { serde_json::from_slice(&std::fs::read(p).ok()?).ok() };
    let s = |v: &serde_json::Value, ptr: &str| v.pointer(ptr).and_then(|x| x.as_str()).unwrap_or("").to_string();
    if let Some(v) = read(format!("/var/lib/docker/containers/{id}/config.v2.json")) {
        c.name = s(&v, "/Name").trim_start_matches('/').to_string();
        c.image = s(&v, "/Config/Image");
        c.image_id = s(&v, "/Image");
        let labels = |k: &str| s(&v, &format!("/Config/Labels/{}", k.replace('/', "~1")));
        c.pod_name = labels("io.kubernetes.pod.name");
        c.pod_namespace = labels("io.kubernetes.pod.namespace");
        return;
    }
    // containerd (k8s.io, moby or default namespaces) and CRI-O keep an OCI
    // spec with CRI annotations.
    let specs = [
        format!("/run/containerd/io.containerd.runtime.v2.task/k8s.io/{id}/config.json"),
        format!("/run/containerd/io.containerd.runtime.v2.task/moby/{id}/config.json"),
        format!("/run/containerd/io.containerd.runtime.v2.task/default/{id}/config.json"),
        format!("/run/containers/storage/overlay-containers/{id}/userdata/config.json"),
        format!("/var/lib/containers/storage/overlay-containers/{id}/userdata/config.json"),
    ];
    for p in specs {
        let Some(v) = read(p) else { continue };
        let a = |k: &str| s(&v, &format!("/annotations/{}", k.replace('/', "~1")));
        c.name = [
            a("io.kubernetes.cri.container-name"),
            a("io.kubernetes.container.name"),
            a("io.podman.annotations.name"),
        ]
        .into_iter()
        .find(|x| !x.is_empty())
        .unwrap_or_default();
        c.image = [a("io.kubernetes.cri.image-name"), a("io.kubernetes.cri-o.ImageName")]
            .into_iter()
            .find(|x| !x.is_empty())
            .unwrap_or_default();
        c.pod_name = [a("io.kubernetes.cri.sandbox-name"), a("io.kubernetes.pod.name")]
            .into_iter()
            .find(|x| !x.is_empty())
            .unwrap_or_default();
        c.pod_namespace = [
            a("io.kubernetes.cri.sandbox-namespace"),
            a("io.kubernetes.pod.namespace"),
        ]
        .into_iter()
        .find(|x| !x.is_empty())
        .unwrap_or_default();
        if c.name.is_empty() {
            c.name = s(&v, "/hostname");
        }
        return;
    }
}

/// Reports containers starting and stopping, seen as new and vanished
/// container IDs among running processes.
pub struct Containers {
    pub interval: Duration,
}

impl Collector for Containers {
    fn name(&self) -> &'static str {
        "container"
    }

    fn run(&mut self, sink: &EventSink) -> Result<()> {
        let mut known: HashMap<String, pb::ContainerContext> = HashMap::new();
        let mut first = true;
        loop {
            let mut now: HashMap<String, (u32, pb::ContainerContext)> = HashMap::new();
            if let Ok(rd) = std::fs::read_dir("/proc") {
                for ent in rd.flatten() {
                    let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                        continue;
                    };
                    if let Some(c) = of_pid(pid) {
                        now.entry(c.container_id.clone()).or_insert((pid, c));
                    }
                }
            }
            let ids: HashSet<String> = now.keys().cloned().collect();
            for (id, (pid, c)) in &now {
                if !known.contains_key(id) && !first {
                    let mut e = new_event(EventType::ContainerStart);
                    e.container = Some(c.clone());
                    // The first process seen gives the context (entrypoint).
                    e.metadata.insert("pid".into(), pid.to_string());
                    sink.emit(e);
                }
            }
            for (id, c) in &known {
                if !ids.contains(id) {
                    let mut e = new_event(EventType::ContainerStop);
                    e.container = Some(c.clone());
                    sink.emit(e);
                }
            }
            known = now.into_iter().map(|(k, (_, c))| (k, c)).collect();
            first = false;
            std::thread::sleep(self.interval);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "4f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8";

    #[test]
    fn parses_runtimes() {
        let docker = format!("0::/system.slice/docker-{ID}.scope\n");
        assert_eq!(parse_cgroup(&docker), Some(("docker", ID.into(), String::new())));
        let v1 = format!("12:memory:/docker/{ID}\n");
        assert_eq!(parse_cgroup(&v1).unwrap().0, "docker");
        let k8s = format!(
            "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1b2c3d4e_5f60_7182_93a4_b5c6d7e8f901.slice/cri-containerd-{ID}.scope\n"
        );
        assert_eq!(
            parse_cgroup(&k8s),
            Some(("containerd", ID.into(), "1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901".into()))
        );
        let crio = format!("0::/kubepods/besteffort/pod1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901/crio-{ID}\n");
        assert_eq!(parse_cgroup(&crio).unwrap().0, "cri-o");
        assert_eq!(parse_cgroup("0::/user.slice/user-1000.slice/session-3.scope\n"), None);
    }
}
