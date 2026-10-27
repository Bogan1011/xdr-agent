//! Kernel and low-level signals, polled from /proc: modules loaded and
//! unloaded, security-relevant sysctls changing, the kernel taint flags and
//! file systems mounted and unmounted. The first scan is the baseline.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use anyhow::Result;
use xdr_core::bus::{EventSink, new_event};
use xdr_core::pb::{self, EventType};
use xdr_core::platform::Collector;

/// Sysctls an attacker changes to weaken the host or to persist.
const SYSCTLS: &[&str] = &[
    "kernel/randomize_va_space",
    "kernel/kptr_restrict",
    "kernel/dmesg_restrict",
    "kernel/yama/ptrace_scope",
    "kernel/modules_disabled",
    "kernel/kexec_load_disabled",
    "kernel/unprivileged_bpf_disabled",
    "kernel/perf_event_paranoid",
    "kernel/core_pattern",
    "kernel/sysrq",
    "kernel/modprobe",
    "fs/suid_dumpable",
    "fs/protected_symlinks",
    "fs/protected_hardlinks",
    "net/ipv4/ip_forward",
    "net/ipv4/conf/all/accept_redirects",
    "net/ipv4/conf/all/send_redirects",
    "net/ipv4/conf/all/rp_filter",
    "net/ipv6/conf/all/forwarding",
];

/// Mount points that container runtimes and the desktop churn through.
const NOISY_MOUNTS: &[&str] = &[
    "/run/docker",
    "/var/lib/docker",
    "/run/containerd",
    "/var/lib/containerd",
    "/var/lib/kubelet",
    "/run/netns",
    "/run/user",
    "/run/credentials",
    "/var/lib/containers",
    "/run/containers",
    "/snap",
    "/proc/sys/fs/binfmt_misc",
];
const NOISY_FS: &[&str] = &["nsfs", "overlay", "shm", "fuse.portal", "autofs", "binfmt_misc"];

pub struct Kernel {
    pub interval: Duration,
}

/// name → "size refcount state" from /proc/modules.
pub fn parse_modules(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let name = f.first()?.to_string();
            let taint = f.get(6).copied().unwrap_or("");
            Some((
                name,
                format!("size {} {} {}", f.get(1).unwrap_or(&""), f.get(4).unwrap_or(&""), taint)
                    .trim()
                    .into(),
            ))
        })
        .collect()
}

/// Mount point → "fstype source" for the mounts worth reporting.
pub fn parse_mounts(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let (left, right) = l.split_once(" - ")?;
            let point = left.split_whitespace().nth(4)?.replace("\\040", " ");
            let mut r = right.split_whitespace();
            let fstype = r.next()?;
            let source = r.next().unwrap_or("");
            let noisy = NOISY_FS.contains(&fstype)
                || NOISY_MOUNTS
                    .iter()
                    .any(|m| point == *m || point.starts_with(&format!("{m}/")));
            (!noisy).then(|| (point, format!("{fstype} {source}")))
        })
        .collect()
}

/// Decodes /proc/sys/kernel/tainted into flag letters, as in `dmesg`.
pub fn taint_flags(v: u64) -> String {
    const F: &[(u8, char, &str)] = &[
        (0, 'P', "proprietary module"),
        (1, 'F', "module force loaded"),
        (4, 'R', "module force unloaded"),
        (7, 'D', "kernel died (oops)"),
        (12, 'O', "out-of-tree module"),
        (13, 'E', "unsigned module"),
        (15, 'K', "live patched"),
    ];
    F.iter()
        .filter(|(bit, _, _)| v & (1 << bit) != 0)
        .map(|(_, c, d)| format!("{c} ({d})"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn emit(sink: &EventSink, t: EventType, k: pb::KernelEvent) {
    let mut e = new_event(t);
    e.payload = Some(pb::event::Payload::Kernel(k));
    sink.emit(e);
}

fn diff_maps(
    sink: &EventSink,
    t: EventType,
    old: &BTreeMap<String, String>,
    new: &BTreeMap<String, String>,
    added: &str,
    removed: &str,
) {
    for (k, v) in new {
        if !old.contains_key(k) {
            emit(
                sink,
                t,
                pb::KernelEvent {
                    action: added.into(),
                    name: k.clone(),
                    new_value: v.clone(),
                    ..Default::default()
                },
            );
        }
    }
    for (k, v) in old {
        if !new.contains_key(k) {
            emit(
                sink,
                t,
                pb::KernelEvent {
                    action: removed.into(),
                    name: k.clone(),
                    old_value: v.clone(),
                    ..Default::default()
                },
            );
        }
    }
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

impl Collector for Kernel {
    fn name(&self) -> &'static str {
        "kernel"
    }

    fn run(&mut self, sink: &EventSink) -> Result<()> {
        let mut modules = parse_modules(&read("/proc/modules"));
        let mut mounts = parse_mounts(&read("/proc/self/mountinfo"));
        let mut sysctls: HashMap<&str, String> =
            SYSCTLS.iter().map(|s| (*s, read(&format!("/proc/sys/{s}")))).collect();
        let mut tainted: u64 = read("/proc/sys/kernel/tainted").parse().unwrap_or(0);
        loop {
            std::thread::sleep(self.interval);
            let m = parse_modules(&read("/proc/modules"));
            diff_maps(
                sink,
                EventType::KernelModule,
                &modules,
                &m,
                "module_loaded",
                "module_unloaded",
            );
            modules = m;

            let m = parse_mounts(&read("/proc/self/mountinfo"));
            diff_maps(sink, EventType::KernelChange, &mounts, &m, "mounted", "unmounted");
            mounts = m;

            for (name, old) in sysctls.iter_mut() {
                let now = read(&format!("/proc/sys/{name}"));
                if now != *old {
                    emit(
                        sink,
                        EventType::KernelChange,
                        pb::KernelEvent {
                            action: "sysctl_changed".into(),
                            name: name.replace('/', "."),
                            old_value: std::mem::replace(old, now.clone()),
                            new_value: now,
                            ..Default::default()
                        },
                    );
                }
            }

            let t: u64 = read("/proc/sys/kernel/tainted").parse().unwrap_or(0);
            if t != tainted {
                emit(
                    sink,
                    EventType::KernelChange,
                    pb::KernelEvent {
                        action: "kernel_tainted".into(),
                        name: "kernel.tainted".into(),
                        old_value: tainted.to_string(),
                        new_value: t.to_string(),
                        detail: taint_flags(t & !tainted),
                        ..Default::default()
                    },
                );
                tainted = t;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modules_and_mounts() {
        let m = parse_modules(
            "nf_tables 352256 3 nft_chain_nat, Live 0x0000000000000000\nrootkit 16384 0 - Live 0x0 (OE)\n",
        );
        assert_eq!(m["rootkit"], "size 16384 Live (OE)");
        let mounts = parse_mounts(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 0:50 / /var/lib/docker/overlay2/x/merged rw - overlay overlay rw\n3 1 0:4 / /run/netns/cni-1 rw - nsfs nsfs rw\n4 1 8:17 / /mnt/usb rw - vfat /dev/sdb1 rw\n",
        );
        assert_eq!(mounts.keys().collect::<Vec<_>>(), ["/", "/mnt/usb"]);
        assert_eq!(mounts["/mnt/usb"], "vfat /dev/sdb1");
        assert_eq!(
            taint_flags(1 << 12 | 1 << 13),
            "O (out-of-tree module), E (unsigned module)"
        );
    }
}
