//! Device control for USB mass storage. Block deauthorizes the device in
//! sysfs, which detaches its drivers before a disk appears. Read-only lets the
//! disk appear, marks its block devices read-only (BLKROSET) and remounts
//! filesystems already mounted from them read-only. New devices are seen
//! through kernel uevents; a periodic rescan catches anything missed. Blocked
//! devices are kept on disk (the Go agent's devctl.json) so they are released
//! when the policy allows them again, even after a restart.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, mpsc};
use std::time::Duration;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use xdr_core::bus::new_event;
use xdr_core::pb::{self, EventType};

use super::{Emitter, policy};

const USB_DEVICES: &str = "/sys/bus/usb/devices";
const MASS_STORAGE: &str = "08";
const RESCAN: Duration = Duration::from_secs(10);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct UsbDevice {
    name: String,
    /// vendor:product
    id: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    serial: String,
}

impl UsbDevice {
    fn key(&self) -> String {
        format!("{}|{}|{}", self.name, self.id, self.serial)
    }

    fn describe(&self) -> String {
        let mut s = format!("USB storage {}", self.id);
        if !self.product.is_empty() {
            s += &format!(" ({})", self.product);
        }
        if !self.serial.is_empty() {
            s += &format!(" serial {}", self.serial);
        }
        s
    }
}

pub type SetReadOnly = fn(&str, bool) -> Result<()>;

struct Inner {
    pol: Option<pb::DeviceControlPolicy>,
    /// sysfs name to the device we deauthorized.
    blocked: BTreeMap<String, UsbDevice>,
    /// Storage devices already reported.
    seen: HashSet<String>,
    /// Block devices we made read-only.
    ro: HashSet<String>,
}

pub struct DeviceControl {
    emit: Emitter,
    file: PathBuf,
    root: PathBuf,
    set_read_only: SetReadOnly,
    inner: Mutex<Inner>,
    tx: mpsc::SyncSender<()>,
    rx: Mutex<Option<mpsc::Receiver<()>>>,
}

fn read_sys(p: impl AsRef<Path>) -> String {
    std::fs::read_to_string(p)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

impl DeviceControl {
    pub fn new(emit: Emitter, file: PathBuf) -> Self {
        Self::with_root(emit, file, USB_DEVICES.into(), set_block_read_only)
    }

    fn with_root(emit: Emitter, file: PathBuf, root: PathBuf, set_read_only: SetReadOnly) -> Self {
        let blocked = std::fs::read(&file)
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or_default();
        let (tx, rx) = mpsc::sync_channel(1);
        DeviceControl {
            emit,
            file,
            root,
            set_read_only,
            inner: Mutex::new(Inner {
                pol: None,
                blocked,
                seen: HashSet::new(),
                ro: HashSet::new(),
            }),
            tx,
            rx: Mutex::new(Some(rx)),
        }
    }

    pub fn set_policy(&self, p: &pb::DeviceControlPolicy) {
        let mut i = self.inner.lock().unwrap();
        if i.pol.as_ref() != Some(p) {
            i.pol = Some(p.clone());
            let _ = self.tx.try_send(());
        }
    }

    pub fn run(&self) {
        let rx = self.rx.lock().unwrap().take().expect("device control runs once");
        let tx = self.tx.clone();
        std::thread::Builder::new()
            .name("uevents".into())
            .spawn(move || {
                if let Err(err) = uevents(&tx) {
                    tracing::warn!("uevent socket unavailable, device control rescans every 10s: {err:#}");
                }
            })
            .expect("spawn uevent thread");
        loop {
            self.scan();
            if let Err(mpsc::RecvTimeoutError::Disconnected) = rx.recv_timeout(RESCAN) {
                return;
            }
        }
    }

    /// USB devices with a mass storage interface.
    fn storage_devices(&self) -> BTreeMap<String, UsbDevice> {
        let mut out = BTreeMap::new();
        let Ok(rd) = std::fs::read_dir(&self.root) else {
            return out;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            // Interfaces are named like 1-1:1.0; root hubs like usb1.
            if name.contains(':') || name.starts_with("usb") {
                continue;
            }
            let dir = self.root.join(&name);
            let storage = std::fs::read_dir(&dir).into_iter().flatten().flatten().any(|i| {
                let n = i.file_name().to_string_lossy().into_owned();
                n.starts_with(&format!("{name}:")) && read_sys(i.path().join("bInterfaceClass")) == MASS_STORAGE
            });
            if !storage {
                continue;
            }
            let id = format!("{}:{}", read_sys(dir.join("idVendor")), read_sys(dir.join("idProduct"))).to_lowercase();
            out.insert(
                name.clone(),
                UsbDevice {
                    product: read_sys(dir.join("product")),
                    serial: read_sys(dir.join("serial")),
                    name,
                    id,
                },
            );
        }
        out
    }

    fn authorize(&self, name: &str, on: bool) -> std::io::Result<()> {
        std::fs::write(self.root.join(name).join("authorized"), if on { "1" } else { "0" })
    }

    fn scan(&self) {
        let mut i = self.inner.lock().unwrap();
        let pol = i.pol.clone().unwrap_or_default();
        let enabled = pol.enabled;
        let block = enabled && pol.usb_storage == policy::USB_BLOCK;
        let read_only = enabled && pol.usb_storage == policy::USB_READ_ONLY;
        let allowed: HashSet<&str> = pol.allowed_devices.iter().map(String::as_str).collect();
        let mut changed = false;

        // Release what the policy no longer blocks, or what was unplugged.
        for (name, dev) in i.blocked.clone() {
            let dir = self.root.join(&name);
            let cur = format!("{}:{}", read_sys(dir.join("idVendor")), read_sys(dir.join("idProduct"))).to_lowercase();
            let gone = cur != dev.id;
            if gone || !block || allowed.contains(dev.id.as_str()) {
                if !gone {
                    if let Err(err) = self.authorize(&name, true) {
                        tracing::warn!(device = %name, "re-authorizing USB device failed: {err}");
                        continue;
                    }
                    tracing::info!(device = %dev.describe(), "USB storage device allowed again");
                }
                i.blocked.remove(&name);
                changed = true;
            }
        }

        let present = self.storage_devices();
        let mut want_ro = HashSet::new();
        for (name, dev) in &present {
            if i.blocked.contains_key(name) {
                continue;
            }
            let listed = allowed.contains(dev.id.as_str());
            if read_only && !listed {
                let disks = self.block_devices(name);
                let mut fresh = false;
                for b in &disks {
                    want_ro.insert(b.clone());
                    if i.ro.contains(b) {
                        continue;
                    }
                    if let Err(err) = (self.set_read_only)(b, true) {
                        tracing::error!(device = %dev.describe(), disk = %b, "making USB storage read-only failed: {err:#}");
                        continue;
                    }
                    i.ro.insert(b.clone());
                    fresh = true;
                }
                if fresh && i.seen.insert(dev.key()) {
                    tracing::warn!(device = %dev.describe(), ?disks, "USB storage device made read-only");
                    self.event("read_only", dev);
                }
                continue;
            }
            if block && !listed {
                if read_sys(self.root.join(name).join("authorized")) == "0" {
                    continue;
                }
                if let Err(err) = self.authorize(name, false) {
                    tracing::error!(device = %dev.describe(), "blocking USB storage failed: {err}");
                    continue;
                }
                i.blocked.insert(name.clone(), dev.clone());
                i.seen.insert(dev.key());
                changed = true;
                tracing::warn!(device = %dev.describe(), "USB storage device blocked");
                self.event("blocked", dev);
                continue;
            }
            if enabled && i.seen.insert(dev.key()) {
                self.event("connected", dev);
            }
        }
        // Make writable again what is unplugged or no longer read-only.
        for b in i.ro.clone() {
            if !want_ro.contains(&b) {
                let _ = (self.set_read_only)(&b, false);
                i.ro.remove(&b);
            }
        }
        let blocked: HashSet<String> = i.blocked.keys().cloned().collect();
        i.seen.retain(|k| {
            let name = k.split('|').next().unwrap_or("");
            present.contains_key(name) || blocked.contains(name)
        });
        if changed && let Ok(raw) = serde_json::to_vec(&i.blocked) {
            let _ = super::fim::write_private(&self.file, &raw);
        }
    }

    /// The disks and partitions (sdb, sdb1...) under a USB storage device.
    fn block_devices(&self, name: &str) -> Vec<String> {
        // <dev>/<dev>:*/host*/target*/*/block/<disk>/<disk>N
        let mut out = Vec::new();
        let dir = self.root.join(name);
        let kids = |p: &Path, pre: &str| -> Vec<PathBuf> {
            std::fs::read_dir(p)
                .into_iter()
                .flatten()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(pre))
                .map(|e| e.path())
                .collect()
        };
        for iface in kids(&dir, &format!("{name}:")) {
            for host in kids(&iface, "host") {
                for target in kids(&host, "target") {
                    for lun in kids(&target, "") {
                        for disk in kids(&lun.join("block"), "") {
                            let d = disk.file_name().unwrap().to_string_lossy().into_owned();
                            let parts = kids(&disk, &d);
                            out.push(d);
                            out.extend(
                                parts
                                    .iter()
                                    .map(|p| p.file_name().unwrap().to_string_lossy().into_owned()),
                            );
                        }
                    }
                }
            }
        }
        out
    }

    fn event(&self, action: &str, dev: &UsbDevice) {
        let mut e = new_event(EventType::DeviceControl);
        e.payload = Some(pb::event::Payload::Policy(pb::PolicyEvent {
            action: action.into(),
            detail: format!("{} on port {}", dev.describe(), dev.name),
            ..Default::default()
        }));
        self.emit.emit(e);
    }

    /// Gives back every device it blocked or made read-only and stops
    /// enforcing, before an uninstall: a blocked USB disk would otherwise
    /// stay unusable until it is replugged.
    pub fn release_all(&self) {
        let mut i = self.inner.lock().unwrap();
        i.pol = None;
        for name in std::mem::take(&mut i.blocked).into_keys() {
            if let Err(err) = self.authorize(&name, true) {
                tracing::warn!(device = %name, "re-authorizing USB device failed: {err}");
            }
        }
        for b in std::mem::take(&mut i.ro) {
            let _ = (self.set_read_only)(&b, false);
        }
        let _ = std::fs::remove_file(&self.file);
    }

    /// Whether the module is on and how many devices it blocks.
    pub fn status(&self) -> (bool, usize) {
        let i = self.inner.lock().unwrap();
        (i.pol.as_ref().is_some_and(|p| p.enabled), i.blocked.len())
    }
}

/// Wakes the scanner when a USB device or disk is added.
fn uevents(tx: &mpsc::SyncSender<()>) -> Result<()> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::NETLINK_KOBJECT_UEVENT,
        )
    };
    if fd < 0 {
        bail!("socket: {}", std::io::Error::last_os_error());
    }
    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    sa.nl_groups = 1;
    if unsafe {
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_nl>() as u32,
        )
    } < 0
    {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        bail!("bind: {err}");
    }
    let mut buf = vec![0u8; 16 << 10];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(libc::EINTR) | Some(libc::ENOBUFS)) {
                continue;
            }
            unsafe { libc::close(fd) };
            bail!("recv: {err}");
        }
        let msg = &buf[..n as usize];
        let has = |s: &[u8]| msg.windows(s.len()).any(|w| w == s);
        // Disks show up as block devices a moment after the USB device.
        if msg.starts_with(b"add@") && (has(b"SUBSYSTEM=usb") || has(b"SUBSYSTEM=block")) {
            let _ = tx.try_send(());
        }
    }
}

/// Sets the kernel's read-only flag on /dev/<dev> and, when making it
/// read-only, remounts filesystems already mounted from it.
fn set_block_read_only(dev: &str, ro: bool) -> Result<()> {
    use std::os::fd::AsRawFd;
    const BLKROSET: libc::c_ulong = 0x125d;
    let f = std::fs::File::open(format!("/dev/{dev}"))?;
    let v: libc::c_int = ro as libc::c_int;
    if unsafe { libc::ioctl(f.as_raw_fd(), BLKROSET as _, &v) } < 0 {
        bail!("BLKROSET /dev/{dev}: {}", std::io::Error::last_os_error());
    }
    if !ro {
        return Ok(());
    }
    let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let want = format!("/dev/{dev}");
    for line in mounts.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 2 || f[0] != want {
            continue;
        }
        let dir = super::fanotify::unescape_mount(f[1]);
        let out = std::process::Command::new("mount")
            .args(["-o", "remount,ro", &dir])
            .output()?;
        if !out.status.success() {
            bail!(
                "remount {dir} read-only: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    static RO_CALLS: StdMutex<Vec<(String, bool)>> = StdMutex::new(Vec::new());

    fn fake_ro(dev: &str, ro: bool) -> Result<()> {
        RO_CALLS.lock().unwrap().push((dev.into(), ro));
        Ok(())
    }

    fn fake_usb(root: &Path, name: &str, id: (&str, &str)) {
        let d = root.join(name);
        let iface = d.join(format!("{name}:1.0"));
        std::fs::create_dir_all(iface.join("host6/target6:0:0/6:0:0:0/block/sdb/sdb1")).unwrap();
        std::fs::write(iface.join("bInterfaceClass"), "08\n").unwrap();
        std::fs::write(d.join("idVendor"), id.0).unwrap();
        std::fs::write(d.join("idProduct"), id.1).unwrap();
        std::fs::write(d.join("product"), "Cruzer").unwrap();
        std::fs::write(d.join("authorized"), "1").unwrap();
    }

    fn policy_events(rx: &mut tokio::sync::mpsc::Receiver<pb::Event>) -> Vec<String> {
        std::iter::from_fn(|| rx.try_recv().ok())
            .map(|e| match e.payload {
                Some(pb::event::Payload::Policy(p)) => p.action,
                _ => panic!(),
            })
            .collect()
    }

    #[test]
    fn blocks_releases_and_makes_read_only() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("usb");
        fake_usb(&root, "1-1", ("0781", "5583"));
        std::fs::create_dir_all(root.join("usb1")).unwrap();
        let (sink, mut rx) = xdr_core::bus::EventSink::channel(16);
        let emit = Emitter::default();
        emit.set(sink);
        let dc = DeviceControl::with_root(emit, tmp.path().join("devctl.json"), root.clone(), fake_ro);
        let mut pol = pb::DeviceControlPolicy {
            enabled: true,
            usb_storage: "block".into(),
            ..Default::default()
        };
        dc.set_policy(&pol);
        dc.scan();
        assert_eq!(read_sys(root.join("1-1/authorized")), "0");
        assert_eq!(policy_events(&mut rx), vec!["blocked"]);
        assert_eq!(dc.status(), (true, 1));
        // The blocked list survives a restart.
        let again = DeviceControl::with_root(
            Emitter::default(),
            tmp.path().join("devctl.json"),
            root.clone(),
            fake_ro,
        );
        assert_eq!(again.inner.lock().unwrap().blocked.len(), 1);

        pol.allowed_devices = vec!["0781:5583".into()];
        dc.set_policy(&pol);
        dc.scan();
        assert_eq!(read_sys(root.join("1-1/authorized")), "1");
        assert_eq!(dc.status(), (true, 0));

        pol.allowed_devices.clear();
        pol.usb_storage = "read_only".into();
        dc.set_policy(&pol);
        dc.scan();
        assert_eq!(dc.block_devices("1-1"), vec!["sdb", "sdb1"]);
        let calls = RO_CALLS.lock().unwrap().clone();
        assert!(calls.contains(&("sdb".into(), true)) && calls.contains(&("sdb1".into(), true)));
        pol.usb_storage = "allow".into();
        dc.set_policy(&pol);
        dc.scan();
        assert!(RO_CALLS.lock().unwrap().contains(&("sdb1".into(), false)));
    }

    #[test]
    fn release_all_unblocks_for_uninstall() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("usb");
        fake_usb(&root, "2-1", ("0781", "5584"));
        let dc = DeviceControl::with_root(
            Emitter::default(),
            tmp.path().join("devctl.json"),
            root.clone(),
            fake_ro,
        );
        dc.set_policy(&pb::DeviceControlPolicy {
            enabled: true,
            usb_storage: "block".into(),
            ..Default::default()
        });
        dc.scan();
        assert_eq!(read_sys(root.join("2-1/authorized")), "0");
        dc.release_all();
        assert_eq!(read_sys(root.join("2-1/authorized")), "1");
        assert_eq!(dc.status(), (false, 0));
        assert!(!tmp.path().join("devctl.json").exists());
        dc.scan();
        assert_eq!(read_sys(root.join("2-1/authorized")), "1");
    }
}
