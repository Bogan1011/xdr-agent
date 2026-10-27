package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/agent/collector"
	"github.com/Bogan1011/xdr-agent/internal/policy"
)

const (
	usbDevices     = "/sys/bus/usb/devices"
	usbMassStorage = "08"
	devctlRescan   = 10 * time.Second
)

// DeviceControl blocks USB mass storage by deauthorizing the device in sysfs,
// which detaches its drivers before a disk appears. In read-only mode it
// lets the disk appear, marks its block devices read-only (BLKROSET) and
// remounts any filesystem already mounted from them read-only. New devices are seen
// through kernel uevents; a periodic rescan catches anything missed. Devices
// it blocked are kept on disk so they are released when the policy allows
// them again, even after a restart.
type DeviceControl struct {
	Log  *slog.Logger
	Emit collector.Emit
	File string
	Root string // sysfs USB devices directory; tests point it elsewhere
	kick chan struct{}
	// SetReadOnly marks a block device (e.g. sdb1) read-only or writable;
	// tests replace it.
	SetReadOnly func(dev string, ro bool) error

	mu      sync.Mutex
	pol     *xdrv1.DeviceControlPolicy
	blocked map[string]usbDevice // sysfs name to the device we deauthorized
	seen    map[string]bool      // storage devices already reported
	ro      map[string]bool      // block devices we made read-only
}

type usbDevice struct {
	Name    string `json:"name"`
	ID      string `json:"id"` // vendor:product
	Product string `json:"product"`
	Serial  string `json:"serial"`
}

func (d usbDevice) key() string { return d.Name + "|" + d.ID + "|" + d.Serial }

func (d usbDevice) String() string {
	s := "USB storage " + d.ID
	if d.Product != "" {
		s += " (" + d.Product + ")"
	}
	if d.Serial != "" {
		s += " serial " + d.Serial
	}
	return s
}

func NewDeviceControl(log *slog.Logger, emit collector.Emit, file string) *DeviceControl {
	d := &DeviceControl{Log: log, Emit: emit, File: file, Root: usbDevices, kick: make(chan struct{}, 1),
		blocked: map[string]usbDevice{}, seen: map[string]bool{}, ro: map[string]bool{}, SetReadOnly: setBlockReadOnly}
	if raw, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(raw, &d.blocked)
	}
	return d
}

func (d *DeviceControl) SetPolicy(p *xdrv1.DeviceControlPolicy) {
	d.mu.Lock()
	changed := !proto.Equal(p, d.pol)
	d.pol = proto.Clone(p).(*xdrv1.DeviceControlPolicy)
	d.mu.Unlock()
	if changed {
		d.trigger()
	}
}

func (d *DeviceControl) trigger() {
	select {
	case d.kick <- struct{}{}:
	default:
	}
}

func (d *DeviceControl) Run(ctx context.Context) {
	go d.uevents(ctx)
	t := time.NewTicker(devctlRescan)
	defer t.Stop()
	for {
		d.scan()
		select {
		case <-ctx.Done():
			return
		case <-d.kick:
		case <-t.C:
		}
	}
}

// uevents wakes the scanner when a USB device is added.
func (d *DeviceControl) uevents(ctx context.Context) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_KOBJECT_UEVENT)
	if err != nil {
		d.Log.Warn("uevent socket unavailable, device control rescans every 10s", "err", err)
		return
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1}); err != nil {
		unix.Close(fd)
		d.Log.Warn("uevent bind failed, device control rescans every 10s", "err", err)
		return
	}
	go func() {
		<-ctx.Done()
		unix.Close(fd)
	}()
	buf := make([]byte, 16<<10)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if err == unix.EINTR || err == unix.ENOBUFS {
				continue
			}
			d.Log.Warn("uevent read failed", "err", err)
			return
		}
		msg := buf[:n]
		// Disks show up as block devices a moment after the USB device.
		if bytes.HasPrefix(msg, []byte("add@")) && (bytes.Contains(msg, []byte("SUBSYSTEM=usb")) || bytes.Contains(msg, []byte("SUBSYSTEM=block"))) {
			d.trigger()
		}
	}
}

func readSys(path string) string {
	raw, _ := os.ReadFile(path)
	return strings.TrimSpace(string(raw))
}

// storageDevices lists USB devices with a mass storage interface.
func (d *DeviceControl) storageDevices() map[string]usbDevice {
	out := map[string]usbDevice{}
	entries, err := os.ReadDir(d.Root)
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		// Interfaces are named like 1-1:1.0; hubs' roots like usb1.
		if strings.Contains(name, ":") || strings.HasPrefix(name, "usb") {
			continue
		}
		dir := filepath.Join(d.Root, name)
		ifaces, _ := filepath.Glob(filepath.Join(dir, name+":*", "bInterfaceClass"))
		storage := false
		for _, f := range ifaces {
			if readSys(f) == usbMassStorage {
				storage = true
				break
			}
		}
		if !storage {
			continue
		}
		out[name] = usbDevice{
			Name: name, ID: strings.ToLower(readSys(filepath.Join(dir, "idVendor")) + ":" + readSys(filepath.Join(dir, "idProduct"))),
			Product: readSys(filepath.Join(dir, "product")), Serial: readSys(filepath.Join(dir, "serial")),
		}
	}
	return out
}

func (d *DeviceControl) authorize(name string, on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	return os.WriteFile(filepath.Join(d.Root, name, "authorized"), []byte(v), 0o644)
}

func (d *DeviceControl) scan() {
	d.mu.Lock()
	defer d.mu.Unlock()
	pol := d.pol
	enabled := pol.GetEnabled()
	block := enabled && pol.GetUsbStorage() == policy.USBStorageBlock
	readOnly := enabled && pol.GetUsbStorage() == policy.USBStorageReadOnly
	allowed := map[string]bool{}
	for _, id := range pol.GetAllowedDevices() {
		allowed[id] = true
	}
	changed := false

	// Release what the policy no longer blocks, or what was unplugged.
	for name, dev := range d.blocked {
		cur := readSys(filepath.Join(d.Root, name, "idVendor")) + ":" + readSys(filepath.Join(d.Root, name, "idProduct"))
		gone := strings.ToLower(cur) != dev.ID
		if gone || !block || allowed[dev.ID] {
			if !gone {
				if err := d.authorize(name, true); err != nil {
					d.Log.Warn("re-authorizing USB device failed", "device", name, "err", err)
					continue
				}
				d.Log.Info("USB storage device allowed again", "device", dev.String())
			}
			delete(d.blocked, name)
			changed = true
		}
	}

	present := d.storageDevices()
	wantRO := map[string]bool{}
	for name, dev := range present {
		if _, ok := d.blocked[name]; ok {
			continue
		}
		if readOnly && !allowed[dev.ID] {
			disks := d.blockDevices(name)
			fresh := false
			for _, b := range disks {
				wantRO[b] = true
				if d.ro[b] {
					continue
				}
				if err := d.SetReadOnly(b, true); err != nil {
					d.Log.Error("making USB storage read-only failed", "device", dev.String(), "disk", b, "err", err)
					continue
				}
				d.ro[b], fresh = true, true
			}
			if fresh && !d.seen[dev.key()] {
				d.seen[dev.key()] = true
				d.Log.Warn("USB storage device made read-only", "device", dev.String(), "disks", disks)
				d.emit("read_only", dev)
			}
			continue
		}
		if block && !allowed[dev.ID] {
			if readSys(filepath.Join(d.Root, name, "authorized")) == "0" {
				continue
			}
			if err := d.authorize(name, false); err != nil {
				d.Log.Error("blocking USB storage failed", "device", dev.String(), "err", err)
				continue
			}
			d.blocked[name] = dev
			changed = true
			d.Log.Warn("USB storage device blocked", "device", dev.String())
			d.emit("blocked", dev)
			d.seen[dev.key()] = true
			continue
		}
		if enabled && !d.seen[dev.key()] {
			d.seen[dev.key()] = true
			d.emit("connected", dev)
		}
	}
	// Make writable again what is unplugged or no longer read-only.
	for b := range d.ro {
		if wantRO[b] {
			continue
		}
		if d.SetReadOnly != nil {
			_ = d.SetReadOnly(b, false)
		}
		delete(d.ro, b)
	}
	for k := range d.seen {
		name, _, _ := strings.Cut(k, "|")
		_, here := present[name]
		_, held := d.blocked[name]
		if !here && !held {
			delete(d.seen, k)
		}
	}
	if changed {
		raw, _ := json.Marshal(d.blocked)
		_ = os.WriteFile(d.File, raw, 0o600)
	}
}

// blockDevices lists the disks and partitions (sdb, sdb1...) under a USB
// storage device.
func (d *DeviceControl) blockDevices(name string) []string {
	var out []string
	disks, _ := filepath.Glob(filepath.Join(d.Root, name, name+":*", "host*", "target*", "*", "block", "*"))
	for _, disk := range disks {
		out = append(out, filepath.Base(disk))
		parts, _ := filepath.Glob(filepath.Join(disk, filepath.Base(disk)+"*"))
		for _, p := range parts {
			out = append(out, filepath.Base(p))
		}
	}
	return out
}

// setBlockReadOnly sets the kernel's read-only flag on /dev/<dev> and, when
// making it read-only, remounts filesystems already mounted from it.
func setBlockReadOnly(dev string, ro bool) error {
	f, err := os.OpenFile("/dev/"+dev, os.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	v := 0
	if ro {
		v = 1
	}
	err = unix.IoctlSetPointerInt(int(f.Fd()), unix.BLKROSET, v)
	f.Close()
	if err != nil || !ro {
		return err
	}
	raw, _ := os.ReadFile("/proc/self/mounts")
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "/dev/"+dev {
			continue
		}
		if out, err := exec.Command("mount", "-o", "remount,ro", unescapeMount(fields[1])).CombinedOutput(); err != nil {
			return fmt.Errorf("remount %s read-only: %v: %s", fields[1], err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func (d *DeviceControl) emit(action string, dev usbDevice) {
	e := collector.NewEvent(xdrv1.EventType_EVENT_TYPE_DEVICE_CONTROL)
	e.Payload = &xdrv1.Event_Policy{Policy: &xdrv1.PolicyEvent{Action: action, Detail: fmt.Sprintf("%s on port %s", dev, dev.Name)}}
	d.Emit(e)
}

// Status reports whether the module is on and how many devices it blocks.
func (d *DeviceControl) Status() (bool, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pol.GetEnabled(), len(d.blocked)
}
