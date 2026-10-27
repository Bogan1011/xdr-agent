package agent

import (
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

func TestSSHFailRegexp(t *testing.T) {
	for line, want := range map[string]string{
		"Failed password for root from 203.0.113.5 port 4242 ssh2":                      "203.0.113.5",
		"Failed password for invalid user bob from 2001:db8::7 port 22 ssh2":            "2001:db8::7",
		"Oct 27 10:00:01 host sshd[1]: Invalid user admin from 198.51.100.2 port 50000": "198.51.100.2",
		"Failed publickey for git from 192.0.2.1 port 1 ssh2: RSA SHA256:abc":           "192.0.2.1",
		"Accepted password for root from 203.0.113.5 port 4242 ssh2":                    "",
		"Connection closed by authenticating user root 203.0.113.5 port 4242 [preauth]": "",
	} {
		got := ""
		if m := sshFailRe.FindStringSubmatch(line); m != nil {
			got = m[1]
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", line, got, want)
		}
	}
}

func TestIntrusionThreshold(t *testing.T) {
	s := &sink{}
	ips := NewIntrusion(slog.Default(), s.emit, nil)
	ips.pol = &xdrv1.IntrusionPreventionPolicy{Enabled: true, MaxFailures: 3, WindowSeconds: 60, BanMinutes: 5}
	ips.allow = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	bad, ok := netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("10.1.2.3")
	now := time.Now()
	ips.failed(bad, now.Add(-2*time.Minute)) // outside the window
	for i := range 3 {
		ips.failed(ok, now)
		if i < 2 {
			ips.failed(bad, now)
		}
	}
	if evs := s.take(); len(evs) != 0 {
		t.Fatalf("raised too early: %v", evs)
	}
	ips.failed(bad, now)
	evs := s.take()
	if len(evs) != 1 || evs[0].GetPolicy().Action != "detected" || evs[0].GetPolicy().RemoteAddr != "203.0.113.5" {
		t.Fatalf("events = %v", evs)
	}
}

func TestWebReputationObserve(t *testing.T) {
	s := &sink{}
	w := NewWebReputation(slog.Default(), s.emit, func() ([]netip.Addr, error) { return nil, nil })
	w.pol = &xdrv1.WebReputationPolicy{Enabled: true, UseThreatIntel: true}
	w.exact = map[netip.Addr]string{netip.MustParseAddr("203.0.113.9"): "threat intel"}
	w.nets = []listedNet{{netip.MustParsePrefix("198.51.100.0/24"), "evil.example"}}
	conn := func(addr string) *xdrv1.Event {
		return &xdrv1.Event{Type: xdrv1.EventType_EVENT_TYPE_NET_CONNECT,
			Payload: &xdrv1.Event_Network{Network: &xdrv1.NetworkEvent{RemoteAddr: addr, Exe: "/usr/bin/curl"}}}
	}
	w.Observe(conn("::ffff:203.0.113.9"))
	w.Observe(conn("203.0.113.9")) // duplicate within a minute
	w.Observe(conn("198.51.100.20"))
	w.Observe(conn("192.0.2.1"))
	evs := s.take()
	if len(evs) != 2 || evs[0].GetPolicy().Action != "detected" || evs[1].GetPolicy().Detail != "domain evil.example" {
		t.Fatalf("events = %v", evs)
	}
}

func TestDeviceControlBlocksStorage(t *testing.T) {
	root := t.TempDir()
	mk := func(name, class string) {
		dev := filepath.Join(root, name)
		os.MkdirAll(filepath.Join(dev, name+":1.0"), 0o755)
		os.WriteFile(filepath.Join(dev, "idVendor"), []byte("0781\n"), 0o644)
		os.WriteFile(filepath.Join(dev, "idProduct"), []byte("5583\n"), 0o644)
		os.WriteFile(filepath.Join(dev, "product"), []byte("Ultra Fit\n"), 0o644)
		os.WriteFile(filepath.Join(dev, "authorized"), []byte("1\n"), 0o644)
		os.WriteFile(filepath.Join(dev, name+":1.0", "bInterfaceClass"), []byte(class+"\n"), 0o644)
	}
	mk("1-1", "08") // storage
	mk("1-2", "03") // keyboard
	auth := func(name string) string { return readSys(filepath.Join(root, name, "authorized")) }

	s := &sink{}
	d := NewDeviceControl(slog.Default(), s.emit, filepath.Join(t.TempDir(), "devctl.json"))
	d.Root = root
	d.SetPolicy(&xdrv1.DeviceControlPolicy{Enabled: true, UsbStorage: "block"})
	d.scan()
	if auth("1-1") != "0" || auth("1-2") != "1" {
		t.Fatalf("authorized: storage=%s keyboard=%s", auth("1-1"), auth("1-2"))
	}
	if evs := s.take(); len(evs) != 1 || evs[0].GetPolicy().Action != "blocked" {
		t.Fatalf("events = %v", evs)
	}
	// The kernel drops the interfaces of a deauthorized device.
	os.RemoveAll(filepath.Join(root, "1-1", "1-1:1.0"))
	d.scan()
	if on, n := d.Status(); !on || n != 1 || len(s.take()) != 0 {
		t.Fatalf("rescan: on=%v blocked=%d", on, n)
	}
	d.SetPolicy(&xdrv1.DeviceControlPolicy{Enabled: true, UsbStorage: "block", AllowedDevices: []string{"0781:5583"}})
	d.scan()
	if auth("1-1") != "1" {
		t.Fatal("allowed device not re-authorized")
	}
}
