package policy

import (
	"net/netip"
	"strings"
	"testing"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

func TestValidateModules(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(p *xdrv1.PreventionPolicy)
		ok   bool
	}{
		{"default", func(p *xdrv1.PreventionPolicy) {}, true},
		{"domain", func(p *xdrv1.PreventionPolicy) { p.WebReputation.BlockedDomains = []string{"Evil.Example.COM."} }, true},
		{"bad domain", func(p *xdrv1.PreventionPolicy) { p.WebReputation.BlockedDomains = []string{"evil com; drop"} }, false},
		{"ips allow", func(p *xdrv1.PreventionPolicy) { p.IntrusionPrevention.Allow = []string{"10.0.0.0/8", "192.168.1.5"} }, true},
		{"ips bad allow", func(p *xdrv1.PreventionPolicy) { p.IntrusionPrevention.Allow = []string{"lan"} }, false},
		{"ips failures", func(p *xdrv1.PreventionPolicy) { p.IntrusionPrevention.MaxFailures = 1 }, false},
		{"usb block", func(p *xdrv1.PreventionPolicy) {
			p.DeviceControl.UsbStorage = "block"
			p.DeviceControl.AllowedDevices = []string{"0781:5583"}
		}, true},
		{"usb mode", func(p *xdrv1.PreventionPolicy) { p.DeviceControl.UsbStorage = "read_only" }, false},
		{"usb id", func(p *xdrv1.PreventionPolicy) { p.DeviceControl.AllowedDevices = []string{"sandisk"} }, false},
		{"app empty", func(p *xdrv1.PreventionPolicy) { p.ApplicationControl.Enabled = true }, false},
		{"app path", func(p *xdrv1.PreventionPolicy) {
			p.ApplicationControl.Enabled = true
			p.ApplicationControl.BlockedPaths = []string{"/tmp/*"}
		}, true},
		{"app relative", func(p *xdrv1.PreventionPolicy) { p.ApplicationControl.BlockedPaths = []string{"tmp"} }, false},
		{"app hash", func(p *xdrv1.PreventionPolicy) {
			p.ApplicationControl.BlockedSha256 = []string{strings.Repeat("AB", 32)}
		}, true},
		{"app bad hash", func(p *xdrv1.PreventionPolicy) { p.ApplicationControl.BlockedSha256 = []string{"abc"} }, false},
	} {
		p := Default()
		c.edit(p)
		Normalize(p)
		if err := Validate(p); (err == nil) != c.ok {
			t.Errorf("%s: err=%v", c.name, err)
		}
	}
}

func TestAppRuleAndDomains(t *testing.T) {
	p := Default()
	p.ApplicationControl.BlockedPaths = []string{"/tmp/*", "/opt/games"}
	p.ApplicationControl.BlockedSha256 = []string{strings.Repeat("ab", 32)}
	if AppRule(p.ApplicationControl, "/tmp/x", "") == "" || AppRule(p.ApplicationControl, "/opt/games/doom", "") == "" {
		t.Error("path rule not matched")
	}
	if AppRule(p.ApplicationControl, "/usr/bin/ls", strings.Repeat("ab", 32)) == "" {
		t.Error("hash rule not matched")
	}
	if AppRule(p.ApplicationControl, "/usr/bin/ls", "") != "" {
		t.Error("unexpected match")
	}
	d := map[string]bool{"evil.com": true}
	if !DomainListed("a.b.Evil.com.", d) || DomainListed("notevil.com", d) {
		t.Error("domain matching")
	}
}

func TestNftScripts(t *testing.T) {
	s := WebReputationRules([]netip.Prefix{netip.MustParsePrefix("203.0.113.7/32"), netip.MustParsePrefix("2001:db8::/32")})
	if !strings.Contains(s, "elements = { 203.0.113.7/32 }") || !strings.Contains(s, "hook forward") {
		t.Errorf("web reputation table:\n%s", s)
	}
	if empty := WebReputationRules(nil); strings.Contains(empty, "elements") {
		t.Errorf("empty sets rendered elements:\n%s", empty)
	}
	if b := Ban(netip.MustParseAddr("2001:db8::1"), 30); b != "add element inet xdr_ips banned6 { 2001:db8::1 timeout 30m }\n" {
		t.Errorf("ban: %q", b)
	}
}
