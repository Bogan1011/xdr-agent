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

func TestLockdownAndScripts(t *testing.T) {
	p := Default()
	ac := p.ApplicationControl
	ac.Enabled, ac.Lockdown, ac.BlockScripts = true, true, true
	ac.BlockedPaths = []string{"/usr/bin/nc"}
	ac.AllowedSha256 = []string{strings.Repeat("cd", 32)}
	Normalize(p)
	if err := validateModules(p); err != nil {
		t.Fatal(err)
	}
	if AppRule(ac, "/usr/bin/ls", "") != "" {
		t.Error("default allow-list should allow /usr")
	}
	if AppRule(ac, "/usr/bin/nc", "") == "" {
		t.Error("block list should win over the allow-list")
	}
	if AppRule(ac, "/home/u/tool", "") == "" || AppRule(ac, "/home/u/tool", strings.Repeat("cd", 32)) != "" {
		t.Error("lockdown by path and hash")
	}
	if !AppNeedsHash(ac, "/home/u/tool") || AppNeedsHash(&xdrv1.ApplicationControlPolicy{Lockdown: true}, "/x") {
		t.Error("AppNeedsHash")
	}
	for _, c := range []struct {
		exe  string
		args []string
		want string
	}{
		{"/usr/bin/bash", []string{"bash", "-x", "x.sh"}, "/tmp/x.sh"},
		{"/usr/bin/dash", []string{"sh", "-c", "/tmp/x.sh"}, ""},
		{"/usr/bin/python3.12", []string{"python3", "-X", "dev", "/tmp/a/y.py"}, "/tmp/a/y.py"},
		{"/usr/bin/python3", []string{"python3", "-m", "http.server"}, ""},
		{"/usr/bin/perl", []string{"perl", "-e", "print 1"}, ""},
		{"/usr/bin/ls", []string{"ls", "/tmp/x"}, ""},
	} {
		got, _ := ScriptRule(ac, c.exe, c.args, "/tmp")
		if got != c.want {
			t.Errorf("%v: got %q want %q", c.args, got, c.want)
		}
	}
	if !ScriptOpened([]string{"bash", "-x", "./x.sh"}, "/tmp", "/tmp/x.sh") || ScriptOpened([]string{"bash"}, "/tmp", "/tmp/x.sh") {
		t.Error("ScriptOpened")
	}
}
