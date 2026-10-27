package policy

import (
	"net/netip"
	"strings"
	"testing"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

func TestValidate(t *testing.T) {
	ok := Default()
	ok.Fim.Enabled = true
	ok.Firewall.Rules = []*xdrv1.FirewallRule{{Direction: "in", Action: "allow", Protocol: "tcp", Ports: "22, 8000-8100", Cidr: "10.0.0.0/8"}}
	if err := Validate(ok); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	for name, r := range map[string]*xdrv1.FirewallRule{
		"direction": {Direction: "sideways", Action: "allow"},
		"action":    {Direction: "in", Action: "maybe"},
		"port":      {Direction: "in", Action: "allow", Protocol: "tcp", Ports: "70000"},
		"range":     {Direction: "in", Action: "allow", Protocol: "tcp", Ports: "90-80"},
		"proto":     {Direction: "in", Action: "allow", Protocol: "any", Ports: "22"},
		"cidr":      {Direction: "out", Action: "deny", Cidr: "10.0.0.300"},
		"comment":   {Direction: "in", Action: "allow", Comment: `x"; drop`},
	} {
		p := Default()
		p.Firewall.Rules = []*xdrv1.FirewallRule{r}
		if Validate(p) == nil {
			t.Errorf("%s: invalid rule accepted", name)
		}
	}
	p := Default()
	p.Fim.Paths = []string{"etc/passwd"}
	if Validate(p) == nil {
		t.Error("relative FIM path accepted")
	}
	p = Default()
	p.Fim.IntervalMinutes = 1
	if Validate(p) == nil {
		t.Error("1 minute interval accepted")
	}
}

func TestMatches(t *testing.T) {
	pats := []string{"/etc/ssh", "/etc/sudoers.d/xdr-*", "/usr/bin/"}
	for path, want := range map[string]bool{
		"/etc/ssh":                   true,
		"/etc/ssh/sshd_config":       true,
		"/etc/sshd":                  false,
		"/etc/sudoers.d/xdr-jit-bob": true,
		"/etc/sudoers.d/admins":      false,
		"/usr/bin/ls":                true,
		"/usr/binary":                false,
	} {
		if got := Matches(path, pats); got != want {
			t.Errorf("Matches(%s) = %v", path, got)
		}
	}
}

func TestFirewallRules(t *testing.T) {
	fw := &xdrv1.FirewallPolicy{Enabled: true, DefaultDenyInbound: true, Rules: []*xdrv1.FirewallRule{
		{Direction: "in", Action: "allow", Protocol: "tcp", Ports: "22", Cidr: "192.168.1.0/24", Comment: "ssh from lab"},
		{Direction: "in", Action: "allow", Protocol: "tcp", Ports: "80,443"},
		{Direction: "out", Action: "deny", Protocol: "any", Cidr: "2001:db8::/32"},
		{Direction: "in", Action: "allow", Protocol: "icmp"},
	}}
	got, err := FirewallRules(fw, []netip.Addr{netip.MustParseAddr("192.168.1.118"), netip.MustParseAddr("::ffff:192.168.1.118")})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"type filter hook input priority 0; policy drop;",
		"type filter hook output priority 0; policy accept;",
		"elements = { 192.168.1.118 }",
		`ip saddr 192.168.1.0/24 tcp dport { 22 } accept comment "ssh from lab"`,
		"tcp dport { 80, 443 } accept",
		"ip6 daddr 2001:db8::/32 drop",
		"meta l4proto { icmp, ipv6-icmp } accept",
		"ip daddr @console4 accept",
		"ct state established,related accept",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, got)
		}
	}
	// Outbound rules go to the output chain only.
	in := got[strings.Index(got, "chain input"):strings.Index(got, "chain output")]
	if strings.Contains(in, "2001:db8") {
		t.Error("outbound rule rendered in the input chain")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	p := Default()
	p.AntiMalware.BlockKnownBad = true
	raw := MarshalJSON(p)
	if !strings.Contains(string(raw), `"block_known_bad":true`) || !strings.Contains(string(raw), `"rules":[]`) {
		t.Fatalf("unexpected JSON %s", raw)
	}
	back, err := UnmarshalJSON(raw)
	if err != nil || !back.AntiMalware.BlockKnownBad || len(back.Fim.Paths) != len(p.Fim.Paths) {
		t.Fatalf("round trip: %v %v", back, err)
	}
}

func TestLegacyPolicy(t *testing.T) {
	p, err := UnmarshalJSON([]byte(`{"block_exec":true,"fim":{"enabled":true,"paths":["/etc"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !p.AntiMalware.Enabled || !p.AntiMalware.BlockKnownBad || p.BlockExec {
		t.Errorf("anti-malware not migrated: %v", p.AntiMalware)
	}
	am := p.ActivityMonitoring
	if !am.Process || !am.File || !am.Network || p.DeviceControl.UsbStorage != "allow" || p.IntrusionPrevention.MaxFailures != 5 {
		t.Errorf("defaults not filled: %v", p)
	}
	if err := Validate(p); err != nil {
		t.Error(err)
	}
}
