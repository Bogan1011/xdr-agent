// Package policy validates prevention policies and renders the nftables
// tables the agent applies for them. The console uses it to reject bad policies before they are
// saved; the agent uses it to apply them.
package policy

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

const (
	// FirewallTable is the nftables table the agent owns.
	FirewallTable = "xdr_firewall"

	maxRules    = 500
	maxFIMPaths = 200
)

// Default is the policy of an endpoint nobody has configured: everything off,
// with the usual critical files ready to monitor once FIM is switched on.
func Default() *xdrv1.PreventionPolicy {
	return &xdrv1.PreventionPolicy{
		Fim: &xdrv1.FimPolicy{
			Paths: []string{
				"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d",
				"/etc/ssh", "/etc/pam.d", "/etc/ld.so.preload", "/etc/hosts", "/etc/crontab", "/etc/cron.d",
				"/etc/cron.hourly", "/etc/cron.daily", "/etc/systemd/system", "/root/.ssh",
				"/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
			},
			// The agent changes these itself: just-in-time sudo grants,
			// session recording, and its binary on self-update.
			Exclude:         []string{"/etc/sudoers.d/xdr-*", "/etc/sudoers.d/.xdr-*", "/usr/local/bin/xdr-agent*"},
			IntervalMinutes: 60,
		},
		Firewall:      &xdrv1.FirewallPolicy{},
		AntiMalware:   &xdrv1.AntiMalwarePolicy{Enabled: true},
		WebReputation: &xdrv1.WebReputationPolicy{UseThreatIntel: true},
		IntrusionPrevention: &xdrv1.IntrusionPreventionPolicy{
			MaxFailures: 5, WindowSeconds: 300, BanMinutes: 30,
		},
		DeviceControl:      &xdrv1.DeviceControlPolicy{UsbStorage: "allow"},
		ActivityMonitoring: &xdrv1.ActivityMonitoringPolicy{Process: true, File: true, Network: true},
		ApplicationControl: &xdrv1.ApplicationControlPolicy{},
		SelfProtection:     &xdrv1.SelfProtectionPolicy{},
	}
}

// Normalize fills missing sections so callers never deal with nil.
func Normalize(p *xdrv1.PreventionPolicy) *xdrv1.PreventionPolicy {
	if p == nil {
		p = &xdrv1.PreventionPolicy{}
	}
	if p.Fim == nil {
		p.Fim = &xdrv1.FimPolicy{}
	}
	if p.Fim.IntervalMinutes == 0 {
		p.Fim.IntervalMinutes = 60
	}
	if p.Firewall == nil {
		p.Firewall = &xdrv1.FirewallPolicy{}
	}
	normalizeModules(p)
	return p
}

// Validate checks a policy before it is stored or applied.
func Validate(p *xdrv1.PreventionPolicy) error {
	p = Normalize(p)
	if n := len(p.Fim.Paths); n > maxFIMPaths {
		return fmt.Errorf("fim: at most %d paths", maxFIMPaths)
	}
	for _, s := range append(append([]string{}, p.Fim.Paths...), p.Fim.Exclude...) {
		if !strings.HasPrefix(s, "/") {
			return fmt.Errorf("fim: path %q must be absolute", s)
		}
		if _, err := filepath.Match(s, "/"); err != nil {
			return fmt.Errorf("fim: bad pattern %q", s)
		}
	}
	if p.Fim.Enabled && len(p.Fim.Paths) == 0 {
		return fmt.Errorf("fim: add at least one path to monitor")
	}
	if p.Fim.IntervalMinutes < 5 || p.Fim.IntervalMinutes > 7*24*60 {
		return fmt.Errorf("fim: interval must be between 5 minutes and 7 days")
	}
	if len(p.Firewall.Rules) > maxRules {
		return fmt.Errorf("firewall: at most %d rules", maxRules)
	}
	for i, r := range p.Firewall.Rules {
		if _, err := ruleExpr(r); err != nil {
			return fmt.Errorf("firewall rule %d: %w", i+1, err)
		}
	}
	return validateModules(p)
}

// Matches reports whether path is one of the patterns: a path prefix, or a
// glob when the pattern contains a glob character.
func Matches(path string, patterns []string) bool {
	for _, p := range patterns {
		if strings.ContainsAny(p, "*?[") {
			if ok, _ := filepath.Match(p, path); ok {
				return true
			}
			continue
		}
		if path == p || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") {
			return true
		}
	}
	return false
}

// ruleExpr renders one rule as an nftables statement.
func ruleExpr(r *xdrv1.FirewallRule) (string, error) {
	var parts []string
	var dirAddr string
	switch r.Direction {
	case "in":
		dirAddr = "saddr"
	case "out":
		dirAddr = "daddr"
	default:
		return "", fmt.Errorf("direction must be in or out")
	}
	var verdict string
	switch r.Action {
	case "allow":
		verdict = "accept"
	case "deny":
		verdict = "drop"
	default:
		return "", fmt.Errorf("action must be allow or deny")
	}
	if c := strings.TrimSpace(r.Cidr); c != "" {
		pfx, err := parsePrefix(c)
		if err != nil {
			return "", err
		}
		fam := "ip"
		if pfx.Addr().Is6() {
			fam = "ip6"
		}
		parts = append(parts, fmt.Sprintf("%s %s %s", fam, dirAddr, pfx))
	}
	ports, err := parsePorts(r.Ports)
	if err != nil {
		return "", err
	}
	switch r.Protocol {
	case "tcp", "udp":
		if ports != "" {
			parts = append(parts, fmt.Sprintf("%s dport { %s }", r.Protocol, ports))
		} else {
			parts = append(parts, "meta l4proto "+r.Protocol)
		}
	case "icmp", "any", "":
		if ports != "" {
			return "", fmt.Errorf("ports need protocol tcp or udp")
		}
		if r.Protocol == "icmp" {
			parts = append(parts, "meta l4proto { icmp, ipv6-icmp }")
		}
	default:
		return "", fmt.Errorf("protocol must be tcp, udp, icmp or any")
	}
	if strings.ContainsAny(r.Comment, "\"\n\\") || len(r.Comment) > 120 {
		return "", fmt.Errorf("comment must be under 120 characters without quotes or backslashes")
	}
	if r.Comment != "" {
		verdict += fmt.Sprintf(" comment %q", r.Comment)
	}
	return strings.TrimSpace(strings.Join(parts, " ") + " " + verdict), nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// parsePorts turns "22, 80-90" into the nftables set "22, 80-90".
func parsePorts(s string) (string, error) {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(f, "-")
		a, err := port(lo)
		if err != nil {
			return "", err
		}
		if !isRange {
			out = append(out, strconv.Itoa(a))
			continue
		}
		b, err := port(hi)
		if err != nil {
			return "", err
		}
		if b <= a {
			return "", fmt.Errorf("port range %q is empty", f)
		}
		out = append(out, fmt.Sprintf("%d-%d", a, b))
	}
	return strings.Join(out, ", "), nil
}

func port(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%q is not a port", s)
	}
	return n, nil
}

// FirewallRules renders the nftables script for the policy. Loopback,
// established connections, DHCP, IPv6 neighbour discovery and the console
// addresses are always allowed, so a bad policy cannot cut the agent off.
// The script replaces the table atomically.
func FirewallRules(fw *xdrv1.FirewallPolicy, console []netip.Addr) (string, error) {
	var v4, v6 []string
	seen := map[netip.Addr]bool{}
	for _, a := range console {
		a = a.Unmap()
		if seen[a] {
			continue
		}
		seen[a] = true
		if a.Is4() {
			v4 = append(v4, a.String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	var in, out []string
	for i, r := range fw.Rules {
		e, err := ruleExpr(r)
		if err != nil {
			return "", fmt.Errorf("rule %d: %w", i+1, err)
		}
		if r.Direction == "in" {
			in = append(in, e)
		} else {
			out = append(out, e)
		}
	}
	set := func(name, typ string, elems []string) string {
		s := fmt.Sprintf("\tset %s {\n\t\ttype %s\n", name, typ)
		if len(elems) > 0 {
			s += "\t\telements = { " + strings.Join(elems, ", ") + " }\n"
		}
		return s + "\t}\n"
	}
	inPolicy := "accept"
	if fw.DefaultDenyInbound {
		inPolicy = "drop"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\ntable inet %s {\n", FirewallTable, FirewallTable, FirewallTable)
	b.WriteString(set("console4", "ipv4_addr", v4))
	b.WriteString(set("console6", "ipv6_addr", v6))
	for _, c := range []struct {
		name, hook, policy, lo, dir, dhcp, nd string
		rules                                 []string
	}{
		{"input", "input", inPolicy, `iif "lo"`, "saddr", "udp sport 67 udp dport 68", "nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert", in},
		{"output", "output", "accept", `oif "lo"`, "daddr", "udp sport 68 udp dport 67", "nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit", out},
	} {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority 0; policy %s;\n", c.name, c.hook, c.policy)
		fmt.Fprintf(&b, "\t\t%s accept\n", c.lo)
		b.WriteString("\t\tct state established,related accept\n")
		fmt.Fprintf(&b, "\t\tip %s @console4 accept\n\t\tip6 %s @console6 accept\n", c.dir, c.dir)
		fmt.Fprintf(&b, "\t\t%s accept\n", c.dhcp)
		fmt.Fprintf(&b, "\t\ticmpv6 type { %s } accept\n", c.nd)
		for _, r := range c.rules {
			fmt.Fprintf(&b, "\t\t%s\n", r)
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String(), nil
}

// DisableFirewall removes the table whether or not it exists.
func DisableFirewall() string {
	return fmt.Sprintf("add table inet %s\ndelete table inet %s\n", FirewallTable, FirewallTable)
}

var jsonOut = protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}

// MarshalJSON renders a policy for the console API and storage, with
// snake_case names and every field present.
func MarshalJSON(p *xdrv1.PreventionPolicy) []byte {
	raw, _ := jsonOut.Marshal(Normalize(p))
	return raw
}

// UnmarshalJSON parses a policy written by MarshalJSON or the console.
func UnmarshalJSON(raw []byte) (*xdrv1.PreventionPolicy, error) {
	p := &xdrv1.PreventionPolicy{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, p); err != nil {
		return nil, err
	}
	return Normalize(p), nil
}

// MarshalState renders the agent's reported state for the console.
func MarshalState(s *xdrv1.PreventionState) []byte {
	if s == nil {
		s = &xdrv1.PreventionState{}
	}
	raw, _ := jsonOut.Marshal(s)
	return raw
}
