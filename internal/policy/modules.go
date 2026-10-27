package policy

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

const (
	// WebReputationTable and IntrusionTable are the nftables tables the
	// agent owns for those modules.
	WebReputationTable = "xdr_webrep"
	IntrusionTable     = "xdr_ips"

	maxDomains      = 1000
	maxAllow        = 100
	maxDevices      = 100
	maxAppPaths     = 500
	maxAppHashes    = 5000
	USBStorageAllow = "allow"
	USBStorageBlock = "block"
)

var (
	domainRe = regexp.MustCompile(`^(?i)([a-z0-9_]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$`)
	deviceRe = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{4}$`)
	sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// normalizeModules fills missing modules. A policy saved before modules
// existed keeps its behaviour: real-time scanning on, exec blocking as it was,
// all telemetry on.
func normalizeModules(p *xdrv1.PreventionPolicy) {
	if p.AntiMalware == nil {
		p.AntiMalware = &xdrv1.AntiMalwarePolicy{Enabled: true, BlockKnownBad: p.BlockExec}
	}
	p.BlockExec = false
	if p.WebReputation == nil {
		p.WebReputation = &xdrv1.WebReputationPolicy{UseThreatIntel: true}
	}
	ips := p.IntrusionPrevention
	if ips == nil {
		ips = &xdrv1.IntrusionPreventionPolicy{}
		p.IntrusionPrevention = ips
	}
	if ips.MaxFailures == 0 {
		ips.MaxFailures = 5
	}
	if ips.WindowSeconds == 0 {
		ips.WindowSeconds = 300
	}
	if ips.BanMinutes == 0 {
		ips.BanMinutes = 30
	}
	if p.DeviceControl == nil {
		p.DeviceControl = &xdrv1.DeviceControlPolicy{}
	}
	if p.DeviceControl.UsbStorage == "" {
		p.DeviceControl.UsbStorage = USBStorageAllow
	}
	for i, d := range p.DeviceControl.AllowedDevices {
		p.DeviceControl.AllowedDevices[i] = strings.ToLower(strings.TrimSpace(d))
	}
	if p.ActivityMonitoring == nil {
		p.ActivityMonitoring = &xdrv1.ActivityMonitoringPolicy{Process: true, File: true, Network: true}
	}
	if p.ApplicationControl == nil {
		p.ApplicationControl = &xdrv1.ApplicationControlPolicy{}
	}
	for i, h := range p.ApplicationControl.BlockedSha256 {
		p.ApplicationControl.BlockedSha256[i] = strings.ToLower(strings.TrimSpace(h))
	}
	wr := p.WebReputation
	for _, l := range [][]string{wr.BlockedDomains, wr.AllowedDomains} {
		for i, d := range l {
			l[i] = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		}
	}
}

func validateModules(p *xdrv1.PreventionPolicy) error {
	wr := p.WebReputation
	if len(wr.BlockedDomains) > maxDomains || len(wr.AllowedDomains) > maxDomains {
		return fmt.Errorf("web reputation: at most %d domains per list", maxDomains)
	}
	for _, d := range append(append([]string{}, wr.BlockedDomains...), wr.AllowedDomains...) {
		if !domainRe.MatchString(d) {
			return fmt.Errorf("web reputation: %q is not a domain name", d)
		}
	}

	ips := p.IntrusionPrevention
	if ips.MaxFailures < 2 || ips.MaxFailures > 100 {
		return fmt.Errorf("intrusion prevention: failed logins must be between 2 and 100")
	}
	if ips.WindowSeconds < 10 || ips.WindowSeconds > 86400 {
		return fmt.Errorf("intrusion prevention: window must be between 10 seconds and a day")
	}
	if ips.BanMinutes > 7*24*60 {
		return fmt.Errorf("intrusion prevention: ban at most 7 days")
	}
	if len(ips.Allow) > maxAllow {
		return fmt.Errorf("intrusion prevention: at most %d allowed addresses", maxAllow)
	}
	for _, a := range ips.Allow {
		if _, err := parsePrefix(a); err != nil {
			return fmt.Errorf("intrusion prevention: %q is not an IP or CIDR", a)
		}
	}

	dc := p.DeviceControl
	if dc.UsbStorage != USBStorageAllow && dc.UsbStorage != USBStorageBlock {
		return fmt.Errorf("device control: USB storage must be allow or block")
	}
	if len(dc.AllowedDevices) > maxDevices {
		return fmt.Errorf("device control: at most %d allowed devices", maxDevices)
	}
	for _, d := range dc.AllowedDevices {
		if !deviceRe.MatchString(d) {
			return fmt.Errorf("device control: %q is not a vendor:product ID like 0781:5583", d)
		}
	}

	ac := p.ApplicationControl
	if len(ac.BlockedPaths) > maxAppPaths || len(ac.BlockedSha256) > maxAppHashes {
		return fmt.Errorf("application control: at most %d paths and %d hashes", maxAppPaths, maxAppHashes)
	}
	for _, s := range ac.BlockedPaths {
		if !strings.HasPrefix(s, "/") {
			return fmt.Errorf("application control: path %q must be absolute", s)
		}
		if _, err := filepath.Match(s, "/"); err != nil {
			return fmt.Errorf("application control: bad pattern %q", s)
		}
	}
	for _, h := range ac.BlockedSha256 {
		if !sha256Re.MatchString(h) {
			return fmt.Errorf("application control: %q is not a SHA-256", h)
		}
	}
	if ac.Enabled && len(ac.BlockedPaths)+len(ac.BlockedSha256) == 0 {
		return fmt.Errorf("application control: add at least one path or hash")
	}
	return nil
}

// AppRule reports which application control rule matches a file, if any.
func AppRule(ac *xdrv1.ApplicationControlPolicy, path, sha string) string {
	if ac == nil {
		return ""
	}
	if sha != "" {
		for _, h := range ac.BlockedSha256 {
			if h == sha {
				return "sha256 " + h
			}
		}
	}
	for _, p := range ac.BlockedPaths {
		if path != "" && Matches(path, []string{p}) {
			return "path " + p
		}
	}
	return ""
}

// DomainListed reports whether host is one of the domains or a subdomain of one.
func DomainListed(host string, domains map[string]bool) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for host != "" {
		if domains[host] {
			return true
		}
		i := strings.IndexByte(host, '.')
		if i < 0 {
			return false
		}
		host = host[i+1:]
	}
	return false
}

// WebReputationRules renders the table that rejects outbound connections,
// including from containers, to the given addresses.
func WebReputationRules(addrs []netip.Prefix) string {
	var v4, v6 []string
	for _, p := range addrs {
		if p.Addr().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	set := func(name, typ string, elems []string) string {
		s := fmt.Sprintf("\tset %s {\n\t\ttype %s\n\t\tflags interval\n\t\tauto-merge\n", name, typ)
		if len(elems) > 0 {
			s += "\t\telements = { " + strings.Join(elems, ", ") + " }\n"
		}
		return s + "\t}\n"
	}
	var b strings.Builder
	t := WebReputationTable
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\ntable inet %s {\n", t, t, t)
	b.WriteString(set("bad4", "ipv4_addr", v4))
	b.WriteString(set("bad6", "ipv6_addr", v6))
	for _, hook := range []string{"output", "forward"} {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority -5; policy accept;\n", hook, hook)
		b.WriteString("\t\tip daddr @bad4 counter reject\n\t\tip6 daddr @bad6 counter reject\n\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// IntrusionRules creates the ban table, keeping bans already in it.
func IntrusionRules() string {
	t := IntrusionTable
	return fmt.Sprintf(`add table inet %[1]s
add set inet %[1]s banned4 { type ipv4_addr; flags timeout; }
add set inet %[1]s banned6 { type ipv6_addr; flags timeout; }
add chain inet %[1]s input { type filter hook input priority -5; policy accept; }
flush chain inet %[1]s input
add rule inet %[1]s input ip saddr @banned4 counter drop
add rule inet %[1]s input ip6 saddr @banned6 counter drop
`, t)
}

// Ban adds an address to the ban table for the given minutes.
func Ban(a netip.Addr, minutes uint32) string {
	set := "banned4"
	if !a.Is4() {
		set = "banned6"
	}
	return fmt.Sprintf("add element inet %s %s { %s timeout %dm }\n", IntrusionTable, set, a, minutes)
}

// DeleteTable removes a table whether or not it exists.
func DeleteTable(name string) string {
	return fmt.Sprintf("add table inet %s\ndelete table inet %s\n", name, name)
}
