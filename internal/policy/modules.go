package policy

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

const (
	// WebReputationTable and IntrusionTable are the nftables tables the
	// agent owns for those modules.
	WebReputationTable = "xdr_webrep"
	IntrusionTable     = "xdr_ips"

	maxDomains         = 1000
	maxAllow           = 100
	maxDevices         = 100
	maxAppPaths        = 500
	maxAppHashes       = 5000
	USBStorageAllow    = "allow"
	USBStorageReadOnly = "read_only"
	USBStorageBlock    = "block"
)

var (
	domainRe = regexp.MustCompile(`^(?i)([a-z0-9_]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$`)
	deviceRe = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{4}$`)
	sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

	// DefaultAllowedPaths is what lockdown allows when the policy names
	// nothing: the system and package-managed locations, including
	// container images, so the host keeps booting and updating.
	DefaultAllowedPaths = []string{
		"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/opt", "/snap",
		"/etc", "/var/lib/docker", "/var/lib/containerd", "/var/lib/snapd",
	}
	// DefaultScriptPaths are the world-writable places droppers use.
	DefaultScriptPaths = []string{"/tmp", "/var/tmp", "/dev/shm"}
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
	if p.SelfProtection == nil {
		p.SelfProtection = &xdrv1.SelfProtectionPolicy{}
	}
	ac := p.ApplicationControl
	for _, l := range [][]string{ac.BlockedSha256, ac.AllowedSha256} {
		for i, h := range l {
			l[i] = strings.ToLower(strings.TrimSpace(h))
		}
	}
	if ac.Lockdown && len(ac.AllowedPaths) == 0 {
		ac.AllowedPaths = append([]string{}, DefaultAllowedPaths...)
	}
	if ac.BlockScripts && len(ac.ScriptPaths) == 0 {
		ac.ScriptPaths = append([]string{}, DefaultScriptPaths...)
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
	if dc.UsbStorage != USBStorageAllow && dc.UsbStorage != USBStorageReadOnly && dc.UsbStorage != USBStorageBlock {
		return fmt.Errorf("device control: USB storage must be allow, read_only or block")
	}
	if sp := p.SelfProtection; sp.Enabled && sp.PasswordHash == "" && sp.NewPassword == "" {
		return fmt.Errorf("self-protection: set a password")
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
	if len(ac.BlockedPaths) > maxAppPaths || len(ac.BlockedSha256) > maxAppHashes ||
		len(ac.AllowedPaths) > maxAppPaths || len(ac.AllowedSha256) > maxAppHashes || len(ac.ScriptPaths) > maxAppPaths {
		return fmt.Errorf("application control: at most %d paths and %d hashes per list", maxAppPaths, maxAppHashes)
	}
	for _, s := range append(append(append([]string{}, ac.BlockedPaths...), ac.AllowedPaths...), ac.ScriptPaths...) {
		if !strings.HasPrefix(s, "/") {
			return fmt.Errorf("application control: path %q must be absolute", s)
		}
		if _, err := filepath.Match(s, "/"); err != nil {
			return fmt.Errorf("application control: bad pattern %q", s)
		}
	}
	for _, h := range append(append([]string{}, ac.BlockedSha256...), ac.AllowedSha256...) {
		if !sha256Re.MatchString(h) {
			return fmt.Errorf("application control: %q is not a SHA-256", h)
		}
	}
	if ac.Enabled && !ac.Lockdown && !ac.BlockScripts && len(ac.BlockedPaths)+len(ac.BlockedSha256) == 0 {
		return fmt.Errorf("application control: add at least one path or hash, or turn on lockdown or script blocking")
	}
	for _, s := range ac.ScriptPaths {
		if s == "/" {
			return fmt.Errorf("application control: script folders cannot include /")
		}
	}
	return nil
}

// AppRule reports which application control rule stops a file, if any. The
// block lists come first; in lockdown anything not on the allow-list is
// stopped too. sha is "" when the file could not be hashed.
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
	if ac.Lockdown && !AppAllowed(ac, path, sha) {
		return "lockdown (not on the allow-list)"
	}
	return ""
}

// AppAllowed reports whether lockdown lets the file run.
func AppAllowed(ac *xdrv1.ApplicationControlPolicy, path, sha string) bool {
	if path != "" && Matches(path, ac.AllowedPaths) {
		return true
	}
	return sha != "" && slices.Contains(ac.AllowedSha256, sha)
}

// AppNeedsHash reports whether AppRule may need the file's hash to decide
// on path.
func AppNeedsHash(ac *xdrv1.ApplicationControlPolicy, path string) bool {
	if ac == nil {
		return false
	}
	if len(ac.BlockedSha256) > 0 {
		return true
	}
	return ac.Lockdown && len(ac.AllowedSha256) > 0 && !Matches(path, ac.AllowedPaths)
}

var interpreterRe = regexp.MustCompile(`^(sh|bash|dash|zsh|ksh|mksh|fish|busybox|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|node|nodejs|lua[0-9.]*|tclsh[0-9.]*|pwsh|osascript)$`)

// IsInterpreter reports whether exe is a shell or script interpreter.
func IsInterpreter(exe string) bool {
	return interpreterRe.MatchString(filepath.Base(exe))
}

// Options that take the next argument as their value, by interpreter.
var valueOpts = map[string][]string{
	"python": {"-W", "-X", "-Q"},
	"sh":     {"-o", "-O", "--rcfile", "--init-file"},
	"perl":   {"-I", "-M", "-m"},
	"ruby":   {"-I", "-r"},
	"node":   {"-r", "--require", "--import"},
}

// Options after which the program is inline code or a module, not a file.
var codeOpts = map[string][]string{
	"python": {"-c", "-m"},
	"sh":     {"-c"},
	"perl":   {"-e", "-E"},
	"ruby":   {"-e"},
	"node":   {"-e", "--eval", "-p", "--print"},
}

func family(exe string) string {
	base := filepath.Base(exe)
	for _, f := range []string{"python", "perl", "ruby", "node"} {
		if strings.HasPrefix(base, f) {
			return f
		}
	}
	return "sh"
}

// ScriptArg returns the script file an interpreter was started with, as an
// absolute path: the first argument after argv[0] that is not an option.
// Inline code (bash -c, python -c) has no script and returns "".
func ScriptArg(exe string, args []string, cwd string) string {
	fam := family(exe)
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 >= len(args) {
				return ""
			}
			a = args[i+1]
		} else if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+") {
			if slices.Contains(codeOpts[fam], a) {
				return ""
			}
			if slices.Contains(valueOpts[fam], a) {
				i++
			}
			continue
		}
		return absPath(a, cwd)
	}
	return ""
}

// ScriptOpened reports whether path is one of the process's arguments, i.e.
// an interpreter opening the script it was asked to run.
func ScriptOpened(args []string, cwd, path string) bool {
	for _, a := range args[min(1, len(args)):] {
		if a != "" && absPath(a, cwd) == path {
			return true
		}
	}
	return false
}

func absPath(a, cwd string) string {
	if a == "" {
		return ""
	}
	if !filepath.IsAbs(a) {
		if cwd == "" {
			return ""
		}
		a = filepath.Join(cwd, a)
	}
	return filepath.Clean(a)
}

// ScriptRule reports the script folder rule an interpreter run breaks, if
// script blocking is on and exe runs a script from one of the folders.
func ScriptRule(ac *xdrv1.ApplicationControlPolicy, exe string, args []string, cwd string) (script, rule string) {
	if ac == nil || !ac.BlockScripts || !IsInterpreter(exe) {
		return "", ""
	}
	script = ScriptArg(exe, args, cwd)
	for _, p := range ac.ScriptPaths {
		if script != "" && Matches(script, []string{p}) {
			return script, "script in " + p
		}
	}
	return "", ""
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
