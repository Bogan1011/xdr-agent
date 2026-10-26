package detect

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/netip"
	"path"
	"regexp"
	"strings"

	"github.com/Bogan1011/xdr-agent/internal/server/store"
	"github.com/Bogan1011/xdr-agent/internal/yara"
)

//go:embed rules
var builtin embed.FS

// Builtin returns the shipped rules, keyed by id. Sigma ids come from the
// rule; YARA ids are "yara-" plus the file name.
func Builtin() ([]store.Rule, error) {
	var out []store.Rule
	err := fs.WalkDir(builtin, "rules", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := builtin.ReadFile(p)
		if err != nil {
			return err
		}
		var r *store.Rule
		switch path.Ext(p) {
		case ".yml":
			r, err = RuleFromSigma(string(raw))
		case ".yar":
			r, err = RuleFromYara("yara-"+strings.TrimSuffix(path.Base(p), ".yar"), string(raw), "")
		default:
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		r.Builtin, r.Enabled = true, true
		out = append(out, *r)
		return nil
	})
	return out, err
}

// RuleFromSigma validates Sigma source and fills the rule's metadata from it.
func RuleFromSigma(src string) (*store.Rule, error) {
	s, err := ParseSigma(src)
	if err != nil {
		return nil, err
	}
	return &store.Rule{ID: s.ID, Kind: "sigma", Name: s.Title, Description: s.Description, Severity: s.Level, Source: src}, nil
}

// RuleFromYara validates YARA source. The severity comes from the first
// rule's meta "severity" unless one is given.
func RuleFromYara(id, src, severity string) (*store.Rule, error) {
	rs, err := yara.Compile(src)
	if err != nil {
		return nil, err
	}
	if rs.Len() == 0 {
		return nil, fmt.Errorf("no rules found")
	}
	first := rs.Rules()[0]
	names := make([]string, 0, rs.Len())
	for _, r := range rs.Rules() {
		names = append(names, r.Name)
	}
	if severity == "" {
		severity = levels[strings.ToLower(first.Meta["severity"])]
	}
	if severity == "" {
		severity = "high"
	}
	if _, ok := levels[severity]; !ok {
		return nil, fmt.Errorf("unknown severity %q", severity)
	}
	return &store.Rule{
		ID: id, Kind: "yara", Name: strings.Join(names, ", "), Description: first.Meta["description"],
		Severity: severity, Source: src,
	}, nil
}

// YaraBundle concatenates enabled YARA rules for the agents and returns
// the bundle with its version. It fails if the rules clash, for example two
// files defining the same rule name.
func YaraBundle(rules []store.Rule) (string, string, error) {
	var b strings.Builder
	for _, r := range rules {
		if r.Kind == "yara" && r.Enabled {
			b.WriteString(r.Source)
			b.WriteString("\n")
		}
	}
	src := b.String()
	if _, err := yara.Compile(src); err != nil {
		return "", "", err
	}
	if src == "" {
		return "", "", nil
	}
	sum := sha256.Sum256([]byte(src))
	return src, hex.EncodeToString(sum[:8]), nil
}

// Match is one detection on one event.
type Match struct {
	RuleID   string
	Name     string
	Kind     string // sigma, ioc, yara
	Severity string
	Tags     []string
	Response []string
	// Detail explains what matched, e.g. the IOC value.
	Detail string
}

// Engine is an immutable snapshot of the detection content.
type Engine struct {
	sigma   []*Sigma
	yaraSev map[string]string // YARA rule name to severity
	hashes  map[string]store.IOC
	ips     map[netip.Addr]store.IOC
	nets    []netIOC
	domains map[string]store.IOC
}

type netIOC struct {
	p   netip.Prefix
	ioc store.IOC
}

// NewEngine compiles rules and IOCs. Rules that fail to compile are skipped
// and reported, so one bad rule cannot stop detection.
func NewEngine(rules []store.Rule, iocs []store.IOC) (*Engine, []error) {
	e := &Engine{
		yaraSev: map[string]string{},
		hashes:  map[string]store.IOC{},
		ips:     map[netip.Addr]store.IOC{},
		domains: map[string]store.IOC{},
	}
	var errs []error
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		switch r.Kind {
		case "sigma":
			s, err := ParseSigma(r.Source)
			if err != nil {
				errs = append(errs, fmt.Errorf("rule %s: %w", r.ID, err))
				continue
			}
			e.sigma = append(e.sigma, s)
		case "yara":
			rs, err := yara.Compile(r.Source)
			if err != nil {
				errs = append(errs, fmt.Errorf("rule %s: %w", r.ID, err))
				continue
			}
			for _, y := range rs.Rules() {
				e.yaraSev[y.Name] = r.Severity
			}
		}
	}
	for _, i := range iocs {
		switch i.Type {
		case "sha256":
			e.hashes[strings.ToLower(i.Value)] = i
		case "ip":
			if p, err := netip.ParsePrefix(i.Value); err == nil {
				e.nets = append(e.nets, netIOC{p.Masked(), i})
			} else if a, err := netip.ParseAddr(i.Value); err == nil {
				e.ips[a.Unmap()] = i
			}
		case "domain":
			e.domains[strings.ToLower(i.Value)] = i
		}
	}
	return e, errs
}

// Counts reports how much content the engine holds.
func (e *Engine) Counts() (sigma, yaraRules, iocs int) {
	return len(e.sigma), len(e.yaraSev), len(e.hashes) + len(e.ips) + len(e.nets) + len(e.domains)
}

var hostRe = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b`)

// Evaluate returns every detection for the event.
func (e *Engine) Evaluate(ev *store.Event) []Match {
	var out []Match
	for _, s := range e.sigma {
		if s.Match(ev) {
			out = append(out, Match{
				RuleID: s.ID, Name: s.Title, Kind: "sigma", Severity: s.Level, Tags: s.Tags, Response: s.Response,
			})
		}
	}
	if ev.Type == "yara_match" {
		for _, name := range strings.Split(ev.Args, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			sev := e.yaraSev[name]
			if sev == "" {
				sev = "high"
			}
			out = append(out, Match{
				RuleID: "yara:" + name, Name: "YARA: " + name, Kind: "yara", Severity: sev,
				Detail: ev.Path, Tags: []string{"attack.t1204"},
			})
		}
	}
	if ev.SHA256 != "" {
		if i, ok := e.hashes[strings.ToLower(ev.SHA256)]; ok {
			out = append(out, iocMatch(i, ev.SHA256))
		}
	}
	if ev.RemoteAddr != "" {
		if a, err := netip.ParseAddr(ev.RemoteAddr); err == nil {
			a = a.Unmap()
			if i, ok := e.ips[a]; ok {
				out = append(out, iocMatch(i, ev.RemoteAddr))
			} else {
				for _, n := range e.nets {
					if n.p.Contains(a) {
						out = append(out, iocMatch(n.ioc, ev.RemoteAddr))
						break
					}
				}
			}
		}
	}
	if len(e.domains) > 0 && ev.Type == "process_exec" && ev.Args != "" {
		// No DNS telemetry yet: look for known-bad domains on command lines
		// (curl, wget, nc, ...), including subdomains of listed domains.
		seen := false
		for _, h := range hostRe.FindAllString(ev.Args, 20) {
			h = strings.ToLower(h)
			for d := h; d != "" && !seen; {
				if i, ok := e.domains[d]; ok {
					out = append(out, iocMatch(i, h))
					seen = true
				}
				_, rest, ok := strings.Cut(d, ".")
				if !ok {
					break
				}
				d = rest
			}
		}
	}
	return out
}

func iocMatch(i store.IOC, val string) Match {
	sev := i.Severity
	if sev == "" {
		sev = "high"
	}
	name := fmt.Sprintf("IOC match: %s %s", i.Type, i.Value)
	if i.Source != "" {
		name += " (" + i.Source + ")"
	}
	return Match{RuleID: "ioc:" + i.Type, Name: name, Kind: "ioc", Severity: sev, Detail: val}
}

// DedupeKey groups repeats of the same detection on the same thing, so a
// noisy rule raises one alert with a count instead of thousands.
func DedupeKey(m Match, ev *store.Event) string {
	h := sha256.New()
	for _, s := range []string{m.RuleID, m.Detail, ev.Exe, ev.Path, ev.RemoteAddr, ev.SHA256} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}
