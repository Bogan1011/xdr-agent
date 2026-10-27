// Package detect evaluates telemetry against Sigma-style rules, IOC lists
// and agent YARA results, and turns hits into alerts.
package detect

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

// Sigma is a compiled Sigma-style rule. The format follows Sigma: logsource,
// named selections of field|modifier: value(s), and a condition over the
// selection names. An extra top-level "response" list names actions to run
// automatically when the rule fires (kill_process, quarantine_file,
// isolate_host).
type Sigma struct {
	ID          string
	Title       string
	Description string
	Level       string
	Tags        []string
	Response    []string

	types []string // event types the rule applies to; empty means all
	cond  cnode
}

type sigmaDoc struct {
	ID          string         `yaml:"id"`
	Title       string         `yaml:"title"`
	Description string         `yaml:"description"`
	Level       string         `yaml:"level"`
	Tags        []string       `yaml:"tags"`
	Response    []string       `yaml:"response"`
	Logsource   map[string]any `yaml:"logsource"`
	Detection   map[string]any `yaml:"detection"`
}

// Fields maps the field names rules may use (lower case, Sigma aliases
// included) to the telemetry column they read.
var Fields = map[string]func(*store.Event) string{
	"type":             func(e *store.Event) string { return e.Type },
	"hostname":         func(e *store.Event) string { return e.Hostname },
	"exe":              func(e *store.Event) string { return e.Exe },
	"image":            func(e *store.Event) string { return e.Exe },
	"cmdline":          func(e *store.Event) string { return e.Args },
	"commandline":      func(e *store.Event) string { return e.Args },
	"args":             func(e *store.Event) string { return e.Args },
	"user":             func(e *store.Event) string { return e.User },
	"uid":              func(e *store.Event) string { return strconv.FormatUint(uint64(e.UID), 10) },
	"pid":              func(e *store.Event) string { return strconv.FormatUint(uint64(e.PID), 10) },
	"ppid":             func(e *store.Event) string { return strconv.FormatUint(uint64(e.PPID), 10) },
	"parent_exe":       func(e *store.Event) string { return e.ParentExe },
	"parentimage":      func(e *store.Event) string { return e.ParentExe },
	"cwd":              func(e *store.Event) string { return e.Cwd },
	"currentdirectory": func(e *store.Event) string { return e.Cwd },
	"sha256":           func(e *store.Event) string { return e.SHA256 },
	"hash":             func(e *store.Event) string { return e.SHA256 },
	"path":             func(e *store.Event) string { return e.Path },
	"targetfilename":   func(e *store.Event) string { return e.Path },
	"old_path":         func(e *store.Event) string { return e.OldPath },
	"size":             func(e *store.Event) string { return strconv.FormatUint(e.Size, 10) },
	"mode":             func(e *store.Event) string { return strconv.FormatUint(uint64(e.Mode), 8) },
	"protocol":         func(e *store.Event) string { return e.Protocol },
	"local_addr":       func(e *store.Event) string { return e.LocalAddr },
	"local_port":       func(e *store.Event) string { return strconv.FormatUint(uint64(e.LocalPort), 10) },
	"sourceport":       func(e *store.Event) string { return strconv.FormatUint(uint64(e.LocalPort), 10) },
	"remote_addr":      func(e *store.Event) string { return e.RemoteAddr },
	"destinationip":    func(e *store.Event) string { return e.RemoteAddr },
	"remote_port":      func(e *store.Event) string { return strconv.FormatUint(uint64(e.RemotePort), 10) },
	"destinationport":  func(e *store.Event) string { return strconv.FormatUint(uint64(e.RemotePort), 10) },
	"yara_rules":       func(e *store.Event) string { return e.Args },
	"action":           func(e *store.Event) string { return e.Path },
	"detail":           func(e *store.Event) string { return e.Args },
}

var categories = map[string][]string{
	"process_creation":    {"process_exec"},
	"process_termination": {"process_exit"},
	"shell_command":       {"shell_command"},
	"file_event":          {"file_create", "file_modify", "file_rename", "file_attrib"},
	"file_change":         {"file_modify"},
	"file_rename":         {"file_rename"},
	"file_delete":         {"file_delete"},
	"network_connection":  {"net_connect"},
	"network_accept":      {"net_accept"},
	"agent_tamper":        {"agent_tamper"},
	"network_listen":      {"net_listen"},
	"yara":                {"yara_match"},
	"fim":                 {"fim_change"},
	"exec_blocked":        {"exec_blocked"},
	"web_reputation":      {"web_reputation"},
	"intrusion":           {"intrusion"},
	"device_control":      {"device_control"},
	"app_control":         {"app_control"},
}

var levels = map[string]string{
	"informational": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical",
}

// Responses are the automatic actions a rule may request.
var Responses = []string{"kill_process", "quarantine_file", "isolate_host"}

// ParseSigma compiles one rule from YAML.
func ParseSigma(src string) (*Sigma, error) {
	var d sigmaDoc
	if err := yaml.Unmarshal([]byte(src), &d); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	if d.Title == "" {
		return nil, fmt.Errorf("title is required")
	}
	if d.ID == "" {
		return nil, fmt.Errorf("id is required")
	}
	r := &Sigma{ID: d.ID, Title: d.Title, Description: d.Description, Tags: d.Tags, Response: d.Response}
	lvl, ok := levels[strings.ToLower(d.Level)]
	if !ok {
		return nil, fmt.Errorf("level must be one of informational, low, medium, high, critical")
	}
	r.Level = lvl
	for _, a := range d.Response {
		if !slices.Contains(Responses, a) {
			return nil, fmt.Errorf("unknown response %q (allowed: %s)", a, strings.Join(Responses, ", "))
		}
	}
	if cat, _ := d.Logsource["category"].(string); cat != "" {
		types, ok := categories[strings.ToLower(cat)]
		if !ok {
			names := make([]string, 0, len(categories))
			for k := range categories {
				names = append(names, k)
			}
			slices.Sort(names)
			return nil, fmt.Errorf("unknown logsource category %q (supported: %s)", cat, strings.Join(names, ", "))
		}
		r.types = types
	}
	if len(d.Detection) == 0 {
		return nil, fmt.Errorf("detection is required")
	}
	sels := map[string]cnode{}
	var condSrc []string
	for name, v := range d.Detection {
		if name == "condition" {
			switch c := v.(type) {
			case string:
				condSrc = []string{c}
			case []any:
				for _, x := range c {
					s, ok := x.(string)
					if !ok {
						return nil, fmt.Errorf("condition must be a string")
					}
					condSrc = append(condSrc, s)
				}
			default:
				return nil, fmt.Errorf("condition must be a string")
			}
			continue
		}
		n, err := parseSelection(v)
		if err != nil {
			return nil, fmt.Errorf("selection %s: %w", name, err)
		}
		sels[name] = n
	}
	if len(condSrc) == 0 {
		return nil, fmt.Errorf("detection.condition is required")
	}
	for _, cs := range condSrc {
		c, err := parseCondition(cs, sels)
		if err != nil {
			return nil, fmt.Errorf("condition: %w", err)
		}
		if r.cond == nil {
			r.cond = c
		} else {
			r.cond = cor{r.cond, c}
		}
	}
	return r, nil
}

// Match reports whether the event fires the rule.
func (r *Sigma) Match(e *store.Event) bool {
	if len(r.types) > 0 && !slices.Contains(r.types, e.Type) {
		return false
	}
	return r.cond.eval(e)
}

// --- selections ---

type cnode interface{ eval(*store.Event) bool }

type (
	cand []cnode
	cor  struct{ l, r cnode }
	cnot struct{ x cnode }
	// anyOf is true when at least n of the nodes are; n = len means all.
	anyOf struct {
		n     int
		nodes []cnode
	}
	fieldMatch struct {
		get      func(*store.Event) string
		all      bool
		matchers []matcher
	}
	keywords []matcher
)

func (a cand) eval(e *store.Event) bool {
	for _, n := range a {
		if !n.eval(e) {
			return false
		}
	}
	return true
}
func (o cor) eval(e *store.Event) bool  { return o.l.eval(e) || o.r.eval(e) }
func (n cnot) eval(e *store.Event) bool { return !n.x.eval(e) }
func (a anyOf) eval(e *store.Event) bool {
	hits := 0
	for _, n := range a.nodes {
		if n.eval(e) {
			hits++
			if hits >= a.n {
				return true
			}
		}
	}
	return false
}

func (f fieldMatch) eval(e *store.Event) bool {
	v := f.get(e)
	for _, m := range f.matchers {
		ok := m.match(v)
		if f.all && !ok {
			return false
		}
		if !f.all && ok {
			return true
		}
	}
	return f.all
}

// keywords match anywhere in the command line, executable or path.
func (k keywords) eval(e *store.Event) bool {
	for _, m := range k {
		if m.match(e.Args) || m.match(e.Exe) || m.match(e.Path) {
			return true
		}
	}
	return false
}

type matcher struct {
	lit    string // lower-cased literal when re is nil
	mode   string // equals, contains, startswith, endswith
	re     *regexp.Regexp
	prefix netip.Prefix
}

func (m matcher) match(v string) bool {
	if m.prefix.IsValid() {
		a, err := netip.ParseAddr(v)
		return err == nil && m.prefix.Contains(a.Unmap())
	}
	if m.re != nil {
		return m.re.MatchString(v)
	}
	v = strings.ToLower(v)
	switch m.mode {
	case "contains":
		return strings.Contains(v, m.lit)
	case "startswith":
		return strings.HasPrefix(v, m.lit)
	case "endswith":
		return strings.HasSuffix(v, m.lit)
	}
	return v == m.lit
}

func newMatcher(val string, mode string) (matcher, error) {
	switch mode {
	case "re":
		re, err := regexp.Compile(val)
		return matcher{re: re}, err
	case "cidr":
		p, err := netip.ParsePrefix(val)
		if err != nil {
			if a, err2 := netip.ParseAddr(val); err2 == nil {
				p, err = netip.PrefixFrom(a, a.BitLen()), nil
			}
		}
		return matcher{prefix: p.Masked()}, err
	}
	if !strings.ContainsAny(val, "*?") {
		return matcher{lit: strings.ToLower(val), mode: mode}, nil
	}
	// Sigma wildcards: * any run, ? one character, \ escapes.
	var b strings.Builder
	b.WriteString("(?is)")
	if mode == "equals" || mode == "startswith" {
		b.WriteString("^")
	}
	for i := 0; i < len(val); i++ {
		c := val[i]
		switch {
		case c == '\\' && i+1 < len(val) && strings.IndexByte(`*?\`, val[i+1]) >= 0:
			b.WriteString(regexp.QuoteMeta(val[i+1 : i+2]))
			i++
		case c == '*':
			b.WriteString(".*")
		case c == '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(val[i : i+1]))
		}
	}
	if mode == "equals" || mode == "endswith" {
		b.WriteString("$")
	}
	re, err := regexp.Compile(b.String())
	return matcher{re: re}, err
}

func scalars(v any) ([]string, error) {
	switch x := v.(type) {
	case nil:
		return []string{""}, nil
	case string:
		return []string{x}, nil
	case int, int64, uint64, float64, bool:
		return []string{fmt.Sprint(x)}, nil
	case []any:
		var out []string
		for _, i := range x {
			s, err := scalars(i)
			if err != nil {
				return nil, err
			}
			out = append(out, s...)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported value %v", v)
}

func parseSelection(v any) (cnode, error) {
	switch x := v.(type) {
	case map[string]any:
		var and cand
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			parts := strings.Split(k, "|")
			get := Fields[strings.ToLower(parts[0])]
			if get == nil {
				return nil, fmt.Errorf("unknown field %q", parts[0])
			}
			f := fieldMatch{get: get}
			mode := "equals"
			for _, mod := range parts[1:] {
				switch mod {
				case "contains", "startswith", "endswith", "re", "cidr":
					mode = mod
				case "all":
					f.all = true
				default:
					return nil, fmt.Errorf("unsupported modifier %q", mod)
				}
			}
			vals, err := scalars(x[k])
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			for _, val := range vals {
				m, err := newMatcher(val, mode)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", k, err)
				}
				f.matchers = append(f.matchers, m)
			}
			and = append(and, f)
		}
		return and, nil
	case []any:
		if len(x) == 0 {
			return nil, fmt.Errorf("empty list")
		}
		if _, isMap := x[0].(map[string]any); isMap {
			n := anyOf{n: 1}
			for _, i := range x {
				s, err := parseSelection(i)
				if err != nil {
					return nil, err
				}
				n.nodes = append(n.nodes, s)
			}
			return n, nil
		}
		vals, err := scalars(x)
		if err != nil {
			return nil, err
		}
		var k keywords
		for _, val := range vals {
			m, err := newMatcher(val, "contains")
			if err != nil {
				return nil, err
			}
			k = append(k, m)
		}
		return k, nil
	}
	return nil, fmt.Errorf("must be a map of fields or a list")
}

// --- conditions ---

func tokenize(s string) []string {
	var out []string
	cur := ""
	flush := func() {
		if cur != "" {
			out = append(out, cur)
			cur = ""
		}
	}
	for _, c := range s {
		switch c {
		case '(', ')':
			flush()
			out = append(out, string(c))
		case ' ', '\t', '\n':
			flush()
		default:
			cur += string(c)
		}
	}
	flush()
	return out
}

type condParser struct {
	toks []string
	i    int
	sels map[string]cnode
}

func parseCondition(s string, sels map[string]cnode) (cnode, error) {
	p := &condParser{toks: tokenize(s), sels: sels}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.i != len(p.toks) {
		return nil, fmt.Errorf("unexpected %q", p.toks[p.i])
	}
	return n, nil
}

func (p *condParser) peek() string {
	if p.i < len(p.toks) {
		return strings.ToLower(p.toks[p.i])
	}
	return ""
}

func (p *condParser) or() (cnode, error) {
	l, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.peek() == "or" {
		p.i++
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		l = cor{l, r}
	}
	return l, nil
}

func (p *condParser) and() (cnode, error) {
	l, err := p.not()
	if err != nil {
		return nil, err
	}
	for p.peek() == "and" {
		p.i++
		r, err := p.not()
		if err != nil {
			return nil, err
		}
		l = cand{l, r}
	}
	return l, nil
}

func (p *condParser) not() (cnode, error) {
	if p.peek() == "not" {
		p.i++
		x, err := p.not()
		if err != nil {
			return nil, err
		}
		return cnot{x}, nil
	}
	return p.primary()
}

func (p *condParser) primary() (cnode, error) {
	t := p.peek()
	if t == "" {
		return nil, fmt.Errorf("unexpected end")
	}
	p.i++
	if t == "(" {
		n, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("missing )")
		}
		p.i++
		return n, nil
	}
	if p.peek() == "of" {
		p.i++
		target := ""
		if p.i < len(p.toks) {
			target = p.toks[p.i]
			p.i++
		}
		var nodes []cnode
		names := make([]string, 0, len(p.sels))
		for name := range p.sels {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			if target == "them" {
				if !strings.HasPrefix(name, "_") {
					nodes = append(nodes, p.sels[name])
				}
			} else if pre, ok := strings.CutSuffix(target, "*"); ok && strings.HasPrefix(name, pre) || name == target {
				nodes = append(nodes, p.sels[name])
			}
		}
		if len(nodes) == 0 {
			return nil, fmt.Errorf("no selection matches %q", target)
		}
		switch t {
		case "all":
			return anyOf{n: len(nodes), nodes: nodes}, nil
		case "any":
			return anyOf{n: 1, nodes: nodes}, nil
		}
		n, err := strconv.Atoi(t)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("bad quantifier %q", t)
		}
		return anyOf{n: n, nodes: nodes}, nil
	}
	n, ok := p.sels[p.toks[p.i-1]]
	if !ok {
		return nil, fmt.Errorf("unknown selection %q", p.toks[p.i-1])
	}
	return n, nil
}
