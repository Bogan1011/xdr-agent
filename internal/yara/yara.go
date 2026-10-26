// Package yara is a pure-Go engine for a practical subset of the YARA rule
// language, so the agent stays a static binary without libyara.
//
// Supported: rule modifiers private and global, tags, meta, text strings
// with nocase/wide/ascii/fullword, hex strings with wildcards, nibbles, jumps
// and alternatives, regular expressions with i/s flags, and conditions built
// from and/or/not, comparisons, $a, #a, $a at N, $a in (N..M), "N|any|all|none
// of them|($a*,...)", filesize, uint8/16/32[be](N), true/false and references
// to earlier rules. Modules (import) and for-loops are not supported.
package yara

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// maxMatches caps the offsets kept per string, which bounds #a and memory.
const maxMatches = 1000

type Rules struct {
	rules []*rule
}

type rule struct {
	name    string
	private bool
	global  bool
	tags    []string
	meta    map[string]string
	strings []*str
	cond    node
}

// Rule describes a compiled rule.
type Rule struct {
	Name string
	Tags []string
	Meta map[string]string
}

// Len is the number of compiled rules.
func (r *Rules) Len() int { return len(r.rules) }

// Rules lists the compiled rules.
func (r *Rules) Rules() []Rule {
	out := make([]Rule, 0, len(r.rules))
	for _, x := range r.rules {
		out = append(out, Rule{Name: x.name, Tags: x.tags, Meta: x.meta})
	}
	return out
}

// Scan returns the names of the non-private rules that match data.
func (r *Rules) Scan(data []byte) []string {
	if r == nil {
		return nil
	}
	sc := &scan{data: data, matches: map[*str][]int{}, results: map[string]bool{}}
	var out []string
	for _, x := range r.rules {
		ok := x.cond.eval(sc) != 0
		sc.results[x.name] = ok
		if x.global && !ok {
			return nil
		}
		if ok && !x.private {
			out = append(out, x.name)
		}
	}
	return out
}

// --- strings ---

type strKind int

const (
	strText strKind = iota
	strHex
	strRegex
)

type str struct {
	name     string
	kind     strKind
	patterns [][]byte // text: one per encoding
	nocase   bool
	fullword bool
	hex      []hexTok
	re       *regexp.Regexp
}

type scan struct {
	data    []byte
	lower   []byte
	matches map[*str][]int
	results map[string]bool
}

func (sc *scan) lowered() []byte {
	if sc.lower == nil {
		sc.lower = asciiLower(sc.data)
	}
	return sc.lower
}

func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// offsets returns where s matches, computed once per scan.
func (sc *scan) offsets(s *str) []int {
	if m, ok := sc.matches[s]; ok {
		return m
	}
	var m []int
	switch s.kind {
	case strText:
		data := sc.data
		if s.nocase {
			data = sc.lowered()
		}
		for _, p := range s.patterns {
			for i := 0; len(m) < maxMatches; {
				j := bytes.Index(data[i:], p)
				if j < 0 {
					break
				}
				at := i + j
				if !s.fullword || ((at == 0 || !isWordByte(data[at-1])) && (at+len(p) >= len(data) || !isWordByte(data[at+len(p)]))) {
					m = append(m, at)
				}
				i = at + 1
			}
		}
	case strHex:
		m = hexFindAll(s.hex, sc.data)
	case strRegex:
		for _, loc := range s.re.FindAllIndex(sc.data, maxMatches) {
			m = append(m, loc[0])
		}
	}
	sc.matches[s] = m
	return m
}

// --- hex strings ---

type hexKind int

const (
	hexByte hexKind = iota
	hexJump
	hexAlt
)

type hexTok struct {
	kind     hexKind
	val      byte
	mask     byte
	min, max int
	alts     [][]hexTok
}

// hexMatch reports the end offset of a match of toks at pos, or -1.
func hexMatch(toks []hexTok, data []byte, pos int) int {
	if len(toks) == 0 {
		return pos
	}
	t := toks[0]
	switch t.kind {
	case hexByte:
		if pos < len(data) && data[pos]&t.mask == t.val {
			return hexMatch(toks[1:], data, pos+1)
		}
	case hexJump:
		for n := t.min; n <= t.max && pos+n <= len(data); n++ {
			if end := hexMatch(toks[1:], data, pos+n); end >= 0 {
				return end
			}
		}
	case hexAlt:
		for _, alt := range t.alts {
			rest := append(append([]hexTok{}, alt...), toks[1:]...)
			if end := hexMatch(rest, data, pos); end >= 0 {
				return end
			}
		}
	}
	return -1
}

func hexFindAll(toks []hexTok, data []byte) []int {
	// Use the leading literal bytes to jump to candidate offsets.
	var prefix []byte
	for _, t := range toks {
		if t.kind != hexByte || t.mask != 0xFF {
			break
		}
		prefix = append(prefix, t.val)
	}
	var m []int
	for i := 0; i < len(data) && len(m) < maxMatches; i++ {
		if len(prefix) > 0 {
			j := bytes.Index(data[i:], prefix)
			if j < 0 {
				break
			}
			i += j
		}
		if hexMatch(toks, data, i) >= 0 {
			m = append(m, i)
		}
	}
	return m
}

// --- conditions ---

type node interface{ eval(*scan) int64 }

type (
	constNode int64
	filesize  struct{}
	andNode   struct{ l, r node }
	orNode    struct{ l, r node }
	notNode   struct{ x node }
	ruleRef   string
	strFound  struct{ s *str }
	strCount  struct{ s *str }
	strAt     struct {
		s  *str
		at node
	}
	strIn struct {
		s      *str
		lo, hi node
	}
	ofNode struct {
		// n < 0 means all; quantity is compared with >=, or == 0 for none.
		n    node
		all  bool
		none bool
		set  []*str
	}
	cmpNode struct {
		op   string
		l, r node
	}
	uintNode struct {
		size int
		be   bool
		off  node
	}
)

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func (c constNode) eval(*scan) int64   { return int64(c) }
func (filesize) eval(sc *scan) int64   { return int64(len(sc.data)) }
func (n andNode) eval(sc *scan) int64  { return b2i(n.l.eval(sc) != 0 && n.r.eval(sc) != 0) }
func (n orNode) eval(sc *scan) int64   { return b2i(n.l.eval(sc) != 0 || n.r.eval(sc) != 0) }
func (n notNode) eval(sc *scan) int64  { return b2i(n.x.eval(sc) == 0) }
func (n ruleRef) eval(sc *scan) int64  { return b2i(sc.results[string(n)]) }
func (n strFound) eval(sc *scan) int64 { return b2i(len(sc.offsets(n.s)) > 0) }
func (n strCount) eval(sc *scan) int64 { return int64(len(sc.offsets(n.s))) }

func (n strAt) eval(sc *scan) int64 {
	at := n.at.eval(sc)
	for _, o := range sc.offsets(n.s) {
		if int64(o) == at {
			return 1
		}
	}
	return 0
}

func (n strIn) eval(sc *scan) int64 {
	lo, hi := n.lo.eval(sc), n.hi.eval(sc)
	for _, o := range sc.offsets(n.s) {
		if int64(o) >= lo && int64(o) <= hi {
			return 1
		}
	}
	return 0
}

func (n ofNode) eval(sc *scan) int64 {
	found := int64(0)
	for _, s := range n.set {
		if len(sc.offsets(s)) > 0 {
			found++
		}
	}
	switch {
	case n.all:
		return b2i(found == int64(len(n.set)))
	case n.none:
		return b2i(found == 0)
	default:
		return b2i(found >= n.n.eval(sc))
	}
}

func (n cmpNode) eval(sc *scan) int64 {
	l, r := n.l.eval(sc), n.r.eval(sc)
	switch n.op {
	case "==":
		return b2i(l == r)
	case "!=":
		return b2i(l != r)
	case "<":
		return b2i(l < r)
	case "<=":
		return b2i(l <= r)
	case ">":
		return b2i(l > r)
	case ">=":
		return b2i(l >= r)
	}
	return 0
}

func (n uintNode) eval(sc *scan) int64 {
	off := n.off.eval(sc)
	if off < 0 || off+int64(n.size) > int64(len(sc.data)) {
		return -1
	}
	b := sc.data[off : off+int64(n.size)]
	var v uint64
	for i := 0; i < n.size; i++ {
		if n.be {
			v = v<<8 | uint64(b[i])
		} else {
			v |= uint64(b[i]) << (8 * i)
		}
	}
	return int64(v)
}

// --- parser ---

// Compile parses YARA source into rules.
func Compile(src string) (*Rules, error) {
	p := &parser{src: src, line: 1}
	rs := &Rules{}
	names := map[string]bool{}
	for {
		p.skipSpace()
		if p.pos >= len(p.src) {
			return rs, nil
		}
		r, err := p.rule(names)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", p.line, err)
		}
		names[r.name] = true
		rs.rules = append(rs.rules, r)
	}
}

type parser struct {
	src  string
	pos  int
	line int
}

func (p *parser) skipSpace() {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == '\n':
			p.line++
			p.pos++
		case c == ' ' || c == '\t' || c == '\r':
			p.pos++
		case strings.HasPrefix(p.src[p.pos:], "//"):
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
		case strings.HasPrefix(p.src[p.pos:], "/*"):
			end := strings.Index(p.src[p.pos+2:], "*/")
			if end < 0 {
				p.pos = len(p.src)
				return
			}
			p.line += strings.Count(p.src[p.pos:p.pos+2+end], "\n")
			p.pos += end + 4
		default:
			return
		}
	}
}

func isIdent(c byte) bool { return isWordByte(c) }

// word reads an identifier, optionally prefixed by $, # or @, with a
// trailing * allowed for string sets.
func (p *parser) word() string {
	p.skipSpace()
	start := p.pos
	if p.pos < len(p.src) && strings.IndexByte("$#@", p.src[p.pos]) >= 0 {
		p.pos++
	}
	for p.pos < len(p.src) && isIdent(p.src[p.pos]) {
		p.pos++
	}
	if p.pos < len(p.src) && p.src[p.pos] == '*' && p.pos > start && p.src[start] == '$' {
		p.pos++
	}
	return p.src[start:p.pos]
}

func (p *parser) peekWord() string {
	pos, line := p.pos, p.line
	w := p.word()
	p.pos, p.line = pos, line
	return w
}

func (p *parser) accept(s string) bool {
	p.skipSpace()
	if !strings.HasPrefix(p.src[p.pos:], s) {
		return false
	}
	// Keywords must not run into a following identifier.
	if isIdent(s[len(s)-1]) && p.pos+len(s) < len(p.src) && isIdent(p.src[p.pos+len(s)]) {
		return false
	}
	p.pos += len(s)
	return true
}

func (p *parser) expect(s string) error {
	if !p.accept(s) {
		return fmt.Errorf("expected %q near %q", s, p.near())
	}
	return nil
}

func (p *parser) near() string {
	end := min(p.pos+20, len(p.src))
	return p.src[p.pos:end]
}

func (p *parser) rule(seen map[string]bool) (*rule, error) {
	r := &rule{meta: map[string]string{}}
	for {
		switch {
		case p.accept("import"), p.accept("include"):
			return nil, fmt.Errorf("modules and includes are not supported")
		case p.accept("private"):
			r.private = true
			continue
		case p.accept("global"):
			r.global = true
			continue
		}
		break
	}
	if err := p.expect("rule"); err != nil {
		return nil, err
	}
	r.name = p.word()
	if r.name == "" || !isIdent(r.name[0]) || (r.name[0] >= '0' && r.name[0] <= '9') {
		return nil, fmt.Errorf("invalid rule name near %q", p.near())
	}
	if seen[r.name] {
		return nil, fmt.Errorf("duplicate rule %q", r.name)
	}
	if p.accept(":") {
		for {
			p.skipSpace()
			if p.pos < len(p.src) && p.src[p.pos] == '{' {
				break
			}
			t := p.word()
			if t == "" {
				return nil, fmt.Errorf("invalid tag near %q", p.near())
			}
			r.tags = append(r.tags, t)
		}
	}
	if err := p.expect("{"); err != nil {
		return nil, err
	}
	if p.accept("meta") {
		if err := p.expect(":"); err != nil {
			return nil, err
		}
		for {
			w := p.peekWord()
			if w == "strings" || w == "condition" || w == "" {
				break
			}
			p.word()
			if err := p.expect("="); err != nil {
				return nil, err
			}
			p.skipSpace()
			if p.pos < len(p.src) && p.src[p.pos] == '"' {
				v, err := p.quoted()
				if err != nil {
					return nil, err
				}
				r.meta[w] = string(v)
			} else {
				r.meta[w] = p.word()
			}
		}
	}
	strs := map[string]*str{}
	anon := 0
	if p.accept("strings") {
		if err := p.expect(":"); err != nil {
			return nil, err
		}
		for {
			p.skipSpace()
			if p.pos >= len(p.src) || p.src[p.pos] != '$' {
				break
			}
			name := p.word()
			if name == "$" {
				anon++
				name = fmt.Sprintf("$#anon%d", anon)
			}
			if strs[name] != nil {
				return nil, fmt.Errorf("duplicate string %s in rule %s", name, r.name)
			}
			if err := p.expect("="); err != nil {
				return nil, err
			}
			s, err := p.stringDef(name)
			if err != nil {
				return nil, fmt.Errorf("string %s: %w", name, err)
			}
			strs[name] = s
			r.strings = append(r.strings, s)
		}
	}
	if err := p.expect("condition"); err != nil {
		return nil, err
	}
	if err := p.expect(":"); err != nil {
		return nil, err
	}
	c := &condParser{p: p, rule: r, strs: strs, rules: seen}
	cond, err := c.expr()
	if err != nil {
		return nil, err
	}
	r.cond = cond
	if err := p.expect("}"); err != nil {
		return nil, err
	}
	return r, nil
}

func (p *parser) quoted() ([]byte, error) {
	p.pos++ // opening quote
	var out []byte
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch c {
		case '"':
			p.pos++
			return out, nil
		case '\n':
			return nil, fmt.Errorf("unterminated string")
		case '\\':
			if p.pos+1 >= len(p.src) {
				return nil, fmt.Errorf("unterminated string")
			}
			e := p.src[p.pos+1]
			p.pos += 2
			switch e {
			case 'n':
				out = append(out, '\n')
			case 't':
				out = append(out, '\t')
			case 'r':
				out = append(out, '\r')
			case '\\', '"':
				out = append(out, e)
			case 'x':
				if p.pos+2 > len(p.src) {
					return nil, fmt.Errorf("bad \\x escape")
				}
				var v byte
				if _, err := fmt.Sscanf(p.src[p.pos:p.pos+2], "%02x", &v); err != nil {
					return nil, fmt.Errorf("bad \\x escape")
				}
				out = append(out, v)
				p.pos += 2
			default:
				return nil, fmt.Errorf("unknown escape \\%c", e)
			}
		default:
			out = append(out, c)
			p.pos++
		}
	}
	return nil, fmt.Errorf("unterminated string")
}

func (p *parser) stringDef(name string) (*str, error) {
	p.skipSpace()
	if p.pos >= len(p.src) {
		return nil, fmt.Errorf("missing value")
	}
	s := &str{name: name}
	switch p.src[p.pos] {
	case '"':
		v, err := p.quoted()
		if err != nil {
			return nil, err
		}
		if len(v) == 0 {
			return nil, fmt.Errorf("empty string")
		}
		s.kind = strText
		wide, ascii := false, false
		for {
			switch {
			case p.accept("nocase"):
				s.nocase = true
			case p.accept("wide"):
				wide = true
			case p.accept("ascii"):
				ascii = true
			case p.accept("fullword"):
				s.fullword = true
			case p.accept("private"):
			default:
				goto done
			}
		}
	done:
		if s.nocase {
			v = asciiLower(v)
		}
		if !wide || ascii {
			s.patterns = append(s.patterns, v)
		}
		if wide {
			w := make([]byte, 0, 2*len(v))
			for _, c := range v {
				w = append(w, c, 0)
			}
			s.patterns = append(s.patterns, w)
		}
	case '{':
		p.pos++
		end := strings.IndexByte(p.src[p.pos:], '}')
		if end < 0 {
			return nil, fmt.Errorf("unterminated hex string")
		}
		body := p.src[p.pos : p.pos+end]
		p.line += strings.Count(body, "\n")
		p.pos += end + 1
		toks, err := parseHex(body)
		if err != nil {
			return nil, err
		}
		s.kind, s.hex = strHex, toks
	case '/':
		p.pos++
		var b strings.Builder
		for {
			if p.pos >= len(p.src) || p.src[p.pos] == '\n' {
				return nil, fmt.Errorf("unterminated regular expression")
			}
			c := p.src[p.pos]
			if c == '\\' && p.pos+1 < len(p.src) {
				if p.src[p.pos+1] == '/' {
					b.WriteByte('/')
				} else {
					b.WriteString(p.src[p.pos : p.pos+2])
				}
				p.pos += 2
				continue
			}
			p.pos++
			if c == '/' {
				break
			}
			b.WriteByte(c)
		}
		flags := ""
		for p.pos < len(p.src) && (p.src[p.pos] == 'i' || p.src[p.pos] == 's') {
			flags += string(p.src[p.pos])
			p.pos++
		}
		expr := b.String()
		if flags != "" {
			expr = "(?" + flags + ")" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, err
		}
		s.kind, s.re = strRegex, re
		for p.accept("nocase") || p.accept("ascii") || p.accept("wide") || p.accept("fullword") || p.accept("private") {
		}
	default:
		return nil, fmt.Errorf("expected a string, hex string or regular expression")
	}
	return s, nil
}

func parseHex(body string) ([]hexTok, error) {
	// Strip comments inside hex strings.
	var clean strings.Builder
	for i := 0; i < len(body); i++ {
		if strings.HasPrefix(body[i:], "//") {
			for i < len(body) && body[i] != '\n' {
				i++
			}
			continue
		}
		c := body[i]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			clean.WriteByte(c)
		}
	}
	h := &hexParser{s: clean.String()}
	toks, err := h.seq(false)
	if err != nil {
		return nil, err
	}
	if h.i != len(h.s) {
		return nil, fmt.Errorf("unexpected %q in hex string", h.s[h.i:])
	}
	if len(toks) == 0 || toks[0].kind == hexJump || toks[len(toks)-1].kind == hexJump {
		return nil, fmt.Errorf("hex string must start and end with bytes")
	}
	return toks, nil
}

type hexParser struct {
	s string
	i int
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// seq parses tokens until the end, or until | or ) inside an alternative.
func (h *hexParser) seq(inAlt bool) ([]hexTok, error) {
	var toks []hexTok
	for h.i < len(h.s) {
		c := h.s[h.i]
		switch {
		case c == '|' || c == ')':
			if !inAlt {
				return nil, fmt.Errorf("unexpected %q in hex string", c)
			}
			return toks, nil
		case c == '(':
			h.i++
			var alts [][]hexTok
			for {
				alt, err := h.seq(true)
				if err != nil {
					return nil, err
				}
				alts = append(alts, alt)
				if h.i >= len(h.s) {
					return nil, fmt.Errorf("unterminated alternative")
				}
				if h.s[h.i] == ')' {
					h.i++
					break
				}
				h.i++ // |
			}
			toks = append(toks, hexTok{kind: hexAlt, alts: alts})
		case c == '[':
			end := strings.IndexByte(h.s[h.i:], ']')
			if end < 0 {
				return nil, fmt.Errorf("unterminated jump")
			}
			spec := h.s[h.i+1 : h.i+end]
			h.i += end + 1
			var lo, hi int
			if a, b, ok := strings.Cut(spec, "-"); ok {
				if _, err := fmt.Sscanf(a, "%d", &lo); a != "" && err != nil {
					return nil, fmt.Errorf("bad jump [%s]", spec)
				}
				if b == "" {
					hi = 1 << 20
				} else if _, err := fmt.Sscanf(b, "%d", &hi); err != nil {
					return nil, fmt.Errorf("bad jump [%s]", spec)
				}
			} else {
				if _, err := fmt.Sscanf(spec, "%d", &lo); err != nil {
					return nil, fmt.Errorf("bad jump [%s]", spec)
				}
				hi = lo
			}
			if lo < 0 || hi < lo {
				return nil, fmt.Errorf("bad jump [%s]", spec)
			}
			toks = append(toks, hexTok{kind: hexJump, min: lo, max: hi})
		default:
			if h.i+1 >= len(h.s) {
				return nil, fmt.Errorf("odd number of hex digits")
			}
			t := hexTok{kind: hexByte}
			for k, d := range []byte{h.s[h.i], h.s[h.i+1]} {
				shift := uint(4 * (1 - k))
				if d == '?' {
					continue
				}
				v, ok := hexNibble(d)
				if !ok {
					return nil, fmt.Errorf("bad hex digit %q", d)
				}
				t.val |= v << shift
				t.mask |= 0xF << shift
			}
			h.i += 2
			toks = append(toks, t)
		}
	}
	if inAlt {
		return nil, fmt.Errorf("unterminated alternative")
	}
	return toks, nil
}

type condParser struct {
	p     *parser
	rule  *rule
	strs  map[string]*str
	rules map[string]bool
}

func (c *condParser) expr() (node, error) {
	l, err := c.and()
	if err != nil {
		return nil, err
	}
	for c.p.accept("or") {
		r, err := c.and()
		if err != nil {
			return nil, err
		}
		l = orNode{l, r}
	}
	return l, nil
}

func (c *condParser) and() (node, error) {
	l, err := c.not()
	if err != nil {
		return nil, err
	}
	for c.p.accept("and") {
		r, err := c.not()
		if err != nil {
			return nil, err
		}
		l = andNode{l, r}
	}
	return l, nil
}

func (c *condParser) not() (node, error) {
	if c.p.accept("not") {
		x, err := c.not()
		if err != nil {
			return nil, err
		}
		return notNode{x}, nil
	}
	return c.cmp()
}

func (c *condParser) cmp() (node, error) {
	l, err := c.primary()
	if err != nil {
		return nil, err
	}
	for _, op := range []string{"==", "!=", "<=", ">=", "<", ">"} {
		if c.p.accept(op) {
			r, err := c.primary()
			if err != nil {
				return nil, err
			}
			return cmpNode{op, l, r}, nil
		}
	}
	return l, nil
}

func (c *condParser) number() (int64, bool) {
	p := c.p
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.src) && (isIdent(p.src[p.pos])) {
		p.pos++
	}
	lit := p.src[start:p.pos]
	if lit == "" || lit[0] < '0' || lit[0] > '9' {
		p.pos = start
		return 0, false
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(lit, "KB"):
		lit, mult = strings.TrimSuffix(lit, "KB"), 1024
	case strings.HasSuffix(lit, "MB"):
		lit, mult = strings.TrimSuffix(lit, "MB"), 1024*1024
	}
	var v int64
	var err error
	if strings.HasPrefix(lit, "0x") || strings.HasPrefix(lit, "0X") {
		v, err = strconv.ParseInt(lit[2:], 16, 64)
	} else {
		v, err = strconv.ParseInt(lit, 10, 64)
	}
	if err != nil {
		p.pos = start
		return 0, false
	}
	return v * mult, true
}

func (c *condParser) strRef(name string) (*str, error) {
	s := c.strs[name]
	if s == nil {
		return nil, fmt.Errorf("undefined string %s in rule %s", name, c.rule.name)
	}
	return s, nil
}

// set parses "them" or "($a, $b*)".
func (c *condParser) set() ([]*str, error) {
	if c.p.accept("them") {
		if len(c.rule.strings) == 0 {
			return nil, fmt.Errorf("rule %s has no strings", c.rule.name)
		}
		return c.rule.strings, nil
	}
	if err := c.p.expect("("); err != nil {
		return nil, err
	}
	var out []*str
	for {
		w := c.p.word()
		if !strings.HasPrefix(w, "$") {
			return nil, fmt.Errorf("expected a string identifier near %q", c.p.near())
		}
		if prefix, ok := strings.CutSuffix(w, "*"); ok {
			n := 0
			for _, s := range c.rule.strings {
				if strings.HasPrefix(s.name, prefix) {
					out = append(out, s)
					n++
				}
			}
			if n == 0 {
				return nil, fmt.Errorf("no strings match %s in rule %s", w, c.rule.name)
			}
		} else {
			s, err := c.strRef(w)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		if c.p.accept(")") {
			return out, nil
		}
		if err := c.p.expect(","); err != nil {
			return nil, err
		}
	}
}

func (c *condParser) of(n *ofNode) (node, error) {
	if err := c.p.expect("of"); err != nil {
		return nil, err
	}
	set, err := c.set()
	if err != nil {
		return nil, err
	}
	n.set = set
	return *n, nil
}

func (c *condParser) primary() (node, error) {
	p := c.p
	if p.accept("(") {
		x, err := c.expr()
		if err != nil {
			return nil, err
		}
		return x, p.expect(")")
	}
	if v, ok := c.number(); ok {
		pos, line := p.pos, p.line
		if p.accept("of") {
			p.pos, p.line = pos, line
			return c.of(&ofNode{n: constNode(v)})
		}
		return constNode(v), nil
	}
	switch {
	case p.accept("true"):
		return constNode(1), nil
	case p.accept("false"):
		return constNode(0), nil
	case p.accept("filesize"):
		return filesize{}, nil
	case p.accept("any"):
		return c.of(&ofNode{n: constNode(1)})
	case p.accept("all"):
		return c.of(&ofNode{all: true})
	case p.accept("none"):
		return c.of(&ofNode{none: true})
	}
	for _, size := range []int{8, 16, 32} {
		for _, be := range []bool{true, false} {
			kw := fmt.Sprintf("uint%d", size)
			if be {
				kw += "be"
			}
			if p.accept(kw) {
				if err := p.expect("("); err != nil {
					return nil, err
				}
				off, err := c.primary()
				if err != nil {
					return nil, err
				}
				return uintNode{size: size / 8, be: be, off: off}, p.expect(")")
			}
		}
	}
	w := p.word()
	switch {
	case strings.HasPrefix(w, "$"):
		s, err := c.strRef(w)
		if err != nil {
			return nil, err
		}
		if p.accept("at") {
			at, err := c.primary()
			if err != nil {
				return nil, err
			}
			return strAt{s, at}, nil
		}
		if p.accept("in") {
			if err := p.expect("("); err != nil {
				return nil, err
			}
			lo, err := c.primary()
			if err != nil {
				return nil, err
			}
			if err := p.expect(".."); err != nil {
				return nil, err
			}
			hi, err := c.primary()
			if err != nil {
				return nil, err
			}
			return strIn{s, lo, hi}, p.expect(")")
		}
		return strFound{s}, nil
	case strings.HasPrefix(w, "#"):
		s, err := c.strRef("$" + w[1:])
		if err != nil {
			return nil, err
		}
		return strCount{s}, nil
	case w != "" && c.rules[w]:
		return ruleRef(w), nil
	case w == "for":
		return nil, fmt.Errorf("for loops are not supported")
	case w != "":
		return nil, fmt.Errorf("unknown identifier %q in rule %s", w, c.rule.name)
	}
	return nil, fmt.Errorf("unexpected %q in condition of rule %s", p.near(), c.rule.name)
}
