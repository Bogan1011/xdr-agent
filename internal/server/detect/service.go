package detect

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

const feedInterval = 6 * time.Hour

// Service owns the live detection engine, raises alerts on ingest, queues
// response commands and refreshes IOC feeds.
type Service struct {
	DB  *store.Postgres
	Log *slog.Logger

	engine  atomic.Pointer[Engine]
	content atomic.Pointer[Content]
	reload  sync.Mutex
}

// Content is what agents download: the YARA bundle, the hash block list for
// exec blocking and the IP and domain IOCs for web reputation.
type Content struct {
	Version, Yara      string
	Blocked            []byte
	BadIPs, BadDomains []string
}

// maxBadNetwork caps each of the IP and domain lists sent to agents.
const maxBadNetwork = 50000

// maxBlocked caps the hash block list sent to agents (16 MiB of digests).
const maxBlocked = 500000

// Init seeds the built-in rules and builds the first engine.
func (s *Service) Init(ctx context.Context) error {
	rules, err := Builtin()
	if err != nil {
		return fmt.Errorf("built-in rules: %w", err)
	}
	if err := s.DB.SeedRules(ctx, rules); err != nil {
		return fmt.Errorf("seed rules: %w", err)
	}
	return s.Reload(ctx)
}

// Reload rebuilds the engine after rules or IOCs change.
func (s *Service) Reload(ctx context.Context) error {
	s.reload.Lock()
	defer s.reload.Unlock()
	rules, err := s.DB.ListRules(ctx)
	if err != nil {
		return err
	}
	iocs, err := s.DB.AllIOCs(ctx)
	if err != nil {
		return err
	}
	e, errs := NewEngine(rules, iocs)
	for _, err := range errs {
		s.Log.Warn("skipping rule", "err", err)
	}
	s.engine.Store(e)
	src, _, err := YaraBundle(rules)
	blocked := BlockList(iocs, maxBlocked)
	ips, domains := NetworkBlockList(iocs, maxBadNetwork)
	ver := ContentVersion(src, blocked, ips, domains)
	if err != nil {
		// Keep serving the previous bundle; saving rules validates the bundle,
		// so this only happens with rules written to the database directly.
		s.Log.Error("YARA bundle does not compile, agents keep the previous rules", "err", err)
	} else {
		s.content.Store(&Content{Version: ver, Yara: src, Blocked: blocked, BadIPs: ips, BadDomains: domains})
	}
	sig, yr, n := e.Counts()
	s.Log.Info("detection content loaded", "sigma_rules", sig, "yara_rules", yr, "iocs", n,
		"blocked_hashes", len(blocked)/32, "content_version", ver)
	return nil
}

// Content is the current agent content; the zero value when none is loaded.
func (s *Service) Content() Content {
	if c := s.content.Load(); c != nil {
		return *c
	}
	return Content{}
}

// Process evaluates ingested events and raises alerts.
func (s *Service) Process(ctx context.Context, events []store.Event) {
	e := s.engine.Load()
	if e == nil {
		return
	}
	for i := range events {
		ev := &events[i]
		for _, m := range e.Evaluate(ev) {
			raw, _ := json.Marshal(ev)
			a := &store.Alert{
				AgentID: ev.AgentID, Hostname: ev.Hostname, RuleID: m.RuleID, RuleName: m.Name, Kind: m.Kind,
				Severity: m.Severity, Tags: m.Tags, Detail: m.Detail, Event: raw,
			}
			id, created, err := s.DB.RaiseAlert(ctx, a, DedupeKey(m, ev))
			if err != nil {
				s.Log.Error("raise alert", "rule", m.RuleID, "err", err)
				continue
			}
			if !created {
				continue
			}
			s.Log.Info("alert raised", "alert_id", id, "rule", m.RuleID, "hostname", ev.Hostname, "severity", m.Severity)
			for _, action := range m.Response {
				s.autoRespond(ctx, id, action, ev)
			}
		}
	}
}

func (s *Service) autoRespond(ctx context.Context, alertID int64, action string, ev *store.Event) {
	args := map[string]string{}
	switch action {
	case "kill_process":
		if ev.PID == 0 {
			return
		}
		args["pid"] = strconv.FormatUint(uint64(ev.PID), 10)
		if ev.Exe != "" {
			args["exe"] = ev.Exe
		}
	case "quarantine_file":
		p := ev.Path
		if p == "" {
			p = ev.Exe
		}
		if p == "" || ev.Type == "file_delete" {
			return
		}
		args["path"] = p
	case "isolate_host":
	default:
		return
	}
	c := &store.Command{AgentID: ev.AgentID, Type: action, Args: args, AlertID: alertID, RequestedBy: "rule"}
	if err := s.QueueCommand(ctx, c); err != nil {
		s.Log.Error("auto response", "action", action, "alert_id", alertID, "err", err)
	}
}

// CommandTypes are the response actions the console can send.
var CommandTypes = []string{"fim_rebaseline", "kill_process", "quarantine_file", "restore_file", "isolate_host", "unisolate_host", "scan_path"}

// ValidateCommand checks a command's arguments before it is queued.
func ValidateCommand(typ string, args map[string]string) error {
	need := func(k string) error {
		if strings.TrimSpace(args[k]) == "" {
			return fmt.Errorf("%s requires %q", typ, k)
		}
		return nil
	}
	switch typ {
	case "kill_process":
		pid, err := strconv.ParseUint(args["pid"], 10, 32)
		if err != nil || pid <= 1 {
			return fmt.Errorf("kill_process requires a pid greater than 1")
		}
	case "quarantine_file", "scan_path":
		if err := need("path"); err != nil {
			return err
		}
		if !strings.HasPrefix(args["path"], "/") {
			return fmt.Errorf("path must be absolute")
		}
	case "restore_file":
		return need("quarantine_id")
	case "update_agent":
		if err := need("version"); err != nil {
			return err
		}
		if len(args["sha256"]) != 64 {
			return fmt.Errorf("update_agent requires a sha256")
		}
	case "isolate_host":
		for _, a := range strings.Split(args["allow"], ",") {
			if a = strings.TrimSpace(a); a == "" {
				continue
			}
			if _, err := netip.ParsePrefix(a); err != nil {
				if _, err := netip.ParseAddr(a); err != nil {
					return fmt.Errorf("allow: %q is not an IP address or CIDR", a)
				}
			}
		}
	case "unisolate_host", "fim_rebaseline":
	case "grant_elevation":
		if err := need("user"); err != nil {
			return err
		}
		if err := need("request_id"); err != nil {
			return err
		}
		if s, err := strconv.ParseUint(args["duration_seconds"], 10, 32); err != nil || s == 0 {
			return fmt.Errorf("grant_elevation requires duration_seconds")
		}
	case "revoke_elevation":
		return need("request_id")
	default:
		return fmt.Errorf("unknown command type %q", typ)
	}
	return nil
}

// QueueCommand validates and stores a command for the agent's next heartbeat.
func (s *Service) QueueCommand(ctx context.Context, c *store.Command) error {
	if c.Args == nil {
		c.Args = map[string]string{}
	}
	if err := ValidateCommand(c.Type, c.Args); err != nil {
		return err
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	c.ID = hex.EncodeToString(b[:])
	if err := s.DB.CreateCommand(ctx, c); err != nil {
		return err
	}
	s.Log.Info("response command queued", "command_id", c.ID, "agent_id", c.AgentID, "type", c.Type, "by", c.RequestedBy)
	return nil
}

// --- IOC feeds ---

var (
	sha256Re = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	domainRe = regexp.MustCompile(`^(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// NormalizeIOC validates an indicator and returns it in canonical form.
func NormalizeIOC(typ, v string) (string, error) {
	v = strings.TrimSpace(v)
	switch typ {
	case "sha256":
		if !sha256Re.MatchString(v) {
			return "", fmt.Errorf("%q is not a SHA-256 hash", v)
		}
		return strings.ToLower(v), nil
	case "ip":
		if p, err := netip.ParsePrefix(v); err == nil {
			return p.Masked().String(), nil
		}
		a, err := netip.ParseAddr(v)
		if err != nil {
			return "", fmt.Errorf("%q is not an IP address or CIDR", v)
		}
		return a.Unmap().String(), nil
	case "domain":
		v = strings.TrimSuffix(strings.ToLower(v), ".")
		if !domainRe.MatchString(v) {
			return "", fmt.Errorf("%q is not a domain name", v)
		}
		return v, nil
	}
	return "", fmt.Errorf("type must be sha256, ip or domain")
}

// ParseFeed extracts indicators of one type from a downloaded list. It
// accepts plain lists and CSVs: comment lines (#, ;, //) are skipped and the
// first field on a line that is a valid indicator is used.
func ParseFeed(typ string, r io.Reader, limit int) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' || strings.HasPrefix(line, "//") {
			continue
		}
		for _, f := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '"' || r == ';' }) {
			// Lists of URLs: take the host.
			if typ == "domain" && strings.Contains(f, "://") {
				f = strings.SplitN(strings.SplitN(f, "://", 2)[1], "/", 2)[0]
				f = strings.Split(f, ":")[0]
			}
			if v, err := NormalizeIOC(typ, f); err == nil {
				if !seen[v] {
					seen[v] = true
					out = append(out, v)
				}
				break
			}
		}
		if len(out) >= limit {
			break
		}
	}
	return out, sc.Err()
}

// RefreshFeed downloads one feed and replaces its indicators.
func (s *Service) RefreshFeed(ctx context.Context, f store.Feed) error {
	err := func() error {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		req, err := http.NewRequestWithContext(cctx, http.MethodGet, f.URL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "xdr-server")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("download: HTTP %d", resp.StatusCode)
		}
		vals, err := ParseFeed(f.Type, io.LimitReader(resp.Body, 200<<20), 500000)
		if err != nil {
			return err
		}
		if len(vals) == 0 {
			return fmt.Errorf("no %s indicators found in the download", f.Type)
		}
		return s.DB.ReplaceFeedIOCs(ctx, f, vals)
	}()
	if err != nil {
		s.Log.Warn("IOC feed refresh failed", "feed", f.Name, "err", err)
		_ = s.DB.SetFeedError(ctx, f.ID, err.Error())
		return err
	}
	s.Log.Info("IOC feed refreshed", "feed", f.Name)
	return s.Reload(ctx)
}

// RunFeeds refreshes enabled feeds that are due, until ctx ends.
func (s *Service) RunFeeds(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		feeds, err := s.DB.ListFeeds(ctx)
		if err != nil {
			s.Log.Warn("list IOC feeds", "err", err)
		}
		for _, f := range feeds {
			if f.Enabled && time.Since(f.LastFetched) > feedInterval {
				_ = s.RefreshFeed(ctx, f)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
