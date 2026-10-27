package agent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/agent/collector"
	"github.com/Bogan1011/xdr-agent/internal/policy"
)

// sshFailRe matches sshd's failed login lines, e.g.
// "Failed password for invalid user bob from 203.0.113.5 port 4242 ssh2" or
// "Invalid user bob from 203.0.113.5 port 4242". An unknown user logs both,
// so it counts twice, which is fine for brute force.
var sshFailRe = regexp.MustCompile(`(?:Failed \S+ for|Invalid user) .*?from ([0-9A-Fa-f:.]+) port \d+`)

// Intrusion watches sshd's log for brute force: an address that fails to log
// in max_failures times within the window is reported and, with prevention
// on, banned with nftables for ban_minutes.
type Intrusion struct {
	Log     *slog.Logger
	Emit    collector.Emit
	Console func() ([]netip.Addr, error)

	mu      sync.Mutex
	pol     *xdrv1.IntrusionPreventionPolicy
	allow   []netip.Prefix
	fails   map[netip.Addr][]time.Time
	bans    map[netip.Addr]time.Time
	stop    context.CancelFunc
	tableOn bool
	err     string
}

func NewIntrusion(log *slog.Logger, emit collector.Emit, console func() ([]netip.Addr, error)) *Intrusion {
	return &Intrusion{Log: log, Emit: emit, Console: console, fails: map[netip.Addr][]time.Time{}, bans: map[netip.Addr]time.Time{}}
}

// SetPolicy starts, changes or stops the watcher.
func (s *Intrusion) SetPolicy(ctx context.Context, p *xdrv1.IntrusionPreventionPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if proto.Equal(p, s.pol) && (s.stop != nil) == p.GetEnabled() {
		return
	}
	s.pol = proto.Clone(p).(*xdrv1.IntrusionPreventionPolicy)
	s.allow = nil
	for _, a := range p.GetAllow() {
		if pr, err := netip.ParsePrefix(a); err == nil {
			s.allow = append(s.allow, pr.Masked())
		} else if ad, err := netip.ParseAddr(a); err == nil {
			s.allow = append(s.allow, netip.PrefixFrom(ad.Unmap(), ad.Unmap().BitLen()))
		}
	}
	// The console is resolved here, not per failed login.
	if s.Console != nil {
		if cs, err := s.Console(); err == nil {
			for _, c := range cs {
				s.allow = append(s.allow, netip.PrefixFrom(c.Unmap(), c.Unmap().BitLen()))
			}
		}
	}
	clear(s.fails)

	wantTable := p.GetEnabled() && p.GetPrevent()
	if wantTable && !s.tableOn {
		if err := nft(policy.IntrusionRules()); err != nil {
			s.err = err.Error()
			s.Log.Error("intrusion prevention table not applied", "err", err)
		} else {
			s.tableOn, s.err = true, ""
		}
	} else if !wantTable && (s.tableOn || tablePresent(policy.IntrusionTable)) {
		if err := nft(policy.DeleteTable(policy.IntrusionTable)); err != nil {
			s.err = err.Error()
		} else {
			s.tableOn, s.err = false, ""
			clear(s.bans)
		}
	}

	if !p.GetEnabled() {
		if s.stop != nil {
			s.stop()
			s.stop = nil
			s.Log.Info("intrusion prevention stopped")
		}
		return
	}
	if s.stop == nil {
		wctx, cancel := context.WithCancel(ctx)
		s.stop = cancel
		go s.watch(wctx)
		s.Log.Info("intrusion prevention started", "prevent", p.Prevent, "max_failures", p.MaxFailures,
			"window_seconds", p.WindowSeconds)
	}
}

// watch follows sshd's messages in the journal, or the auth log on hosts
// without journald, restarting the reader when it ends.
func (s *Intrusion) watch(ctx context.Context) {
	for ctx.Err() == nil {
		var err error
		if _, lerr := exec.LookPath("journalctl"); lerr == nil {
			err = s.followJournal(ctx)
		} else {
			err = s.followFile(ctx)
		}
		if ctx.Err() != nil {
			return
		}
		s.Log.Warn("sshd log reader stopped, restarting in 10s", "err", err)
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
		}
	}
}

func (s *Intrusion) followJournal(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "journalctl", "-f", "-n", "0", "-o", "cat",
		"_COMM=sshd", "_COMM=sshd-session", "SYSLOG_IDENTIFIER=sshd")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	s.scan(out)
	return cmd.Wait()
}

// followFile tails /var/log/auth.log or /var/log/secure, reopening it when
// it is rotated.
func (s *Intrusion) followFile(ctx context.Context) error {
	var path string
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if _, err := os.Stat(p); err == nil {
			path = p
			break
		}
	}
	if path == "" {
		return fmt.Errorf("no journalctl, /var/log/auth.log or /var/log/secure")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { f.Close() }()
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	r := bufio.NewReader(f)
	var partial string
	for {
		line, err := r.ReadString('\n')
		if err == nil {
			s.line(partial + line)
			partial = ""
			continue
		}
		partial += line
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
		st, serr := os.Stat(path)
		cur, _ := f.Seek(0, io.SeekCurrent)
		fst, _ := f.Stat()
		if serr == nil && (!os.SameFile(st, fst) || st.Size() < cur) {
			nf, err := os.Open(path)
			if err != nil {
				return err
			}
			f.Close()
			f, r, partial = nf, bufio.NewReader(nf), ""
		}
	}
}

func (s *Intrusion) scan(r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		s.line(sc.Text())
	}
}

// line counts a failed login and acts when the address reaches the limit.
func (s *Intrusion) line(l string) {
	m := sshFailRe.FindStringSubmatch(l)
	if m == nil {
		return
	}
	a, err := netip.ParseAddr(m[1])
	if err != nil {
		return
	}
	s.failed(a.Unmap(), time.Now())
}

func (s *Intrusion) allowed(a netip.Addr) bool {
	if a.IsLoopback() || a.IsUnspecified() {
		return true
	}
	for _, p := range s.allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (s *Intrusion) failed(a netip.Addr, now time.Time) {
	s.mu.Lock()
	pol := s.pol
	if pol == nil || !pol.Enabled || s.allowed(a) {
		s.mu.Unlock()
		return
	}
	window := time.Duration(pol.WindowSeconds) * time.Second
	ts := s.fails[a][:0:0]
	for _, t := range s.fails[a] {
		if now.Sub(t) < window {
			ts = append(ts, t)
		}
	}
	ts = append(ts, now)
	if len(ts) < int(pol.MaxFailures) {
		if len(s.fails) > 50000 {
			clear(s.fails)
		}
		s.fails[a] = ts
		s.mu.Unlock()
		return
	}
	delete(s.fails, a)
	action := "detected"
	detail := fmt.Sprintf("%d failed SSH logins in %s", len(ts), window)
	if pol.Prevent {
		if err := nft(policy.Ban(a, pol.BanMinutes)); err != nil {
			s.Log.Error("ban failed", "addr", a, "err", err)
			s.err = err.Error()
		} else {
			action = "banned"
			detail += fmt.Sprintf(", banned for %d minutes", pol.BanMinutes)
			s.bans[a] = now.Add(time.Duration(pol.BanMinutes) * time.Minute)
		}
	}
	s.mu.Unlock()
	s.Log.Warn("SSH brute force", "addr", a, "action", action, "failures", len(ts))
	e := collector.NewEvent(xdrv1.EventType_EVENT_TYPE_INTRUSION)
	e.Payload = &xdrv1.Event_Policy{Policy: &xdrv1.PolicyEvent{Action: action, Detail: detail, RemoteAddr: a.String()}}
	s.Emit(e)
}

// Status reports whether the module runs and how many addresses are banned.
func (s *Intrusion) Status() (on bool, banned int, err string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for a, until := range s.bans {
		if now.After(until) {
			delete(s.bans, a)
		}
	}
	return s.stop != nil, len(s.bans), s.err
}
