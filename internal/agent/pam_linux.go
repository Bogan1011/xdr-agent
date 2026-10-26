package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

// Privileged access management on the host:
//   - just-in-time sudo: a local user asks with `xdr-agent elevate`, an admin
//     approves in the console, and the agent installs a sudoers drop-in that
//     it removes, ending the user's sudo sessions, when the grant expires or
//     is revoked;
//   - session recording: granted sessions, or every sudo session when the
//     console asks, are recorded by sudo's own I/O logging and uploaded once
//     they finish;
//   - the host's privileged accounts are reported to the console.

const (
	// PamSocket is where `xdr-agent elevate` reaches the running agent.
	PamSocket     = "/run/xdr-agent/pam.sock"
	jitPrefix     = "xdr-jit-"
	recordAllName = "xdr-session-recording"
	pamInterval   = 30 * time.Second
	maxElevation  = 24 * time.Hour
	// inventoryEvery bounds how stale the console's account list can get when
	// nothing changes.
	inventoryEvery = 6 * time.Hour
)

var validUserName = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

type grant struct {
	RequestID string    `json:"request_id"`
	User      string    `json:"user"`
	UID       uint32    `json:"uid"`
	Start     time.Time `json:"start"`
	Until     time.Time `json:"until"`
	// Ended is set once the grant is removed; ended grants are kept for a
	// while so recordings that finish late still map to their request.
	Ended time.Time `json:"ended,omitempty"`
}

type PAM struct {
	log    *slog.Logger
	client xdrv1.AgentServiceClient

	// Paths are fields so tests can point them at a temporary root.
	root       string // prefix for /etc/passwd, /etc/shadow, home directories
	sudoersDir string
	ioDir      string
	stateFile  string
	socket     string
	// validate checks a sudoers file before it is installed.
	validate func(path string) error

	mu        sync.Mutex
	grants    []grant
	recordAll *bool // nil until the console sent a policy
	// requests made through the socket, so a user only sees their own.
	requests map[string]uint32
	lastAsk  map[uint32]time.Time
	// revoked requests, so a grant that arrives after its revoke (both run
	// concurrently) is not installed.
	revoked map[string]bool

	invHash string
	invSent time.Time
}

func newPAM(cfg *Config, log *slog.Logger) *PAM {
	p := &PAM{
		log:        log,
		root:       "/",
		sudoersDir: "/etc/sudoers.d",
		ioDir:      "/var/log/xdr-agent/sudo-io",
		stateFile:  filepath.Join(cfg.StateDir, "pam.json"),
		socket:     PamSocket,
		validate:   visudo,
		requests:   map[string]uint32{},
		lastAsk:    map[uint32]time.Time{},
		revoked:    map[string]bool{},
	}
	p.load()
	return p
}

func visudo(path string) error {
	out, err := exec.Command("visudo", "-cqf", path).CombinedOutput()
	if errors.Is(err, exec.ErrNotFound) {
		return errors.New("sudo is not installed on this host")
	}
	if err != nil {
		return fmt.Errorf("visudo rejected the rule: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *PAM) load() {
	raw, err := os.ReadFile(p.stateFile)
	if err != nil {
		return
	}
	if err := json.Unmarshal(raw, &p.grants); err != nil {
		p.log.Warn("pam state unreadable, starting empty", "err", err)
	}
}

// save must be called with p.mu held.
func (p *PAM) save() {
	raw, _ := json.Marshal(p.grants)
	tmp := p.stateFile + ".tmp"
	err := os.WriteFile(tmp, raw, 0o600)
	if err == nil {
		err = os.Rename(tmp, p.stateFile)
	}
	if err != nil {
		p.log.Error("save pam state", "err", err)
	}
}

func (p *PAM) Run(ctx context.Context, client xdrv1.AgentServiceClient) {
	p.client = client
	go p.serve(ctx)
	t := time.NewTicker(pamInterval)
	defer t.Stop()
	for {
		p.sweep()
		p.uploadSessions(ctx)
		p.reportInventory(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// SetPolicy applies the console's session recording setting.
func (p *PAM) SetPolicy(pol *xdrv1.PamPolicy) {
	on := pol.GetRecordAllSudo()
	p.mu.Lock()
	changed := p.recordAll == nil || *p.recordAll != on
	p.recordAll = &on
	p.mu.Unlock()
	if changed {
		p.applyRecordAll(on)
	}
}

func (p *PAM) applyRecordAll(on bool) {
	path := filepath.Join(p.sudoersDir, recordAllName)
	if !on {
		if err := os.Remove(path); err == nil {
			p.log.Info("recording of all sudo sessions turned off")
		}
		return
	}
	body := "# Managed by xdr-agent: the console records every sudo session on this host.\n" +
		"Defaults log_output, iolog_dir=" + p.ioDir + "/%{user}\n"
	if err := p.install(path, body); err != nil {
		p.log.Error("turn on sudo session recording", "err", err)
		return
	}
	p.log.Info("recording all sudo sessions")
}

// install validates a sudoers drop-in and moves it into place. sudo skips
// files whose name contains a dot, so the temporary file is never live.
func (p *PAM) install(path, body string) error {
	if err := os.MkdirAll(p.ioDir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, []byte(body), 0o440); err != nil {
		return err
	}
	if err := p.validate(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func (p *PAM) grantFile(uid uint32) string {
	return filepath.Join(p.sudoersDir, jitPrefix+strconv.FormatUint(uint64(uid), 10))
}

// sudoersRule is the drop-in for one grant. NOTAFTER makes sudo itself stop
// honouring the rule at expiry, in case the agent is not running then.
func sudoersRule(g grant, ioDir string, notAfter bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by xdr-agent: just-in-time elevation %s, expires %s.\n", g.RequestID, g.Until.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "Defaults:%s log_output, iolog_dir=%s/%%{user}\n", g.User, ioDir)
	if notAfter {
		fmt.Fprintf(&b, "%s ALL=(ALL:ALL) NOTAFTER=%s ALL\n", g.User, g.Until.UTC().Format("20060102150405Z"))
	} else {
		fmt.Fprintf(&b, "%s ALL=(ALL:ALL) ALL\n", g.User)
	}
	return b.String()
}

// Grant gives a user sudo for a limited time.
func (p *PAM) Grant(args map[string]string) (string, error) {
	name, id := args["user"], args["request_id"]
	if !validUserName.MatchString(name) || name == "root" {
		return "", fmt.Errorf("invalid user %q", name)
	}
	if id == "" {
		return "", errors.New("request_id is required")
	}
	secs, err := strconv.ParseUint(args["duration_seconds"], 10, 32)
	d := time.Duration(secs) * time.Second
	if err != nil || d <= 0 || d > maxElevation {
		return "", fmt.Errorf("duration must be between 1s and %s", maxElevation)
	}
	uid, err := p.lookupUID(name)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	revoked := p.revoked[id]
	p.mu.Unlock()
	if revoked {
		return "", errors.New("request was revoked before the grant arrived")
	}
	now := time.Now()
	g := grant{RequestID: id, User: name, UID: uid, Start: now, Until: now.Add(d)}
	path := p.grantFile(uid)
	if err := p.install(path, sudoersRule(g, p.ioDir, true)); err != nil {
		// sudo before 1.9.1 has no NOTAFTER; the agent's sweep still expires it.
		if err2 := p.install(path, sudoersRule(g, p.ioDir, false)); err2 != nil {
			return "", err2
		}
	}
	p.mu.Lock()
	for i := range p.grants {
		if p.grants[i].UID == uid && p.grants[i].Ended.IsZero() {
			p.grants[i].Ended = now
		}
	}
	p.grants = append(p.grants, g)
	p.save()
	p.mu.Unlock()
	p.log.Warn("just-in-time sudo granted", "request_id", id, "user", name, "until", g.Until)
	return fmt.Sprintf("sudo granted to %s until %s", name, g.Until.UTC().Format(time.RFC3339)), nil
}

func (p *PAM) lookupUID(name string) (uint32, error) {
	accts, err := readPasswd(filepath.Join(p.root, "etc/passwd"))
	if err != nil {
		return 0, err
	}
	for _, a := range accts {
		if a.name == name {
			if a.uid == 0 {
				return 0, fmt.Errorf("%s already has uid 0", name)
			}
			return a.uid, nil
		}
	}
	return 0, fmt.Errorf("no local account %q on this host", name)
}

// Revoke removes a grant now and ends the user's running sudo sessions.
func (p *PAM) Revoke(args map[string]string) (string, error) {
	id := args["request_id"]
	p.mu.Lock()
	var found *grant
	for i := range p.grants {
		if p.grants[i].RequestID == id && p.grants[i].Ended.IsZero() {
			found = &p.grants[i]
		}
	}
	if found == nil {
		p.revoked[id] = true
		p.mu.Unlock()
		return "no active grant for this request", nil
	}
	g := *found
	found.Ended = time.Now()
	p.save()
	p.mu.Unlock()
	n := p.end(g)
	p.log.Warn("just-in-time sudo revoked", "request_id", id, "user", g.User, "sessions_ended", n)
	return fmt.Sprintf("sudo removed from %s, %d session(s) ended", g.User, n), nil
}

// end removes a grant's sudoers file and stops the user's sudo processes.
func (p *PAM) end(g grant) int {
	if err := os.Remove(p.grantFile(g.UID)); err != nil && !os.IsNotExist(err) {
		p.log.Error("remove sudoers grant", "user", g.User, "err", err)
	}
	return killSudo(g.UID)
}

// killSudo signals every sudo process started by uid. sudo passes SIGTERM
// on to the command it runs, so root shells opened with the grant end too.
func killSudo(uid uint32) int {
	ents, _ := os.ReadDir("/proc")
	n := 0
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile("/proc/" + e.Name() + "/status")
		if err != nil {
			continue
		}
		name, ruid := statusFields(string(raw))
		if name == "sudo" && ruid == int64(uid) {
			if syscall.Kill(pid, syscall.SIGTERM) == nil {
				n++
			}
		}
	}
	return n
}

// statusFields returns Name and the real uid from /proc/<pid>/status.
func statusFields(s string) (string, int64) {
	name, ruid := "", int64(-1)
	for _, l := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(l, "Name:"); ok {
			name = strings.TrimSpace(v)
		} else if v, ok := strings.CutPrefix(l, "Uid:"); ok {
			if f := strings.Fields(v); len(f) > 0 {
				ruid, _ = strconv.ParseInt(f[0], 10, 64)
			}
		}
	}
	return name, ruid
}

// sweep ends expired grants and forgets old ones.
func (p *PAM) sweep() {
	now := time.Now()
	var expired []grant
	p.mu.Lock()
	kept := p.grants[:0]
	for _, g := range p.grants {
		if g.Ended.IsZero() && now.After(g.Until) {
			g.Ended = now
			expired = append(expired, g)
		}
		if g.Ended.IsZero() || now.Sub(g.Ended) < 48*time.Hour {
			kept = append(kept, g)
		}
	}
	p.grants = kept
	if len(expired) > 0 {
		p.save()
	}
	p.mu.Unlock()
	for _, g := range expired {
		n := p.end(g)
		p.log.Warn("just-in-time sudo expired", "request_id", g.RequestID, "user", g.User, "sessions_ended", n)
	}
	// A grant file the agent no longer tracks, e.g. after its state was lost,
	// is removed rather than left granting sudo forever.
	files, _ := filepath.Glob(filepath.Join(p.sudoersDir, jitPrefix+"*"))
	for _, f := range files {
		uid, err := strconv.ParseUint(strings.TrimPrefix(filepath.Base(f), jitPrefix), 10, 32)
		if err == nil && p.activeGrant(uint32(uid)) != nil {
			continue
		}
		p.log.Warn("removing untracked just-in-time sudoers file", "path", f)
		os.Remove(f)
	}
}

func (p *PAM) activeGrant(uid uint32) *grant {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.grants {
		if g := p.grants[i]; g.UID == uid && g.Ended.IsZero() {
			return &g
		}
	}
	return nil
}

// grantAt finds the grant a user held at a moment, for labelling recordings.
func (p *PAM) grantAt(name string, t time.Time) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, g := range p.grants {
		end := g.Ended
		if end.IsZero() {
			end = g.Until
		}
		if g.User == name && !t.Before(g.Start.Add(-time.Minute)) && !t.After(end) {
			return g.RequestID
		}
	}
	return ""
}

// --- local socket for `xdr-agent elevate` ---

// ElevateMsg is the request and reply on the local PAM socket, one JSON line each.
type ElevateMsg struct {
	Op       string `json:"op,omitempty"` // request or status
	ID       string `json:"id,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Duration int64  `json:"duration_seconds,omitempty"`
	Status   string `json:"status,omitempty"`
	Note     string `json:"note,omitempty"`
	Expires  int64  `json:"expires_unix,omitempty"`
	Error    string `json:"error,omitempty"`
}

func (p *PAM) serve(ctx context.Context) {
	if err := os.MkdirAll(filepath.Dir(p.socket), 0o755); err != nil {
		p.log.Error("pam socket dir", "err", err)
		return
	}
	os.Remove(p.socket)
	l, err := net.Listen("unix", p.socket)
	if err != nil {
		p.log.Error("pam socket", "err", err)
		return
	}
	// Any local user may ask; the peer's uid, not the message, says who.
	os.Chmod(p.socket, 0o666)
	go func() { <-ctx.Done(); l.Close() }()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() == nil {
				p.log.Error("pam socket accept", "err", err)
			}
			return
		}
		go p.handle(ctx, c.(*net.UnixConn))
	}
}

func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var cerr error
	err = raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	return cred.Uid, nil
}

func (p *PAM) handle(ctx context.Context, c *net.UnixConn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	reply := func(m ElevateMsg) { json.NewEncoder(c).Encode(m) }
	uid, err := peerUID(c)
	if err != nil {
		reply(ElevateMsg{Error: "cannot identify the caller"})
		return
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	var req ElevateMsg
	if err != nil || json.Unmarshal(line, &req) != nil {
		reply(ElevateMsg{Error: "bad request"})
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	switch req.Op {
	case "request":
		reply(p.ask(cctx, uid, req))
	case "status":
		p.mu.Lock()
		owner, ok := p.requests[req.ID]
		p.mu.Unlock()
		if !ok || (owner != uid && uid != 0) {
			reply(ElevateMsg{Error: "unknown request"})
			return
		}
		st, err := p.client.GetElevation(cctx, &xdrv1.GetElevationRequest{Id: req.ID})
		if err != nil {
			reply(ElevateMsg{Error: "console unreachable: " + err.Error()})
			return
		}
		reply(ElevateMsg{ID: st.Id, Status: st.Status, Note: st.Note, Expires: st.ExpiresUnix})
	default:
		reply(ElevateMsg{Error: "unknown op"})
	}
}

func (p *PAM) ask(ctx context.Context, uid uint32, req ElevateMsg) ElevateMsg {
	if uid == 0 {
		return ElevateMsg{Error: "root does not need elevation"}
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return ElevateMsg{Error: "unknown local account"}
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" || len(reason) > 500 {
		return ElevateMsg{Error: "give a reason of up to 500 characters"}
	}
	p.mu.Lock()
	if time.Since(p.lastAsk[uid]) < 30*time.Second {
		p.mu.Unlock()
		return ElevateMsg{Error: "wait 30 seconds between requests"}
	}
	p.lastAsk[uid] = time.Now()
	p.mu.Unlock()
	st, err := p.client.RequestElevation(ctx, &xdrv1.ElevationRequest{
		User: u.Username, Uid: uid, Reason: reason, DurationSeconds: uint64(max(req.Duration, 0)),
	})
	if err != nil {
		return ElevateMsg{Error: "console unreachable: " + err.Error()}
	}
	p.mu.Lock()
	p.requests[st.Id] = uid
	p.mu.Unlock()
	p.log.Info("elevation requested", "request_id", st.Id, "user", u.Username)
	return ElevateMsg{ID: st.Id, Status: st.Status, Note: st.Note, Expires: st.ExpiresUnix}
}

// AskElevation is the client side of the socket, used by `xdr-agent elevate`.
func AskElevation(m ElevateMsg) (ElevateMsg, error) {
	c, err := net.DialTimeout("unix", PamSocket, 5*time.Second)
	if err != nil {
		return ElevateMsg{}, fmt.Errorf("the XDR agent is not reachable on this host: %w", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	if err := json.NewEncoder(c).Encode(m); err != nil {
		return ElevateMsg{}, err
	}
	var out ElevateMsg
	if err := json.NewDecoder(c).Decode(&out); err != nil {
		return ElevateMsg{}, err
	}
	if out.Error != "" {
		return out, errors.New(out.Error)
	}
	return out, nil
}
