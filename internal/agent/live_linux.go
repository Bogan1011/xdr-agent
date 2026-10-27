package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

const maxShells = 8

var shellUser = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// Live keeps the stream the console uses to reach the agent at once, for
// remote shells and the live activity view.
type Live struct {
	cfg *Config
	log *slog.Logger

	sendMu sync.Mutex
	stream xdrv1.AgentService_LiveClient

	mu     sync.Mutex
	shells map[string]*shell

	actMu   sync.Mutex
	sampler activitySampler
}

func newLive(cfg *Config, log *slog.Logger) *Live {
	return &Live{cfg: cfg, log: log, shells: map[string]*shell{}}
}

// Run keeps the stream open, reconnecting with backoff.
func (l *Live) Run(ctx context.Context, client xdrv1.AgentServiceClient) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := l.serve(ctx, client)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		l.log.Debug("live stream closed, reconnecting", "err", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

func (l *Live) serve(ctx context.Context, client xdrv1.AgentServiceClient) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := client.Live(sctx)
	if err != nil {
		return err
	}
	l.sendMu.Lock()
	l.stream = st
	l.sendMu.Unlock()
	// The console forgets its shells when the stream drops, so end them too.
	defer l.closeAll()
	for {
		m, err := st.Recv()
		if err != nil {
			return err
		}
		switch msg := m.Msg.(type) {
		case *xdrv1.LiveDown_ShellOpen:
			l.open(ctx, msg.ShellOpen)
		case *xdrv1.LiveDown_ShellInput:
			if s := l.shell(msg.ShellInput.SessionId); s != nil {
				_, _ = s.ptm.Write(msg.ShellInput.Data)
			}
		case *xdrv1.LiveDown_ShellResize:
			if s := l.shell(msg.ShellResize.SessionId); s != nil {
				s.resize(msg.ShellResize.Cols, msg.ShellResize.Rows)
			}
		case *xdrv1.LiveDown_ShellClose:
			if s := l.shell(msg.ShellClose.SessionId); s != nil {
				s.kill()
			}
		case *xdrv1.LiveDown_Activity:
			go l.activity(msg.Activity.RequestId)
		}
	}
}

func (l *Live) send(m *xdrv1.LiveUp) {
	l.sendMu.Lock()
	defer l.sendMu.Unlock()
	if l.stream != nil {
		_ = l.stream.Send(m)
	}
}

func (l *Live) activity(id string) {
	l.mu.Lock()
	users := make(map[string]string, len(l.shells))
	for _, s := range l.shells {
		users[s.tty] = s.user
	}
	l.mu.Unlock()
	l.actMu.Lock()
	act := l.sampler.snapshot(users)
	l.actMu.Unlock()
	act.RequestId = id
	l.send(&xdrv1.LiveUp{Msg: &xdrv1.LiveUp_Activity{Activity: act}})
}

func (l *Live) shell(id string) *shell {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.shells[id]
}

func (l *Live) exit(id string, code int32, msg string) {
	l.send(&xdrv1.LiveUp{Msg: &xdrv1.LiveUp_ShellExit{ShellExit: &xdrv1.ShellExit{SessionId: id, ExitCode: code, Error: msg}}})
}

func (l *Live) open(ctx context.Context, req *xdrv1.ShellOpen) {
	user := req.User
	if user == "" {
		user = "root"
	}
	switch {
	case l.cfg.DisableRemoteShell:
		l.exit(req.SessionId, -1, "remote shell is turned off in this host's agent config")
		return
	case !shellUser.MatchString(user):
		l.exit(req.SessionId, -1, "invalid user name")
		return
	}
	l.mu.Lock()
	if len(l.shells) >= maxShells {
		l.mu.Unlock()
		l.exit(req.SessionId, -1, fmt.Sprintf("at most %d remote shells per host", maxShells))
		return
	}
	s, err := startShell(user, req.Cols, req.Rows)
	if err == nil {
		s.id = req.SessionId
		l.shells[s.id] = s
	}
	l.mu.Unlock()
	if err != nil {
		l.log.Warn("remote shell failed to start", "user", user, "err", err)
		l.exit(req.SessionId, -1, err.Error())
		return
	}
	l.log.Info("remote shell opened from the console", "session", s.id, "user", user, "tty", s.tty)
	go l.pump(s)
}

// pump forwards terminal output until the shell ends. Background jobs the
// shell left behind can keep the terminal open, so the end of the shell
// process, not of its output, closes the session.
func (l *Live) pump(s *shell) {
	done := make(chan int32, 1)
	go func() {
		err := s.cmd.Wait()
		code := int32(0)
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = int32(ee.ExitCode())
		}
		// Let the last output drain before closing.
		time.Sleep(300 * time.Millisecond)
		_ = s.ptm.Close()
		done <- code
	}()
	buf := make([]byte, 32<<10)
	for {
		n, err := s.ptm.Read(buf)
		if n > 0 {
			l.send(&xdrv1.LiveUp{Msg: &xdrv1.LiveUp_ShellOutput{ShellOutput: &xdrv1.ShellData{SessionId: s.id, Data: append([]byte(nil), buf[:n]...)}}})
		}
		if err != nil {
			break
		}
	}
	code := <-done
	l.mu.Lock()
	delete(l.shells, s.id)
	l.mu.Unlock()
	l.log.Info("remote shell closed", "session", s.id, "user", s.user, "exit_code", code)
	l.exit(s.id, code, "")
}

func (l *Live) closeAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.shells {
		s.kill()
	}
}

type shell struct {
	id, user, tty string
	ptm           *os.File
	cmd           *exec.Cmd
}

// startShell runs a login shell for user on a new pseudo-terminal.
func startShell(user string, cols, rows uint32) (*shell, error) {
	ptm, pts, tty, err := openPTY()
	if err != nil {
		return nil, fmt.Errorf("allocate terminal: %w", err)
	}
	defer pts.Close()
	su, err := exec.LookPath("su")
	if err != nil {
		su = "/bin/su"
	}
	// su from root needs no password and gives the user's own login
	// environment.
	cmd := exec.Command(su, "-l", user)
	cmd.Env = []string{"TERM=xterm-256color", "LANG=C.UTF-8"}
	cmd.Dir = "/"
	cmd.Stdin, cmd.Stdout, cmd.Stderr = pts, pts, pts
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	s := &shell{user: user, tty: tty, ptm: ptm, cmd: cmd}
	s.resize(cols, rows)
	if err := cmd.Start(); err != nil {
		ptm.Close()
		return nil, err
	}
	// The agent runs niced and shielded from the OOM killer; the shell
	// should not.
	_ = unix.Setpriority(unix.PRIO_PROCESS, cmd.Process.Pid, 0)
	_ = os.WriteFile("/proc/"+strconv.Itoa(cmd.Process.Pid)+"/oom_score_adj", []byte("0"), 0)
	return s, nil
}

func openPTY() (ptm, pts *os.File, tty string, err error) {
	ptm, err = os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, "", err
	}
	var n int
	ctl := func(fd uintptr) {
		if err = unix.IoctlSetPointerInt(int(fd), unix.TIOCSPTLCK, 0); err == nil {
			n, err = unix.IoctlGetInt(int(fd), unix.TIOCGPTN)
		}
	}
	// Control, not Fd, keeps the master non-blocking in the runtime poller,
	// so Close unblocks a pending Read.
	if rc, cerr := ptm.SyscallConn(); cerr != nil {
		err = cerr
	} else if cerr := rc.Control(ctl); cerr != nil {
		err = cerr
	}
	if err != nil {
		ptm.Close()
		return nil, nil, "", err
	}
	tty = "pts/" + strconv.Itoa(n)
	pts, err = os.OpenFile("/dev/"+tty, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		ptm.Close()
		return nil, nil, "", err
	}
	return ptm, pts, tty, nil
}

func (s *shell) resize(cols, rows uint32) {
	if cols == 0 || rows == 0 || cols > 1000 || rows > 1000 {
		return
	}
	if rc, err := s.ptm.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) {
			_ = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Col: uint16(cols), Row: uint16(rows)})
		})
	}
}

// kill hangs up the whole session, as closing a terminal window does.
func (s *shell) kill() {
	if s.cmd.Process != nil {
		_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGHUP)
		_ = s.cmd.Process.Signal(syscall.SIGHUP)
	}
	go func(p *os.Process) {
		time.Sleep(3 * time.Second)
		_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
	}(s.cmd.Process)
}
