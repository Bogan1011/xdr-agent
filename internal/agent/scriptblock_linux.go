package agent

import (
	"context"
	"encoding/binary"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/agent/collector"
	"github.com/Bogan1011/xdr-agent/internal/policy"
)

const (
	maxScriptDirs      = 4096
	scriptRescanPeriod = 3 * time.Second
)

// ScriptBlocker stops shells and interpreters from running scripts kept in
// the script folders (by default /tmp, /var/tmp and /dev/shm). It marks
// those folders for open permission events and denies the open when the
// opener is an interpreter whose script argument is that file. Subfolders
// made since the last rescan are not marked yet; application control kills
// interpreters started on scripts there instead (see Prevention.observeExec).
type ScriptBlocker struct {
	Log  *slog.Logger
	Emit collector.Emit

	pol     atomic.Pointer[xdrv1.ApplicationControlPolicy]
	changed chan struct{}

	mu     sync.Mutex
	marked map[string]bool
	on     bool
	err    string
}

func NewScriptBlocker(log *slog.Logger, emit collector.Emit) *ScriptBlocker {
	return &ScriptBlocker{Log: log, Emit: emit, changed: make(chan struct{}, 1), marked: map[string]bool{}}
}

// SetPolicy enforces script blocking when ac turns it on in block mode.
func (s *ScriptBlocker) SetPolicy(ac *xdrv1.ApplicationControlPolicy) {
	if ac != nil && !(ac.Enabled && ac.Block && ac.BlockScripts) {
		ac = nil
	}
	old := s.pol.Swap(ac)
	if old == ac || old != nil && ac != nil && strings.Join(old.ScriptPaths, "\n") == strings.Join(ac.ScriptPaths, "\n") {
		return
	}
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// Status reports whether blocking is active, over how many folders, and why
// it is not when it should be.
func (s *ScriptBlocker) Status() (bool, int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.on, len(s.marked), s.err
}

// Covers reports whether opens in dir are being checked.
func (s *ScriptBlocker) Covers(dir string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.on && s.marked[dir]
}

func (s *ScriptBlocker) Run(ctx context.Context) {
	for {
		select {
		case <-s.changed:
		default:
		}
		ac := s.pol.Load()
		if ac == nil {
			select {
			case <-ctx.Done():
				return
			case <-s.changed:
				continue
			}
		}
		rctx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- s.enforce(rctx, ac.ScriptPaths) }()
		var err error
		select {
		case <-ctx.Done():
			cancel()
			<-done
			return
		case <-s.changed:
			cancel()
			err = <-done
		case err = <-done:
			cancel()
		}
		s.mu.Lock()
		s.on, s.marked = false, map[string]bool{}
		if err != nil {
			s.err = err.Error()
		}
		s.mu.Unlock()
		if err != nil {
			s.Log.Error("script blocking unavailable", "err", err)
			// Retried on the next policy change.
			select {
			case <-ctx.Done():
				return
			case <-s.changed:
			}
		}
	}
}

func (s *ScriptBlocker) enforce(ctx context.Context, roots []string) error {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		return fmt.Errorf("fanotify_init: %w", err)
	}
	f := os.NewFile(uintptr(fd), "fanotify-scripts")
	defer f.Close()
	if err := s.mark(fd, roots); err != nil {
		return err
	}
	s.mu.Lock()
	s.on, s.err = true, ""
	n := len(s.marked)
	s.mu.Unlock()
	s.Log.Info("script blocking active", "folders", n)

	go func() {
		t := time.NewTicker(scriptRescanPeriod)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				f.Close()
				return
			case <-t.C:
				_ = s.mark(fd, roots)
			}
		}
	}()

	buf := make([]byte, 64*unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	for {
		n, err := f.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read fanotify: %w", err)
		}
		for off := 0; off+int(unsafe.Sizeof(unix.FanotifyEventMetadata{})) <= n; {
			m := *(*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[off]))
			if m.Event_len == 0 {
				break
			}
			off += int(m.Event_len)
			if m.Fd >= 0 {
				s.handle(f, m)
			}
		}
	}
}

// mark adds the script folders and their subfolders not yet marked. Marks
// of deleted folders go away with the inode.
func (s *ScriptBlocker) mark(fd int, roots []string) error {
	var firstErr error
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(dir string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return nil
			}
			s.mu.Lock()
			done, full := s.marked[dir], len(s.marked) >= maxScriptDirs
			s.mu.Unlock()
			if full {
				return filepath.SkipAll
			}
			if done {
				return nil
			}
			if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, unix.FAN_OPEN_PERM|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, dir); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("fanotify_mark %s: %w", dir, err)
				}
				return nil
			}
			s.mu.Lock()
			s.marked[dir] = true
			s.mu.Unlock()
			return nil
		})
	}
	s.mu.Lock()
	n := len(s.marked)
	s.mu.Unlock()
	if n == 0 && firstErr != nil {
		return firstErr
	}
	return nil
}

func (s *ScriptBlocker) handle(f *os.File, m unix.FanotifyEventMetadata) {
	path, rule := s.check(int(m.Pid), int(m.Fd))
	resp := uint32(unix.FAN_ALLOW)
	if rule != "" {
		resp = unix.FAN_DENY
	}
	var out [8]byte
	binary.NativeEndian.PutUint32(out[0:], uint32(m.Fd))
	binary.NativeEndian.PutUint32(out[4:], resp)
	if _, err := f.Write(out[:]); err != nil {
		s.Log.Warn("fanotify response failed", "err", err)
	}
	unix.Close(int(m.Fd))
	if rule != "" {
		s.Log.Warn("script blocked", "path", path, "rule", rule, "pid", m.Pid)
		s.Emit(appControlEvent("blocked", path, "", rule, uint32(m.Pid)))
	}
}

// check returns the rule that denies this open, if the opener is an
// interpreter opening the script it was started with.
func (s *ScriptBlocker) check(pid, fd int) (string, string) {
	ac := s.pol.Load()
	if ac == nil || pid == os.Getpid() {
		return "", ""
	}
	proc := "/proc/" + strconv.Itoa(pid)
	exe, err := os.Readlink(proc + "/exe")
	if err != nil || !policy.IsInterpreter(strings.TrimSuffix(exe, " (deleted)")) {
		return "", ""
	}
	raw, err := os.ReadFile(proc + "/cmdline")
	if err != nil {
		return "", ""
	}
	args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	cwd, _ := os.Readlink(proc + "/cwd")
	path, _ := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	script, rule := policy.ScriptRule(ac, exe, args, cwd)
	if rule == "" || script != path {
		return "", ""
	}
	return path, rule
}
