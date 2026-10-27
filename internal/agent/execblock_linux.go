package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/agent/collector"
	"github.com/Bogan1011/xdr-agent/internal/agent/procfs"
	"github.com/Bogan1011/xdr-agent/internal/policy"
)

// Pseudo and network filesystems are not marked: nothing worth blocking runs
// from the former, and a slow server on the latter would stall every exec.
var execSkipFS = map[string]bool{
	"proc": true, "sysfs": true, "cgroup": true, "cgroup2": true, "devpts": true, "mqueue": true,
	"debugfs": true, "tracefs": true, "securityfs": true, "pstore": true, "bpf": true, "configfs": true,
	"fusectl": true, "hugetlbfs": true, "autofs": true, "binfmt_misc": true, "rpc_pipefs": true,
	"nsfs": true, "efivarfs": true, "nfs": true, "nfs4": true, "cifs": true, "smb3": true, "9p": true,
}

const execWorkers = 4

// ExecBlocker denies execution of files whose SHA-256 is on the block list
// (hash IOCs) or that an application control rule lists, using fanotify permission events (FAN_OPEN_EXEC_PERM, Linux 5.0+). The
// kernel holds each exec until the agent answers; closing the fanotify
// descriptor, e.g. when the agent stops, allows everything again.
type ExecBlocker struct {
	Log      *slog.Logger
	Emit     collector.Emit
	MaxBytes int64

	hashes atomic.Pointer[map[[32]byte]struct{}]
	// iocOn enforces the hash IOCs; app, when set, the application rules.
	iocOn atomic.Bool
	app   atomic.Pointer[xdrv1.ApplicationControlPolicy]

	mu    sync.Mutex
	cache map[fileKey][32]byte
}

type fileKey struct {
	dev, ino     uint64
	size         int64
	mtime, ctime int64
}

const maxExecCache = 20000

func NewExecBlocker(log *slog.Logger, emit collector.Emit, maxBytes int64) *ExecBlocker {
	b := &ExecBlocker{Log: log, Emit: emit, MaxBytes: maxBytes, cache: map[fileKey][32]byte{}}
	empty := map[[32]byte]struct{}{}
	b.hashes.Store(&empty)
	b.iocOn.Store(true)
	return b
}

// SetRules chooses what is enforced: the hash IOCs, and application control
// rules (nil for none).
func (b *ExecBlocker) SetRules(iocs bool, app *xdrv1.ApplicationControlPolicy) {
	b.iocOn.Store(iocs)
	b.app.Store(app)
}

// Enforcing reports whether any rule would block something.
func (b *ExecBlocker) Enforcing() bool {
	return b.iocOn.Load() && b.Len() > 0 || b.app.Load() != nil
}

// SetHashes replaces the block list with concatenated 32-byte digests.
func (b *ExecBlocker) SetHashes(raw []byte) int {
	m := make(map[[32]byte]struct{}, len(raw)/32)
	for i := 0; i+32 <= len(raw); i += 32 {
		m[[32]byte(raw[i:i+32])] = struct{}{}
	}
	b.hashes.Store(&m)
	return len(m)
}

// Len is the size of the block list.
func (b *ExecBlocker) Len() int { return len(*b.hashes.Load()) }

func (b *ExecBlocker) blocked(sum [32]byte) bool {
	_, ok := (*b.hashes.Load())[sum]
	return ok
}

// Run enforces until ctx is cancelled. It returns an error when the kernel
// does not support exec permission events.
func (b *ExecBlocker) Run(ctx context.Context, started func()) error {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		return fmt.Errorf("fanotify_init: %w", err)
	}
	f := os.NewFile(uintptr(fd), "fanotify")
	defer f.Close()

	marked := map[string]bool{}
	if n, err := b.markMounts(fd, marked); err != nil {
		return err
	} else if n == 0 {
		return errors.New("no filesystem could be marked for exec permission events")
	}
	started()

	events := make(chan unix.FanotifyEventMetadata, 256)
	var wg sync.WaitGroup
	for range execWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for m := range events {
				b.handle(f, m)
			}
		}()
	}
	defer wg.Wait()
	defer close(events)

	go func() {
		// Containers and new mounts bring new filesystems.
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				f.Close()
				return
			case <-t.C:
				_, _ = b.markMounts(fd, marked)
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
			if m.Fd < 0 {
				continue
			}
			events <- m
		}
	}
}

// markMounts adds a filesystem mark for every mounted filesystem not yet
// marked, falling back to a mount mark on kernels without FAN_MARK_FILESYSTEM.
func (b *ExecBlocker) markMounts(fd int, marked map[string]bool) (int, error) {
	mf, err := os.Open("/proc/self/mounts")
	if err != nil {
		return 0, err
	}
	defer mf.Close()
	sc := bufio.NewScanner(mf)
	added := 0
	var lastErr error
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 {
			continue
		}
		dir, fstype := unescapeMount(f[1]), f[2]
		if marked[dir] || execSkipFS[fstype] || strings.HasPrefix(fstype, "fuse") {
			continue
		}
		err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, dir)
		if errors.Is(err, unix.EINVAL) {
			err = unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, dir)
		}
		if err != nil {
			lastErr = fmt.Errorf("fanotify_mark %s: %w", dir, err)
			if dir == "/" {
				return added, fmt.Errorf("%w (exec blocking needs Linux 5.0 or later with fanotify permission events)", lastErr)
			}
			continue
		}
		marked[dir] = true
		added++
	}
	if added == 0 && lastErr != nil && len(marked) == 0 {
		return 0, lastErr
	}
	return added, nil
}

// unescapeMount decodes the octal escapes /proc/self/mounts uses for spaces.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				out.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		out.WriteByte(s[i])
	}
	return out.String()
}

func (b *ExecBlocker) handle(f *os.File, m unix.FanotifyEventMetadata) {
	allow := true
	var sum [32]byte
	var hashed bool
	var path, rule string
	app := b.app.Load()
	iocs := b.iocOn.Load() && b.Len() > 0
	if int(m.Pid) != os.Getpid() && (iocs || app != nil) {
		if iocs || len(app.GetBlockedSha256()) > 0 {
			sum, hashed = b.hash(int(m.Fd))
		}
		if iocs && hashed && b.blocked(sum) {
			allow = false
		} else if app != nil {
			path, _ = os.Readlink("/proc/self/fd/" + strconv.Itoa(int(m.Fd)))
			sha := ""
			if hashed {
				sha = hex.EncodeToString(sum[:])
			}
			rule = policy.AppRule(app, path, sha)
			allow = rule == ""
		}
	}
	resp := unix.FanotifyResponse{Fd: m.Fd, Response: unix.FAN_ALLOW}
	if !allow {
		resp.Response = unix.FAN_DENY
	}
	var out [8]byte
	binary.NativeEndian.PutUint32(out[0:], uint32(resp.Fd))
	binary.NativeEndian.PutUint32(out[4:], resp.Response)
	if _, err := f.Write(out[:]); err != nil {
		b.Log.Warn("fanotify response failed", "err", err)
	}
	if !allow {
		sha := ""
		if hashed {
			sha = hex.EncodeToString(sum[:])
		}
		if rule != "" {
			b.reportApp(path, uint32(m.Pid), sha, rule)
		} else {
			b.report(int(m.Fd), uint32(m.Pid), sha)
		}
	}
	unix.Close(int(m.Fd))
}

// hash returns the file's SHA-256, cached by identity and change times so a
// binary that runs often is read once.
func (b *ExecBlocker) hash(fd int) ([32]byte, bool) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return [32]byte{}, false
	}
	if b.MaxBytes > 0 && st.Size > b.MaxBytes {
		return [32]byte{}, false
	}
	key := fileKey{dev: st.Dev, ino: st.Ino, size: st.Size, mtime: st.Mtim.Nano(), ctime: st.Ctim.Nano()}
	b.mu.Lock()
	sum, ok := b.cache[key]
	b.mu.Unlock()
	if ok {
		return sum, true
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(fdReaderAt(fd), 0, st.Size)); err != nil {
		return [32]byte{}, false
	}
	copy(sum[:], h.Sum(nil))
	b.mu.Lock()
	if len(b.cache) >= maxExecCache {
		clear(b.cache)
	}
	b.cache[key] = sum
	b.mu.Unlock()
	return sum, true
}

type fdReaderAt int

func (fd fdReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := unix.Pread(int(fd), p, off)
	if n == 0 && err == nil && len(p) > 0 {
		return 0, io.EOF
	}
	return n, err
}

func (b *ExecBlocker) report(fd int, pid uint32, sha string) {
	path, _ := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	pe := &xdrv1.ProcessEvent{Pid: pid, Exe: path, Sha256: sha}
	if info, err := procfs.Read(pid); err == nil {
		pe.Ppid, pe.Uid, pe.Gid, pe.User, pe.ParentExe, pe.Cwd = info.PPID, info.UID, info.GID, info.User, info.Exe, info.Cwd
	}
	b.Log.Warn("execution blocked", "path", path, "sha256", sha, "pid", pid, "caller", pe.ParentExe)
	e := collector.NewEvent(xdrv1.EventType_EVENT_TYPE_EXEC_BLOCKED)
	e.Payload = &xdrv1.Event_Process{Process: pe}
	b.Emit(e)
}

// reportApp raises the event for an exec denied by application control.
func (b *ExecBlocker) reportApp(path string, pid uint32, sha, rule string) {
	b.Log.Warn("execution blocked by application control", "path", path, "rule", rule, "pid", pid)
	b.Emit(appControlEvent("blocked", path, sha, rule, pid))
}

// appControlEvent describes a file an application control rule matched; pid
// is the process that ran (or tried to run) it.
func appControlEvent(action, path, sha, rule string, pid uint32) *xdrv1.Event {
	pe := &xdrv1.PolicyEvent{Action: action, Exe: path, Sha256: sha, Pid: pid, Detail: "matched " + rule}
	if info, err := procfs.Read(pid); err == nil {
		pe.User = info.User
		if action == "blocked" {
			pe.Detail += ", run by " + info.Exe
		}
	}
	e := collector.NewEvent(xdrv1.EventType_EVENT_TYPE_APP_CONTROL)
	e.Payload = &xdrv1.Event_Policy{Policy: pe}
	return e
}
