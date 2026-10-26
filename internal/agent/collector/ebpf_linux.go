package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/agent/ebpf"
	"github.com/Bogan1011/xdr-agent/internal/agent/procfs"
)

// EBPFFile reports file changes in the watched trees together with the
// process that made them. Unlike inotify it has no watch limit and sees
// every directory under the configured paths, including new ones.
type EBPFFile struct {
	Reader  *ringbuf.Reader
	Paths   []string // trees to report on
	Exclude []string // path prefixes to skip
	Hasher  *procfs.Hasher
	Log     *slog.Logger

	// writes holds write-opens until the writer has had time to finish, so
	// the reported hash is of the new content.
	writes map[string]pendingWrite
}

type pendingWrite struct {
	ev    ebpf.FileEvent
	since time.Time
}

// writeSettle is how long a write-open waits before the file is hashed.
const writeSettle = time.Second

func (f *EBPFFile) Name() string { return "file-ebpf" }

func (f *EBPFFile) Run(ctx context.Context, emit Emit) error {
	f.writes = map[string]pendingWrite{}
	f.Log.Info("eBPF file collector running", "paths", len(f.Paths))
	return readRing(ctx, f.Reader, func(raw []byte) {
		ev, err := ebpf.ParseFileEvent(raw)
		if err == nil {
			f.handle(ev, emit)
		}
	}, func() { f.flush(emit) })
}

func (f *EBPFFile) handle(ev ebpf.FileEvent, emit Emit) {
	if !f.wanted(ev.Path) && (ev.OldPath == "" || !f.wanted(ev.OldPath)) {
		return
	}
	switch ev.Op {
	case ebpf.FileWrite:
		if _, ok := f.writes[ev.Path]; !ok {
			f.writes[ev.Path] = pendingWrite{ev: ev, since: time.Now()}
		}
	case ebpf.FileCreate:
		f.emitFile(emit, xdrv1.EventType_EVENT_TYPE_FILE_CREATE, ev)
	case ebpf.FileDelete:
		f.settle(emit, ev.Path)
		f.emitFile(emit, xdrv1.EventType_EVENT_TYPE_FILE_DELETE, ev)
	case ebpf.FileRename:
		f.settle(emit, ev.OldPath)
		f.emitFile(emit, xdrv1.EventType_EVENT_TYPE_FILE_RENAME, ev)
	case ebpf.FileChmod:
		f.emitFile(emit, xdrv1.EventType_EVENT_TYPE_FILE_ATTRIB, ev)
	}
}

// settle reports a pending write at once, before the file goes away.
func (f *EBPFFile) settle(emit Emit, path string) {
	if w, ok := f.writes[path]; ok {
		delete(f.writes, path)
		f.emitFile(emit, xdrv1.EventType_EVENT_TYPE_FILE_MODIFY, w.ev)
	}
}

func (f *EBPFFile) flush(emit Emit) {
	now := time.Now()
	for path, w := range f.writes {
		if now.Sub(w.since) >= writeSettle {
			delete(f.writes, path)
			f.emitFile(emit, xdrv1.EventType_EVENT_TYPE_FILE_MODIFY, w.ev)
		}
	}
}

func (f *EBPFFile) wanted(path string) bool {
	if !underAny(path, f.Paths) {
		return false
	}
	return !underAny(path, f.Exclude)
}

func underAny(path string, roots []string) bool {
	for _, r := range roots {
		r = strings.TrimSuffix(r, "/")
		if r == "" || path == r || strings.HasPrefix(path, r+"/") {
			return true
		}
	}
	return false
}

func (f *EBPFFile) emitFile(emit Emit, t xdrv1.EventType, ev ebpf.FileEvent) {
	fe := &xdrv1.FileEvent{
		Path:    ev.Path,
		OldPath: ev.OldPath,
		Pid:     ev.PID,
		Ppid:    ev.PPID,
		Exe:     processExe(ev.PID, ev.Comm),
		User:    procfs.Username(ev.UID),
		Uid:     ev.UID,
	}
	if ev.Op == ebpf.FileCreate || ev.Op == ebpf.FileChmod {
		fe.Mode = ev.Mode
	}
	if st, err := os.Lstat(ev.Path); err == nil && t != xdrv1.EventType_EVENT_TYPE_FILE_DELETE {
		fe.Size = uint64(st.Size())
		if s, ok := st.Sys().(*syscall.Stat_t); ok {
			fe.Uid = s.Uid
			fe.Mode = s.Mode
		}
		if st.Mode().IsRegular() && (t == xdrv1.EventType_EVENT_TYPE_FILE_MODIFY || t == xdrv1.EventType_EVENT_TYPE_FILE_RENAME) {
			fe.Sha256 = f.Hasher.Hash(ev.Path)
		}
	}
	e := NewEvent(t)
	e.Payload = &xdrv1.Event_File{File: fe}
	emit(e)
}

// EBPFNetwork reports every TCP connect and accept with the process behind
// it, including connections too short for /proc polling to see.
type EBPFNetwork struct {
	Reader *ringbuf.Reader
	Log    *slog.Logger
}

func (n *EBPFNetwork) Name() string { return "network-ebpf" }

func (n *EBPFNetwork) Run(ctx context.Context, emit Emit) error {
	n.Log.Info("eBPF network collector running")
	return readRing(ctx, n.Reader, func(raw []byte) {
		if ev, err := ebpf.ParseNetEvent(raw); err == nil {
			emit(netEvent(ev))
		}
	}, nil)
}

func netEvent(ev ebpf.NetEvent) *xdrv1.Event {
	proto := "tcp"
	if ev.IPv6 {
		proto = "tcp6"
	}
	t := xdrv1.EventType_EVENT_TYPE_NET_CONNECT
	if ev.Op == ebpf.NetAccept {
		t = xdrv1.EventType_EVENT_TYPE_NET_ACCEPT
	}
	e := NewEvent(t)
	e.Payload = &xdrv1.Event_Network{Network: &xdrv1.NetworkEvent{
		Protocol:   proto,
		LocalAddr:  ev.LocalAddr.String(),
		LocalPort:  uint32(ev.LocalPort),
		RemoteAddr: ev.RemoteAddr.String(),
		RemotePort: uint32(ev.RemotePort),
		Pid:        ev.PID,
		Exe:        processExe(ev.PID, ev.Comm),
		Uid:        ev.UID,
	}}
	return e
}

// processExe names the process behind an event. A process that already
// exited is named by its command name in brackets.
func processExe(pid uint32, comm string) string {
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		return exe
	}
	if comm == "" {
		return ""
	}
	return "[" + comm + "]"
}

// readRing feeds ring buffer records to handle and calls tick, when set,
// about twice a second. It returns when ctx is done.
func readRing(ctx context.Context, r *ringbuf.Reader, handle func([]byte), tick func()) error {
	const tickEvery = 500 * time.Millisecond
	var rec ringbuf.Record
	last := time.Now()
	for ctx.Err() == nil {
		r.SetDeadline(time.Now().Add(tickEvery))
		err := r.ReadInto(&rec)
		switch {
		case err == nil:
			handle(rec.RawSample)
		case errors.Is(err, os.ErrDeadlineExceeded):
		case errors.Is(err, ringbuf.ErrClosed):
			return nil
		default:
			return fmt.Errorf("read ring buffer: %w", err)
		}
		if tick != nil && time.Since(last) >= tickEvery {
			tick()
			last = time.Now()
		}
	}
	return nil
}
