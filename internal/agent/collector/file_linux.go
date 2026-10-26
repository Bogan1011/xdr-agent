package collector

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/agent/procfs"
)

// File watches configured directory trees with inotify. inotify cannot say
// which process touched a file; it is the fallback for kernels where the
// eBPF collector (EBPFFile) cannot load.
type File struct {
	Paths      []string // directory trees to watch recursively
	Exclude    []string // path prefixes to skip
	MaxWatches int
	Hasher     *procfs.Hasher
	Log        *slog.Logger

	fd      int
	watches map[int32]string
}

const fileMask = unix.IN_CREATE | unix.IN_CLOSE_WRITE | unix.IN_DELETE | unix.IN_MOVED_FROM |
	unix.IN_MOVED_TO | unix.IN_ATTRIB | unix.IN_DELETE_SELF | unix.IN_ONLYDIR

func (f *File) Name() string { return "file" }

func (f *File) Run(ctx context.Context, emit Emit) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return fmt.Errorf("inotify init: %w", err)
	}
	f.fd = fd
	f.watches = make(map[int32]string)
	defer unix.Close(fd)

	for _, p := range f.Paths {
		f.addTree(p)
	}
	f.Log.Info("file collector watching", "dirs", len(f.watches))

	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return fmt.Errorf("epoll: %w", err)
	}
	defer unix.Close(epfd)
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}); err != nil {
		return fmt.Errorf("epoll ctl: %w", err)
	}

	pendingMoves := map[uint32]string{} // cookie -> old path
	buf := make([]byte, 256*1024)
	events := make([]unix.EpollEvent, 1)
	for ctx.Err() == nil {
		n, err := unix.EpollWait(epfd, events, 500)
		if err != nil && err != unix.EINTR {
			return fmt.Errorf("epoll wait: %w", err)
		}
		if n <= 0 {
			// Moves out of the watched trees never get a MOVED_TO; treat as deletes.
			for c, old := range pendingMoves {
				f.emitFile(emit, xdrv1.EventType_EVENT_TYPE_FILE_DELETE, old, "")
				delete(pendingMoves, c)
			}
			continue
		}
		for {
			r, err := unix.Read(fd, buf)
			if err != nil || r <= 0 {
				break
			}
			f.parse(buf[:r], pendingMoves, emit)
		}
	}
	return nil
}

func (f *File) parse(buf []byte, pendingMoves map[uint32]string, emit Emit) {
	for off := 0; off+unix.SizeofInotifyEvent <= len(buf); {
		raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
		nameBytes := buf[off+unix.SizeofInotifyEvent : off+unix.SizeofInotifyEvent+int(raw.Len)]
		off += unix.SizeofInotifyEvent + int(raw.Len)
		name := strings.TrimRight(string(nameBytes), "\x00")

		if raw.Mask&unix.IN_Q_OVERFLOW != 0 {
			f.Log.Warn("inotify queue overflowed; some file events were lost")
			continue
		}
		dir, ok := f.watches[raw.Wd]
		if !ok {
			continue
		}
		if raw.Mask&unix.IN_IGNORED != 0 || raw.Mask&unix.IN_DELETE_SELF != 0 {
			delete(f.watches, raw.Wd)
			continue
		}
		path := filepath.Join(dir, name)
		if f.excluded(path) {
			continue
		}
		isDir := raw.Mask&unix.IN_ISDIR != 0

		switch {
		case raw.Mask&unix.IN_CREATE != 0:
			if isDir {
				f.addTree(path)
			}
			f.emitFile(emit, xdrv1.EventType_EVENT_TYPE_FILE_CREATE, path, "")
		case raw.Mask&unix.IN_CLOSE_WRITE != 0:
			f.emitFile(emit, xdrv1.EventType_EVENT_TYPE_FILE_MODIFY, path, "")
		case raw.Mask&unix.IN_DELETE != 0:
			f.emitFile(emit, xdrv1.EventType_EVENT_TYPE_FILE_DELETE, path, "")
		case raw.Mask&unix.IN_MOVED_FROM != 0:
			pendingMoves[raw.Cookie] = path
		case raw.Mask&unix.IN_MOVED_TO != 0:
			old := pendingMoves[raw.Cookie]
			delete(pendingMoves, raw.Cookie)
			if isDir {
				f.addTree(path)
			}
			if old == "" {
				f.emitFile(emit, xdrv1.EventType_EVENT_TYPE_FILE_CREATE, path, "")
			} else {
				f.emitFile(emit, xdrv1.EventType_EVENT_TYPE_FILE_RENAME, path, old)
			}
		case raw.Mask&unix.IN_ATTRIB != 0:
			f.emitFile(emit, xdrv1.EventType_EVENT_TYPE_FILE_ATTRIB, path, "")
		}
	}
}

func (f *File) emitFile(emit Emit, t xdrv1.EventType, path, old string) {
	fe := &xdrv1.FileEvent{Path: path, OldPath: old}
	if st, err := os.Lstat(path); err == nil {
		fe.Size = uint64(st.Size())
		fe.Mode = uint32(st.Mode().Perm())
		if s, ok := st.Sys().(*syscall.Stat_t); ok {
			fe.Uid = s.Uid
			fe.Mode = s.Mode
		}
		if st.Mode().IsRegular() && (t == xdrv1.EventType_EVENT_TYPE_FILE_MODIFY || t == xdrv1.EventType_EVENT_TYPE_FILE_RENAME || t == xdrv1.EventType_EVENT_TYPE_FILE_CREATE) {
			fe.Sha256 = f.Hasher.Hash(path)
		}
	}
	e := NewEvent(t)
	e.Payload = &xdrv1.Event_File{File: fe}
	emit(e)
}

func (f *File) excluded(path string) bool {
	for _, ex := range f.Exclude {
		if path == ex || strings.HasPrefix(path, strings.TrimSuffix(ex, "/")+"/") {
			return true
		}
	}
	return false
}

func (f *File) addTree(root string) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if f.excluded(p) {
			return filepath.SkipDir
		}
		if len(f.watches) >= f.MaxWatches {
			f.Log.Warn("inotify watch limit reached; directory not watched", "dir", p, "limit", f.MaxWatches)
			return fs.SkipAll
		}
		wd, err := unix.InotifyAddWatch(f.fd, p, fileMask)
		if err != nil {
			return nil
		}
		f.watches[int32(wd)] = p
		return nil
	})
}
