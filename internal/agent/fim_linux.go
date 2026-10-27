package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/agent/collector"
	"github.com/Bogan1011/xdr-agent/internal/policy"
)

const (
	fimMaxFiles = 200000
	// fimMaxHash bounds the bytes hashed per file; larger files are compared
	// by their first fimMaxHash bytes plus size and change time.
	fimMaxHash = 512 << 20
	// fimDebounce groups the file events of one change (write, chmod, rename).
	fimDebounce = 2 * time.Second
)

// fimEntry is what the baseline records for one file or symlink.
type fimEntry struct {
	SHA256  string `json:"h,omitempty"`
	Link    string `json:"l,omitempty"`
	Mode    uint32 `json:"m"`
	UID     uint32 `json:"u"`
	GID     uint32 `json:"g"`
	Size    int64  `json:"s"`
	Ino     uint64 `json:"i"`
	Ctime   int64  `json:"c"`
	Removed bool   `json:"x,omitempty"`
}

// same reports whether two entries describe the same content, permissions
// and owner. Inode and change time only decide whether to re-hash.
func (e fimEntry) same(o fimEntry) bool {
	return e.Removed == o.Removed && e.SHA256 == o.SHA256 && e.Link == o.Link &&
		e.Mode == o.Mode && e.UID == o.UID && e.GID == o.GID
}

type fimState struct {
	Roots    []string            `json:"roots"`
	Baseline map[string]fimEntry `json:"baseline"`
	// Reported holds the last drift reported per path, so one change raises
	// one event however many scans see it.
	Reported map[string]fimEntry `json:"reported"`
}

// FIM keeps a baseline of the monitored files and reports drift from it:
// on file events under the monitored paths (after a short debounce) and on a
// full rescan every interval. The baseline changes only when the console asks
// for a new one, so drift stays visible until someone accepts it.
type FIM struct {
	Log  *slog.Logger
	Emit collector.Emit
	File string

	mu      sync.Mutex
	policy  *xdrv1.FimPolicy
	st      *fimState
	files   int
	pending map[string]bool
	changed chan struct{}
	rebase  chan chan error
}

func NewFIM(log *slog.Logger, emit collector.Emit, file string) *FIM {
	return &FIM{Log: log, Emit: emit, File: file, pending: map[string]bool{},
		changed: make(chan struct{}, 1), rebase: make(chan chan error)}
}

// SetPolicy applies a new policy; a change triggers a rescan.
func (f *FIM) SetPolicy(p *xdrv1.FimPolicy) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if proto.Equal(p, f.policy) {
		return
	}
	f.policy = proto.Clone(p).(*xdrv1.FimPolicy)
	select {
	case f.changed <- struct{}{}:
	default:
	}
}

func (f *FIM) active() *xdrv1.FimPolicy {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policy == nil || !f.policy.Enabled || len(f.policy.Paths) == 0 {
		return nil
	}
	return f.policy
}

// Status reports whether FIM runs and how many files the baseline holds.
func (f *FIM) Status() (bool, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.policy != nil && f.policy.Enabled && f.st != nil, f.files
}

// Notify queues a changed path for a check against the baseline.
func (f *FIM) Notify(path string) {
	if path == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policy == nil || !f.policy.Enabled || !f.covered(path) || len(f.pending) > 10000 {
		return
	}
	f.pending[path] = true
}

// covered reports whether path is monitored. Callers hold mu.
func (f *FIM) covered(path string) bool {
	return policy.Matches(path, f.policy.Paths) && !policy.Matches(path, f.policy.Exclude)
}

// Rebaseline accepts the current state of the monitored files.
func (f *FIM) Rebaseline(ctx context.Context) (string, error) {
	if f.active() == nil {
		return "", errors.New("file integrity monitoring is not enabled on this endpoint")
	}
	done := make(chan error, 1)
	select {
	case f.rebase <- done:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	select {
	case err := <-done:
		if err != nil {
			return "", err
		}
		_, n := f.Status()
		return fmt.Sprintf("new FIM baseline recorded (%d files)", n), nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (f *FIM) Run(ctx context.Context) {
	f.load()
	debounce := time.NewTicker(fimDebounce)
	defer debounce.Stop()
	var next <-chan time.Time
	schedule := func() {
		if p := f.active(); p != nil {
			next = time.After(time.Duration(p.IntervalMinutes) * time.Minute)
		} else {
			next = nil
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-f.changed:
			if f.active() == nil {
				f.reset()
			} else {
				f.scan(false)
			}
			schedule()
		case <-next:
			f.scan(false)
			schedule()
		case done := <-f.rebase:
			done <- f.scan(true)
			schedule()
		case <-debounce.C:
			f.mu.Lock()
			paths := make([]string, 0, len(f.pending))
			for p := range f.pending {
				paths = append(paths, p)
			}
			clear(f.pending)
			f.mu.Unlock()
			if len(paths) > 0 {
				f.check(paths)
			}
		}
	}
}

func (f *FIM) load() {
	raw, err := os.ReadFile(f.File)
	if err != nil {
		return
	}
	var st fimState
	if err := json.Unmarshal(raw, &st); err != nil {
		f.Log.Warn("FIM baseline unreadable, a new one will be recorded", "err", err)
		return
	}
	if st.Reported == nil {
		st.Reported = map[string]fimEntry{}
	}
	f.mu.Lock()
	f.st, f.files = &st, len(st.Baseline)
	f.mu.Unlock()
}

func (f *FIM) save() {
	raw, err := json.Marshal(f.st)
	if err == nil {
		tmp := f.File + ".tmp"
		if err = os.WriteFile(tmp, raw, 0o600); err == nil {
			err = os.Rename(tmp, f.File)
		}
	}
	if err != nil {
		f.Log.Error("saving FIM baseline failed", "err", err)
	}
}

// reset drops the baseline when FIM is switched off, so switching it on
// again records a fresh one instead of reporting everything since.
func (f *FIM) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.st != nil {
		f.Log.Info("FIM disabled, baseline removed")
	}
	f.st, f.files = nil, 0
	_ = os.Remove(f.File)
}

// scan walks every monitored path and compares the result with the baseline.
func (f *FIM) scan(rebaseline bool) error {
	f.mu.Lock()
	p := proto.Clone(f.policy).(*xdrv1.FimPolicy)
	prev := f.st
	f.mu.Unlock()
	if p == nil || !p.Enabled {
		return nil
	}
	start := time.Now()
	cur := map[string]fimEntry{}
	for _, root := range p.Paths {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if policy.Matches(path, p.Exclude) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if len(cur) >= fimMaxFiles {
				return fs.SkipAll
			}
			if e, ok := fimStat(path, prev); ok {
				cur[path] = e
			}
			return nil
		})
	}
	if len(cur) >= fimMaxFiles {
		f.Log.Warn("FIM file limit reached, narrow the monitored paths", "limit", fimMaxFiles)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.st == nil || rebaseline {
		f.st = &fimState{Roots: slices.Clone(p.Paths), Baseline: cur, Reported: map[string]fimEntry{}}
		f.files = len(cur)
		f.save()
		f.Log.Info("FIM baseline recorded", "files", len(cur), "took", time.Since(start).Round(time.Millisecond))
		return nil
	}
	st := f.st
	// Files under paths added to the policy join the baseline silently.
	var added []string
	for _, r := range p.Paths {
		if !slices.Contains(st.Roots, r) {
			added = append(added, r)
		}
	}
	for path, e := range cur {
		if _, ok := st.Baseline[path]; !ok && policy.Matches(path, added) {
			st.Baseline[path] = e
		}
	}
	// Paths no longer monitored leave it.
	for path := range st.Baseline {
		if !f.covered(path) {
			delete(st.Baseline, path)
			delete(st.Reported, path)
		}
	}
	st.Roots = slices.Clone(p.Paths)
	drift := 0
	for path, base := range st.Baseline {
		e, ok := cur[path]
		if !ok {
			e = fimEntry{Removed: true}
		}
		if f.compare(path, &base, e) {
			drift++
		}
	}
	for path, e := range cur {
		if _, ok := st.Baseline[path]; !ok && f.compare(path, nil, e) {
			drift++
		}
	}
	f.files = len(st.Baseline)
	f.save()
	f.Log.Info("FIM scan done", "files", len(cur), "new_drift", drift, "took", time.Since(start).Round(time.Millisecond))
	return nil
}

// check compares single paths reported by file events.
func (f *FIM) check(paths []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.st == nil || f.policy == nil || !f.policy.Enabled {
		return
	}
	n := 0
	for _, path := range paths {
		if !f.covered(path) {
			continue
		}
		e, ok := fimStat(path, f.st)
		if !ok {
			if _, err := os.Lstat(path); err == nil {
				continue // a directory or something else not tracked
			}
			e = fimEntry{Removed: true}
		}
		var base *fimEntry
		if b, ok := f.st.Baseline[path]; ok {
			base = &b
		} else if e.Removed {
			delete(f.st.Reported, path)
			continue
		}
		if f.compare(path, base, e) {
			n++
		}
	}
	if n > 0 {
		f.save()
	}
}

// compare reports drift of cur from base (nil when the file is new) once per
// distinct state. Callers hold mu.
func (f *FIM) compare(path string, base *fimEntry, cur fimEntry) bool {
	change := fimChange(base, cur)
	if change == "" {
		delete(f.st.Reported, path)
		return false
	}
	if last, ok := f.st.Reported[path]; ok && last.same(cur) {
		return false
	}
	f.st.Reported[path] = cur
	fe := &xdrv1.FileEvent{Path: path, Change: change, Sha256: cur.SHA256, Size: uint64(max(cur.Size, 0)), Mode: cur.Mode, Uid: cur.UID}
	if base != nil {
		fe.OldSha256 = base.SHA256
	}
	e := collector.NewEvent(xdrv1.EventType_EVENT_TYPE_FIM_CHANGE)
	e.Payload = &xdrv1.Event_File{File: fe}
	f.Emit(e)
	f.Log.Warn("file integrity drift", "path", path, "change", change)
	return true
}

// fimChange names what differs: added, removed, or a comma separated list of
// content, permissions and owner.
func fimChange(base *fimEntry, cur fimEntry) string {
	switch {
	case base == nil && cur.Removed:
		return ""
	case base == nil:
		return "added"
	case cur.Removed && !base.Removed:
		return "removed"
	}
	var c []string
	if base.SHA256 != cur.SHA256 || base.Link != cur.Link {
		c = append(c, "content")
	}
	if base.Mode != cur.Mode {
		c = append(c, "permissions")
	}
	if base.UID != cur.UID || base.GID != cur.GID {
		c = append(c, "owner")
	}
	return strings.Join(c, ",")
}

// fimStat records a regular file or symlink. The hash is reused from prev
// when the inode, size and change time are unchanged; changing content
// always moves the change time.
func fimStat(path string, prev *fimState) (fimEntry, bool) {
	fi, err := os.Lstat(path)
	if err != nil {
		return fimEntry{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fimEntry{}, false
	}
	e := fimEntry{Mode: st.Mode & 0o7777, UID: st.Uid, GID: st.Gid,
		Size: st.Size, Ino: st.Ino, Ctime: st.Ctim.Nano()}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		e.Link, _ = os.Readlink(path)
		return e, true
	case !fi.Mode().IsRegular():
		return fimEntry{}, false
	}
	if prev != nil {
		for _, m := range []map[string]fimEntry{prev.Baseline, prev.Reported} {
			if old, ok := m[path]; ok && !old.Removed && old.Ino == e.Ino && old.Size == e.Size && old.Ctime == e.Ctime && old.SHA256 != "" {
				e.SHA256 = old.SHA256
				return e, true
			}
		}
	}
	fh, err := os.Open(path)
	if err != nil {
		return e, true
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(fh, fimMaxHash)); err == nil {
		e.SHA256 = hex.EncodeToString(h.Sum(nil))
	}
	return e, true
}
