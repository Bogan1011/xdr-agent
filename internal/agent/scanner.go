package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/agent/collector"
	"github.com/Bogan1011/xdr-agent/internal/yara"
)

// Scanner runs the console's YARA rules over new and changed files and
// over the binaries of new processes. Work is queued and dropped when the
// queue is full, so scanning never slows the collectors down.
type Scanner struct {
	Log      *slog.Logger
	Emit     collector.Emit
	MaxBytes int64
	// Skip lists path prefixes that are never scanned.
	Skip []string
	// OnMatch, when set, may act on a matched file and returns what it did.
	OnMatch func(path string) string

	rules   atomic.Pointer[yara.Rules]
	version atomic.Value // string
	queue   chan scanReq

	mu   sync.Mutex
	seen map[string]string // file identity to the content version it was scanned with
}

type scanReq struct {
	path   string
	sha256 string
	pid    uint32
}

const maxSeen = 50000

func NewScanner(log *slog.Logger, emit collector.Emit, maxBytes int64, skip []string) *Scanner {
	s := &Scanner{Log: log, Emit: emit, MaxBytes: maxBytes, Skip: skip, queue: make(chan scanReq, 512), seen: map[string]string{}}
	s.version.Store("")
	return s
}

// Version is the content version of the loaded rules.
func (s *Scanner) Version() string { return s.version.Load().(string) }

// Update compiles and swaps in a new rule set.
func (s *Scanner) Update(version, src string) error {
	var rs *yara.Rules
	if strings.TrimSpace(src) != "" {
		var err error
		if rs, err = yara.Compile(src); err != nil {
			return err
		}
	}
	s.rules.Store(rs)
	s.version.Store(version)
	s.Log.Info("YARA rules loaded", "version", version, "rules", rs.Len())
	return nil
}

// Submit queues a file for scanning without blocking.
func (s *Scanner) Submit(path, sha string, pid uint32) {
	if s.rules.Load() == nil || path == "" {
		return
	}
	select {
	case s.queue <- scanReq{path, sha, pid}:
	default:
	}
}

// Observe queues the files that an event introduces.
func (s *Scanner) Observe(e *xdrv1.Event) {
	switch p := e.Payload.(type) {
	case *xdrv1.Event_Process:
		if e.Type == xdrv1.EventType_EVENT_TYPE_PROCESS_EXEC {
			s.Submit(p.Process.Exe, p.Process.Sha256, p.Process.Pid)
		}
	case *xdrv1.Event_File:
		switch e.Type {
		case xdrv1.EventType_EVENT_TYPE_FILE_MODIFY, xdrv1.EventType_EVENT_TYPE_FILE_RENAME, xdrv1.EventType_EVENT_TYPE_FILE_ATTRIB:
			s.Submit(p.File.Path, p.File.Sha256, 0)
		}
	}
}

func (s *Scanner) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case r := <-s.queue:
			if _, err := s.scanFile(r, false); err != nil {
				s.Log.Debug("scan skipped", "path", r.path, "err", err)
			}
		}
	}
}

func (s *Scanner) skipped(path string) bool {
	for _, p := range s.Skip {
		if path == p || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") {
			return true
		}
	}
	return strings.HasPrefix(path, "/proc/") || strings.HasPrefix(path, "/sys/") || strings.HasPrefix(path, "/dev/") && !strings.HasPrefix(path, "/dev/shm/")
}

// scanFile scans one regular file and emits a match event. With force it
// rescans files already scanned with the current rules.
func (s *Scanner) scanFile(r scanReq, force bool) (bool, error) {
	rules := s.rules.Load()
	if rules == nil {
		return false, fmt.Errorf("no rules loaded")
	}
	if s.skipped(r.path) {
		return false, fmt.Errorf("excluded path")
	}
	f, err := os.Open(r.path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !st.Mode().IsRegular() || st.Size() == 0 {
		return false, fmt.Errorf("not a regular non-empty file")
	}
	if st.Size() > s.MaxBytes {
		return false, fmt.Errorf("larger than %d bytes", s.MaxBytes)
	}
	version := s.Version()
	key := r.sha256
	if key == "" {
		key = fmt.Sprintf("%s|%d|%d", r.path, st.Size(), st.ModTime().UnixNano())
	}
	if !force {
		s.mu.Lock()
		done := s.seen[key] == version
		s.mu.Unlock()
		if done {
			return false, nil
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, s.MaxBytes))
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	s.mu.Lock()
	if len(s.seen) >= maxSeen {
		clear(s.seen)
	}
	s.seen[key] = version
	s.seen[hash] = version
	s.mu.Unlock()

	names := rules.Scan(data)
	if len(names) == 0 {
		return false, nil
	}
	s.Log.Warn("YARA match", "path", r.path, "rules", names, "sha256", hash)
	var action string
	if s.OnMatch != nil {
		f.Close()
		action = s.OnMatch(r.path)
	}
	e := collector.NewEvent(xdrv1.EventType_EVENT_TYPE_YARA_MATCH)
	e.Payload = &xdrv1.Event_Yara{Yara: &xdrv1.YaraMatch{
		Path: r.path, Sha256: hash, Rules: names, Pid: r.pid, Size: uint64(len(data)), Action: action,
	}}
	s.Emit(e)
	return true, nil
}

// ScanPath scans a file or a directory tree on request from the console.
func (s *Scanner) ScanPath(ctx context.Context, root string) (string, error) {
	if s.rules.Load() == nil {
		return "", fmt.Errorf("no YARA rules loaded yet")
	}
	const maxFiles = 200000
	files, matches := 0, 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if p == root {
				return err
			}
			return nil
		}
		if d.IsDir() {
			if p != root && s.skipped(p+"/") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if files >= maxFiles {
			return fs.SkipAll
		}
		files++
		if hit, _ := s.scanFile(scanReq{path: p}, true); hit {
			matches++
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("scanned %d files under %s, %d matched", files, root, matches), nil
}
