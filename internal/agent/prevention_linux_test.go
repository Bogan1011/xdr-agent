package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

type sink struct {
	mu     sync.Mutex
	events []*xdrv1.Event
}

func (s *sink) emit(e *xdrv1.Event) {
	s.mu.Lock()
	s.events = append(s.events, e)
	s.mu.Unlock()
}

func (s *sink) take() []*xdrv1.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.events
	s.events = nil
	return out
}

func changes(evs []*xdrv1.Event) map[string]string {
	out := map[string]string{}
	for _, e := range evs {
		out[filepath.Base(e.GetFile().Path)] = e.GetFile().Change
	}
	return out
}

func TestFIMDrift(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "etc")
	os.MkdirAll(filepath.Join(root, "sub"), 0o755)
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("passwd", "root:x:0:0")
	write("hosts", "127.0.0.1 localhost")
	write("sub/skip.tmp", "x")
	os.Symlink("passwd", filepath.Join(root, "link"))

	s := &sink{}
	f := NewFIM(slog.Default(), s.emit, filepath.Join(dir, "fim.json"))
	f.SetPolicy(&xdrv1.FimPolicy{Enabled: true, Paths: []string{root}, Exclude: []string{root + "/sub/*.tmp"}, IntervalMinutes: 60})
	f.scan(false)
	if on, n := f.Status(); !on || n != 3 {
		t.Fatalf("baseline: on=%v files=%d, want 3", on, n)
	}
	if evs := s.take(); len(evs) != 0 {
		t.Fatalf("baseline raised %d events", len(evs))
	}

	write("passwd", "root:x:0:0\nevil:x:0:0")
	os.Chmod(filepath.Join(root, "hosts"), 0o666)
	write("new", "x")
	write("sub/skip.tmp", "changed")
	os.Remove(filepath.Join(root, "link"))
	f.scan(false)
	got := changes(s.take())
	want := map[string]string{"passwd": "content", "hosts": "permissions", "new": "added", "link": "removed"}
	if len(got) != len(want) {
		t.Fatalf("drift = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: change %q, want %q", k, got[k], v)
		}
	}

	// The same drift is reported once, also after a restart.
	f2 := NewFIM(slog.Default(), s.emit, filepath.Join(dir, "fim.json"))
	f2.load()
	f2.SetPolicy(f.policy)
	f2.scan(false)
	if evs := s.take(); len(evs) != 0 {
		t.Fatalf("repeat scan raised %v", changes(evs))
	}

	// A further change to a drifted file is reported again, with the
	// baseline hash.
	write("passwd", "root:x:0:0\nevil2:x:0:0")
	f2.check([]string{filepath.Join(root, "passwd"), filepath.Join(root, "sub/skip.tmp")})
	evs := s.take()
	if len(evs) != 1 || evs[0].GetFile().OldSha256 == "" || evs[0].GetFile().Change != "content" {
		t.Fatalf("event check: %v", evs)
	}

	// Restoring the file clears the drift; a new baseline accepts the rest.
	write("passwd", "root:x:0:0")
	f2.check([]string{filepath.Join(root, "passwd")})
	if _, ok := f2.st.Reported[filepath.Join(root, "passwd")]; ok || len(s.take()) != 0 {
		t.Fatal("restored file still reported")
	}
	f2.scan(true)
	write("hosts", "changed")
	f2.scan(false)
	if got := changes(s.take()); len(got) != 1 || got["hosts"] != "content" {
		t.Fatalf("after rebaseline: %v", got)
	}
}

func TestFIMNewRootIsSilent(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	os.MkdirAll(a, 0o755)
	os.MkdirAll(b, 0o755)
	os.WriteFile(filepath.Join(a, "1"), []byte("1"), 0o644)
	os.WriteFile(filepath.Join(b, "2"), []byte("2"), 0o644)
	s := &sink{}
	f := NewFIM(slog.Default(), s.emit, filepath.Join(dir, "fim.json"))
	f.SetPolicy(&xdrv1.FimPolicy{Enabled: true, Paths: []string{a}, IntervalMinutes: 60})
	f.scan(false)
	f.SetPolicy(&xdrv1.FimPolicy{Enabled: true, Paths: []string{b}, IntervalMinutes: 60})
	f.scan(false)
	if evs := s.take(); len(evs) != 0 {
		t.Fatalf("policy change raised %v", changes(evs))
	}
	if _, n := f.Status(); n != 1 {
		t.Fatalf("baseline files = %d, want 1", n)
	}
	f.Notify(filepath.Join(a, "1"))
	if len(f.pending) != 0 {
		t.Fatal("path outside the policy queued")
	}
}

func TestExecBlockerHashes(t *testing.T) {
	b := NewExecBlocker(slog.Default(), func(*xdrv1.Event) {}, 0)
	x, y := sha256.Sum256([]byte("x")), sha256.Sum256([]byte("y"))
	if n := b.SetHashes(append(append(x[:], y[:]...), 1, 2, 3)); n != 2 {
		t.Fatalf("SetHashes = %d", n)
	}
	if !b.blocked(x) || b.blocked(sha256.Sum256([]byte("z"))) {
		t.Fatal("block list lookup")
	}
	if got := unescapeMount(`/mnt/my\040disk`); got != "/mnt/my disk" {
		t.Fatalf("unescapeMount = %q", got)
	}
}

// TestExecBlocking runs a real fanotify blocker when the test runs as root
// on a kernel that supports it.
func TestExecBlocking(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	dir := t.TempDir()
	bad, good := filepath.Join(dir, "bad"), filepath.Join(dir, "good")
	cp := func(dst string, extra string) {
		raw, err := os.ReadFile("/bin/true")
		if err != nil {
			t.Skip("no /bin/true")
		}
		os.WriteFile(dst, append(raw, extra...), 0o755)
	}
	cp(bad, "bad")
	cp(good, "good")
	raw, _ := os.ReadFile(bad)
	sum := sha256.Sum256(raw)

	s := &sink{}
	b := NewExecBlocker(slog.Default(), s.emit, 64<<20)
	b.SetHashes(sum[:])
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx, func() { close(started) }) }()
	select {
	case err := <-done:
		t.Skipf("fanotify unavailable: %v", err)
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("blocker did not start")
	}
	defer func() {
		cancel()
		<-done
	}()

	if err := exec.Command(good).Run(); err != nil {
		t.Fatalf("allowed binary failed: %v", err)
	}
	err := exec.Command(bad).Run()
	if err == nil || !errors.Is(err, os.ErrPermission) && !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("blocked binary ran: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	evs := s.take()
	if len(evs) != 1 || evs[0].Type != xdrv1.EventType_EVENT_TYPE_EXEC_BLOCKED || evs[0].GetProcess().Exe != bad {
		t.Fatalf("events = %v", evs)
	}
}
