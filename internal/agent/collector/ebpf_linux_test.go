package collector

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/agent/ebpf"
	"github.com/Bogan1011/xdr-agent/internal/agent/procfs"
)

func TestEBPFFileHandle(t *testing.T) {
	dir := t.TempDir()
	f := &EBPFFile{
		Paths: []string{dir}, Exclude: []string{filepath.Join(dir, "skip")},
		Hasher: procfs.NewHasher(10), Log: slog.Default(), writes: map[string]pendingWrite{},
	}
	var got []*xdrv1.Event
	emit := func(e *xdrv1.Event) { got = append(got, e) }

	tmp, final := filepath.Join(dir, "a.tmp"), filepath.Join(dir, "a")
	os.WriteFile(final, []byte("hello"), 0o644)
	f.handle(ebpf.FileEvent{Op: ebpf.FileWrite, Path: tmp, PID: 99, Comm: "vim"}, emit)
	f.handle(ebpf.FileEvent{Op: ebpf.FileWrite, Path: tmp, PID: 99}, emit) // merged
	f.handle(ebpf.FileEvent{Op: ebpf.FileCreate, Path: "/elsewhere/x"}, emit)
	f.handle(ebpf.FileEvent{Op: ebpf.FileCreate, Path: filepath.Join(dir, "skip", "x")}, emit)
	if len(got) != 0 {
		t.Fatalf("emitted early or outside the watched paths: %v", got)
	}
	// Renaming the temp file reports its pending write first.
	f.handle(ebpf.FileEvent{Op: ebpf.FileRename, Path: final, OldPath: tmp, PID: 99, Comm: "vim"}, emit)
	if len(got) != 2 || got[0].Type != xdrv1.EventType_EVENT_TYPE_FILE_MODIFY || got[1].Type != xdrv1.EventType_EVENT_TYPE_FILE_RENAME {
		t.Fatalf("got %v", got)
	}
	fe := got[1].GetFile()
	if fe.Pid != 99 || fe.OldPath != tmp || fe.Sha256 == "" || fe.Size != 5 {
		t.Errorf("rename event %+v", fe)
	}
	if fe.Exe != "[vim]" {
		t.Errorf("exe of an exited process = %q", fe.Exe)
	}
	if len(f.writes) != 0 {
		t.Errorf("pending writes left: %v", f.writes)
	}
}

func TestShellEvent(t *testing.T) {
	e := shellEvent(ebpf.ShellEvent{PID: 4242424, UID: 0, Src: ebpf.ShellInteractive, Comm: "bash", Command: "history -c\n"})
	se := e.GetShell()
	if e.Type != xdrv1.EventType_EVENT_TYPE_SHELL_COMMAND || se.Command != "history -c" || se.Source != "interactive" ||
		se.User != "root" || se.Exe != "[bash]" {
		t.Fatalf("event %v", e)
	}
	if shellEvent(ebpf.ShellEvent{Src: ebpf.ShellString, Command: "x"}).GetShell().Source != "string" {
		t.Error("source of bash -c")
	}
}
