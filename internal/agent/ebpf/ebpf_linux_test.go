package ebpf

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

// TestLoadAndCapture loads the programs into the running kernel. It needs
// root and BTF, so it only runs when XDR_EBPF_TEST=1.
func TestLoadAndCapture(t *testing.T) {
	if os.Getenv("XDR_EBPF_TEST") != "1" {
		t.Skip("set XDR_EBPF_TEST=1 and run as root")
	}
	p, err := Load(slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.Files == nil || p.Net == nil {
		t.Fatalf("hooks missing: files=%v net=%v", p.Files != nil, p.Net != nil)
	}

	// The agent's own pid is filtered in the kernel, so act from a child.
	dir := t.TempDir()
	target := filepath.Join(dir, "probe.txt")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	script := "echo hi > " + target + " && mv " + target + " " + target + ".2 && rm " + target + ".2" +
		" && exec 3<>/dev/tcp/127.0.0.1/" + itoa(port)
	if out, err := runShell(script); err != nil {
		t.Fatalf("%v: %s", err, out)
	}

	want := map[uint32]string{FileCreate: target, FileWrite: target, FileRename: target + ".2", FileDelete: target + ".2"}
	got := map[uint32]FileEvent{}
	for len(got) < len(want) {
		rec, err := read(p.Files)
		if err != nil {
			t.Fatalf("file events so far %+v: %v", got, err)
		}
		e, err := ParseFileEvent(rec.RawSample)
		if err != nil {
			t.Fatal(err)
		}
		if want[e.Op] == e.Path {
			got[e.Op] = e
		}
	}
	if got[FileRename].OldPath != target {
		t.Errorf("rename old path = %q", got[FileRename].OldPath)
	}
	if got[FileCreate].PID == 0 || got[FileCreate].Comm == "" {
		t.Errorf("no process attribution: %+v", got[FileCreate])
	}

	for {
		rec, err := read(p.Net)
		if err != nil {
			t.Fatalf("no connect event: %v", err)
		}
		e, err := ParseNetEvent(rec.RawSample)
		if err != nil {
			t.Fatal(err)
		}
		if e.Op == NetConnect && int(e.RemotePort) == port {
			if !e.RemoteAddr.Equal(net.IPv4(127, 0, 0, 1)) || e.LocalPort == 0 || e.PID == 0 {
				t.Errorf("bad connect event %+v", e)
			}
			return
		}
	}
}

func read(r *ringbuf.Reader) (ringbuf.Record, error) {
	r.SetDeadline(time.Now().Add(5 * time.Second))
	rec, err := r.Read()
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return rec, errors.New("timed out")
	}
	return rec, err
}
