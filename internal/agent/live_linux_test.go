package agent

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseStat(t *testing.T) {
	raw := "4242 (tmux: server (x)) S 1 4242 4242 34817 4300 4194560 100 0 0 0 250 50 0 0 20 0 1 0 1000 1234567 300 18446744073709551615"
	p, err := parseStat(raw, 1_700_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if p.ppid != 1 || p.sid != 4242 || p.tpgid != 4300 || p.ticks != 300 || p.start != 1_700_000_010 {
		t.Fatalf("parsed %+v", p)
	}
	if p.rss != 300*uint64(os.Getpagesize()) || p.command != "[tmux: server (x)]" {
		t.Fatalf("parsed %+v", p)
	}
	if ttyName(p.tty) != "pts/1" {
		t.Fatalf("tty %d = %s", p.tty, ttyName(p.tty))
	}
}

func TestTTYName(t *testing.T) {
	for nr, want := range map[uint32]string{34816: "pts/0", 34817 + 255: "pts/256", 1025: "tty1", 4<<8 | 64: "ttyS0"} {
		if got := ttyName(nr); got != want {
			t.Errorf("ttyName(%d) = %s, want %s", nr, got, want)
		}
	}
	if !isShell("-bash") || !isShell("/usr/bin/zsh -l") || isShell("vim /etc/hosts") {
		t.Error("isShell")
	}
}

func TestPTYRoundTrip(t *testing.T) {
	ptm, pts, tty, err := openPTY()
	if err != nil {
		t.Skip("no pty:", err)
	}
	defer ptm.Close()
	if !strings.HasPrefix(tty, "pts/") {
		t.Fatal(tty)
	}
	cmd := exec.Command("/bin/sh", "-c", "read x; echo got:$x; tty")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = pts, pts, pts
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pts.Close()
	(&shell{ptm: ptm}).resize(100, 30)
	ptm.Write([]byte("hello\n"))
	var out strings.Builder
	buf := make([]byte, 1024)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(out.String(), "/dev/"+tty) {
		ptm.SetReadDeadline(time.Now().Add(time.Second))
		n, _ := ptm.Read(buf)
		out.Write(buf[:n])
	}
	cmd.Wait()
	if !strings.Contains(out.String(), "got:hello") || !strings.Contains(out.String(), "/dev/"+tty) {
		t.Fatalf("output %q", out.String())
	}
}

func TestActivitySnapshot(t *testing.T) {
	var s activitySampler
	s.snapshot(nil)
	act := s.snapshot(nil)
	if len(act.Top) == 0 || act.MemTotalBytes == 0 {
		t.Fatalf("snapshot %+v", act)
	}
}
