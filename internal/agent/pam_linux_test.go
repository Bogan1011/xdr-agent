package agent

import (
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func testPAM(t *testing.T) *PAM {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "etc/passwd"), "root:x:0:0:root:/root:/bin/bash\nalice:x:4242:4242::/home/alice:/bin/bash\n")
	p := &PAM{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), root: root,
		sudoersDir: filepath.Join(root, "etc/sudoers.d"), ioDir: filepath.Join(root, "sudo-io"),
		stateFile: filepath.Join(root, "pam.json"), validate: func(string) error { return nil },
		requests: map[string]uint32{}, lastAsk: map[uint32]time.Time{}, revoked: map[string]bool{},
	}
	os.MkdirAll(p.sudoersDir, 0o755)
	return p
}

func TestGrantAndRevoke(t *testing.T) {
	p := testPAM(t)
	if _, err := p.Grant(map[string]string{"user": "alice", "request_id": "r1", "duration_seconds": "600"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(p.sudoersDir, "xdr-jit-4242"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "alice ALL=(ALL:ALL) NOTAFTER=") || !strings.Contains(string(raw), "Defaults:alice log_output") {
		t.Fatalf("unexpected rule:\n%s", raw)
	}
	if p.grantAt("alice", time.Now()) != "r1" {
		t.Fatal("recording not mapped to the grant")
	}
	if _, err := p.Revoke(map[string]string{"request_id": "r1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(p.sudoersDir, "xdr-jit-4242")); !os.IsNotExist(err) {
		t.Fatal("grant file still present after revoke")
	}
}

func TestGrantRejects(t *testing.T) {
	p := testPAM(t)
	for _, args := range []map[string]string{
		{"user": "root", "request_id": "r", "duration_seconds": "60"},
		{"user": "bob", "request_id": "r", "duration_seconds": "60"},
		{"user": "alice ALL=(ALL) ALL", "request_id": "r", "duration_seconds": "60"},
		{"user": "alice", "request_id": "r", "duration_seconds": "999999"},
		{"user": "alice", "request_id": "", "duration_seconds": "60"},
	} {
		if _, err := p.Grant(args); err == nil {
			t.Errorf("grant %v accepted", args)
		}
	}
}

func TestSweepExpiresAndRemovesUntracked(t *testing.T) {
	p := testPAM(t)
	if _, err := p.Grant(map[string]string{"user": "alice", "request_id": "r1", "duration_seconds": "1"}); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(p.sudoersDir, "xdr-jit-9999")
	writeFile(t, stray, "x ALL=(ALL) ALL\n")
	p.grants[0].Until = time.Now().Add(-time.Second)
	p.sweep()
	for _, f := range []string{stray, filepath.Join(p.sudoersDir, "xdr-jit-4242")} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("%s not removed", f)
		}
	}
}

func TestCollectAccounts(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "etc/passwd"), strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1::/usr/sbin:/usr/sbin/nologin",
		"alice:x:1000:1000::/home/alice:/bin/bash",
		"bob:x:1001:1001::/home/bob:/bin/bash",
		"carol:x:1002:1002::/home/carol:/bin/bash",
		"dave:x:1003:1003::/home/dave:/bin/bash",
		"eve:x:1004:1004::/home/eve:/bin/bash",
	}, "\n"))
	writeFile(t, filepath.Join(root, "etc/group"), "root:x:0:\nsudo:x:27:alice\ndocker:x:999:bob\nalice:x:1000:\n")
	writeFile(t, filepath.Join(root, "etc/shadow"), "root:!:19000::::::\nalice:$6$abc:19500::::::\nbob::19000::::::\n")
	writeFile(t, filepath.Join(root, "etc/sudoers"), "Defaults env_reset\n# comment\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n")
	writeFile(t, filepath.Join(root, "etc/sudoers.d/ops"), "User_Alias OPS = carol, \\\n  dave\nOPS ALL=(ALL) NOPASSWD: ALL\n")
	writeFile(t, filepath.Join(root, "etc/sudoers.d/xdr-jit-1004"), "eve ALL=(ALL:ALL) ALL\n")
	writeFile(t, filepath.Join(root, "etc/sudoers.d/ignored.bak"), "daemon ALL=(ALL) ALL\n")
	writeFile(t, filepath.Join(root, "home/alice/.ssh/authorized_keys"), "ssh-ed25519 AAAA a\n# c\nssh-rsa BBBB b\n")

	inv, err := collectAccounts(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, a := range inv.Accounts {
		got[a.Name] = a.Sources
		switch a.Name {
		case "alice":
			if a.SshKeys != 2 || a.Password != "set" || a.Nopasswd {
				t.Errorf("alice: %+v", a)
			}
		case "bob":
			if a.Password != "empty" {
				t.Errorf("bob password %q", a.Password)
			}
		case "carol":
			if !a.Nopasswd {
				t.Error("carol should be NOPASSWD")
			}
		}
	}
	want := map[string][]string{
		"root":  {"uid0", "sudoers"},
		"alice": {"sudoers:%sudo"},
		"bob":   {"group:docker"},
		"carol": {"sudoers.d/ops"},
		"dave":  {"sudoers.d/ops"},
		"eve":   {"jit"},
	}
	for name, src := range want {
		if !slices.Equal(got[name], src) {
			t.Errorf("%s: sources %v, want %v", name, got[name], src)
		}
	}
	if _, ok := got["daemon"]; ok {
		t.Error("daemon listed from a file sudo ignores")
	}
	if inv.InteractiveAccounts != 6 {
		t.Errorf("interactive = %d", inv.InteractiveAccounts)
	}
}

func TestReadSession(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "alice/00/00/01")
	writeFile(t, filepath.Join(dir, "log"), "1761480000:alice:root::/dev/pts/1:24:80\n/home/alice\n/bin/bash -i\n")
	writeFile(t, filepath.Join(dir, "timing"), "4 0.500000 10\n4 1.250000 20\n5 0.250000 30 100\n")
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("root@host:~# id\nuid=0(root)\n"))
	zw.Close()
	if err := os.WriteFile(filepath.Join(dir, "ttyout"), gz.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	// Still running: the timing file is writable.
	if len(sessionDirs(root)) != 0 {
		t.Fatal("running session picked up")
	}
	os.Chmod(filepath.Join(dir, "timing"), 0o400)
	dirs := sessionDirs(root)
	if len(dirs) != 1 {
		t.Fatalf("dirs = %v", dirs)
	}
	r, err := readSession(root, dirs[0])
	if err != nil {
		t.Fatal(err)
	}
	if r.User != "alice" || r.RunasUser != "root" || r.Tty != "/dev/pts/1" || r.Cwd != "/home/alice" ||
		r.Command != "/bin/bash -i" || r.StartUnix != 1761480000 || r.DurationMs != 2000 {
		t.Fatalf("parsed %+v", r)
	}
	if string(r.Output) != "root@host:~# id\nuid=0(root)\n" || r.SessionId != "alice/00/00/01@1761480000" {
		t.Fatalf("output %q id %q", r.Output, r.SessionId)
	}
	os.WriteFile(filepath.Join(dir, uploadedMarker), nil, 0o600)
	if len(sessionDirs(root)) != 0 {
		t.Fatal("uploaded session picked up again")
	}
}

func TestParseLogJSON(t *testing.T) {
	raw := []byte(`{"timestamp":{"seconds":1761480000,"nanoseconds":5},"submituser":"alice","runuser":"root","ttyname":"/dev/pts/2","submitcwd":"/tmp","command":"/usr/bin/apt","runargv":["apt","update"]}`)
	rec := &xdrv1.SessionRecording{}
	parseLogJSON(raw, rec)
	if rec.User != "alice" || rec.Command != "apt update" || rec.StartUnix != 1761480000 || rec.Tty != "/dev/pts/2" {
		t.Fatalf("parsed %+v", rec)
	}
}

func TestStatusFields(t *testing.T) {
	name, uid := statusFields("Name:\tsudo\nUmask:\t0022\nState:\tS\nUid:\t1000\t0\t0\t0\n")
	if name != "sudo" || uid != 1000 {
		t.Fatalf("got %q %d", name, uid)
	}
}

func TestRevokeBeforeGrant(t *testing.T) {
	p := testPAM(t)
	p.Revoke(map[string]string{"request_id": "r1"})
	if _, err := p.Grant(map[string]string{"user": "alice", "request_id": "r1", "duration_seconds": "60"}); err == nil {
		t.Fatal("grant installed after its revoke")
	}
}
