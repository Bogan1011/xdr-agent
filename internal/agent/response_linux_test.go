package agent

import (
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)


func TestQuarantineRestore(t *testing.T) {
	dir := t.TempDir()
	a := &Agent{cfg: &Config{StateDir: filepath.Join(dir, "state")}, log: slog.Default()}
	f := filepath.Join(dir, "evil.sh")
	if err := os.WriteFile(f, []byte("#!/bin/sh\necho evil\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	id, err := a.quarantineFile(map[string]string{"path": f})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Fatal("file still present after quarantine")
	}
	if st, err := os.Stat(filepath.Join(a.quarantineDir(), id+".bin")); err != nil || st.Mode().Perm() != 0 {
		t.Fatalf("quarantined copy: %v %v", st, err)
	}
	if _, err := a.restoreFile(map[string]string{"quarantine_id": id}); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(f); err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("restored file: %v %v", st, err)
	}
	if _, err := a.quarantineFile(map[string]string{"path": "/proc/self/status"}); err == nil {
		t.Error("quarantined a /proc file")
	}
	if _, err := a.restoreFile(map[string]string{"quarantine_id": "../../etc/passwd"}); err == nil {
		t.Error("accepted a bad id")
	}
}

func TestIsolationRules(t *testing.T) {
	ps := dedupePrefixes([]netip.Prefix{
		netip.MustParsePrefix("192.168.1.118/32"),
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("10.0.0.5/32"),
		netip.MustParsePrefix("10.0.0.5/32"),
		netip.MustParsePrefix("fd00::1/128"),
	})
	if len(ps) != 3 {
		t.Fatalf("dedupe: %v", ps)
	}
	r := isolationRules(ps)
	for _, want := range []string{
		"elements = { 192.168.1.0/24, 10.0.0.5/32 }",
		"elements = { fd00::1/128 }",
		"policy drop;",
		"ct original ip daddr @allow4 accept",
		`iif "lo" accept`,
	} {
		if !strings.Contains(r, want) {
			t.Errorf("ruleset missing %q:\n%s", want, r)
		}
	}
}

func TestScannerEmitsMatch(t *testing.T) {
	dir := t.TempDir()
	var got []string
	s := NewScanner(slog.Default(), func(e *xdrv1.Event) { got = append(got, e.GetYara().Rules...) }, 1<<20, nil)
	if err := s.Update("v1", `rule T { strings: $a = "needle" condition: $a }`); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hay needle hay"), 0o644)
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("hay"), 0o644)
	msg, err := s.ScanPath(t.Context(), dir)
	if err != nil || !strings.Contains(msg, "scanned 2 files") || len(got) != 1 || got[0] != "T" {
		t.Fatalf("msg=%q err=%v got=%v", msg, err, got)
	}
}
