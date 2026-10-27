package procfs

import (
	"os"
	"testing"
)

func TestProcessGUIDStable(t *testing.T) {
	pid := uint32(os.Getpid())
	a, err := StartTicks(pid)
	if err != nil {
		t.Skip("no /proc:", err)
	}
	b, _ := StartTicks(pid)
	if a != b || ProcessGUID(pid, a) != ProcessGUID(pid, b) {
		t.Fatal("process_guid changed for the same process")
	}
	if ProcessGUID(pid, a) == ProcessGUID(pid, a+1) {
		t.Fatal("a reused PID must get a new process_guid")
	}
	if g := ProcessGUID(pid, a); len(g) != 36 {
		t.Fatalf("unexpected guid format %q", g)
	}
	if StartTimeUnixNano(a) <= 0 {
		t.Fatal("start time not resolved")
	}
}

// The Rust agent derives the same GUID (agent-rs/crates/xdr-linux/src/procfs.rs).
func TestGUIDVector(t *testing.T) {
	if g := guidFor("b", 1, 2); g != "ff16d78f-6c31-9e86-59f9-c481be0a2194" {
		t.Fatalf("guid = %s", g)
	}
}
