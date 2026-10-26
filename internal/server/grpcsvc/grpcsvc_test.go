package grpcsvc

import (
	"strings"
	"testing"
	"time"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

func TestJoinArgs(t *testing.T) {
	got := joinArgs([]string{"sh", "-c", "echo hi", ""})
	want := `sh -c "echo hi" ""`
	if got != want {
		t.Errorf("joinArgs = %s, want %s", got, want)
	}
}

func TestEventTypeName(t *testing.T) {
	if got := EventTypeName(xdrv1.EventType_EVENT_TYPE_NET_CONNECT); got != "net_connect" {
		t.Errorf("EventTypeName = %s", got)
	}
}

func TestNewPrivileged(t *testing.T) {
	prev := []byte(`[{"name":"root","sources":["uid0"]},{"name":"alice","sources":["sudoers:%sudo"]}]`)
	cur := []*xdrv1.PrivilegedAccount{
		{Name: "root", Sources: []string{"uid0"}},
		{Name: "alice", Sources: []string{"sudoers:%sudo", "group:docker"}},
		{Name: "eve", Sources: []string{"jit"}},
		{Name: "mallory", Sources: []string{"sudoers.d/backdoor"}},
	}
	var names []string
	for _, a := range NewPrivileged(prev, cur) {
		names = append(names, a.Name)
	}
	if strings.Join(names, ",") != "alice,mallory" {
		t.Fatalf("new privileged = %v", names)
	}
}

func TestElevationDuration(t *testing.T) {
	for in, want := range map[uint64]time.Duration{0: time.Hour, 60: 5 * time.Minute, 1800: 30 * time.Minute, 86400: MaxElevation} {
		if got := ElevationDuration(in); got != want {
			t.Errorf("ElevationDuration(%d) = %s, want %s", in, got, want)
		}
	}
}
