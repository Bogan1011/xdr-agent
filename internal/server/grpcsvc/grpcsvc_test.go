package grpcsvc

import (
	"testing"

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
