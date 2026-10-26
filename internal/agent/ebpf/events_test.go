package ebpf

import (
	"encoding/binary"
	"net"
	"testing"
)

// slots writes names into a path buffer the way build_path does: the leaf in
// slot 0, then each parent.
func slots(names ...string) []byte {
	b := make([]byte, pathBuf)
	for i, n := range names {
		copy(b[i*nameSlot:], n)
	}
	return b
}

func TestParseFileEvent(t *testing.T) {
	le := binary.LittleEndian
	raw := make([]byte, fileEventLen)
	le.PutUint32(raw[0:], 42)
	le.PutUint32(raw[4:], 1)
	le.PutUint32(raw[8:], 1000)
	le.PutUint32(raw[12:], FileRename)
	le.PutUint32(raw[20:], 4)
	le.PutUint32(raw[24:], 3)
	copy(raw[32:], "mv")
	// The new name /tmp/x/b crosses an empty mount slot; the old one is /tmp/a.
	copy(raw[fileHeaderLen:], slots("b", "x", "", "tmp"))
	copy(raw[fileHeaderLen+pathBuf:], slots("a", "tmp", ""))

	e, err := ParseFileEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if e.PID != 42 || e.PPID != 1 || e.UID != 1000 || e.Op != FileRename || e.Comm != "mv" {
		t.Errorf("header %+v", e)
	}
	if e.Path != "/tmp/x/b" || e.OldPath != "/tmp/a" {
		t.Errorf("paths %q %q", e.Path, e.OldPath)
	}
	if _, err := ParseFileEvent(raw[:100]); err == nil {
		t.Error("short record accepted")
	}
}

func TestJoinSlots(t *testing.T) {
	for _, tc := range []struct {
		buf  []byte
		n    uint32
		want string
	}{
		{slots("", "etc", "passwd"), 0, "/"},
		{slots("", "passwd", "etc"), 3, "/etc/passwd"},
		{slots("passwd", "etc"), 2, "/etc/passwd"},
		{slots("f", "deep"), 2 | pathTruncated, "/.../deep/f"},
	} {
		if got := joinSlots(tc.buf, tc.n); got != tc.want {
			t.Errorf("joinSlots(%d) = %q, want %q", tc.n&^pathTruncated, got, tc.want)
		}
	}
}

func TestParseNetEvent(t *testing.T) {
	le := binary.LittleEndian
	raw := make([]byte, netEventLen)
	le.PutUint32(raw[0:], 7)
	le.PutUint16(raw[12:], NetConnect)
	le.PutUint16(raw[14:], 2)
	le.PutUint16(raw[16:], 51000)
	binary.BigEndian.PutUint16(raw[18:], 443)
	copy(raw[24:], []byte{10, 0, 0, 5})
	copy(raw[40:], []byte{93, 184, 216, 34})
	copy(raw[56:], "curl")
	e, err := ParseNetEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if e.IPv6 || e.LocalPort != 51000 || e.RemotePort != 443 || e.Comm != "curl" || e.PID != 7 {
		t.Errorf("%+v", e)
	}
	if !e.RemoteAddr.Equal(net.IPv4(93, 184, 216, 34)) || e.LocalAddr.String() != "10.0.0.5" {
		t.Errorf("addrs %v %v", e.LocalAddr, e.RemoteAddr)
	}

	le.PutUint16(raw[14:], 10)
	copy(raw[40:], net.ParseIP("2001:db8::1"))
	e, _ = ParseNetEvent(raw)
	if !e.IPv6 || e.RemoteAddr.String() != "2001:db8::1" {
		t.Errorf("v6 %+v", e)
	}
}
