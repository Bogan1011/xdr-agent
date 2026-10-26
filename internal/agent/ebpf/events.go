package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

// Operations reported in FileEvent.Op and NetEvent.Op; they match xdr.bpf.c.
const (
	FileCreate = 1
	FileWrite  = 2
	FileDelete = 3
	FileRename = 4
	FileChmod  = 5

	NetConnect = 1
	NetAccept  = 2
)

const (
	nameSlot      = 128
	pathSlots     = 32
	pathBuf       = nameSlot * pathSlots
	pathTruncated = 0x80000000
	fileHeaderLen = 8*4 + 16
	fileEventLen  = fileHeaderLen + 2*pathBuf
	netEventLen   = 3*4 + 4*2 + 4 + 16 + 16 + 16
	afInet        = 2
)

// FileEvent is a decoded file_event record.
type FileEvent struct {
	PID, PPID, UID uint32
	Op             uint32
	Mode           uint32
	Comm           string
	Path           string // the file, or its new name for a rename
	OldPath        string // set for renames
}

// NetEvent is a decoded net_event record.
type NetEvent struct {
	PID, PPID, UID uint32
	Op             uint16
	IPv6           bool
	LocalAddr      net.IP
	LocalPort      uint16
	RemoteAddr     net.IP
	RemotePort     uint16
	Comm           string
}

var errShort = errors.New("ebpf: short record")

// ParseFileEvent decodes a raw file_event from the ring buffer.
func ParseFileEvent(b []byte) (FileEvent, error) {
	if len(b) < fileEventLen {
		return FileEvent{}, errShort
	}
	le := binary.LittleEndian
	e := FileEvent{
		PID:  le.Uint32(b[0:]),
		PPID: le.Uint32(b[4:]),
		UID:  le.Uint32(b[8:]),
		Op:   le.Uint32(b[12:]),
		Mode: le.Uint32(b[16:]),
		Comm: cString(b[32:48]),
	}
	pathLen, path2Len := le.Uint32(b[20:]), le.Uint32(b[24:])
	e.Path = joinSlots(b[fileHeaderLen:fileHeaderLen+pathBuf], pathLen)
	if path2Len > 0 {
		e.OldPath = joinSlots(b[fileHeaderLen+pathBuf:fileEventLen], path2Len)
	}
	return e, nil
}

// ParseNetEvent decodes a raw net_event from the ring buffer.
func ParseNetEvent(b []byte) (NetEvent, error) {
	if len(b) < netEventLen {
		return NetEvent{}, errShort
	}
	le := binary.LittleEndian
	e := NetEvent{
		PID:        le.Uint32(b[0:]),
		PPID:       le.Uint32(b[4:]),
		UID:        le.Uint32(b[8:]),
		Op:         le.Uint16(b[12:]),
		IPv6:       le.Uint16(b[14:]) != afInet,
		LocalPort:  le.Uint16(b[16:]),
		RemotePort: binary.BigEndian.Uint16(b[18:]),
		Comm:       cString(b[56:72]),
	}
	n := 16
	if !e.IPv6 {
		n = 4
	}
	e.LocalAddr = net.IP(bytes.Clone(b[24 : 24+n]))
	e.RemoteAddr = net.IP(bytes.Clone(b[40 : 40+n]))
	return e, nil
}

// joinSlots turns name slots, written leaf first, into an absolute path. A
// path deeper than the slots allow starts with "/...".
func joinSlots(buf []byte, n uint32) string {
	truncated := n&pathTruncated != 0
	n &^= pathTruncated
	if n > pathSlots {
		n = pathSlots
	}
	var sb strings.Builder
	if truncated {
		sb.WriteString("/...")
	}
	for i := int(n) - 1; i >= 0; i-- {
		name := cString(buf[i*nameSlot : (i+1)*nameSlot])
		if name == "" || name == "/" {
			continue
		}
		sb.WriteByte('/')
		sb.WriteString(name)
	}
	if sb.Len() == 0 {
		return "/"
	}
	return sb.String()
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
