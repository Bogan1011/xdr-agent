package collector

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

// Network polls /proc/net for new TCP connections and listening sockets and
// attributes them to a process through socket inodes. Polling can miss
// connections shorter than the interval; the eBPF collector fixes that.
type Network struct {
	Interval time.Duration
	// ListenOnly reports only listening sockets, for when the eBPF collector
	// reports connections.
	ListenOnly bool
}

const (
	tcpEstablished = "01"
	tcpListen      = "0A"
)

type sock struct {
	proto      string
	state      string
	local      string
	localPort  uint32
	remote     string
	remotePort uint32
	uid        uint32
	inode      uint64
}

func (n *Network) Name() string { return "network" }

func (n *Network) Run(ctx context.Context, emit Emit) error {
	seen := map[uint64]bool{}
	first := true
	t := time.NewTicker(n.Interval)
	defer t.Stop()
	for {
		socks := append(readSockets("/proc/net/tcp", "tcp"), readSockets("/proc/net/tcp6", "tcp6")...)
		current := make(map[uint64]bool, len(socks))
		var fresh []sock
		for _, s := range socks {
			if s.inode == 0 {
				continue
			}
			current[s.inode] = true
			if !seen[s.inode] {
				fresh = append(fresh, s)
			}
		}
		seen = current

		// Listening sockets present at startup are reported once so the
		// dashboard knows the host's exposed services; existing outbound
		// connections are not, to avoid a burst on every restart.
		if len(fresh) > 0 {
			owners := socketOwners()
			self := uint32(os.Getpid())
			for _, s := range fresh {
				if (first || n.ListenOnly) && s.state != tcpListen {
					continue
				}
				pid := owners[s.inode]
				if pid == self {
					continue
				}
				n.emit(emit, s, pid)
			}
		}
		first = false

		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (n *Network) emit(emit Emit, s sock, pid uint32) {
	t := xdrv1.EventType_EVENT_TYPE_NET_CONNECT
	if s.state == tcpListen {
		t = xdrv1.EventType_EVENT_TYPE_NET_LISTEN
	}
	ne := &xdrv1.NetworkEvent{
		Protocol:   s.proto,
		LocalAddr:  s.local,
		LocalPort:  s.localPort,
		RemoteAddr: s.remote,
		RemotePort: s.remotePort,
		Pid:        pid,
		Uid:        s.uid,
	}
	if pid != 0 {
		ne.Exe, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	}
	e := NewEvent(t)
	e.Payload = &xdrv1.Event_Network{Network: ne}
	emit(e)
}

func readSockets(path, proto string) []sock {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []sock
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		st := fields[3]
		if st != tcpEstablished && st != tcpListen {
			continue
		}
		la, lp := parseAddr(fields[1])
		ra, rp := parseAddr(fields[2])
		uid, _ := strconv.ParseUint(fields[7], 10, 32)
		ino, _ := strconv.ParseUint(fields[9], 10, 64)
		out = append(out, sock{proto: proto, state: st, local: la, localPort: lp, remote: ra, remotePort: rp, uid: uint32(uid), inode: ino})
	}
	return out
}

// parseAddr decodes "0100007F:0016" style addresses. The kernel prints each
// 32-bit word of the address in host (little-endian) byte order.
func parseAddr(s string) (string, uint32) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0
	}
	port, _ := strconv.ParseUint(p, 16, 16)
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw)%4 != 0 {
		return "", uint32(port)
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(ip[i:], binary.LittleEndian.Uint32(raw[i:]))
	}
	return ip.String(), uint32(port)
}

// socketOwners maps socket inodes to the pid holding them.
func socketOwners() map[uint64]uint32 {
	out := map[uint64]uint32{}
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, p := range procs {
		pid, err := strconv.ParseUint(p.Name(), 10, 32)
		if err != nil {
			continue
		}
		dir := "/proc/" + p.Name() + "/fd"
		fds, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(dir + "/" + fd.Name())
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			ino, err := strconv.ParseUint(link[8:len(link)-1], 10, 64)
			if err == nil {
				out[ino] = uint32(pid)
			}
		}
	}
	return out
}
