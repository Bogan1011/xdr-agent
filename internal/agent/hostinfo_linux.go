package agent

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

// Version is set at build time with -ldflags "-X ...agent.Version=...".
var Version = "dev"

func HostInfo() *xdrv1.HostInfo {
	h := &xdrv1.HostInfo{
		Os:           "linux",
		Arch:         runtime.GOARCH,
		AgentVersion: Version,
	}
	h.Hostname, _ = os.Hostname()

	var u unix.Utsname
	if unix.Uname(&u) == nil {
		h.Kernel = unix.ByteSliceToString(u.Release[:])
	}
	if f, err := os.Open("/etc/os-release"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"`)
			switch k {
			case "PRETTY_NAME":
				h.OsVersion = v
			}
		}
		f.Close()
	}
	if id, err := os.ReadFile("/etc/machine-id"); err == nil {
		h.MachineId = strings.TrimSpace(string(id))
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			h.IpAddresses = append(h.IpAddresses, ipn.IP.String())
		}
	}
	return h
}
