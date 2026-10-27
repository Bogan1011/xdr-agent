package agent

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/agent/procfs"
)

const (
	// clockTicks is USER_HZ, 100 on every Linux architecture the agent supports.
	clockTicks = 100
	topProcs   = 12
	maxCommand = 300
)

// liveProc is one process as the activity view needs it.
type liveProc struct {
	pid, ppid, sid, tpgid uint32
	tty                   uint32
	uid                   uint32
	ticks                 uint64
	start                 int64
	rss                   uint64
	command               string
}

// parseStat reads the fields of /proc/<pid>/stat the activity view uses.
// The command name can hold spaces and parentheses, so fields are counted
// from the last ')'.
func parseStat(raw string, bootUnix int64) (*liveProc, error) {
	i := strings.LastIndexByte(raw, ')')
	if i < 0 {
		return nil, fmt.Errorf("malformed stat")
	}
	comm := raw[strings.IndexByte(raw, '(')+1 : i]
	f := strings.Fields(raw[i+1:])
	// f[0] is field 3 (state); field N is f[N-3].
	if len(f) < 22 {
		return nil, fmt.Errorf("short stat")
	}
	u := func(n int) uint64 { v, _ := strconv.ParseUint(f[n-3], 10, 64); return v }
	p := &liveProc{
		ppid: uint32(u(4)), sid: uint32(u(6)), tty: uint32(u(7)),
		ticks: u(14) + u(15), rss: u(24) * uint64(os.Getpagesize()),
		command: "[" + comm + "]",
	}
	if tp, err := strconv.ParseInt(f[8-3], 10, 32); err == nil && tp > 0 {
		p.tpgid = uint32(tp)
	}
	p.start = bootUnix + int64(u(22)/clockTicks)
	return p, nil
}

// ttyName turns a stat tty_nr into a device name such as pts/3 or tty1.
func ttyName(nr uint32) string {
	major := (nr >> 8) & 0xfff
	minor := (nr & 0xff) | ((nr >> 12) & 0xfff00)
	switch {
	case major >= 136 && major <= 143:
		return "pts/" + strconv.FormatUint(uint64(minor+(major-136)*256), 10)
	case major == 4 && minor < 64:
		return "tty" + strconv.FormatUint(uint64(minor), 10)
	case major == 4:
		return "ttyS" + strconv.FormatUint(uint64(minor-64), 10)
	}
	return fmt.Sprintf("tty(%d,%d)", major, minor)
}

func bootTime() int64 {
	raw, _ := os.ReadFile("/proc/stat")
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	return time.Now().Unix()
}

func readProcs(bootUnix int64) map[uint32]*liveProc {
	out := map[uint32]*liveProc{}
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		base := "/proc/" + e.Name()
		raw, err := os.ReadFile(base + "/stat")
		if err != nil {
			continue
		}
		p, err := parseStat(string(raw), bootUnix)
		if err != nil {
			continue
		}
		p.pid = uint32(pid)
		if st, err := os.Stat(base); err == nil {
			if s, ok := st.Sys().(*syscall.Stat_t); ok {
				p.uid = s.Uid
			}
		}
		if cl, err := os.ReadFile(base + "/cmdline"); err == nil {
			if cl = bytes.TrimRight(cl, "\x00"); len(cl) > 0 {
				p.command = string(bytes.ReplaceAll(cl, []byte{0}, []byte{' '}))
			}
		}
		p.command = truncate(p.command, maxCommand)
		out[p.pid] = p
	}
	return out
}

// sshClient is the client address of an SSH login, from its environment.
func sshClient(pid uint32) string {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return ""
	}
	for _, kv := range bytes.Split(raw, []byte{0}) {
		if v, ok := bytes.CutPrefix(kv, []byte("SSH_CONNECTION=")); ok {
			return firstField(string(v))
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

// activitySampler remembers CPU time between snapshots so it can report
// CPU use since the previous one.
type activitySampler struct {
	prev     map[uint32]uint64
	prevTime time.Time
}

// snapshot describes the terminals in use and the busiest processes.
// consoleUsers maps the ttys of console remote shells to their user.
func (s *activitySampler) snapshot(consoleUsers map[string]string) *xdrv1.Activity {
	now := time.Now()
	procs := readProcs(bootTime())
	elapsed := now.Sub(s.prevTime).Seconds()
	cpu := func(p *liveProc) float64 {
		before, ok := s.prev[p.pid]
		if !ok || elapsed <= 0 || elapsed > 600 || p.ticks < before {
			return 0
		}
		return 100 * float64(p.ticks-before) / clockTicks / elapsed
	}
	lp := func(p *liveProc) *xdrv1.LiveProcess {
		out := &xdrv1.LiveProcess{
			Pid: p.pid, Ppid: p.ppid, User: procfs.Username(p.uid), Command: p.command,
			CpuPercent: cpu(p), RssBytes: p.rss, StartUnix: p.start,
		}
		if p.tty != 0 {
			out.Tty = ttyName(p.tty)
		}
		return out
	}

	act := &xdrv1.Activity{}
	byTTY := map[uint32][]*liveProc{}
	all := make([]*xdrv1.LiveProcess, 0, len(procs))
	for _, p := range procs {
		if p.tty != 0 {
			byTTY[p.tty] = append(byTTY[p.tty], p)
		}
		all = append(all, lp(p))
	}
	for nr, ps := range byTTY {
		sort.Slice(ps, func(i, j int) bool {
			return ps[i].start < ps[j].start || (ps[i].start == ps[j].start && ps[i].pid < ps[j].pid)
		})
		// The session leader is the login shell (or su for console shells).
		leader := ps[0]
		for _, p := range ps {
			if p.pid == p.sid {
				leader = p
				break
			}
		}
		t := &xdrv1.TerminalSession{
			Tty: ttyName(nr), User: procfs.Username(leader.uid), From: sshClient(leader.pid), LoginUnix: leader.start,
		}
		if u, ok := consoleUsers[t.Tty]; ok {
			t.User, t.Console = u, true
		}
		if st, err := os.Stat("/dev/" + t.Tty); err == nil {
			if s, ok := st.Sys().(*syscall.Stat_t); ok {
				if idle := now.Unix() - s.Atim.Sec; idle > 0 {
					t.IdleSeconds = uint64(idle)
				}
			}
		}
		// What runs in the foreground, unless it is the shell at its prompt.
		if fg, ok := procs[leader.tpgid]; ok && fg.pid != leader.pid && !isShell(fg.command) {
			t.Current = fg.command
		}
		for _, p := range ps {
			t.Processes = append(t.Processes, lp(p))
		}
		act.Terminals = append(act.Terminals, t)
	}
	sort.Slice(act.Terminals, func(i, j int) bool { return act.Terminals[i].LoginUnix > act.Terminals[j].LoginUnix })
	sort.Slice(all, func(i, j int) bool {
		return all[i].CpuPercent > all[j].CpuPercent || (all[i].CpuPercent == all[j].CpuPercent && all[i].RssBytes > all[j].RssBytes)
	})
	act.Top = all[:min(topProcs, len(all))]

	s.prev = make(map[uint32]uint64, len(procs))
	for _, p := range procs {
		s.prev[p.pid] = p.ticks
	}
	s.prevTime = now

	if raw, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(raw)); len(f) > 0 {
			act.Load1, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if raw, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(raw)); len(f) > 0 {
			up, _ := strconv.ParseFloat(f[0], 64)
			act.UptimeSeconds = uint64(up)
		}
	}
	act.MemTotalBytes, act.MemAvailableBytes = meminfo()
	return act
}

func isShell(cmd string) bool {
	name := strings.TrimPrefix(firstField(cmd), "-")
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	switch name {
	case "bash", "sh", "zsh", "dash", "fish", "ksh", "tcsh", "csh":
		return true
	}
	return false
}

func meminfo() (total, avail uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), ":")
		n, _ := strconv.ParseUint(strings.Fields(v + " 0")[0], 10, 64)
		switch k {
		case "MemTotal":
			total = n << 10
		case "MemAvailable":
			avail = n << 10
		}
	}
	return total, avail
}
