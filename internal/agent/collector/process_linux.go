package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/agent/procfs"
)

// Process collects exec and exit events from the kernel's process events
// connector (CONFIG_PROC_EVENTS). It needs CAP_NET_ADMIN, so the agent runs
// as root. An eBPF collector can replace it later without changing the
// event schema.
type Process struct {
	Hasher *procfs.Hasher
	Log    *slog.Logger

	mu    sync.Mutex
	procs map[uint32]string // pid -> exe, used for exit events and parent lookup
}

const (
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1
	procCnMcastIgnore = 2
	procEventExec     = 0x00000002
	procEventExit     = 0x80000000
	nlmsgHdrLen       = 16
	cnMsgHdrLen       = 20
	procEventHdrLen   = 16
	maxTrackedProcs   = 65536
)

func (p *Process) Name() string { return "process" }

func (p *Process) Run(ctx context.Context, emit Emit) error {
	p.procs = make(map[uint32]string)
	p.seed()

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc, Pid: uint32(os.Getpid())}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}
	if err := p.subscribe(fd, procCnMcastListen); err != nil {
		return fmt.Errorf("subscribe to process events: %w", err)
	}
	defer p.subscribe(fd, procCnMcastIgnore)

	go func() {
		<-ctx.Done()
		// Unblock Recvfrom.
		unix.Shutdown(fd, unix.SHUT_RDWR)
	}()

	self := uint32(os.Getpid())
	buf := make([]byte, 64*1024)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			if err == unix.ENOBUFS {
				p.Log.Warn("process events overflowed the socket buffer; some events were lost")
				continue
			}
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("netlink recv: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			continue
		}
		for _, m := range msgs {
			p.handle(m.Data, self, emit)
		}
	}
}

func (p *Process) subscribe(fd int, op uint32) error {
	msg := make([]byte, nlmsgHdrLen+cnMsgHdrLen+4)
	le := binary.LittleEndian
	le.PutUint32(msg[0:], uint32(len(msg)))
	le.PutUint16(msg[4:], unix.NLMSG_DONE)
	le.PutUint32(msg[12:], uint32(os.Getpid()))
	cn := msg[nlmsgHdrLen:]
	le.PutUint32(cn[0:], cnIdxProc)
	le.PutUint32(cn[4:], cnValProc)
	le.PutUint16(cn[16:], 4)
	le.PutUint32(cn[cnMsgHdrLen:], op)
	return unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

func (p *Process) handle(data []byte, self uint32, emit Emit) {
	if len(data) < cnMsgHdrLen+procEventHdrLen {
		return
	}
	le := binary.LittleEndian
	ev := data[cnMsgHdrLen:]
	what := le.Uint32(ev[0:])
	body := ev[procEventHdrLen:]

	switch what {
	case procEventExec:
		if len(body) < 8 {
			return
		}
		pid, tgid := le.Uint32(body[0:]), le.Uint32(body[4:])
		if pid != tgid || pid == self {
			return
		}
		p.onExec(pid, emit)
	case procEventExit:
		if len(body) < 12 {
			return
		}
		pid, tgid, code := le.Uint32(body[0:]), le.Uint32(body[4:]), le.Uint32(body[8:])
		if pid != tgid {
			return
		}
		p.onExit(pid, code, emit)
	}
}

func (p *Process) onExec(pid uint32, emit Emit) {
	info, err := procfs.Read(pid)
	if err != nil {
		// Short-lived process already gone; report what we know.
		info = &procfs.Info{PID: pid}
	}
	p.mu.Lock()
	if len(p.procs) >= maxTrackedProcs {
		p.procs = make(map[uint32]string)
	}
	p.procs[pid] = info.Exe
	parent := p.procs[info.PPID]
	p.mu.Unlock()
	if parent == "" && info.PPID != 0 {
		parent, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", info.PPID))
	}

	e := NewEvent(xdrv1.EventType_EVENT_TYPE_PROCESS_EXEC)
	e.Payload = &xdrv1.Event_Process{Process: &xdrv1.ProcessEvent{
		Pid:       info.PID,
		Ppid:      info.PPID,
		Uid:       info.UID,
		Gid:       info.GID,
		User:      info.User,
		Exe:       info.Exe,
		Args:      info.Args,
		Cwd:       info.Cwd,
		Sha256:    p.Hasher.Hash(info.Exe),
		ParentExe: parent,
	}}
	emit(e)
}

func (p *Process) onExit(pid, code uint32, emit Emit) {
	p.mu.Lock()
	exe, ok := p.procs[pid]
	delete(p.procs, pid)
	p.mu.Unlock()
	if !ok {
		return
	}
	e := NewEvent(xdrv1.EventType_EVENT_TYPE_PROCESS_EXIT)
	// exit_code holds the raw wait status; the high byte is the exit status.
	e.Payload = &xdrv1.Event_Process{Process: &xdrv1.ProcessEvent{
		Pid:      pid,
		Exe:      exe,
		ExitCode: int32(code >> 8),
	}}
	emit(e)
}

// seed records already running processes so their exits and children have
// context.
func (p *Process) seed() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range entries {
		var pid uint32
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil {
			continue
		}
		if exe, err := os.Readlink("/proc/" + e.Name() + "/exe"); err == nil {
			p.procs[pid] = exe
		}
	}
}
