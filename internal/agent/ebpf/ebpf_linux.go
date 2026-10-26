package ebpf

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ErrNoBTF means the kernel has no BTF, so the CO-RE programs cannot be
// relocated and the agent must use its inotify and /proc collectors.
var ErrNoBTF = errors.New("kernel BTF not available")

// Probes holds the loaded programs. A reader is nil when its hooks could not
// be attached; the agent then falls back to the older collector for that
// source.
type Probes struct {
	Files *ringbuf.Reader
	Net   *ringbuf.Reader

	objs  xdrObjects
	links []link.Link
}

type hook struct {
	symbol string
	prog   *ebpf.Program
	ret    bool
}

// Load loads and attaches the eBPF programs. It returns an error only when
// nothing could be attached.
func Load(log *slog.Logger) (*Probes, error) {
	if _, err := btf.LoadKernelSpec(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoBTF, err)
	}
	// Kernels before 5.11 charge BPF memory to RLIMIT_MEMLOCK.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Debug("raising memlock limit failed", "err", err)
	}
	spec, err := loadXdr()
	if err != nil {
		return nil, err
	}
	if err := spec.Variables["agent_tgid"].Set(uint32(os.Getpid())); err != nil {
		return nil, fmt.Errorf("set agent_tgid: %w", err)
	}
	p := &Probes{}
	if err := spec.LoadAndAssign(&p.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Debug("verifier log", "log", fmt.Sprintf("%+v", ve))
		}
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	fileHooks := []hook{
		{symbol: "security_path_mknod", prog: p.objs.FileCreate},
		{symbol: "security_file_open", prog: p.objs.FileOpen},
		{symbol: "security_path_unlink", prog: p.objs.FileDelete},
		{symbol: "security_path_rename", prog: p.objs.FileRename},
		{symbol: "security_path_chmod", prog: p.objs.FileChmod},
	}
	netHooks := []hook{
		{symbol: "tcp_connect", prog: p.objs.NetConnect},
		{symbol: "inet_csk_accept", prog: p.objs.NetAccept, ret: true},
	}
	if err := p.attach(fileHooks); err != nil {
		log.Warn("eBPF file hooks unavailable, using inotify", "err", err)
	} else if p.Files, err = ringbuf.NewReader(p.objs.FileEvents); err != nil {
		log.Warn("eBPF file ring buffer", "err", err)
	}
	if err := p.attach(netHooks); err != nil {
		log.Warn("eBPF network hooks unavailable, polling /proc/net", "err", err)
	} else if p.Net, err = ringbuf.NewReader(p.objs.NetEvents); err != nil {
		log.Warn("eBPF network ring buffer", "err", err)
	}
	if p.Files == nil && p.Net == nil {
		p.Close()
		return nil, errors.New("no eBPF hooks could be attached")
	}
	return p, nil
}

// attach attaches every hook of a group, or none of them.
func (p *Probes) attach(hooks []hook) error {
	var got []link.Link
	for _, h := range hooks {
		var l link.Link
		var err error
		if h.ret {
			l, err = link.Kretprobe(h.symbol, h.prog, nil)
		} else {
			l, err = link.Kprobe(h.symbol, h.prog, nil)
		}
		if err != nil {
			for _, l := range got {
				l.Close()
			}
			return fmt.Errorf("%s: %w", h.symbol, err)
		}
		got = append(got, l)
	}
	p.links = append(p.links, got...)
	return nil
}

func (p *Probes) Close() error {
	if p.Files != nil {
		p.Files.Close()
	}
	if p.Net != nil {
		p.Net.Close()
	}
	for _, l := range p.links {
		l.Close()
	}
	return p.objs.Close()
}
