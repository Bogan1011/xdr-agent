package agent

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/agent/collector"
	"github.com/Bogan1011/xdr-agent/internal/policy"
)

const (
	webRepRefresh = 10 * time.Minute
	// maxResolve caps the domains resolved per refresh; the policy's own
	// domains come first, then threat intel.
	maxResolve     = 2000
	webRepDedupe   = time.Minute
	resolveWorkers = 16
)

// WebReputation rejects outbound connections to known-bad addresses: IP IOCs
// and the addresses of listed domains, resolved every few minutes. It
// reports connections to them seen by the network collectors.
type WebReputation struct {
	Log     *slog.Logger
	Emit    collector.Emit
	Console func() ([]netip.Addr, error)

	mu         sync.Mutex
	pol        *xdrv1.WebReputationPolicy
	intelIPs   []string
	intelDoms  []string
	exact      map[netip.Addr]string // address to why it is listed
	nets       []listedNet
	script     string
	err        string
	lastReport map[string]time.Time
	kick       chan struct{}
}

type listedNet struct {
	p      netip.Prefix
	reason string
}

func NewWebReputation(log *slog.Logger, emit collector.Emit, console func() ([]netip.Addr, error)) *WebReputation {
	return &WebReputation{Log: log, Emit: emit, Console: console, lastReport: map[string]time.Time{}, kick: make(chan struct{}, 1)}
}

func (w *WebReputation) SetPolicy(p *xdrv1.WebReputationPolicy) {
	w.mu.Lock()
	changed := !proto.Equal(p, w.pol)
	w.pol = proto.Clone(p).(*xdrv1.WebReputationPolicy)
	w.mu.Unlock()
	if changed {
		w.refresh()
	}
}

// SetIntel takes the IP and domain IOCs from the detection content.
func (w *WebReputation) SetIntel(ips, domains []string) {
	w.mu.Lock()
	w.intelIPs, w.intelDoms = ips, domains
	w.mu.Unlock()
	w.refresh()
}

func (w *WebReputation) refresh() {
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

func (w *WebReputation) Run(ctx context.Context) {
	t := time.NewTicker(webRepRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.kick:
		case <-t.C:
		}
		w.rebuild(ctx)
	}
}

func (w *WebReputation) rebuild(ctx context.Context) {
	w.mu.Lock()
	pol := w.pol
	ips, doms := w.intelIPs, w.intelDoms
	w.mu.Unlock()
	if pol == nil || !pol.Enabled {
		w.mu.Lock()
		w.exact, w.nets = nil, nil
		w.mu.Unlock()
		w.apply(nil, false)
		return
	}

	allowed := map[string]bool{}
	for _, d := range pol.AllowedDomains {
		allowed[d] = true
	}
	exact := map[netip.Addr]string{}
	var nets []listedNet
	var resolve []string
	seen := map[string]bool{}
	addDomain := func(d string) {
		if !seen[d] && !policy.DomainListed(d, allowed) && len(resolve) < maxResolve {
			seen[d] = true
			resolve = append(resolve, d)
		}
	}
	for _, d := range pol.BlockedDomains {
		addDomain(d)
	}
	if pol.UseThreatIntel {
		for _, s := range ips {
			if p, err := netip.ParsePrefix(s); err == nil {
				if p.IsSingleIP() {
					exact[p.Addr().Unmap()] = "threat intel"
				} else {
					nets = append(nets, listedNet{p.Masked(), "threat intel"})
				}
			} else if a, err := netip.ParseAddr(s); err == nil {
				exact[a.Unmap()] = "threat intel"
			}
		}
		for _, d := range doms {
			addDomain(d)
		}
	}
	for d, addrs := range resolveAll(ctx, resolve) {
		for _, a := range addrs {
			exact[a] = d
		}
	}

	// Never cut the agent off from the console, or the host from itself.
	console, _ := w.Console()
	for _, a := range console {
		delete(exact, a.Unmap())
	}
	for a := range exact {
		if a.IsLoopback() || a.IsUnspecified() {
			delete(exact, a)
		}
	}
	kept := nets[:0]
	for _, n := range nets {
		ok := !n.p.Contains(netip.IPv4Unspecified()) && !n.p.Contains(netip.IPv6Unspecified())
		for _, a := range console {
			ok = ok && !n.p.Contains(a.Unmap())
		}
		if ok {
			kept = append(kept, n)
		}
	}
	nets = kept

	w.mu.Lock()
	w.exact, w.nets = exact, nets
	w.mu.Unlock()
	prefixes := make([]netip.Prefix, 0, len(exact)+len(nets))
	for a := range exact {
		prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
	}
	for _, n := range nets {
		prefixes = append(prefixes, n.p)
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].Addr().Less(prefixes[j].Addr()) })
	w.apply(prefixes, pol.Block)
}

// apply installs or removes the nftables table.
func (w *WebReputation) apply(prefixes []netip.Prefix, block bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !block {
		if w.script != "" || tablePresent(policy.WebReputationTable) {
			if err := nft(policy.DeleteTable(policy.WebReputationTable)); err != nil {
				w.err = err.Error()
				return
			}
			w.Log.Info("web reputation blocking stopped")
		}
		w.script, w.err = "", ""
		return
	}
	script := policy.WebReputationRules(prefixes)
	if script == w.script && tablePresent(policy.WebReputationTable) {
		return
	}
	if err := nft(script); err != nil {
		w.err = err.Error()
		w.Log.Error("web reputation block list not applied", "err", err)
		return
	}
	w.script, w.err = script, ""
	w.Log.Info("web reputation block list applied", "addresses", len(prefixes))
}

// resolveAll looks up the domains in parallel, each with a short timeout.
func resolveAll(ctx context.Context, domains []string) map[string][]netip.Addr {
	out := map[string][]netip.Addr{}
	var mu sync.Mutex
	work := make(chan string)
	var wg sync.WaitGroup
	for range resolveWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range work {
				cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
				addrs, err := net.DefaultResolver.LookupNetIP(cctx, "ip", d)
				cancel()
				if err != nil {
					continue
				}
				for i := range addrs {
					addrs[i] = addrs[i].Unmap()
				}
				mu.Lock()
				out[d] = addrs
				mu.Unlock()
			}
		}()
	}
	for _, d := range domains {
		if ctx.Err() != nil {
			break
		}
		work <- d
	}
	close(work)
	wg.Wait()
	return out
}

// listed reports why an address is on the list, or "".
func (w *WebReputation) listed(a netip.Addr) string {
	if r, ok := w.exact[a]; ok {
		return r
	}
	for _, n := range w.nets {
		if n.p.Contains(a) {
			return n.reason
		}
	}
	return ""
}

// Observe reports connections to listed addresses.
func (w *WebReputation) Observe(e *xdrv1.Event) {
	ne := e.GetNetwork()
	if ne == nil || e.Type != xdrv1.EventType_EVENT_TYPE_NET_CONNECT {
		return
	}
	a, err := netip.ParseAddr(ne.RemoteAddr)
	if err != nil {
		return
	}
	a = a.Unmap()
	w.mu.Lock()
	if w.pol == nil || !w.pol.Enabled {
		w.mu.Unlock()
		return
	}
	reason := w.listed(a)
	action := "detected"
	if w.script != "" {
		action = "blocked"
	}
	key := a.String() + "|" + ne.Exe
	now := time.Now()
	recent := now.Sub(w.lastReport[key]) < webRepDedupe
	if reason != "" && !recent {
		if len(w.lastReport) > 10000 {
			clear(w.lastReport)
		}
		w.lastReport[key] = now
	}
	w.mu.Unlock()
	if reason == "" || recent {
		return
	}
	detail := "listed by " + reason
	if reason != "threat intel" {
		detail = "domain " + reason
	}
	ev := collector.NewEvent(xdrv1.EventType_EVENT_TYPE_WEB_REPUTATION)
	ev.Payload = &xdrv1.Event_Policy{Policy: &xdrv1.PolicyEvent{
		Action: action, Detail: detail, RemoteAddr: a.String(), Pid: ne.Pid, Exe: ne.Exe,
	}}
	w.Emit(ev)
}

// Status is the number of listed addresses and whether they are blocked.
func (w *WebReputation) Status() (addrs int, blocking bool, err string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.exact) + len(w.nets), w.script != "", w.err
}
