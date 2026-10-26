package agent

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/policy"
)

const firewallCheckInterval = 2 * time.Minute

// Prevention enforces the console's prevention policy: exec blocking of
// known-bad hashes, file integrity monitoring and the host firewall. The last
// policy is kept on disk so it applies at boot before the console answers.
type Prevention struct {
	a    *Agent
	log  *slog.Logger
	file string
	exec *ExecBlocker
	fim  *FIM

	mu         sync.Mutex
	policy     *xdrv1.PreventionPolicy
	execStop   context.CancelFunc
	execOn     bool
	execErr    string
	fwScript   string
	fwErr      string
	reconcileC chan struct{}
}

func newPrevention(a *Agent, log *slog.Logger) *Prevention {
	p := &Prevention{
		a: a, log: log, file: a.cfg.path("prevention.json"),
		exec:       NewExecBlocker(log.With("component", "exec-block"), a.send, a.cfg.ScanMaxBytes),
		fim:        NewFIM(log.With("component", "fim"), a.send, a.cfg.path("fim.json")),
		reconcileC: make(chan struct{}, 1),
	}
	if raw, err := os.ReadFile(p.file); err == nil {
		pol := &xdrv1.PreventionPolicy{}
		if protojson.Unmarshal(raw, pol) == nil {
			p.policy = pol
			p.fim.SetPolicy(pol.Fim)
		}
	}
	return p
}

// SetPolicy takes the policy from a heartbeat.
func (p *Prevention) SetPolicy(pol *xdrv1.PreventionPolicy) {
	if pol == nil {
		return
	}
	p.mu.Lock()
	if proto.Equal(pol, p.policy) {
		p.mu.Unlock()
		return
	}
	p.policy = proto.Clone(pol).(*xdrv1.PreventionPolicy)
	p.mu.Unlock()
	if raw, err := protojson.Marshal(pol); err == nil {
		_ = os.WriteFile(p.file, raw, 0o600)
	}
	p.log.Info("prevention policy changed", "block_exec", pol.BlockExec, "fim", pol.GetFim().GetEnabled(),
		"firewall", pol.GetFirewall().GetEnabled())
	p.fim.SetPolicy(pol.Fim)
	p.reconcile()
}

// SetBlocklist takes the hash IOCs from the detection content.
func (p *Prevention) SetBlocklist(raw []byte) {
	n := p.exec.SetHashes(raw)
	p.log.Info("exec block list loaded", "hashes", n)
	p.reconcile()
}

// Observe feeds file events to FIM.
func (p *Prevention) Observe(e *xdrv1.Event) {
	if fe := e.GetFile(); fe != nil {
		p.fim.Notify(fe.Path)
		if fe.OldPath != "" {
			p.fim.Notify(fe.OldPath)
		}
	}
}

func (p *Prevention) reconcile() {
	select {
	case p.reconcileC <- struct{}{}:
	default:
	}
}

func (p *Prevention) Run(ctx context.Context) {
	go p.fim.Run(ctx)
	p.apply(ctx)
	t := time.NewTicker(firewallCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			p.mu.Lock()
			if p.execStop != nil {
				p.execStop()
			}
			p.mu.Unlock()
			return
		case <-p.reconcileC:
			p.apply(ctx)
		case <-t.C:
			p.checkFirewall()
		}
	}
}

func (p *Prevention) apply(ctx context.Context) {
	p.mu.Lock()
	pol := policy.Normalize(proto.Clone(p.policy).(*xdrv1.PreventionPolicy))
	p.mu.Unlock()
	p.applyExec(ctx, pol.BlockExec && p.exec.Len() > 0)
	p.applyFirewall(pol.Firewall)
}

func (p *Prevention) applyExec(ctx context.Context, want bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if want == (p.execStop != nil) {
		return
	}
	if !want {
		p.execStop()
		p.execStop, p.execOn = nil, false
		p.log.Info("exec blocking stopped")
		return
	}
	ectx, cancel := context.WithCancel(ctx)
	p.execStop, p.execErr = cancel, ""
	go func() {
		err := p.exec.Run(ectx, func() {
			p.mu.Lock()
			p.execOn = true
			p.mu.Unlock()
			p.log.Info("exec blocking active", "hashes", p.exec.Len())
		})
		p.mu.Lock()
		defer p.mu.Unlock()
		p.execOn = false
		if err != nil && ectx.Err() == nil {
			p.log.Error("exec blocking unavailable", "err", err)
			p.execErr = err.Error()
			// Not retried on a timer: the next policy or block list change
			// tries again.
			cancel()
			p.execStop = nil
		}
	}()
}

func (p *Prevention) applyFirewall(fw *xdrv1.FirewallPolicy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !fw.Enabled {
		if p.fwScript != "" || firewallPresent() {
			if err := nft(policy.DisableFirewall()); err != nil {
				p.fwErr = err.Error()
				return
			}
			p.log.Info("host firewall removed")
		}
		p.fwScript, p.fwErr = "", ""
		return
	}
	addrs, err := p.a.consoleAddrs()
	if err != nil {
		p.fwErr = err.Error()
		p.log.Error("host firewall not applied", "err", err)
		return
	}
	script, err := policy.FirewallRules(fw, addrs)
	if err == nil && script == p.fwScript && firewallPresent() {
		return
	}
	if err == nil {
		err = nft(script)
	}
	if err != nil {
		p.fwErr = err.Error()
		p.log.Error("host firewall not applied", "err", err)
		return
	}
	p.fwScript, p.fwErr = script, ""
	p.log.Info("host firewall applied", "rules", len(fw.Rules), "default_deny_inbound", fw.DefaultDenyInbound)
}

// checkFirewall puts the table back when someone deletes it.
func (p *Prevention) checkFirewall() {
	p.mu.Lock()
	script := p.fwScript
	p.mu.Unlock()
	if script == "" || firewallPresent() {
		return
	}
	if err := nft(script); err != nil {
		p.log.Error("restoring host firewall failed", "err", err)
		return
	}
	p.log.Warn("host firewall table was removed outside the agent, restored")
	p.a.tamperEvent("firewall_restored", "nftables table inet "+policy.FirewallTable+" was deleted and has been re-applied")
}

func firewallPresent() bool {
	if _, err := exec.LookPath("nft"); err != nil {
		return false
	}
	return exec.Command("nft", "list", "table", "inet", policy.FirewallTable).Run() == nil
}

// State is what the agent reports in its heartbeat.
func (p *Prevention) State() *xdrv1.PreventionState {
	fimOn, files := p.fim.Status()
	p.mu.Lock()
	defer p.mu.Unlock()
	s := &xdrv1.PreventionState{
		ExecBlocking: p.execOn, BlockedHashes: uint32(p.exec.Len()),
		FimActive: fimOn, FimFiles: uint32(files), FirewallApplied: p.fwScript != "",
	}
	switch {
	case p.execErr != "":
		s.Error = "exec blocking: " + p.execErr
	case p.fwErr != "":
		s.Error = "firewall: " + p.fwErr
	}
	return s
}
