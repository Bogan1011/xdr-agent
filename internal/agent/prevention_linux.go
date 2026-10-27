package agent

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/policy"
)

const firewallCheckInterval = 2 * time.Minute

// Prevention enforces the endpoint's policy, module by module: anti-malware
// (real-time YARA scanning, exec blocking of hash IOCs, auto-quarantine), web
// reputation, file integrity, the host firewall, intrusion prevention, device
// control, activity monitoring and application control. The last policy is
// kept on disk so it applies at boot before the console answers.
type Prevention struct {
	a    *Agent
	log  *slog.Logger
	file string
	exec *ExecBlocker
	fim  *FIM
	web  *WebReputation
	ips  *Intrusion
	dev  *DeviceControl
	scr  *ScriptBlocker

	// Read on every event, so kept outside mu.
	realtime, quarantine        atomic.Bool
	sendProc, sendFile, sendNet atomic.Bool
	appMonitor                  atomic.Pointer[xdrv1.ApplicationControlPolicy]

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
		web:        NewWebReputation(log.With("component", "web-reputation"), a.send, a.consoleAddrs),
		ips:        NewIntrusion(log.With("component", "intrusion"), a.send, a.consoleAddrs),
		dev:        NewDeviceControl(log.With("component", "device-control"), a.send, a.cfg.path("devctl.json")),
		scr:        NewScriptBlocker(log.With("component", "script-block"), a.send),
		reconcileC: make(chan struct{}, 1),
	}
	pol := &xdrv1.PreventionPolicy{}
	if raw, err := os.ReadFile(p.file); err == nil && protojson.Unmarshal(raw, pol) == nil {
		p.policy = pol
		p.fim.SetPolicy(pol.Fim)
	}
	p.setFlags(policy.Normalize(proto.Clone(pol).(*xdrv1.PreventionPolicy)))
	return p
}

// setFlags publishes the settings that are read per event.
func (p *Prevention) setFlags(pol *xdrv1.PreventionPolicy) {
	am, act, ac := pol.AntiMalware, pol.ActivityMonitoring, pol.ApplicationControl
	p.realtime.Store(am.Enabled)
	p.quarantine.Store(am.Enabled && am.AutoQuarantine)
	p.sendProc.Store(act.Process)
	p.sendFile.Store(act.File)
	p.sendNet.Store(act.Network)
	if ac.Enabled {
		p.appMonitor.Store(ac)
	} else {
		p.appMonitor.Store(nil)
	}
}

// RealtimeScan reports whether new files and processes are YARA scanned.
func (p *Prevention) RealtimeScan() bool { return p.realtime.Load() }

// AutoQuarantine reports whether YARA matches are quarantined.
func (p *Prevention) AutoQuarantine() bool { return p.quarantine.Load() }

// Telemetry reports whether activity monitoring sends this event type.
// Prevention and detection events are always sent.
func (p *Prevention) Telemetry(t xdrv1.EventType) bool {
	switch t {
	case xdrv1.EventType_EVENT_TYPE_PROCESS_EXEC, xdrv1.EventType_EVENT_TYPE_PROCESS_EXIT,
		xdrv1.EventType_EVENT_TYPE_SHELL_COMMAND:
		return p.sendProc.Load()
	case xdrv1.EventType_EVENT_TYPE_FILE_CREATE, xdrv1.EventType_EVENT_TYPE_FILE_MODIFY, xdrv1.EventType_EVENT_TYPE_FILE_DELETE,
		xdrv1.EventType_EVENT_TYPE_FILE_RENAME, xdrv1.EventType_EVENT_TYPE_FILE_ATTRIB:
		return p.sendFile.Load()
	case xdrv1.EventType_EVENT_TYPE_NET_CONNECT, xdrv1.EventType_EVENT_TYPE_NET_LISTEN, xdrv1.EventType_EVENT_TYPE_NET_ACCEPT:
		return p.sendNet.Load()
	}
	return true
}

// SetIntel takes the IP and domain IOCs for web reputation.
func (p *Prevention) SetIntel(ips, domains []string) { p.web.SetIntel(ips, domains) }

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
	n := policy.Normalize(proto.Clone(pol).(*xdrv1.PreventionPolicy))
	p.log.Info("policy changed", "policy", pol.Name, "modules", modulesOn(n))
	p.setFlags(n)
	p.fim.SetPolicy(pol.Fim)
	p.reconcile()
}

// SetBlocklist takes the hash IOCs from the detection content.
func (p *Prevention) SetBlocklist(raw []byte) {
	n := p.exec.SetHashes(raw)
	p.log.Info("exec block list loaded", "hashes", n)
	p.reconcile()
}

// modulesOn names the modules a policy switches on, for the log.
func modulesOn(p *xdrv1.PreventionPolicy) []string {
	var out []string
	for _, m := range []struct {
		name string
		on   bool
	}{
		{"anti-malware", p.AntiMalware.Enabled || p.AntiMalware.BlockKnownBad}, {"web-reputation", p.WebReputation.Enabled},
		{"file-integrity", p.Fim.Enabled}, {"firewall", p.Firewall.Enabled},
		{"intrusion-prevention", p.IntrusionPrevention.Enabled}, {"device-control", p.DeviceControl.Enabled},
		{"application-control", p.ApplicationControl.Enabled},
	} {
		if m.on {
			out = append(out, m.name)
		}
	}
	return out
}

// Observe feeds file events to FIM, connections to web reputation and new
// processes to application control.
func (p *Prevention) Observe(e *xdrv1.Event) {
	if fe := e.GetFile(); fe != nil {
		p.fim.Notify(fe.Path)
		if fe.OldPath != "" {
			p.fim.Notify(fe.OldPath)
		}
	}
	if e.GetNetwork() != nil {
		p.web.Observe(e)
	}
	if pe := e.GetProcess(); pe != nil && e.Type == xdrv1.EventType_EVENT_TYPE_PROCESS_EXEC {
		p.observeExec(pe)
	}
}

// observeExec reports executions that application control lists but does
// not block: monitor mode, or blocking that could not start. Interpreters
// started on a script the script blocker cannot see yet are stopped here.
func (p *Prevention) observeExec(pe *xdrv1.ProcessEvent) {
	ac := p.appMonitor.Load()
	if ac == nil {
		return
	}
	if script, rule := policy.ScriptRule(ac, pe.Exe, pe.Args, pe.Cwd); rule != "" {
		switch {
		case !ac.Block:
			p.log.Warn("script from a script folder", "path", script, "rule", rule, "pid", pe.Pid)
			p.a.send(appControlEvent("detected", script, "", rule, pe.Pid))
		case !p.scr.Covers(filepath.Dir(script)):
			_, err := killProcess(map[string]string{"pid": strconv.Itoa(int(pe.Pid)), "exe": pe.Exe})
			p.log.Warn("script stopped after start", "path", script, "rule", rule, "pid", pe.Pid, "err", err)
			if err == nil {
				p.a.send(appControlEvent("blocked", script, "", rule+", stopped after start", pe.Pid))
			}
		}
	}
	p.mu.Lock()
	enforced := ac.Block && p.execOn
	p.mu.Unlock()
	if enforced {
		return
	}
	if rule := policy.AppRule(ac, pe.Exe, pe.Sha256); rule != "" {
		p.log.Warn("application control match", "path", pe.Exe, "rule", rule, "pid", pe.Pid)
		p.a.send(appControlEvent("detected", pe.Exe, pe.Sha256, rule, pe.Pid))
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
	go p.web.Run(ctx)
	go p.dev.Run(ctx)
	go p.scr.Run(ctx)
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
	var app *xdrv1.ApplicationControlPolicy
	if ac := pol.ApplicationControl; ac.Enabled && ac.Block {
		app = ac
	}
	p.exec.SetRules(pol.AntiMalware.BlockKnownBad, app)
	p.applyExec(ctx, p.exec.Enforcing())
	p.applyFirewall(pol.Firewall)
	p.web.SetPolicy(pol.WebReputation)
	p.ips.SetPolicy(ctx, pol.IntrusionPrevention)
	p.dev.SetPolicy(pol.DeviceControl)
	p.scr.SetPolicy(pol.ApplicationControl)
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
		if p.fwScript != "" || tablePresent(policy.FirewallTable) {
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
	if err == nil && script == p.fwScript && tablePresent(policy.FirewallTable) {
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
	if script == "" || tablePresent(policy.FirewallTable) {
		return
	}
	if err := nft(script); err != nil {
		p.log.Error("restoring host firewall failed", "err", err)
		return
	}
	p.log.Warn("host firewall table was removed outside the agent, restored")
	p.a.tamperEvent("firewall_restored", "nftables table inet "+policy.FirewallTable+" was deleted and has been re-applied")
}

// tablePresent reports whether one of the agent's nftables tables exists.
func tablePresent(name string) bool {
	if _, err := exec.LookPath("nft"); err != nil {
		return false
	}
	return exec.Command("nft", "list", "table", "inet", name).Run() == nil
}

// State is what the agent reports in its heartbeat.
func (p *Prevention) State() *xdrv1.PreventionState {
	fimOn, files := p.fim.Status()
	webAddrs, webBlocking, webErr := p.web.Status()
	ipsOn, banned, ipsErr := p.ips.Status()
	devOn, devBlocked := p.dev.Status()
	scrOn, _, scrErr := p.scr.Status()
	p.mu.Lock()
	defer p.mu.Unlock()
	s := &xdrv1.PreventionState{
		ExecBlocking: p.execOn, BlockedHashes: uint32(p.exec.Len()),
		FimActive: fimOn, FimFiles: uint32(files), FirewallApplied: p.fwScript != "",
		PolicyName: p.policy.GetName(), RealtimeScan: p.realtime.Load(),
		WebReputationAddrs: uint32(webAddrs), WebReputationBlocking: webBlocking,
		IntrusionPrevention: ipsOn, BannedAddrs: uint32(banned),
		DeviceControl: devOn, BlockedDevices: uint32(devBlocked), AppControl: p.appMonitor.Load() != nil,
		ScriptBlocking: scrOn,
	}
	switch {
	case p.execErr != "":
		s.Error = "exec blocking: " + p.execErr
	case p.fwErr != "":
		s.Error = "firewall: " + p.fwErr
	case webErr != "":
		s.Error = "web reputation: " + webErr
	case ipsErr != "":
		s.Error = "intrusion prevention: " + ipsErr
	case scrErr != "" && !scrOn:
		s.Error = "script blocking: " + scrErr
	}
	return s
}
