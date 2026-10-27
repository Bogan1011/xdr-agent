package agent

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/agent/collector"
	"github.com/Bogan1011/xdr-agent/internal/policy"
)

// Tamper protection raises the bar for stopping or removing the agent without
// the console. Root can always undo it, so every attempt is also reported.
// While it is on:
//   - the binary, config, CA and unit file are immutable (chattr +i), so rm,
//     mv and editors fail;
//   - a unit drop-in sets RefuseManualStop, so systemctl stop is refused;
//   - SIGTERM and friends are ignored unless the host is shutting down;
//   - a restart after SIGKILL or a crash is reported.
//
// The console's maintenance token, or the policy's admin password, suspends
// it locally (xdr-agent maintenance --token ... or --password ...), e.g. to
// uninstall without the console.

const (
	unitFile       = "/etc/systemd/system/xdr-agent.service"
	dropInDir      = "/etc/systemd/system/xdr-agent.service.d"
	dropInFile     = dropInDir + "/10-tamper-protection.conf"
	dropInContent  = "# Managed by xdr-agent tamper protection; removed when it is turned off.\n[Unit]\nRefuseManualStop=yes\n"
	fsImmutableFL  = 0x00000010
	tamperInterval = 30 * time.Second
)

type tamperPolicy struct {
	Enabled      bool   `json:"enabled"`
	TokenSHA256  string `json:"token_sha256"`
	PasswordSalt string `json:"password_salt,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
}

// unlocks reports whether secret is the maintenance token or the admin password.
func (p tamperPolicy) unlocks(secret string) bool {
	return tokenMatches(secret, p.TokenSHA256) || policy.PasswordMatches(secret, p.PasswordSalt, p.PasswordHash)
}

type maintenance struct {
	Token string    `json:"token"`
	Until time.Time `json:"until"`
}

type Tamper struct {
	cfg   *Config
	log   *slog.Logger
	event func(action, detail string)

	mu        sync.Mutex
	policy    tamperPolicy
	applied   bool
	released  bool
	maintTill time.Time
	kick      chan struct{}
}

func newTamper(cfg *Config, log *slog.Logger, event func(action, detail string)) *Tamper {
	t := &Tamper{cfg: cfg, log: log, event: event, kick: make(chan struct{}, 1)}
	// The last policy from the console applies until it is reachable again.
	if raw, err := os.ReadFile(cfg.path("tamper.json")); err == nil {
		_ = json.Unmarshal(raw, &t.policy)
	}
	return t
}

func (t *Tamper) protectedPaths() []string {
	paths := []string{unitFile, dropInFile, t.cfg.CAFile}
	if t.cfg.Path != "" {
		paths = append(paths, t.cfg.Path)
	}
	if exe, err := executable(); err == nil {
		paths = append(paths, exe)
	}
	return paths
}

func executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// SetPolicy applies the console's policy from a heartbeat response.
func (t *Tamper) SetPolicy(p *xdrv1.TamperPolicy) {
	if p == nil {
		return
	}
	np := tamperPolicy{Enabled: p.Enabled, TokenSHA256: p.MaintenanceTokenSha256, PasswordSalt: p.PasswordSalt, PasswordHash: p.PasswordHash}
	t.mu.Lock()
	changed := np != t.policy
	t.policy = np
	t.mu.Unlock()
	if !changed {
		return
	}
	raw, _ := json.Marshal(np)
	if err := os.WriteFile(t.cfg.path("tamper.json"), raw, 0o600); err != nil {
		t.log.Warn("saving tamper policy", "err", err)
	}
	t.log.Info("tamper protection policy changed", "enabled", np.Enabled)
	select {
	case t.kick <- struct{}{}:
	default:
	}
}

// Applied reports whether protection is currently in place.
func (t *Tamper) Applied() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.applied
}

// Release removes protection for good, before an uninstall the console asked for.
func (t *Tamper) Release() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.released = true
	t.removeLocked()
}

// StopAllowed decides whether a termination signal may stop the agent.
func (t *Tamper) StopAllowed(sig os.Signal) bool {
	t.mu.Lock()
	applied := t.applied
	t.mu.Unlock()
	if !applied || t.maintenanceActive() || shuttingDown() {
		return true
	}
	t.event("signal_ignored", fmt.Sprintf("%s ignored: tamper protection is on", sig))
	t.log.Warn("termination signal ignored, tamper protection is on", "signal", sig.String())
	return false
}

// WithUnlocked runs fn with path's immutable flag cleared, and restores the
// flag on whatever file is at path afterwards. Used by self-update.
func (t *Tamper) WithUnlocked(path string, fn func() error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.applied {
		_ = setImmutable(path, false)
	}
	err := fn()
	if t.applied {
		_ = setImmutable(path, true)
	}
	return err
}

func (t *Tamper) Run(ctx context.Context) {
	tick := time.NewTicker(tamperInterval)
	defer tick.Stop()
	for {
		t.reconcile()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-t.kick:
		}
	}
}

func (t *Tamper) reconcile() {
	maint := t.maintenanceActive()
	t.mu.Lock()
	defer t.mu.Unlock()
	want := t.policy.Enabled && !t.released && !maint
	if !want {
		if t.applied || fileExists(dropInFile) {
			t.removeLocked()
			t.log.Info("tamper protection removed", "maintenance", maint)
		}
		return
	}
	if t.applied {
		// Someone cleared a flag or deleted the drop-in: report and restore.
		for _, p := range t.protectedPaths() {
			if on, err := immutable(p); err == nil && !on {
				t.event("protection_removed", "immutable flag cleared on "+p)
			} else if errors.Is(err, os.ErrNotExist) && p == dropInFile {
				t.event("protection_removed", p+" deleted")
			}
		}
	}
	if err := t.applyLocked(); err != nil {
		t.log.Warn("applying tamper protection", "err", err)
	}
	if !t.applied {
		t.applied = true
		t.log.Info("tamper protection applied")
	}
}

func (t *Tamper) applyLocked() error {
	cur, err := os.ReadFile(dropInFile)
	if err != nil || string(cur) != dropInContent {
		_ = setImmutable(dropInFile, false)
		if err := os.MkdirAll(dropInDir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dropInFile, []byte(dropInContent), 0o644); err != nil {
			return err
		}
		daemonReload()
	}
	var errs []error
	for _, p := range t.protectedPaths() {
		if err := setImmutable(p, true); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (t *Tamper) removeLocked() {
	for _, p := range t.protectedPaths() {
		_ = setImmutable(p, false)
	}
	if fileExists(dropInFile) {
		_ = os.Remove(dropInFile)
		_ = os.Remove(dropInDir)
		daemonReload()
	}
	t.applied = false
}

// maintenanceActive reports whether a valid maintenance token was entered
// locally and has not expired. It reports the start of a maintenance window once.
func (t *Tamper) maintenanceActive() bool {
	raw, err := os.ReadFile(t.cfg.path("maintenance.json"))
	if err != nil {
		return false
	}
	var m maintenance
	if json.Unmarshal(raw, &m) != nil || time.Now().After(m.Until) {
		return false
	}
	t.mu.Lock()
	pol := t.policy
	first := !m.Until.Equal(t.maintTill)
	t.mu.Unlock()
	if !pol.unlocks(m.Token) {
		if first {
			t.mu.Lock()
			t.maintTill = m.Until
			t.mu.Unlock()
			t.event("maintenance_rejected", "maintenance file with a wrong token or password")
		}
		return false
	}
	if first {
		t.mu.Lock()
		t.maintTill = m.Until
		t.mu.Unlock()
		t.event("maintenance", "tamper protection suspended locally with the maintenance token or admin password until "+m.Until.Format(time.RFC3339))
	}
	return true
}

func tokenMatches(token, hash string) bool {
	if token == "" || hash == "" {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(strings.ToLower(hash))) == 1
}

// EnterMaintenance is the local "xdr-agent maintenance" command: it checks
// the token against the last policy from the console, suspends protection
// for d and removes it right away so the service can be stopped.
func EnterMaintenance(cfg *Config, token string, d time.Duration) (string, error) {
	t := newTamper(cfg, slog.New(slog.DiscardHandler), func(string, string) {})
	if !t.policy.Enabled && !fileExists(dropInFile) {
		return "tamper protection is off; nothing to do", nil
	}
	if !t.policy.unlocks(token) {
		return "", errors.New("wrong maintenance token or password (the token is on the endpoint's page in the console; the password is set in the policy's Self-protection module)")
	}
	until := time.Now().Add(d).UTC()
	raw, _ := json.Marshal(maintenance{Token: token, Until: until})
	if err := os.WriteFile(cfg.path("maintenance.json"), raw, 0o600); err != nil {
		return "", err
	}
	t.mu.Lock()
	t.removeLocked()
	t.mu.Unlock()
	return "tamper protection suspended until " + until.Format(time.RFC3339) + "; the agent can now be stopped or uninstalled", nil
}

func (a *Agent) tamperEvent(action, detail string) {
	e := collector.NewEvent(xdrv1.EventType_EVENT_TYPE_AGENT_TAMPER)
	e.Payload = &xdrv1.Event_Tamper{Tamper: &xdrv1.TamperEvent{Action: action, Detail: detail, Pid: uint32(os.Getpid())}}
	a.send(e)
}

// checkUncleanExit reports when the previous agent process in this boot did
// not shut down cleanly (SIGKILL or a crash), then marks this one as running.
func (a *Agent) checkUncleanExit() {
	boot, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	marker := a.cfg.path("running")
	if prev, err := os.ReadFile(marker); err == nil && len(boot) > 0 && string(prev) == string(boot) {
		a.tamperEvent("unclean_restart", "the previous agent process ended without a clean shutdown (killed with SIGKILL or crashed)")
	}
	_ = os.WriteFile(marker, boot, 0o600)
}

func (a *Agent) clearRunningMarker() { _ = os.Remove(a.cfg.path("running")) }

// shuttingDown is true while systemd is stopping the system, the one time a
// protected agent must honor SIGTERM.
func shuttingDown() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "systemctl", "is-system-running").Output()
	s := strings.TrimSpace(string(out))
	return s == "stopping" || s == "offline"
}

func daemonReload() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "systemctl", "daemon-reload").Run()
}

func fileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func immutable(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	flags, err := unix.IoctlGetUint32(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return false, err
	}
	return flags&fsImmutableFL != 0, nil
}

func setImmutable(path string, on bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	flags, err := unix.IoctlGetUint32(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return fmt.Errorf("%s: get flags: %w", path, err)
	}
	nf := flags &^ fsImmutableFL
	if on {
		nf |= fsImmutableFL
	}
	if nf == flags {
		return nil
	}
	if err := unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, int(nf)); err != nil {
		return fmt.Errorf("%s: set flags: %w", path, err)
	}
	return nil
}
