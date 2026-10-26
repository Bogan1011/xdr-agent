package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

// Self-update: the console sends the version and SHA-256 it offers, the
// agent downloads the binary over its mTLS connection, checks the hash and
// that the binary runs, swaps it in and exits so systemd starts the new one.
// The new binary must reach the console within updateConfirmTimeout and
// within maxUpdateStarts starts, or the previous binary is put back.

const (
	maxBinarySize        = 200 << 20
	updateConfirmTimeout = 3 * time.Minute
	maxUpdateStarts      = 3
)

type pendingUpdate struct {
	From       string    `json:"from"`
	To         string    `json:"to"`
	Starts     int       `json:"starts"`
	Started    time.Time `json:"started"`
	RolledBack bool      `json:"rolled_back"`
}

type updater struct {
	mu        sync.Mutex
	confirmed bool
}

func (a *Agent) updateDir() string { return a.cfg.path("update") }

func (a *Agent) selfUpdate(ctx context.Context, args map[string]string) (string, error) {
	want, sum := args["version"], strings.ToLower(args["sha256"])
	if want == "" || len(sum) != 64 {
		return "", fmt.Errorf("version and sha256 are required")
	}
	if want == Version {
		return "already running " + want, nil
	}
	exe, err := executable()
	if err != nil {
		return "", err
	}
	dir := a.updateDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	staged := filepath.Join(dir, "xdr-agent.new")
	if err := a.download(ctx, staged, sum); err != nil {
		os.Remove(staged)
		return "", err
	}
	vctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	out, err := exec.CommandContext(vctx, staged, "-version").Output()
	cancel()
	if got := strings.TrimSpace(string(out)); err != nil || got != want {
		os.Remove(staged)
		return "", fmt.Errorf("downloaded binary does not run or reports version %q, want %q: %v", got, want, err)
	}
	if err := copyFile(exe, filepath.Join(dir, "xdr-agent.prev")); err != nil {
		return "", fmt.Errorf("back up current binary: %w", err)
	}
	if err := a.replaceBinary(exe, staged); err != nil {
		return "", err
	}
	os.Remove(staged)
	if err := a.savePending(&pendingUpdate{From: Version, To: want, Started: time.Now().UTC()}); err != nil {
		return "", err
	}
	return fmt.Sprintf("installed %s (was %s), restarting", want, Version), nil
}

func (a *Agent) download(ctx context.Context, path, sum string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	w := io.MultiWriter(f, h)
	var off uint64
	for {
		var chunk *xdrv1.AgentBinaryChunk
		for try := 0; ; try++ {
			cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			chunk, err = a.client.GetAgentBinary(cctx, &xdrv1.AgentBinaryRequest{Arch: runtime.GOARCH, Offset: off})
			cancel()
			if err == nil || try == 3 || ctx.Err() != nil {
				break
			}
			time.Sleep(time.Duration(try+1) * 2 * time.Second)
		}
		if err != nil {
			return fmt.Errorf("download at offset %d: %w", off, err)
		}
		if chunk.TotalSize > maxBinarySize {
			return fmt.Errorf("binary is %d bytes, larger than allowed", chunk.TotalSize)
		}
		if _, err := w.Write(chunk.Data); err != nil {
			return err
		}
		off += uint64(len(chunk.Data))
		if off >= chunk.TotalSize {
			break
		}
		if len(chunk.Data) == 0 {
			return fmt.Errorf("download stalled at offset %d", off)
		}
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sum {
		return fmt.Errorf("checksum mismatch: got %s, console offered %s", got, sum)
	}
	return f.Close()
}

// replaceBinary swaps src in at exe atomically, keeping tamper protection.
func (a *Agent) replaceBinary(exe, src string) error {
	tmp := exe + ".new"
	if err := copyFile(src, tmp); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	err := a.tamper.WithUnlocked(exe, func() error { return os.Rename(tmp, exe) })
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", exe, err)
	}
	return nil
}

func (a *Agent) loadPending() *pendingUpdate {
	raw, err := os.ReadFile(filepath.Join(a.updateDir(), "pending.json"))
	if err != nil {
		return nil
	}
	p := &pendingUpdate{}
	if json.Unmarshal(raw, p) != nil {
		return nil
	}
	return p
}

func (a *Agent) savePending(p *pendingUpdate) error {
	raw, _ := json.Marshal(p)
	return os.WriteFile(filepath.Join(a.updateDir(), "pending.json"), raw, 0o600)
}

func (a *Agent) clearPending() {
	os.Remove(filepath.Join(a.updateDir(), "pending.json"))
	os.Remove(filepath.Join(a.updateDir(), "xdr-agent.prev"))
}

// checkUpdate runs at start. After an update it counts starts of the new
// binary and arms the rollback timer; confirmUpdate disarms it.
func (a *Agent) checkUpdate(ctx context.Context) {
	p := a.loadPending()
	if p == nil {
		return
	}
	if p.To != Version {
		// The old binary is running again: a rollback, or a manual reinstall.
		a.log.Warn("agent update did not stick", "from", p.From, "to", p.To, "running", Version, "rolled_back", p.RolledBack)
		a.clearPending()
		return
	}
	p.Starts++
	_ = a.savePending(p)
	if p.Starts > maxUpdateStarts {
		a.rollback(p, fmt.Sprintf("version %s failed to start %d times", p.To, maxUpdateStarts))
	}
	a.log.Info("running updated agent, waiting to reach the console", "from", p.From, "to", p.To)
	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(updateConfirmTimeout):
			a.upd.mu.Lock()
			ok := a.upd.confirmed
			a.upd.mu.Unlock()
			if !ok {
				a.rollback(p, fmt.Sprintf("version %s did not reach the console within %s", p.To, updateConfirmTimeout))
			}
		}
	}()
}

// confirmUpdate is called after each successful heartbeat.
func (a *Agent) confirmUpdate() {
	a.upd.mu.Lock()
	defer a.upd.mu.Unlock()
	if a.upd.confirmed {
		return
	}
	a.upd.confirmed = true
	if p := a.loadPending(); p != nil && p.To == Version {
		a.log.Info("agent update confirmed", "from", p.From, "to", p.To)
		a.clearPending()
	}
}

// rollback puts the previous binary back and exits; systemd starts it.
func (a *Agent) rollback(p *pendingUpdate, reason string) {
	a.log.Error("rolling back agent update", "reason", reason, "to", p.From)
	exe, err := executable()
	prev := filepath.Join(a.updateDir(), "xdr-agent.prev")
	if err == nil {
		err = a.replaceBinary(exe, prev)
	}
	if err != nil {
		a.log.Error("rollback failed, keeping the new binary", "err", err)
		return
	}
	p.RolledBack = true
	_ = a.savePending(p)
	a.clearRunningMarker()
	os.Exit(1)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
