package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestTokenMatches(t *testing.T) {
	h := hexSum([]byte("xdrm_abc"))
	if !tokenMatches("xdrm_abc", h) || !tokenMatches("xdrm_abc", strings.ToUpper(h)) {
		t.Fatal("right token rejected")
	}
	if tokenMatches("xdrm_abd", h) || tokenMatches("", h) || tokenMatches("xdrm_abc", "") {
		t.Fatal("wrong token accepted")
	}
}

func TestEnterMaintenance(t *testing.T) {
	cfg := &Config{StateDir: t.TempDir()}
	raw, _ := json.Marshal(tamperPolicy{Enabled: true, TokenSHA256: hexSum([]byte("good"))})
	os.WriteFile(cfg.path("tamper.json"), raw, 0o600)

	if _, err := EnterMaintenance(cfg, "bad", time.Hour); err == nil {
		t.Fatal("wrong token accepted")
	}
	if _, err := os.Stat(cfg.path("maintenance.json")); err == nil {
		t.Fatal("maintenance file written for a wrong token")
	}
	if _, err := EnterMaintenance(cfg, "good", time.Hour); err != nil {
		t.Fatal(err)
	}
	var events []string
	tp := newTamper(cfg, slog.New(slog.DiscardHandler), func(a, _ string) { events = append(events, a) })
	if !tp.maintenanceActive() || !tp.maintenanceActive() {
		t.Fatal("maintenance not active")
	}
	if len(events) != 1 || events[0] != "maintenance" {
		t.Fatalf("events %v, want one maintenance event", events)
	}
	// A forged file with another token does not suspend protection.
	raw, _ = json.Marshal(maintenance{Token: "forged", Until: time.Now().Add(time.Hour)})
	os.WriteFile(cfg.path("maintenance.json"), raw, 0o600)
	if tp.maintenanceActive() {
		t.Fatal("forged maintenance accepted")
	}
}

type fakeBinaryClient struct {
	xdrv1.AgentServiceClient
	data []byte
}

func (f *fakeBinaryClient) GetAgentBinary(_ context.Context, r *xdrv1.AgentBinaryRequest, _ ...grpc.CallOption) (*xdrv1.AgentBinaryChunk, error) {
	end := min(int(r.Offset)+3, len(f.data))
	return &xdrv1.AgentBinaryChunk{Data: f.data[r.Offset:end], TotalSize: uint64(len(f.data))}, nil
}

func TestDownload(t *testing.T) {
	data := []byte("pretend this is an ELF binary")
	a := &Agent{client: &fakeBinaryClient{data: data}}
	path := filepath.Join(t.TempDir(), "bin")
	if err := a.download(context.Background(), path, hexSum(data)); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != string(data) {
		t.Fatalf("got %q", got)
	}
	if err := a.download(context.Background(), path, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("want checksum mismatch, got %v", err)
	}
}

func TestPendingUpdateRoundTrip(t *testing.T) {
	a := &Agent{cfg: &Config{StateDir: t.TempDir()}}
	os.MkdirAll(a.updateDir(), 0o700)
	if a.loadPending() != nil {
		t.Fatal("pending update without a marker")
	}
	a.savePending(&pendingUpdate{From: "0.1.0", To: "0.2.0", Starts: 1})
	if p := a.loadPending(); p == nil || p.To != "0.2.0" || p.Starts != 1 {
		t.Fatalf("got %+v", p)
	}
	a.clearPending()
	if a.loadPending() != nil {
		t.Fatal("marker not cleared")
	}
}
