package release

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "VERSION"), []byte("0.2.0\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte("AA11  xdr-agent-linux-amd64\nbb22 *xdr-agent-linux-arm64\njunk\n"), 0o644)
	r, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "0.2.0" || r.SHA256["amd64"] != "aa11" || r.SHA256["arm64"] != "bb22" {
		t.Fatalf("got %+v", r)
	}
	if p, err := r.Path("amd64"); err != nil || p != filepath.Join(dir, "xdr-agent-linux-amd64") {
		t.Fatalf("path %q %v", p, err)
	}
	if _, err := r.Path("../etc/passwd"); err == nil {
		t.Fatal("unknown arch accepted")
	}
}
