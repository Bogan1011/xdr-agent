// Package release describes the agent binaries the server hands out, for
// installers and for agent self-update.
package release

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Arches are the architectures the server builds the agent for.
var Arches = []string{"amd64", "arm64"}

type Release struct {
	Version string `json:"version"`
	// SHA256 maps an architecture to the hex SHA-256 of its binary.
	SHA256 map[string]string `json:"sha256"`
	dir    string
}

// Load reads VERSION and SHA256SUMS from the downloads directory. The files
// are re-read on every call so a rebuilt image or a copied-in binary is
// picked up without a restart.
func Load(dir string) (*Release, error) {
	if dir == "" {
		return nil, fmt.Errorf("no downloads directory configured")
	}
	v, err := os.ReadFile(filepath.Join(dir, "VERSION"))
	if err != nil {
		return nil, err
	}
	r := &Release{Version: strings.TrimSpace(string(v)), SHA256: map[string]string{}, dir: dir}
	f, err := os.Open(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if arch, ok := strings.CutPrefix(name, "xdr-agent-linux-"); ok {
			r.SHA256[arch] = strings.ToLower(fields[0])
		}
	}
	return r, sc.Err()
}

// Path is the binary for arch, or an error for an unknown architecture.
func (r *Release) Path(arch string) (string, error) {
	if _, ok := r.SHA256[arch]; !ok {
		return "", fmt.Errorf("no agent binary for %q", arch)
	}
	return filepath.Join(r.dir, "xdr-agent-linux-"+arch), nil
}
