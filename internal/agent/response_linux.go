package agent

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// --- kill ---

func killProcess(args map[string]string) (string, error) {
	pid, err := strconv.Atoi(args["pid"])
	if err != nil || pid <= 1 {
		return "", fmt.Errorf("invalid pid %q", args["pid"])
	}
	if pid == os.Getpid() {
		return "", errors.New("refusing to kill the agent itself")
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("process %d is not running", pid)
	}
	exe = strings.TrimSuffix(exe, " (deleted)")
	// The pid may have been reused since the event; only kill the process
	// the console saw.
	if want := args["exe"]; want != "" && err == nil && exe != want {
		return "", fmt.Errorf("pid %d is now %s, not %s; not killed", pid, exe, want)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return "", fmt.Errorf("kill %d: %w", pid, err)
	}
	return fmt.Sprintf("killed pid %d (%s)", pid, exe), nil
}

// --- quarantine ---

type quarantineRecord struct {
	ID     string    `json:"id"`
	Path   string    `json:"path"`
	SHA256 string    `json:"sha256"`
	Size   int64     `json:"size"`
	Mode   uint32    `json:"mode"`
	UID    int       `json:"uid"`
	GID    int       `json:"gid"`
	Time   time.Time `json:"time"`
}

func (a *Agent) quarantineDir() string { return filepath.Join(a.cfg.StateDir, "quarantine") }

func protectedPath(p string) error {
	for _, pre := range []string{"/proc/", "/sys/", "/dev/"} {
		if strings.HasPrefix(p, pre) {
			return fmt.Errorf("refusing to touch %s", p)
		}
	}
	if self, err := os.Executable(); err == nil && self == p {
		return errors.New("refusing to quarantine the agent binary")
	}
	return nil
}

func (a *Agent) quarantineFile(args map[string]string) (string, error) {
	p := filepath.Clean(args["path"])
	if !filepath.IsAbs(p) {
		return "", errors.New("path must be absolute")
	}
	if err := protectedPath(p); err != nil {
		return "", err
	}
	if strings.HasPrefix(p, a.cfg.StateDir+"/") {
		return "", errors.New("refusing to quarantine agent state")
	}
	st, err := os.Lstat(p)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", p)
	}
	dir := a.quarantineDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	id := hex.EncodeToString(b[:])
	dst := filepath.Join(dir, id+".bin")
	if err := moveFile(p, dst); err != nil {
		return "", err
	}
	// Strip all permission bits so the quarantined copy cannot be executed.
	_ = os.Chmod(dst, 0)
	sum, _ := fileSHA256(dst)
	sys := st.Sys().(*syscall.Stat_t)
	rec := quarantineRecord{ID: id, Path: p, SHA256: sum, Size: st.Size(), Mode: uint32(st.Mode().Perm()),
		UID: int(sys.Uid), GID: int(sys.Gid), Time: time.Now().UTC()}
	raw, _ := json.MarshalIndent(rec, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, id+".json"), raw, 0o600); err != nil {
		return "", err
	}
	return id, nil
}

func (a *Agent) restoreFile(args map[string]string) (string, error) {
	id := args["quarantine_id"]
	if len(id) != 16 || strings.Trim(id, "0123456789abcdef") != "" {
		return "", fmt.Errorf("invalid quarantine id %q", id)
	}
	dir := a.quarantineDir()
	raw, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		return "", fmt.Errorf("no quarantined file %s", id)
	}
	var rec quarantineRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return "", err
	}
	if _, err := os.Lstat(rec.Path); err == nil {
		return "", fmt.Errorf("%s already exists; not overwriting it", rec.Path)
	}
	if err := os.MkdirAll(filepath.Dir(rec.Path), 0o755); err != nil {
		return "", err
	}
	if err := moveFile(filepath.Join(dir, id+".bin"), rec.Path); err != nil {
		return "", err
	}
	_ = os.Chown(rec.Path, rec.UID, rec.GID)
	_ = os.Chmod(rec.Path, os.FileMode(rec.Mode))
	_ = os.Remove(filepath.Join(dir, id+".json"))
	return fmt.Sprintf("restored %s", rec.Path), nil
}

// moveFile renames, falling back to copy and delete across filesystems.
func moveFile(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil || !errors.Is(err, syscall.EXDEV) {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	return os.Remove(src)
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// --- network isolation ---

const isolationTable = "xdr_isolation"

type isolationState struct {
	Allow []string `json:"allow"`
}

func (a *Agent) isolationFile() string { return filepath.Join(a.cfg.StateDir, "isolation.json") }

// Isolated reports whether isolation is in force.
func (a *Agent) Isolated() bool {
	_, err := os.Stat(a.isolationFile())
	return err == nil
}

// consoleAddrs resolves the console endpoints so they stay reachable.
func (a *Agent) consoleAddrs() ([]netip.Addr, error) {
	var out []netip.Addr
	for _, hp := range []string{a.cfg.Server, a.cfg.EnrollServer} {
		host, _, err := net.SplitHostPort(hp)
		if err != nil {
			host = hp
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("resolve console %s: %w", host, err)
		}
		for _, ip := range ips {
			if addr, ok := netip.AddrFromSlice(ip); ok {
				out = append(out, addr.Unmap())
			}
		}
	}
	return out, nil
}

// isolationRules renders the nftables ruleset. Matching on the original
// conntrack tuple keeps the console reachable even when it runs in Docker
// on the same host, where the packet's address is rewritten by DNAT.
func isolationRules(allow []netip.Prefix) string {
	var v4, v6 []string
	for _, p := range allow {
		if p.Addr().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	set := func(name, typ string, elems []string) string {
		s := fmt.Sprintf("\tset %s {\n\t\ttype %s\n\t\tflags interval\n", name, typ)
		if len(elems) > 0 {
			s += "\t\telements = { " + strings.Join(elems, ", ") + " }\n"
		}
		return s + "\t}\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\ntable inet %s {\n", isolationTable, isolationTable, isolationTable)
	b.WriteString(set("allow4", "ipv4_addr", v4))
	b.WriteString(set("allow6", "ipv6_addr", v6))
	for _, c := range []struct{ name, hook, lo, dhcp, nd string }{
		{"input", "input", `iif "lo"`, "udp sport 67 udp dport 68", "nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert"},
		{"output", "output", `oif "lo"`, "udp sport 68 udp dport 67", "nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit"},
	} {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority -10; policy drop;\n", c.name, c.hook)
		fmt.Fprintf(&b, "\t\t%s accept\n", c.lo)
		b.WriteString("\t\tct original ip saddr @allow4 accept\n\t\tct original ip daddr @allow4 accept\n")
		b.WriteString("\t\tct original ip6 saddr @allow6 accept\n\t\tct original ip6 daddr @allow6 accept\n")
		fmt.Fprintf(&b, "\t\t%s accept\n", c.dhcp)
		fmt.Fprintf(&b, "\t\ticmpv6 type { %s } accept\n", c.nd)
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func nft(script string) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return errors.New("nft not found: install the nftables package to use host isolation")
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}

func (a *Agent) applyIsolation(allow []string) (string, error) {
	addrs, err := a.consoleAddrs()
	if err != nil {
		return "", err
	}
	var prefixes []netip.Prefix
	for _, ad := range addrs {
		prefixes = append(prefixes, netip.PrefixFrom(ad, ad.BitLen()))
	}
	for _, s := range allow {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			prefixes = append(prefixes, p.Masked())
		} else if ad, err := netip.ParseAddr(s); err == nil {
			ad = ad.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(ad, ad.BitLen()))
		} else {
			return "", fmt.Errorf("invalid allow entry %q", s)
		}
	}
	if err := nft(isolationRules(dedupePrefixes(prefixes))); err != nil {
		return "", err
	}
	strs := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		strs = append(strs, p.String())
	}
	return "host isolated; reachable: " + strings.Join(strs, ", "), nil
}

// nft rejects overlapping interval elements, so drop exact duplicates and
// prefixes contained in another.
func dedupePrefixes(in []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for i, p := range in {
		covered := false
		for j, q := range in {
			if i != j && q.Bits() <= p.Bits() && q.Contains(p.Addr()) && (q.Bits() < p.Bits() || j < i) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	return out
}

func (a *Agent) isolate(args map[string]string) (string, error) {
	allow := strings.Split(args["allow"], ",")
	msg, err := a.applyIsolation(allow)
	if err != nil {
		return "", err
	}
	raw, _ := json.Marshal(isolationState{Allow: allow})
	if err := os.WriteFile(a.isolationFile(), raw, 0o600); err != nil {
		return "", err
	}
	return msg, nil
}

func (a *Agent) unisolate() (string, error) {
	if err := nft(fmt.Sprintf("add table inet %s\ndelete table inet %s\n", isolationTable, isolationTable)); err != nil {
		return "", err
	}
	if err := os.Remove(a.isolationFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return "network isolation removed", nil
}

// restoreIsolation re-applies isolation after a reboot or agent restart.
func (a *Agent) restoreIsolation() {
	raw, err := os.ReadFile(a.isolationFile())
	if err != nil {
		return
	}
	var st isolationState
	_ = json.Unmarshal(raw, &st)
	if msg, err := a.applyIsolation(st.Allow); err != nil {
		a.log.Error("re-applying network isolation failed", "err", err)
	} else {
		a.log.Warn("network isolation re-applied", "detail", msg)
	}
}
