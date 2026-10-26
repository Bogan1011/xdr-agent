package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

// rootGroups give root without sudo: their members can start a privileged
// container or mount the host's disks.
var rootGroups = []string{"docker", "lxd", "disk"}

type passwdEntry struct {
	name        string
	uid, gid    uint32
	home, shell string
}

func readPasswd(path string) ([]passwdEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []passwdEntry
	s := bufio.NewScanner(f)
	for s.Scan() {
		f := strings.Split(s.Text(), ":")
		if len(f) < 7 || strings.HasPrefix(f[0], "#") {
			continue
		}
		uid, err1 := strconv.ParseUint(f[2], 10, 32)
		gid, err2 := strconv.ParseUint(f[3], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, passwdEntry{name: f[0], uid: uint32(uid), gid: uint32(gid), home: f[5], shell: f[6]})
	}
	return out, s.Err()
}

func interactiveShell(sh string) bool {
	return sh != "" && !strings.HasSuffix(sh, "nologin") && !strings.HasSuffix(sh, "/false") && !strings.HasSuffix(sh, "/sync")
}

// readGroups returns each user's supplementary groups and the name of every gid.
func readGroups(path string) (map[string][]string, map[uint32]string) {
	members, names := map[string][]string{}, map[uint32]string{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return members, names
	}
	for _, l := range strings.Split(string(raw), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 4 {
			continue
		}
		if gid, err := strconv.ParseUint(f[2], 10, 32); err == nil {
			names[uint32(gid)] = f[0]
		}
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members[m] = append(members[m], f[0])
			}
		}
	}
	return members, names
}

type shadowEntry struct {
	state   string // set, locked, empty or none
	changed int64
}

func readShadow(path string) map[string]shadowEntry {
	out := map[string]shadowEntry{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(raw), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 3 {
			continue
		}
		e := shadowEntry{}
		switch h := f[1]; {
		case h == "":
			e.state = "empty"
		case h == "*" || h == "!*" || h == "!!":
			e.state = "none"
		case strings.HasPrefix(h, "!"):
			e.state = "locked"
		default:
			e.state = "set"
		}
		// The change date is in days since the epoch.
		if d, err := strconv.ParseInt(f[2], 10, 64); err == nil && d > 0 {
			e.changed = d * 86400
		}
		out[f[0]] = e
	}
	return out
}

// sudoGrant is what the sudoers files give one user or %group.
type sudoGrant struct {
	source   string
	nopasswd bool
}

// readSudoers parses user specifications from sudoers and its drop-ins. It
// handles the common forms (user, %group, User_Alias), not every corner of
// the grammar.
func readSudoers(etc, dropIns string) map[string][]sudoGrant {
	files := []string{filepath.Join(etc, "sudoers")}
	ents, _ := os.ReadDir(dropIns)
	for _, e := range ents {
		// sudo skips names with a dot or ending in ~.
		if !e.IsDir() && !strings.Contains(e.Name(), ".") && !strings.HasSuffix(e.Name(), "~") {
			files = append(files, filepath.Join(dropIns, e.Name()))
		}
	}
	out := map[string][]sudoGrant{}
	aliases := map[string][]string{}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		source := "sudoers"
		if base := filepath.Base(path); base != "sudoers" {
			source = "sudoers.d/" + base
			if strings.HasPrefix(base, jitPrefix) {
				source = "jit"
			}
		}
		for _, l := range logicalLines(string(raw)) {
			fields := strings.Fields(l)
			if len(fields) < 2 {
				continue
			}
			switch {
			case fields[0] == "User_Alias":
				name, list, ok := strings.Cut(strings.TrimPrefix(l, "User_Alias"), "=")
				if ok {
					aliases[strings.TrimSpace(name)] = splitList(list)
				}
				continue
			case strings.HasPrefix(fields[0], "Defaults"), strings.HasSuffix(fields[0], "_Alias"),
				strings.HasPrefix(fields[0], "@include"), strings.HasPrefix(fields[0], "#include"):
				continue
			}
			who, rest, ok := strings.Cut(l, " ")
			if !ok || !strings.Contains(rest, "=") {
				continue
			}
			g := sudoGrant{source: source, nopasswd: strings.Contains(rest, "NOPASSWD:")}
			for _, u := range splitList(who) {
				if names, ok := aliases[u]; ok {
					for _, n := range names {
						out[n] = append(out[n], g)
					}
					continue
				}
				out[u] = append(out[u], g)
			}
		}
	}
	return out
}

// logicalLines joins continuation lines and drops comments and blanks.
func logicalLines(s string) []string {
	var out []string
	var cur strings.Builder
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "#include") {
			continue
		}
		if c, ok := strings.CutSuffix(l, "\\"); ok {
			cur.WriteString(c + " ")
			continue
		}
		cur.WriteString(l)
		if t := strings.TrimSpace(cur.String()); t != "" {
			out = append(out, t)
		}
		cur.Reset()
	}
	return out
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func countKeys(home string) uint32 {
	var n uint32
	for _, name := range []string{"authorized_keys", "authorized_keys2"} {
		raw, err := os.ReadFile(filepath.Join(home, ".ssh", name))
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(raw), "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				n++
			}
		}
	}
	return n
}

// lastlogRecord is struct lastlog: a 32-bit time, a 32-byte line and a
// 256-byte host, indexed by uid.
const lastlogRecord = 4 + 32 + 256

func lastLogin(f *os.File, uid uint32) (int64, string) {
	if f == nil {
		return 0, ""
	}
	var rec [lastlogRecord]byte
	if _, err := f.ReadAt(rec[:], int64(uid)*lastlogRecord); err != nil {
		return 0, ""
	}
	t := int64(binary.LittleEndian.Uint32(rec[:4]))
	host := strings.TrimRight(string(rec[36:]), "\x00")
	return t, host
}

// collectAccounts lists the accounts that can act as root.
func collectAccounts(root string) (*xdrv1.PrivilegedAccounts, error) {
	etc := filepath.Join(root, "etc")
	users, err := readPasswd(filepath.Join(etc, "passwd"))
	if err != nil {
		return nil, err
	}
	groups, gidNames := readGroups(filepath.Join(etc, "group"))
	shadow := readShadow(filepath.Join(etc, "shadow"))
	sudo := readSudoers(etc, filepath.Join(etc, "sudoers.d"))
	lastlog, _ := os.Open(filepath.Join(root, "var/log/lastlog"))
	if lastlog != nil {
		defer lastlog.Close()
	}

	out := &xdrv1.PrivilegedAccounts{}
	for _, u := range users {
		if interactiveShell(u.shell) {
			out.InteractiveAccounts++
		}
		member := slices.Clone(groups[u.name])
		if g, ok := gidNames[u.gid]; ok && !slices.Contains(member, g) {
			member = append(member, g)
		}
		sort.Strings(member)
		a := &xdrv1.PrivilegedAccount{Name: u.name, Uid: u.uid, Shell: u.shell, Home: u.home, Groups: member}
		if u.uid == 0 {
			a.Sources = append(a.Sources, "uid0")
		}
		add := func(gs []sudoGrant, via string) {
			for _, g := range gs {
				src := g.source + via
				if g.source == "jit" {
					src = "jit"
				}
				if !slices.Contains(a.Sources, src) {
					a.Sources = append(a.Sources, src)
				}
				a.Nopasswd = a.Nopasswd || g.nopasswd
			}
		}
		add(sudo[u.name], "")
		for _, g := range member {
			add(sudo["%"+g], ":%"+g)
			if slices.Contains(rootGroups, g) {
				a.Sources = append(a.Sources, "group:"+g)
			}
		}
		if len(a.Sources) == 0 {
			continue
		}
		if sh, ok := shadow[u.name]; ok {
			a.Password, a.PasswordChangedUnix = sh.state, sh.changed
		}
		a.SshKeys = countKeys(filepath.Join(root, u.home))
		a.LastLoginUnix, a.LastLoginFrom = lastLogin(lastlog, u.uid)
		out.Accounts = append(out.Accounts, a)
	}
	return out, nil
}

// reportInventory sends the privileged accounts when they changed or the
// last report is getting old.
func (p *PAM) reportInventory(ctx context.Context) {
	inv, err := collectAccounts(p.root)
	if err != nil {
		p.log.Warn("collect privileged accounts", "err", err)
		return
	}
	raw, _ := proto.MarshalOptions{Deterministic: true}.Marshal(inv)
	sum := sha256.Sum256(raw)
	h := hex.EncodeToString(sum[:])
	if h == p.invHash && time.Since(p.invSent) < inventoryEvery {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := p.client.ReportPrivilegedAccounts(cctx, inv); err != nil {
		p.log.Warn("report privileged accounts", "err", err)
		return
	}
	p.invHash, p.invSent = h, time.Now()
}
