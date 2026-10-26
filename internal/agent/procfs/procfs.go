// Package procfs reads process metadata from /proc and hashes executables.
package procfs

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MaxHashSize is the largest file the agent will hash (64 MiB).
const MaxHashSize = 64 << 20

type Info struct {
	PID  uint32
	PPID uint32
	UID  uint32
	GID  uint32
	User string
	Exe  string
	Args []string
	Cwd  string
}

// Read collects what /proc knows about pid. It returns an error if the
// process has already exited.
func Read(pid uint32) (*Info, error) {
	base := fmt.Sprintf("/proc/%d", pid)
	info := &Info{PID: pid}

	status, err := os.ReadFile(base + "/status")
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(status))
	for sc.Scan() {
		line := sc.Text()
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(val)
		if len(fields) == 0 {
			continue
		}
		switch key {
		case "PPid":
			info.PPID = parseU32(fields[0])
		case "Uid":
			info.UID = parseU32(fields[0])
		case "Gid":
			info.GID = parseU32(fields[0])
		}
	}

	info.Exe, _ = os.Readlink(base + "/exe")
	info.Cwd, _ = os.Readlink(base + "/cwd")
	if raw, err := os.ReadFile(base + "/cmdline"); err == nil {
		raw = bytes.TrimRight(raw, "\x00")
		if len(raw) > 0 {
			for _, a := range bytes.Split(raw, []byte{0}) {
				info.Args = append(info.Args, string(a))
			}
		}
	}
	info.User = Username(info.UID)
	return info, nil
}

func parseU32(s string) uint32 {
	v, _ := strconv.ParseUint(s, 10, 32)
	return uint32(v)
}

var (
	userMu    sync.Mutex
	userCache = map[uint32]string{}
)

// Username resolves a uid to a login name, caching results.
func Username(uid uint32) string {
	userMu.Lock()
	defer userMu.Unlock()
	if name, ok := userCache[uid]; ok {
		return name
	}
	name := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}
	userCache[uid] = name
	return name
}

type hashKey struct {
	path  string
	size  int64
	mtime time.Time
	ino   uint64
}

// Hasher computes SHA-256 of files, reusing results while the file's size,
// mtime and inode are unchanged.
type Hasher struct {
	mu    sync.Mutex
	cache map[hashKey]string
	limit int
}

func NewHasher(limit int) *Hasher {
	return &Hasher{cache: make(map[hashKey]string), limit: limit}
}

func (h *Hasher) Hash(path string) string {
	// Strip the " (deleted)" suffix the kernel appends to replaced binaries.
	path = strings.TrimSuffix(path, " (deleted)")
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > MaxHashSize {
		return ""
	}
	key := hashKey{path: path, size: st.Size(), mtime: st.ModTime(), ino: inode(st)}

	h.mu.Lock()
	if v, ok := h.cache[key]; ok {
		h.mu.Unlock()
		return v
	}
	h.mu.Unlock()

	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return ""
	}
	v := hex.EncodeToString(sum.Sum(nil))

	h.mu.Lock()
	if len(h.cache) >= h.limit {
		h.cache = make(map[hashKey]string)
	}
	h.cache[key] = v
	h.mu.Unlock()
	return v
}
