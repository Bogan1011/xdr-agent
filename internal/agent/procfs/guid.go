package procfs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// clockTicks is USER_HZ, which is 100 on every Linux architecture we ship.
const clockTicks = 100

var (
	bootOnce sync.Once
	bootID   string
	bootTime int64 // unix seconds
)

func loadBoot() {
	if raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		bootID = strings.TrimSpace(string(raw))
	}
	if raw, err := os.ReadFile("/proc/stat"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if v, ok := strings.CutPrefix(line, "btime "); ok {
				bootTime, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			}
		}
	}
}

// BootID is the kernel's random ID for the current boot.
func BootID() string {
	bootOnce.Do(loadBoot)
	return bootID
}

// StartTicks returns a process's start time in clock ticks since boot, field
// 22 of /proc/<pid>/stat. Together with the PID and boot ID it identifies the
// process even after the PID is reused.
func StartTicks(pid uint32) (uint64, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// The command name in parentheses may contain spaces; fields follow the last ')'.
	s := string(raw)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, fmt.Errorf("malformed stat for pid %d", pid)
	}
	f := strings.Fields(s[i+1:])
	// f[0] is field 3 (state), so field 22 is f[19].
	if len(f) < 20 {
		return 0, fmt.Errorf("short stat for pid %d", pid)
	}
	return strconv.ParseUint(f[19], 10, 64)
}

// StartTimeUnixNano converts StartTicks to wall-clock time.
func StartTimeUnixNano(ticks uint64) int64 {
	bootOnce.Do(loadBoot)
	if bootTime == 0 {
		return 0
	}
	return bootTime*1e9 + int64(ticks)*(1e9/clockTicks)
}

// ProcessGUID derives a stable process identity from the boot ID, PID and
// start ticks, formatted like a UUID.
func ProcessGUID(pid uint32, startTicks uint64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%d/%d", BootID(), pid, startTicks)))
	h := hex.EncodeToString(sum[:16])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
