package ebpf

import (
	"os/exec"
	"strconv"
)

func itoa(i int) string { return strconv.Itoa(i) }

func runShell(s string) ([]byte, error) { return exec.Command("bash", "-c", s).CombinedOutput() }
