package pipeline

import (
	"fmt"
	"path"
	"strings"

	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

// Summary is a one-line, plain-English description of an event, stored with
// it so the console, alert notes and a local language model can explain the
// event without decoding every column.
func Summary(r *store.Event) string {
	who := r.User
	if who == "" && r.PID != 0 {
		who = fmt.Sprintf("pid %d", r.PID)
	}
	if who == "" {
		who = "something"
	}
	proc := base(r.Exe)
	by := who
	if proc != "" {
		by = who + " (" + proc + ")"
	}
	var s string
	switch r.Type {
	case "process_exec":
		s = fmt.Sprintf("%s started %s", who, clip(orDefault(r.Args, r.Exe), 200))
		if r.ParentExe != "" {
			s += " from " + base(r.ParentExe)
		}
		if r.EUID != r.UID && r.EUID == 0 {
			s += " as root (setuid)"
		}
		if r.TTY != "" {
			s += " on " + r.TTY
		}
	case "process_exit":
		s = fmt.Sprintf("%s exited with code %d", orDefault(proc, "a process"), r.ExitCode)
		if r.DurationMS > 0 {
			s += fmt.Sprintf(" after %s", duration(r.DurationMS))
		}
	case "file_create", "file_modify", "file_delete", "file_attrib", "file_open":
		verb := map[string]string{"file_create": "created", "file_modify": "modified", "file_delete": "deleted",
			"file_attrib": "changed permissions of", "file_open": "opened sensitive file"}[r.Type]
		s = fmt.Sprintf("%s %s %s", by, verb, r.Path)
	case "file_rename":
		s = fmt.Sprintf("%s renamed %s to %s", by, r.OldPath, r.Path)
	case "fim_change":
		s = fmt.Sprintf("Monitored file %s changed (%s)", r.Path, r.Args)
	case "net_connect":
		s = fmt.Sprintf("%s connected to %s:%d over %s", by, r.RemoteAddr, r.RemotePort, r.Protocol)
	case "net_accept":
		s = fmt.Sprintf("%s accepted a %s connection from %s on port %d", by, r.Protocol, r.RemoteAddr, r.LocalPort)
	case "net_listen":
		s = fmt.Sprintf("%s is listening on %s port %d", by, r.Protocol, r.LocalPort)
	case "dns_query":
		s = fmt.Sprintf("%s looked up %s (%s)", by, r.DNSQuery, orDefault(r.DNSType, "?"))
		switch {
		case r.DNSRcode == "NOERROR" && len(r.DNSAnswers) > 0:
			s += " → " + strings.Join(firstWords(r.DNSAnswers, 3), ", ")
		case r.DNSRcode != "":
			s += " → " + r.DNSRcode
		}
	case "auth_login":
		s = fmt.Sprintf("%s logged in via %s", r.User, orDefault(r.Path, "login"))
		if r.RemoteAddr != "" {
			s += " from " + r.RemoteAddr
		}
		if r.Category != "" {
			s += " using " + r.Category
		}
	case "auth_logout":
		s = fmt.Sprintf("%s logged out of %s", r.User, orDefault(r.Path, "a session"))
	case "auth_failed":
		s = fmt.Sprintf("Failed %s login for %s", orDefault(r.Path, ""), orDefault(r.User, "unknown user"))
		if r.RemoteAddr != "" {
			s += " from " + r.RemoteAddr
		}
		if r.OldValue != "" {
			s += ": " + r.OldValue
		}
	case "sudo":
		s = fmt.Sprintf("%s ran sudo as %s: %s", r.User, orDefault(r.TargetUser, "root"), clip(r.Args, 200))
		if r.Outcome == "failure" {
			s += " (denied)"
		}
	case "su":
		s = fmt.Sprintf("%s switched user to %s with su", r.User, orDefault(r.TargetUser, "root"))
		if r.Outcome == "failure" {
			s += " (failed)"
		}
	case "account_change":
		s = fmt.Sprintf("Local account change: %s %s", strings.ReplaceAll(r.Action, "_", " "), r.TargetUser)
	case "persistence":
		s = fmt.Sprintf("%s %s %s persistence at %s", by, orDefault(r.Action, "changed"), strings.ReplaceAll(r.Category, "_", " "), r.Path)
		if r.NewValue != "" {
			s += ": " + clip(firstLine(r.NewValue), 160)
		}
	case "process_access":
		s = fmt.Sprintf("%s accessed the memory of %s (pid %d) via %s", by, orDefault(base(r.Path), "another process"), r.TargetPID, r.Action)
	case "memory_protect":
		s = fmt.Sprintf("%s has writable and executable memory (%s)", orDefault(proc, "a process"), orDefault(r.Args, r.NewValue))
	case "process_injection":
		s = fmt.Sprintf("Possible code injection in %s: %s", orDefault(proc, fmt.Sprintf("pid %d", r.PID)), orDefault(r.Args, r.Action))
	case "kernel_module":
		s = fmt.Sprintf("Kernel module %s %s", r.Path, strings.TrimPrefix(r.Action, "module_"))
	case "kernel_change":
		s = fmt.Sprintf("Kernel setting %s %s", r.Path, strings.ReplaceAll(r.Action, "_", " "))
		if r.OldValue != "" || r.NewValue != "" {
			s += fmt.Sprintf(": %s → %s", r.OldValue, r.NewValue)
		}
	case "container_start", "container_stop":
		s = fmt.Sprintf("Container %s (%s) %s", orDefault(r.ContainerName, short(r.ContainerID)), orDefault(r.ContainerImage, "unknown image"),
			map[bool]string{true: "started", false: "stopped"}[r.Type == "container_start"])
	case "inventory":
		s = fmt.Sprintf("Inventory %s: %s", r.Category, r.Action)
	case "yara_match":
		s = fmt.Sprintf("Malware rule %s matched %s", r.Args, r.Path)
	case "exec_blocked":
		s = fmt.Sprintf("Blocked %s from running %s", by, r.Exe)
	case "agent_tamper":
		s = fmt.Sprintf("Agent tamper attempt: %s %s", r.Path, r.Args)
	default:
		s = strings.TrimSpace(strings.ReplaceAll(r.Type, "_", " ") + " " + r.Path + " " + r.Args)
	}
	if r.ContainerID != "" && !strings.HasPrefix(r.Type, "container_") {
		s += " in container " + orDefault(r.ContainerName, short(r.ContainerID))
	}
	return clip(s, 400)
}

func base(p string) string {
	if p == "" {
		return ""
	}
	return path.Base(p)
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

// firstWords keeps "A 1.2.3.4" from "A 1.2.3.4 ttl=60" for the first n answers.
func firstWords(answers []string, n int) []string {
	var out []string
	for i, a := range answers {
		if i == n {
			out = append(out, "…")
			break
		}
		f := strings.Fields(a)
		if len(f) > 1 {
			out = append(out, f[1])
		}
	}
	return out
}

func duration(ms uint64) string {
	switch {
	case ms < 1000:
		return fmt.Sprintf("%dms", ms)
	case ms < 120_000:
		return fmt.Sprintf("%.1fs", float64(ms)/1000)
	case ms < 7_200_000:
		return fmt.Sprintf("%dm", ms/60_000)
	default:
		return fmt.Sprintf("%dh", ms/3_600_000)
	}
}
