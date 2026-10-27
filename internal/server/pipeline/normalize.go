// Package pipeline is the detection pipeline every ingested batch goes
// through: normalize (wire event to stored row), enrich (process context and
// storyline from what the server has seen), store, then detect and correlate
// in the detection service, which runs in xdr-server or as xdr-detect.
package pipeline

import (
	"fmt"
	"math"
	"strings"
	"time"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

// Source is the authenticated agent a batch came from.
type Source struct {
	TenantID, AgentID, Hostname string
}

// Normalize turns an agent's event into a stored row.
func Normalize(src Source, e *xdrv1.Event) store.Event {
	// Identity comes from the authenticated certificate and the enrollment
	// record, never from what the agent claims in the envelope.
	r := store.Event{
		Time:          time.Unix(0, e.TimestampUnixNano).UTC(),
		TenantID:      src.TenantID,
		AgentID:       src.AgentID,
		EndpointID:    src.AgentID,
		Hostname:      src.Hostname,
		EventID:       e.Id,
		SchemaVersion: uint16(e.SchemaVersion),
		Type:          EventTypeName(e.Type),
		Priority:      PriorityName(e.Priority),
		Metadata:      e.Metadata,
		Collector:     e.Collector,
		DNSAnswers:    []string{},
		LoginUID:      math.MaxUint32,
	}
	// Agent clocks can be wrong; keep events inside a sane window so they
	// land in a valid partition.
	if now := time.Now(); r.Time.After(now.Add(time.Hour)) || r.Time.Before(now.AddDate(0, 0, -30)) {
		r.Time = now.UTC()
	}
	switch p := e.Payload.(type) {
	case *xdrv1.Event_Process:
		pe := p.Process
		r.PID, r.PPID, r.UID, r.User = pe.Pid, pe.Ppid, pe.Uid, pe.User
		r.Exe, r.Args, r.Cwd, r.SHA256 = pe.Exe, JoinArgs(pe.Args), pe.Cwd, pe.Sha256
		r.ParentExe, r.ExitCode = pe.ParentExe, pe.ExitCode
		r.GID, r.Group, r.EUID = pe.Gid, pe.Group, pe.Euid
		if pe.SessionId != 0 || pe.LoginUid != 0 {
			r.LoginUID = pe.LoginUid
		}
		r.TTY, r.SessionID, r.Capabilities = pe.Tty, pe.SessionId, pe.Capabilities
		r.MD5, r.SHA1, r.DurationMS = pe.Md5, pe.Sha1, pe.DurationMs
		if pe.ExeMode != 0 {
			r.Mode, r.Owner = pe.ExeMode, fmt.Sprint(pe.ExeUid)
		}
	case *xdrv1.Event_File:
		fe := p.File
		r.Path, r.OldPath, r.Size, r.Mode, r.UID, r.SHA256 = fe.Path, fe.OldPath, fe.Size, fe.Mode, fe.Uid, fe.Sha256
		r.PID, r.PPID, r.Exe, r.User = fe.Pid, fe.Ppid, fe.Exe, fe.User
		r.GID, r.Inode, r.Device, r.Owner = fe.Gid, fe.Inode, fe.Device, fe.Owner
		r.Filesystem, r.MountPoint, r.MD5, r.SHA1 = fe.Filesystem, fe.MountPoint, fe.Md5, fe.Sha1
		if fe.Change != "" {
			// FIM drift: what changed is kept in args so rules can match it.
			r.Args = fe.Change
			if fe.OldSha256 != "" {
				r.Args += " old_sha256=" + fe.OldSha256
			}
		}
	case *xdrv1.Event_Network:
		ne := p.Network
		r.Protocol, r.LocalAddr, r.LocalPort = ne.Protocol, ne.LocalAddr, ne.LocalPort
		r.RemoteAddr, r.RemotePort, r.PID, r.Exe, r.UID = ne.RemoteAddr, ne.RemotePort, ne.Pid, ne.Exe, ne.Uid
		r.Direction, r.User, r.NetNamespace = ne.Direction, ne.User, ne.NetNamespace
	case *xdrv1.Event_Yara:
		y := p.Yara
		r.Path, r.SHA256, r.Size, r.PID = y.Path, y.Sha256, y.Size, y.Pid
		// The matched rule names are kept in args, then what anti-malware did.
		r.Args = strings.Join(y.Rules, ", ")
		if y.Action != "" {
			r.Args += "; " + y.Action
		}
	case *xdrv1.Event_Tamper:
		t := p.Tamper
		// The action is kept in path so rules can match it exactly.
		r.Path, r.Args, r.PID, r.Exe = t.Action, t.Detail, t.Pid, t.Exe
	case *xdrv1.Event_Policy:
		pe := p.Policy
		// Like tamper events, the action is kept in path.
		r.Path, r.Args, r.RemoteAddr, r.PID, r.Exe, r.SHA256, r.User = pe.Action, pe.Detail, pe.RemoteAddr, pe.Pid, pe.Exe, pe.Sha256, pe.User
		r.Action = pe.Action
	case *xdrv1.Event_Dns:
		d := p.Dns
		r.DNSQuery, r.DNSType, r.DNSRcode = strings.ToLower(strings.TrimSuffix(d.Query, ".")), d.QueryType, d.ResponseCode
		r.RemoteAddr, r.RemotePort, r.Protocol, r.PID, r.Exe = d.Server, d.ServerPort, d.Protocol, d.Pid, d.Exe
		for _, a := range d.Answers {
			r.DNSAnswers = append(r.DNSAnswers, a.Type+" "+a.Data+" ttl="+fmt.Sprint(a.Ttl))
		}
		switch {
		case d.ResponseCode == "":
		case d.ResponseCode == "NOERROR":
			r.Outcome = "success"
		default:
			r.Outcome = "failure"
		}
	case *xdrv1.Event_Auth:
		a := p.Auth
		r.Action, r.User, r.UID, r.RemoteAddr, r.RemotePort = a.Action, a.User, a.Uid, a.SourceIp, a.SourcePort
		r.TTY, r.Category, r.TargetUser, r.Args, r.PID = a.Tty, a.Method, a.TargetUser, a.Command, a.Pid
		r.Path, r.NewValue = a.Service, a.Detail
		r.OldValue = a.FailureReason
		r.Outcome = outcome(a.Success)
	case *xdrv1.Event_Persistence:
		pe := p.Persistence
		r.Category, r.Action, r.Path, r.SHA256 = pe.PersistenceType, pe.Operation, pe.Path, pe.Sha256
		r.OldValue, r.NewValue, r.PID, r.Exe, r.User, r.UID = pe.OldValue, pe.NewValue, pe.Pid, pe.Exe, pe.User, pe.Uid
		if pe.OldSha256 != "" {
			r.Args = "old_sha256=" + pe.OldSha256
		}
	case *xdrv1.Event_Memory:
		m := p.Memory
		r.Action, r.PID, r.Exe, r.User = m.Operation, m.SourcePid, m.SourceExe, m.SourceUser
		r.TargetPID, r.TargetGUID, r.TargetUser, r.Path = m.TargetPid, m.TargetProcessGuid, m.TargetUser, m.TargetExe
		r.OldValue, r.NewValue, r.Size, r.Args = m.OldProtection, m.NewProtection, m.Size, m.Detail
		if m.Injection {
			r.Category = "injection"
		} else if m.Rwx {
			r.Category = "rwx"
		}
	case *xdrv1.Event_Kernel:
		k := p.Kernel
		r.Action, r.Path, r.OldValue, r.NewValue, r.Args, r.PID, r.Exe = k.Action, k.Name, k.OldValue, k.NewValue, k.Detail, k.Pid, k.Exe
	case *xdrv1.Event_Inventory:
		inv := p.Inventory
		r.Category, r.Action = inv.Kind, inv.Action
		r.NewValue, r.OldValue = inventoryItems(inv.Added), inventoryItems(inv.Removed)
		if len(inv.Attributes) > 0 {
			if r.Metadata == nil {
				r.Metadata = map[string]string{}
			}
			for k, v := range inv.Attributes {
				r.Metadata[k] = v
			}
		}
	}
	applyProcessContext(&r, e.ProcessContext)
	applyContainer(&r, e.Container)
	r.Summary = Summary(&r)
	return r
}

func outcome(ok bool) string {
	if ok {
		return "success"
	}
	return "failure"
}

// inventoryItems renders items one per line, "name version detail", capped
// so a full package list stays a reasonable row.
func inventoryItems(items []*xdrv1.InventoryItem) string {
	var b strings.Builder
	for _, it := range items {
		if b.Len() > 64<<10 {
			fmt.Fprintf(&b, "... (%d items in total)\n", len(items))
			break
		}
		b.WriteString(strings.TrimSpace(it.Name + " " + it.Version + " " + it.Detail))
		b.WriteByte('\n')
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func applyContainer(r *store.Event, c *xdrv1.ContainerContext) {
	if c == nil {
		return
	}
	r.ContainerID, r.ContainerName, r.ContainerImage = c.ContainerId, c.Name, c.Image
	r.PodName, r.PodNamespace = c.PodName, c.PodNamespace
}

// applyProcessContext adds the actor's identity and parent. Payload fields
// win; the context fills what a collector did not know, e.g. the user behind
// a network connection.
func applyProcessContext(r *store.Event, pc *xdrv1.ProcessContext) {
	if pc == nil {
		return
	}
	r.ProcessGUID, r.ParentGUID = pc.ProcessGuid, pc.ParentProcessGuid
	r.ParentArgs, r.ParentUser, r.ParentSHA256 = pc.ParentCommandLine, pc.ParentUser, pc.ParentSha256
	r.PIDNamespace, r.MntNamespace = pc.PidNamespace, pc.MntNamespace
	if r.NetNamespace == 0 {
		r.NetNamespace = pc.NetNamespace
	}
	if r.TTY == "" {
		r.TTY, r.SessionID = pc.Tty, pc.SessionId
	}
	if r.Cwd == "" {
		r.Cwd = pc.Cwd
	}
	if r.LoginUID == math.MaxUint32 && (pc.SessionId != 0 || pc.LoginUid != 0) {
		r.LoginUID = pc.LoginUid
	}
	if pc.StartTimeUnixNano > 0 {
		r.ProcessStart = time.Unix(0, pc.StartTimeUnixNano).UTC()
	}
	if r.PID == 0 {
		r.PID = pc.Pid
	}
	if r.PPID == 0 {
		r.PPID = pc.Ppid
	}
	if r.User == "" {
		r.User = pc.User
	}
	if r.ParentExe == "" {
		r.ParentExe = pc.ParentExecutable
	}
	// For file, network and policy events exe is the actor; keep the
	// payload's value when it names something else (a blocked or scanned file).
	if r.Exe == "" && r.Type != "exec_blocked" {
		r.Exe = pc.Executable
	}
}

// EventTypeName is the stored name of an event type, e.g. "process_exec".
func EventTypeName(t xdrv1.EventType) string {
	return strings.ToLower(strings.TrimPrefix(t.String(), "EVENT_TYPE_"))
}

// PriorityName is the stored form of a priority, e.g. "critical".
func PriorityName(p xdrv1.Priority) string {
	if p == xdrv1.Priority_PRIORITY_UNSPECIFIED {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(p.String(), "PRIORITY_"))
}

// JoinArgs renders argv as a shell-like string; arguments with spaces are quoted.
func JoinArgs(args []string) string {
	var b strings.Builder
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		if a == "" || strings.ContainsAny(a, " \t\"'") {
			fmt.Fprintf(&b, "%q", a)
		} else {
			b.WriteString(a)
		}
	}
	return b.String()
}
