package pipeline

import (
	"path"
	"strings"
	"sync"

	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

// defaultCacheSize is how many processes the enricher remembers per
// generation; two generations are kept.
const defaultCacheSize = 200_000

// Enricher fills in what an event's own agent did not send, from the
// processes the server has seen start: the parent of a process, the actor of
// a file or network event, and the storyline (the process tree an event
// belongs to).
type Enricher struct {
	// Size bounds each cache generation; zero means defaultCacheSize.
	Size int

	mu       sync.Mutex
	cur, old map[string]*procInfo
}

type procInfo struct {
	parent, exe, args, user, sha256 string
	storyline                       string
}

// sessionRoots are the executables that start unrelated work: services, logins
// and schedulers. A storyline stops below them, so every SSH session or cron
// job is its own storyline instead of one tree under sshd or systemd.
var sessionRoots = map[string]bool{
	"systemd": true, "init": true, "sshd": true, "sshd-session": true, "cron": true, "crond": true,
	"atd": true, "anacron": true, "login": true, "agetty": true, "dockerd": true,
	"containerd": true, "containerd-shim": true, "containerd-shim-runc-v2": true, "runc": true,
	"gdm-session-worker": true, "lightdm": true, "xdr-agent": true, "xdr-agent-rs": true,
}

// IsSessionRoot reports whether exe starts unrelated work (see sessionRoots).
func IsSessionRoot(exe string) bool {
	if exe == "" {
		return false
	}
	return sessionRoots[path.Base(strings.TrimSuffix(exe, " (deleted)"))]
}

func key(agentID, guid string) string { return agentID + "/" + guid }

func (e *Enricher) get(k string) *procInfo {
	if p := e.cur[k]; p != nil {
		return p
	}
	if p := e.old[k]; p != nil {
		e.put(k, p)
		return p
	}
	return nil
}

func (e *Enricher) put(k string, p *procInfo) {
	size := e.Size
	if size <= 0 {
		size = defaultCacheSize
	}
	if e.cur == nil || len(e.cur) >= size {
		e.old, e.cur = e.cur, make(map[string]*procInfo, min(size, 1024))
	}
	e.cur[k] = p
}

// Enrich completes one event in place.
func (e *Enricher) Enrich(ev *store.Event) {
	if ev.ProcessGUID == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	k := key(ev.AgentID, ev.ProcessGUID)
	self := e.get(k)
	if ev.Type == "process_exec" {
		// An execve keeps the GUID, so the newest image wins.
		prev := self
		self = &procInfo{parent: ev.ParentGUID, exe: ev.Exe, args: ev.Args, user: ev.User, sha256: ev.SHA256}
		if prev != nil && self.parent == "" {
			self.parent = prev.parent
		}
		if prev != nil && prev.storyline != "" {
			// The process keeps its place in the tree across execve.
			self.storyline = prev.storyline
		} else {
			self.storyline = e.storyline(ev, self.parent)
		}
		e.put(k, self)
	}
	if self != nil {
		if ev.ParentGUID == "" {
			ev.ParentGUID = self.parent
		}
		if ev.User == "" {
			ev.User = self.user
		}
		if ev.Exe == "" && ev.Type != "exec_blocked" {
			ev.Exe = self.exe
		}
	}
	if ev.ParentGUID != "" {
		if p := e.get(key(ev.AgentID, ev.ParentGUID)); p != nil {
			if ev.ParentExe == "" {
				ev.ParentExe = p.exe
			}
			if ev.ParentArgs == "" {
				ev.ParentArgs = p.args
			}
			if ev.ParentUser == "" {
				ev.ParentUser = p.user
			}
			if ev.ParentSHA256 == "" {
				ev.ParentSHA256 = p.sha256
			}
		}
	}
	switch {
	case self != nil:
		ev.StorylineGUID = self.storyline
	default:
		ev.StorylineGUID = e.storyline(ev, ev.ParentGUID)
	}
}

// storyline is the GUID of the topmost known ancestor below a session root.
func (e *Enricher) storyline(ev *store.Event, parent string) string {
	if ev.Type == "process_exec" && IsSessionRoot(ev.Exe) {
		return ev.ProcessGUID
	}
	if parent == "" {
		return ev.ProcessGUID
	}
	p := e.get(key(ev.AgentID, parent))
	switch {
	case p == nil && IsSessionRoot(ev.ParentExe):
		return ev.ProcessGUID
	case p == nil:
		// The parent started before the agent or the server did; it is the
		// oldest ancestor known.
		return parent
	case IsSessionRoot(p.exe):
		return ev.ProcessGUID
	case p.storyline != "":
		return p.storyline
	}
	return parent
}
