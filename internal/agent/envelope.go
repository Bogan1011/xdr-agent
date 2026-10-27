package agent

import (
	"strings"
	"sync"
	"time"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/agent/procfs"
)

// SchemaVersion is the SecurityEvent envelope version this agent produces.
const SchemaVersion = 1

const (
	maxProcContexts = 20000
	// recheckAfter bounds how long a cached context is trusted before its
	// start time is compared again, in case an exit event was missed.
	recheckAfter = 30 * time.Second
)

type procEntry struct {
	ctx     *xdrv1.ProcessContext
	start   uint64
	checked time.Time
}

// procContexts maps PIDs to process contexts with a stable process_guid.
type procContexts struct {
	mu     sync.Mutex
	byPID  map[uint32]*procEntry
	hasher *procfs.Hasher
}

func newProcContexts(h *procfs.Hasher) *procContexts {
	return &procContexts{byPID: make(map[uint32]*procEntry), hasher: h}
}

// envelope fills the schema_version 1 fields before an event is queued.
func (a *Agent) envelope(e *xdrv1.Event) {
	if e.SchemaVersion != 0 {
		return
	}
	e.SchemaVersion = SchemaVersion
	e.AgentId = a.agentID.Load().(string)
	e.Priority = priorityFor(e)
	if e.ProcessContext == nil {
		e.ProcessContext = a.procs.forEvent(e)
	}
}

// priorityFor ranks events for the local queue: prevention, malware and
// tamper events must survive pressure, high-volume file telemetry goes first.
func priorityFor(e *xdrv1.Event) xdrv1.Priority {
	switch e.Type {
	case xdrv1.EventType_EVENT_TYPE_EXEC_BLOCKED, xdrv1.EventType_EVENT_TYPE_YARA_MATCH,
		xdrv1.EventType_EVENT_TYPE_AGENT_TAMPER:
		return xdrv1.Priority_PRIORITY_CRITICAL
	case xdrv1.EventType_EVENT_TYPE_FIM_CHANGE, xdrv1.EventType_EVENT_TYPE_WEB_REPUTATION,
		xdrv1.EventType_EVENT_TYPE_INTRUSION, xdrv1.EventType_EVENT_TYPE_DEVICE_CONTROL,
		xdrv1.EventType_EVENT_TYPE_APP_CONTROL:
		return xdrv1.Priority_PRIORITY_HIGH
	case xdrv1.EventType_EVENT_TYPE_FILE_CREATE, xdrv1.EventType_EVENT_TYPE_FILE_MODIFY,
		xdrv1.EventType_EVENT_TYPE_FILE_DELETE, xdrv1.EventType_EVENT_TYPE_FILE_RENAME,
		xdrv1.EventType_EVENT_TYPE_FILE_ATTRIB, xdrv1.EventType_EVENT_TYPE_NET_LISTEN:
		return xdrv1.Priority_PRIORITY_LOW
	}
	return xdrv1.Priority_PRIORITY_NORMAL
}

// actorPID is the process that caused the event.
func actorPID(e *xdrv1.Event) uint32 {
	switch p := e.Payload.(type) {
	case *xdrv1.Event_Process:
		return p.Process.Pid
	case *xdrv1.Event_File:
		return p.File.Pid
	case *xdrv1.Event_Network:
		return p.Network.Pid
	case *xdrv1.Event_Yara:
		return p.Yara.Pid
	case *xdrv1.Event_Tamper:
		return p.Tamper.Pid
	case *xdrv1.Event_Policy:
		return p.Policy.Pid
	case *xdrv1.Event_Shell:
		return p.Shell.Pid
	}
	return 0
}

func (p *procContexts) forEvent(e *xdrv1.Event) *xdrv1.ProcessContext {
	pid := actorPID(e)
	if pid == 0 {
		return nil
	}
	switch e.Type {
	case xdrv1.EventType_EVENT_TYPE_PROCESS_EXEC:
		return p.exec(e.GetProcess(), e.TimestampUnixNano)
	case xdrv1.EventType_EVENT_TYPE_PROCESS_EXIT:
		c := p.lookup(pid, e.TimestampUnixNano)
		p.mu.Lock()
		delete(p.byPID, pid)
		p.mu.Unlock()
		return c
	}
	return p.lookup(pid, e.TimestampUnixNano)
}

// exec records a new process image. A PID keeps its process_guid across
// execve, since the start time does not change.
func (p *procContexts) exec(pe *xdrv1.ProcessEvent, ts int64) *xdrv1.ProcessContext {
	start, err := procfs.StartTicks(pe.Pid)
	c := &xdrv1.ProcessContext{
		Pid: pe.Pid, Ppid: pe.Ppid, Executable: pe.Exe, CommandLine: strings.Join(pe.Args, " "),
		User: pe.User, Uid: pe.Uid, Sha256: pe.Sha256,
	}
	if err == nil {
		c.ProcessGuid = procfs.ProcessGUID(pe.Pid, start)
		c.StartTimeUnixNano = procfs.StartTimeUnixNano(start)
	} else {
		// Already gone: the exec time is unique enough for a short-lived process.
		c.ProcessGuid = procfs.ProcessGUID(pe.Pid, uint64(ts))
		c.StartTimeUnixNano = ts
	}
	p.setParent(c, ts)
	p.put(pe.Pid, &procEntry{ctx: c, start: start, checked: time.Now()})
	return c
}

func (p *procContexts) lookup(pid uint32, ts int64) *xdrv1.ProcessContext {
	if c := p.cached(pid); c != nil {
		return c
	}
	start, err := procfs.StartTicks(pid)
	if err != nil {
		return &xdrv1.ProcessContext{Pid: pid}
	}
	info, err := procfs.Read(pid)
	if err != nil {
		return &xdrv1.ProcessContext{Pid: pid}
	}
	c := &xdrv1.ProcessContext{
		ProcessGuid: procfs.ProcessGUID(pid, start), Pid: pid, Ppid: info.PPID,
		Executable: info.Exe, CommandLine: strings.Join(info.Args, " "), User: info.User, Uid: info.UID,
		StartTimeUnixNano: procfs.StartTimeUnixNano(start),
	}
	if p.hasher != nil && info.Exe != "" {
		c.Sha256 = p.hasher.Hash(info.Exe)
	}
	p.setParent(c, ts)
	p.put(pid, &procEntry{ctx: c, start: start, checked: time.Now()})
	return c
}

// cached returns a context that is still valid for pid, re-reading the start
// time now and then so a reused PID gets a fresh identity.
func (p *procContexts) cached(pid uint32) *xdrv1.ProcessContext {
	p.mu.Lock()
	en, ok := p.byPID[pid]
	p.mu.Unlock()
	if !ok {
		return nil
	}
	if time.Since(en.checked) < recheckAfter {
		return en.ctx
	}
	start, err := procfs.StartTicks(pid)
	if err != nil || start == en.start {
		// An exited process keeps its last identity for late events.
		p.mu.Lock()
		en.checked = time.Now()
		p.mu.Unlock()
		return en.ctx
	}
	return nil
}

func (p *procContexts) setParent(c *xdrv1.ProcessContext, ts int64) {
	if c.Ppid == 0 {
		return
	}
	par := p.cached(c.Ppid)
	if par == nil {
		par = p.lookup(c.Ppid, ts)
	}
	c.ParentProcessGuid = par.ProcessGuid
	c.ParentExecutable = par.Executable
	c.ParentCommandLine = par.CommandLine
	c.ParentUser = par.User
	c.ParentSha256 = par.Sha256
}

func (p *procContexts) put(pid uint32, en *procEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.byPID) >= maxProcContexts {
		// Rare: drop everything rather than track LRU order on every event.
		clear(p.byPID)
	}
	p.byPID[pid] = en
}
