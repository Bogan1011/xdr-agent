package agent

import (
	"os"
	"testing"
	"time"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/agent/procfs"
)

func TestEnvelopeProcessContext(t *testing.T) {
	if _, err := procfs.StartTicks(uint32(os.Getpid())); err != nil {
		t.Skip("no /proc:", err)
	}
	a := &Agent{procs: newProcContexts(nil)}
	a.agentID.Store("agent-1")
	pid := uint32(os.Getpid())
	ts := time.Now().UnixNano()

	exec := &xdrv1.Event{Type: xdrv1.EventType_EVENT_TYPE_PROCESS_EXEC, TimestampUnixNano: ts,
		Payload: &xdrv1.Event_Process{Process: &xdrv1.ProcessEvent{Pid: pid, Ppid: uint32(os.Getppid()), Exe: "/bin/test"}}}
	a.envelope(exec)
	pc := exec.ProcessContext
	if exec.SchemaVersion != SchemaVersion || exec.AgentId != "agent-1" || pc == nil || pc.ProcessGuid == "" {
		t.Fatalf("envelope not filled: %+v", exec)
	}
	if pc.ParentProcessGuid == "" || pc.ParentExecutable == "" {
		t.Fatalf("parent context missing: %+v", pc)
	}

	file := &xdrv1.Event{Type: xdrv1.EventType_EVENT_TYPE_FILE_MODIFY, TimestampUnixNano: ts,
		Payload: &xdrv1.Event_File{File: &xdrv1.FileEvent{Pid: pid, Path: "/tmp/x"}}}
	a.envelope(file)
	if file.ProcessContext.GetProcessGuid() != pc.ProcessGuid {
		t.Fatal("events of one process must share its process_guid")
	}
	if file.Priority != xdrv1.Priority_PRIORITY_LOW {
		t.Fatalf("file event priority = %v", file.Priority)
	}
	blocked := &xdrv1.Event{Type: xdrv1.EventType_EVENT_TYPE_EXEC_BLOCKED}
	a.envelope(blocked)
	if blocked.Priority != xdrv1.Priority_PRIORITY_CRITICAL {
		t.Fatalf("blocked exec priority = %v", blocked.Priority)
	}
}
