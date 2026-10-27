package live

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

type memCommands struct {
	mu      sync.Mutex
	pending map[string][]*store.Command
}

func (m *memCommands) add(agentID, id, typ string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending[agentID] = append(m.pending[agentID], &store.Command{ID: id, AgentID: agentID, Type: typ, Args: map[string]string{"pid": "42"}})
}

func (m *memCommands) TakeCommands(_ context.Context, agentID string) ([]*store.Command, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.pending[agentID]
	delete(m.pending, agentID)
	return c, nil
}

func (m *memCommands) RequeueCommand(context.Context, string) error { return nil }

func (m *memCommands) PendingCommandAgents(context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []string
	for id := range m.pending {
		ids = append(ids, id)
	}
	return ids, nil
}

func nextCommand(t *testing.T, down chan *xdrv1.LiveDown) *xdrv1.AgentCommand {
	t.Helper()
	for {
		select {
		case m := <-down:
			if c, ok := m.Msg.(*xdrv1.LiveDown_Command); ok {
				return c.Command
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no command pushed")
		}
	}
}

func TestPushCommands(t *testing.T) {
	cmds := &memCommands{pending: map[string][]*store.Command{}}
	h := &Hub{Log: slog.New(slog.DiscardHandler), Commands: cmds}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fakeAgent{ctx: ctx, down: make(chan *xdrv1.LiveDown, 16), up: make(chan *xdrv1.LiveUp, 16)}
	go h.Serve("a1", "web01", f)
	for !h.Online("a1") {
		time.Sleep(time.Millisecond)
	}

	// Before the hello the agent may be an old one: nothing is pushed.
	cmds.add("a1", "c0", "kill_process")
	h.Notify("a1")
	time.Sleep(50 * time.Millisecond)
	if len(f.down) != 0 {
		t.Fatal("pushed to an agent that did not say hello")
	}

	// The hello delivers what was waiting.
	f.up <- &xdrv1.LiveUp{Msg: &xdrv1.LiveUp_Hello{Hello: &xdrv1.LiveHello{Commands: true}}}
	if c := nextCommand(t, f.down); c.Id != "c0" || c.Type != xdrv1.CommandType_COMMAND_TYPE_KILL_PROCESS || c.Args["pid"] != "42" {
		t.Fatalf("pushed %+v", c)
	}

	// Then a queued command goes out at once.
	cmds.add("a1", "c1", "isolate_host")
	h.Notify("a1")
	if c := nextCommand(t, f.down); c.Id != "c1" {
		t.Fatalf("pushed %+v", c)
	}

	// And one queued by another process is found by the dispatcher.
	go h.RunDispatcher(ctx)
	cmds.add("a1", "c2", "scan_path")
	if c := nextCommand(t, f.down); c.Id != "c2" {
		t.Fatalf("pushed %+v", c)
	}
}
