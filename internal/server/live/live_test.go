package live

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

// fakeAgent answers like the agent: activity snapshots, and an echoing
// shell that exits on "exit".
type fakeAgent struct {
	ctx  context.Context
	down chan *xdrv1.LiveDown
	up   chan *xdrv1.LiveUp
}

func (f *fakeAgent) Context() context.Context { return f.ctx }
func (f *fakeAgent) Send(m *xdrv1.LiveDown) error {
	f.down <- m
	return nil
}
func (f *fakeAgent) Recv() (*xdrv1.LiveUp, error) {
	select {
	case m := <-f.up:
		return m, nil
	case <-f.ctx.Done():
		return nil, io.EOF
	}
}

func (f *fakeAgent) run() {
	for m := range f.down {
		switch msg := m.Msg.(type) {
		case *xdrv1.LiveDown_Activity:
			f.up <- &xdrv1.LiveUp{Msg: &xdrv1.LiveUp_Activity{Activity: &xdrv1.Activity{RequestId: msg.Activity.RequestId, Load1: 1.5}}}
		case *xdrv1.LiveDown_ShellInput:
			id := msg.ShellInput.SessionId
			if string(msg.ShellInput.Data) == "exit" {
				f.up <- &xdrv1.LiveUp{Msg: &xdrv1.LiveUp_ShellExit{ShellExit: &xdrv1.ShellExit{SessionId: id}}}
				continue
			}
			f.up <- &xdrv1.LiveUp{Msg: &xdrv1.LiveUp_ShellOutput{ShellOutput: &xdrv1.ShellData{SessionId: id, Data: msg.ShellInput.Data}}}
		}
	}
}

func TestHub(t *testing.T) {
	h := &Hub{Log: slog.New(slog.DiscardHandler)}
	if _, err := h.Activity(context.Background(), "a1"); err != ErrOffline {
		t.Fatalf("offline agent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeAgent{ctx: ctx, down: make(chan *xdrv1.LiveDown, 16), up: make(chan *xdrv1.LiveUp, 16)}
	go f.run()
	served := make(chan error, 1)
	go func() { served <- h.Serve("a1", "web01", f) }()
	for !h.Online("a1") {
		time.Sleep(time.Millisecond)
	}

	act, err := h.Activity(context.Background(), "a1")
	if err != nil || act.Load1 != 1.5 {
		t.Fatalf("activity %v %v", act, err)
	}

	s, err := h.Open("a1", "root", "admin", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_, ch, stop := s.Subscribe()
	defer stop()
	s.Input([]byte("whoami"))
	if got := string(<-ch); got != "whoami" {
		t.Fatalf("output %q", got)
	}
	// A late viewer sees what happened so far.
	replay, _, stopW := s.Subscribe()
	stopW()
	if string(replay) != "whoami" {
		t.Fatalf("replay %q", replay)
	}
	if n := len(h.Shells("a1")); n != 1 {
		t.Fatalf("%d shells", n)
	}
	s.Input([]byte("exit"))
	<-s.Done()
	if _, open := <-ch; open {
		t.Fatal("subscriber not closed")
	}
	if len(h.Shells("")) != 0 {
		t.Fatal("shell still listed")
	}

	// Shells end when the agent disconnects.
	s2, _ := h.Open("a1", "root", "admin", 80, 24)
	cancel()
	<-served
	<-s2.Done()
	if s2.Reason() != "the agent disconnected" || h.Online("a1") {
		t.Fatalf("after disconnect: %q online=%v", s2.Reason(), h.Online("a1"))
	}
}

func TestRecordingCap(t *testing.T) {
	s := &Shell{subs: map[chan []byte]bool{}}
	chunk := make([]byte, 1<<20)
	for range 5 {
		s.output(chunk)
	}
	if len(s.rec) != maxRecording || !s.truncated || len(s.tail) != replayBytes {
		t.Fatalf("rec=%d truncated=%v tail=%d", len(s.rec), s.truncated, len(s.tail))
	}
}
