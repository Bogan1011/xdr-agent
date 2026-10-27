// Package live relays the console's remote shells and live activity requests
// to agents over the stream each agent keeps open, and records the shells as
// privileged sessions.
package live

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

const (
	// maxRecording matches the cap on sudo session recordings.
	maxRecording = 4 << 20
	// replayBytes is how much recent output a viewer joining a shell sees.
	replayBytes     = 64 << 10
	activityTimeout = 5 * time.Second
	outQueue        = 512
)

var (
	ErrOffline  = errors.New("the agent is not connected")
	ErrNotFound = errors.New("no such remote shell")
)

// Hub tracks the connected agents and the remote shells running on them.
type Hub struct {
	DB  *store.Postgres
	Log *slog.Logger

	mu     sync.Mutex
	agents map[string]*conn
	shells map[string]*Shell
}

type conn struct {
	agentID, hostname string
	out               chan *xdrv1.LiveDown
	done              chan struct{}

	mu      sync.Mutex
	pending map[string]chan *xdrv1.Activity
}

// send queues a message for the agent; it fails when the agent is gone or
// not reading.
func (c *conn) send(m *xdrv1.LiveDown) bool {
	select {
	case c.out <- m:
		return true
	case <-c.done:
	case <-time.After(5 * time.Second):
	}
	return false
}

// Stream is the agent side of the gRPC stream.
type Stream interface {
	Context() context.Context
	Send(*xdrv1.LiveDown) error
	Recv() (*xdrv1.LiveUp, error)
}

// Serve runs one agent's live stream until it ends. A reconnecting agent
// replaces its previous stream.
func (h *Hub) Serve(agentID, hostname string, st Stream) error {
	c := &conn{agentID: agentID, hostname: hostname, out: make(chan *xdrv1.LiveDown, outQueue),
		done: make(chan struct{}), pending: map[string]chan *xdrv1.Activity{}}
	h.mu.Lock()
	if h.agents == nil {
		h.agents, h.shells = map[string]*conn{}, map[string]*Shell{}
	}
	h.agents[agentID] = c
	h.mu.Unlock()
	defer h.drop(c)

	errc := make(chan error, 1)
	go func() {
		for {
			select {
			case m := <-c.out:
				if err := st.Send(m); err != nil {
					errc <- err
					return
				}
			case <-st.Context().Done():
				return
			}
		}
	}()
	go func() {
		for {
			m, err := st.Recv()
			if err != nil {
				errc <- err
				return
			}
			h.handle(c, m)
		}
	}()
	return <-errc
}

func (h *Hub) handle(c *conn, m *xdrv1.LiveUp) {
	switch msg := m.Msg.(type) {
	case *xdrv1.LiveUp_ShellOutput:
		if s := h.shell(msg.ShellOutput.SessionId); s != nil && s.conn == c {
			s.output(msg.ShellOutput.Data)
		}
	case *xdrv1.LiveUp_ShellExit:
		if s := h.shell(msg.ShellExit.SessionId); s != nil && s.conn == c {
			reason := msg.ShellExit.Error
			if reason == "" {
				reason = "shell exited"
			}
			h.end(s, reason)
		}
	case *xdrv1.LiveUp_Activity:
		c.mu.Lock()
		ch := c.pending[msg.Activity.RequestId]
		delete(c.pending, msg.Activity.RequestId)
		c.mu.Unlock()
		if ch != nil {
			ch <- msg.Activity
		}
	}
}

func (h *Hub) drop(c *conn) {
	close(c.done)
	h.mu.Lock()
	if h.agents[c.agentID] == c {
		delete(h.agents, c.agentID)
	}
	var orphans []*Shell
	for _, s := range h.shells {
		if s.conn == c {
			orphans = append(orphans, s)
		}
	}
	h.mu.Unlock()
	for _, s := range orphans {
		h.end(s, "the agent disconnected")
	}
}

func (h *Hub) conn(agentID string) *conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.agents[agentID]
}

// Online reports whether the agent has its live stream open.
func (h *Hub) Online(agentID string) bool { return h.conn(agentID) != nil }

// Activity asks the agent what is happening on the host right now.
func (h *Hub) Activity(ctx context.Context, agentID string) (*xdrv1.Activity, error) {
	c := h.conn(agentID)
	if c == nil {
		return nil, ErrOffline
	}
	id := newID()
	ch := make(chan *xdrv1.Activity, 1)
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()
	if !c.send(&xdrv1.LiveDown{Msg: &xdrv1.LiveDown_Activity{Activity: &xdrv1.ActivityRequest{RequestId: id}}}) {
		return nil, ErrOffline
	}
	ctx, cancel := context.WithTimeout(ctx, activityTimeout)
	defer cancel()
	select {
	case a := <-ch:
		return a, nil
	case <-c.done:
		return nil, ErrOffline
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Shell is a remote shell opened from the console.
type Shell struct {
	ID       string    `json:"id"`
	AgentID  string    `json:"agent_id"`
	Hostname string    `json:"hostname"`
	User     string    `json:"user"`
	Admin    string    `json:"admin"`
	Started  time.Time `json:"started_at"`
	Viewers  int       `json:"viewers"`

	conn *conn
	done chan struct{}

	mu        sync.Mutex
	rec       []byte
	truncated bool
	tail      []byte
	subs      map[chan []byte]bool
	reason    string
}

// Open starts a login shell for user on the agent.
func (h *Hub) Open(agentID, user, admin string, cols, rows uint32) (*Shell, error) {
	c := h.conn(agentID)
	if c == nil {
		return nil, ErrOffline
	}
	s := &Shell{
		ID: newID(), AgentID: agentID, Hostname: c.hostname, User: user, Admin: admin, Started: time.Now().UTC(),
		conn: c, done: make(chan struct{}), subs: map[chan []byte]bool{},
	}
	h.mu.Lock()
	h.shells[s.ID] = s
	h.mu.Unlock()
	if !c.send(&xdrv1.LiveDown{Msg: &xdrv1.LiveDown_ShellOpen{ShellOpen: &xdrv1.ShellOpen{SessionId: s.ID, User: user, Cols: cols, Rows: rows}}}) {
		h.end(s, "the agent is not reachable")
		return nil, ErrOffline
	}
	h.Log.Info("remote shell opened", "session", s.ID, "hostname", s.Hostname, "user", user, "admin", admin)
	return s, nil
}

func (h *Hub) shell(id string) *Shell {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.shells[id]
}

// Get returns a running shell.
func (h *Hub) Get(id string) (*Shell, error) {
	if s := h.shell(id); s != nil {
		return s, nil
	}
	return nil, ErrNotFound
}

// Shells lists the running shells, newest first; agentID filters when set.
func (h *Hub) Shells(agentID string) []Shell {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := []Shell{}
	for _, s := range h.shells {
		if agentID == "" || s.AgentID == agentID {
			s.mu.Lock()
			out = append(out, Shell{ID: s.ID, AgentID: s.AgentID, Hostname: s.Hostname, User: s.User,
				Admin: s.Admin, Started: s.Started, Viewers: len(s.subs)})
			s.mu.Unlock()
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.After(out[j].Started) })
	return out
}

// Input sends keystrokes to the shell.
func (s *Shell) Input(data []byte) {
	s.conn.send(&xdrv1.LiveDown{Msg: &xdrv1.LiveDown_ShellInput{ShellInput: &xdrv1.ShellData{SessionId: s.ID, Data: data}}})
}

// Resize sets the terminal size.
func (s *Shell) Resize(cols, rows uint32) {
	s.conn.send(&xdrv1.LiveDown{Msg: &xdrv1.LiveDown_ShellResize{ShellResize: &xdrv1.ShellResize{SessionId: s.ID, Cols: cols, Rows: rows}}})
}

// Close hangs up the shell; the agent reports its exit.
func (h *Hub) Close(s *Shell) {
	if !s.conn.send(&xdrv1.LiveDown{Msg: &xdrv1.LiveDown_ShellClose{ShellClose: &xdrv1.ShellClose{SessionId: s.ID}}}) {
		h.end(s, "the agent disconnected")
	}
}

// Subscribe returns recent output and a channel of new output, closed when
// the shell ends. A viewer too slow to keep up misses output.
func (s *Shell) Subscribe() (replay []byte, ch chan []byte, cancel func()) {
	ch = make(chan []byte, 1024)
	s.mu.Lock()
	defer s.mu.Unlock()
	replay = append([]byte(nil), s.tail...)
	select {
	case <-s.done:
		close(ch)
		return replay, ch, func() {}
	default:
	}
	s.subs[ch] = true
	return replay, ch, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.subs[ch] {
			delete(s.subs, ch)
			close(ch)
		}
	}
}

// Done is closed when the shell has ended; Reason then says why.
func (s *Shell) Done() <-chan struct{} { return s.done }

func (s *Shell) Reason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reason
}

func (s *Shell) output(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	room := maxRecording - len(s.rec)
	if len(data) > room {
		s.truncated = true
	}
	if room > 0 {
		s.rec = append(s.rec, data[:min(room, len(data))]...)
	}
	s.tail = append(s.tail, data...)
	if over := len(s.tail) - replayBytes; over > 0 {
		s.tail = append([]byte(nil), s.tail[over:]...)
	}
	for ch := range s.subs {
		select {
		case ch <- data:
		default:
		}
	}
}

// end closes the shell once and stores its recording.
func (h *Hub) end(s *Shell, reason string) {
	h.mu.Lock()
	if h.shells[s.ID] != s {
		h.mu.Unlock()
		return
	}
	delete(h.shells, s.ID)
	h.mu.Unlock()

	s.mu.Lock()
	s.reason = reason
	close(s.done)
	for ch := range s.subs {
		close(ch)
	}
	s.subs = map[chan []byte]bool{}
	rec, truncated := s.rec, s.truncated
	s.mu.Unlock()

	dur := time.Since(s.Started)
	h.Log.Info("remote shell ended", "session", s.ID, "hostname", s.Hostname, "user", s.User, "admin", s.Admin,
		"reason", reason, "duration", dur.Round(time.Second))
	if h.DB == nil {
		return
	}
	if rec == nil {
		rec = []byte{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := h.DB.SaveSession(ctx, &store.Session{
		AgentID: s.AgentID, Hostname: s.Hostname, SessionID: "console-" + s.ID, Username: s.Admin, RunasUser: s.User,
		TTY: "console", Command: "Remote shell from the XDR console", StartedAt: s.Started,
		DurationMs: dur.Milliseconds(), Output: rec, Truncated: truncated,
	})
	if err != nil {
		h.Log.Error("save remote shell recording", "session", s.ID, "err", err)
	}
}

func newID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
