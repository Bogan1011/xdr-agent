// Package storyline builds the process tree around one process, keyed by
// process_guid: its ancestors up to the session that started it, everything
// that session started, and what each process did.
package storyline

import (
	"context"
	"sort"
	"time"

	"github.com/Bogan1011/xdr-agent/internal/server/pipeline"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

const (
	maxAncestors = 16
	maxDepth     = 12
	maxNodes     = 300
	maxEvents    = 1000
)

// Source reads process telemetry; *store.ClickHouse implements it.
type Source interface {
	Processes(ctx context.Context, agentID string, guids []string) ([]store.Event, error)
	Children(ctx context.Context, agentID string, parents []string, limit int) ([]store.Event, error)
	Activity(ctx context.Context, agentID string, guids []string, limit int) ([]store.Event, error)
}

// Node is one process in the tree.
type Node struct {
	GUID       string    `json:"guid"`
	ParentGUID string    `json:"parent_guid"`
	Depth      int       `json:"depth"`
	PID        uint32    `json:"pid"`
	PPID       uint32    `json:"ppid"`
	Exe        string    `json:"exe"`
	Args       string    `json:"args"`
	User       string    `json:"user"`
	SHA256     string    `json:"sha256"`
	Started    time.Time `json:"started"`
	// Images are earlier executables of the same process (execve).
	Images   []string       `json:"images,omitempty"`
	Exited   bool           `json:"exited"`
	ExitCode int32          `json:"exit_code"`
	Counts   map[string]int `json:"counts"`
	// Known is false for a process seen only through its activity.
	Known bool `json:"known"`

	last time.Time // time of the current image's exec
}

// Storyline is the tree, in display order (depth first, oldest first).
type Storyline struct {
	AgentID string `json:"agent_id"`
	Root    string `json:"root"`
	Focus   string `json:"focus"`
	// Session is the service or login that started the root, shown for
	// context without its other children.
	Session   *Node         `json:"session,omitempty"`
	Nodes     []*Node       `json:"nodes"`
	Events    []store.Event `json:"events"`
	Truncated bool          `json:"truncated"`
}

// Build returns the storyline of the process focus on agentID.
func Build(ctx context.Context, src Source, agentID, focus string) (*Storyline, error) {
	st := &Storyline{AgentID: agentID, Focus: focus, Nodes: []*Node{}, Events: []store.Event{}}
	nodes := map[string]*Node{}

	// Walk up to the topmost ancestor below a session root.
	root, cur := focus, focus
	for i := 0; i < maxAncestors && cur != ""; i++ {
		evs, err := src.Processes(ctx, agentID, []string{cur})
		if err != nil {
			return nil, err
		}
		n := merge(nodes, evs)[cur]
		if n == nil {
			break
		}
		if pipeline.IsSessionRoot(n.Exe) && cur != focus {
			delete(nodes, cur)
			st.Session = n
			break
		}
		root, cur = cur, n.ParentGUID
	}
	st.Root = root

	// Then everything the root started, level by level.
	level, expanded := []string{root}, map[string]bool{}
	for depth := 0; depth < maxDepth && len(level) > 0; depth++ {
		for _, g := range level {
			expanded[g] = true
		}
		evs, err := src.Children(ctx, agentID, level, maxNodes)
		if err != nil {
			return nil, err
		}
		level = nil
		for guid := range merge(nodes, evs) {
			if !expanded[guid] {
				level = append(level, guid)
			}
		}
		if len(nodes) >= maxNodes {
			st.Truncated = len(level) > 0
			break
		}
	}
	if nodes[focus] == nil {
		// The process started before the agent; show it from its activity.
		nodes[focus] = &Node{GUID: focus, Counts: map[string]int{}}
	}
	if nodes[root] == nil {
		nodes[root] = &Node{GUID: root, Counts: map[string]int{}}
	}

	guids := make([]string, 0, len(nodes))
	for g := range nodes {
		guids = append(guids, g)
	}
	acts, err := src.Activity(ctx, agentID, guids, maxEvents)
	if err != nil {
		return nil, err
	}
	if len(acts) == maxEvents {
		st.Truncated = true
	}
	for _, ev := range acts {
		n := nodes[ev.ProcessGUID]
		if n == nil {
			continue
		}
		n.Counts[ev.Type]++
		if ev.Type == "process_exit" {
			n.Exited, n.ExitCode = true, ev.ExitCode
			continue
		}
		if !n.Known {
			n.PID, n.PPID, n.User, n.ParentGUID = ev.PID, ev.PPID, ev.User, ev.ParentGUID
			if n.Exe == "" {
				n.Exe = ev.Exe
			}
		}
		st.Events = append(st.Events, ev)
	}
	st.Nodes = order(nodes, root)
	return st, nil
}

// merge adds process_exec events to the node set and returns the nodes
// they touched. Several execs of one GUID are one process that called execve.
func merge(nodes map[string]*Node, evs []store.Event) map[string]*Node {
	touched := map[string]*Node{}
	// Oldest first, so the last exec is the current image.
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.Before(evs[j].Time) })
	for _, ev := range evs {
		n := nodes[ev.ProcessGUID]
		if n == nil {
			n = &Node{GUID: ev.ProcessGUID, Counts: map[string]int{}, Started: ev.Time}
			nodes[ev.ProcessGUID] = n
		}
		touched[ev.ProcessGUID] = n
		if ev.Time.Before(n.Started) {
			n.Started = ev.Time
		}
		if n.Known && !ev.Time.After(n.last) {
			// Seen already, or older than the current image.
			continue
		}
		if n.Known && n.Exe != ev.Exe {
			n.Images = append(n.Images, n.Exe)
		}
		n.Exe, n.Args, n.User, n.SHA256 = ev.Exe, ev.Args, ev.User, ev.SHA256
		n.PID, n.PPID, n.last, n.Known = ev.PID, ev.PPID, ev.Time, true
		if ev.ParentGUID != "" {
			n.ParentGUID = ev.ParentGUID
		}
	}
	return touched
}

// order lays the tree out depth first from root, children oldest first.
// Nodes not reachable from root (the focus seen only by its activity) follow.
func order(nodes map[string]*Node, root string) []*Node {
	kids := map[string][]*Node{}
	for _, n := range nodes {
		if n.GUID != root {
			kids[n.ParentGUID] = append(kids[n.ParentGUID], n)
		}
	}
	for _, k := range kids {
		sort.Slice(k, func(i, j int) bool {
			if !k[i].Started.Equal(k[j].Started) {
				return k[i].Started.Before(k[j].Started)
			}
			return k[i].GUID < k[j].GUID
		})
	}
	out := make([]*Node, 0, len(nodes))
	seen := map[string]bool{}
	var walk func(n *Node, depth int)
	walk = func(n *Node, depth int) {
		if seen[n.GUID] {
			return
		}
		seen[n.GUID] = true
		n.Depth = depth
		out = append(out, n)
		for _, c := range kids[n.GUID] {
			walk(c, depth+1)
		}
	}
	walk(nodes[root], 0)
	for _, n := range nodes {
		if !seen[n.GUID] {
			walk(n, 1)
		}
	}
	return out
}
