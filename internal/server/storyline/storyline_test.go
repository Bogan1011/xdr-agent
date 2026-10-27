package storyline

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

type fake []store.Event

func (f fake) pick(keep func(store.Event) bool) []store.Event {
	var out []store.Event
	for _, e := range f {
		if keep(e) {
			out = append(out, e)
		}
	}
	return out
}

func (f fake) Processes(_ context.Context, _ string, guids []string) ([]store.Event, error) {
	return f.pick(func(e store.Event) bool { return e.Type == "process_exec" && slices.Contains(guids, e.ProcessGUID) }), nil
}

func (f fake) Children(_ context.Context, _ string, parents []string, _ int) ([]store.Event, error) {
	return f.pick(func(e store.Event) bool { return e.Type == "process_exec" && slices.Contains(parents, e.ParentGUID) }), nil
}

func (f fake) Activity(_ context.Context, _ string, guids []string, _ int) ([]store.Event, error) {
	return f.pick(func(e store.Event) bool { return e.Type != "process_exec" && slices.Contains(guids, e.ProcessGUID) }), nil
}

var t0 = time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)

func ev(sec int, typ, guid, parent, exe string) store.Event {
	return store.Event{Time: t0.Add(time.Duration(sec) * time.Second), Type: typ, ProcessGUID: guid, ParentGUID: parent, Exe: exe}
}

func TestBuild(t *testing.T) {
	src := fake{
		ev(0, "process_exec", "systemd", "", "/usr/lib/systemd/systemd"),
		ev(1, "process_exec", "sshd", "systemd", "/usr/sbin/sshd"),
		ev(2, "process_exec", "bash", "sshd", "/usr/bin/bash"),
		ev(3, "process_exec", "curl", "bash", "/usr/bin/curl"),
		ev(4, "net_connect", "curl", "bash", "/usr/bin/curl"),
		ev(5, "process_exit", "curl", "bash", "/usr/bin/curl"),
		ev(6, "process_exec", "sh", "bash", "/bin/sh"),
		ev(7, "process_exec", "sh", "bash", "/usr/bin/python3"), // execve
		ev(8, "file_create", "sh", "bash", "/usr/bin/python3"),
		// Another login under the same sshd is not part of this storyline.
		ev(9, "process_exec", "bash2", "sshd", "/usr/bin/bash"),
	}
	st, err := Build(context.Background(), src, "a1", "sh")
	if err != nil {
		t.Fatal(err)
	}
	if st.Root != "bash" || st.Session == nil || st.Session.GUID != "sshd" {
		t.Fatalf("root %s session %+v", st.Root, st.Session)
	}
	var got []string
	for _, n := range st.Nodes {
		got = append(got, strings.Repeat(" ", n.Depth)+n.GUID)
	}
	if strings.Join(got, ",") != "bash, curl, sh" {
		t.Fatalf("tree %q", got)
	}
	sh := st.Nodes[2]
	if sh.Exe != "/usr/bin/python3" || len(sh.Images) != 1 || sh.Images[0] != "/bin/sh" || sh.Counts["file_create"] != 1 {
		t.Fatalf("sh node %+v", sh)
	}
	curl := st.Nodes[1]
	if !curl.Exited || curl.Counts["net_connect"] != 1 {
		t.Fatalf("curl node %+v", curl)
	}
	if len(st.Events) != 2 {
		t.Fatalf("events %d", len(st.Events))
	}
}

func TestBuildUnknownProcess(t *testing.T) {
	src := fake{ev(1, "net_connect", "old", "p", "/usr/sbin/nginx")}
	st, err := Build(context.Background(), src, "a1", "old")
	if err != nil {
		t.Fatal(err)
	}
	if st.Root != "old" || len(st.Nodes) != 1 || st.Nodes[0].Exe != "/usr/sbin/nginx" || st.Nodes[0].Known {
		t.Fatalf("storyline %+v", st)
	}
}
