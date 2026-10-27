package pipeline

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

func TestJoinArgs(t *testing.T) {
	got := JoinArgs([]string{"sh", "-c", "echo hi", ""})
	want := `sh -c "echo hi" ""`
	if got != want {
		t.Errorf("JoinArgs = %s, want %s", got, want)
	}
}

func TestEventTypeName(t *testing.T) {
	if got := EventTypeName(xdrv1.EventType_EVENT_TYPE_NET_CONNECT); got != "net_connect" {
		t.Errorf("EventTypeName = %s", got)
	}
}

func TestNormalizeIdentityFromSource(t *testing.T) {
	e := &xdrv1.Event{Id: "e1", AgentId: "spoofed", TenantId: "evil", TimestampUnixNano: time.Now().UnixNano(),
		Type:           xdrv1.EventType_EVENT_TYPE_NET_CONNECT,
		Payload:        &xdrv1.Event_Network{Network: &xdrv1.NetworkEvent{RemoteAddr: "10.0.0.1", RemotePort: 443}},
		ProcessContext: &xdrv1.ProcessContext{ProcessGuid: "g1", Executable: "/usr/bin/curl", User: "bob"}}
	r := Normalize(Source{TenantID: "default", AgentID: "a1", Hostname: "web1"}, e)
	if r.AgentID != "a1" || r.TenantID != "default" || r.Hostname != "web1" {
		t.Fatalf("identity %+v", r)
	}
	if r.Exe != "/usr/bin/curl" || r.User != "bob" || r.ProcessGUID != "g1" {
		t.Fatalf("process context not applied: %+v", r)
	}
}

func exec(guid, parent, exe string) store.Event {
	return store.Event{AgentID: "a1", Type: "process_exec", ProcessGUID: guid, ParentGUID: parent, Exe: exe, Args: exe, User: "bob"}
}

func TestEnricherStoryline(t *testing.T) {
	var en Enricher
	evs := []store.Event{
		exec("sshd", "", "/usr/sbin/sshd"),
		exec("bash", "sshd", "/usr/bin/bash"),
		exec("curl", "bash", "/usr/bin/curl"),
		exec("sh", "curl", "/bin/sh"),
		// A second login is its own storyline.
		exec("bash2", "sshd", "/usr/bin/bash"),
	}
	for i := range evs {
		en.Enrich(&evs[i])
	}
	for i, want := range []string{"sshd", "bash", "bash", "bash", "bash2"} {
		if evs[i].StorylineGUID != want {
			t.Errorf("%s storyline = %s, want %s", evs[i].ProcessGUID, evs[i].StorylineGUID, want)
		}
	}
	if evs[3].ParentExe != "/usr/bin/curl" {
		t.Errorf("parent exe not filled: %q", evs[3].ParentExe)
	}

	// A network event from the shell gets its actor and storyline.
	net := store.Event{AgentID: "a1", Type: "net_connect", ProcessGUID: "sh"}
	en.Enrich(&net)
	if net.Exe != "/bin/sh" || net.User != "bob" || net.ParentGUID != "curl" || net.StorylineGUID != "bash" {
		t.Errorf("network event %+v", net)
	}

	// execve keeps the GUID and the storyline.
	re := exec("sh", "", "/usr/bin/python3")
	en.Enrich(&re)
	if re.StorylineGUID != "bash" || re.ParentGUID != "curl" {
		t.Errorf("after execve %+v", re)
	}

	// An unknown parent that is not a session root is the oldest ancestor known.
	orphan := exec("x", "unknown", "/usr/bin/x")
	en.Enrich(&orphan)
	if orphan.StorylineGUID != "unknown" {
		t.Errorf("orphan storyline = %s", orphan.StorylineGUID)
	}
	cron := exec("job", "crond-guid", "/bin/sh")
	cron.ParentExe = "/usr/sbin/cron"
	en.Enrich(&cron)
	if cron.StorylineGUID != "job" {
		t.Errorf("cron job storyline = %s", cron.StorylineGUID)
	}
}

func TestEnricherEviction(t *testing.T) {
	en := Enricher{Size: 2}
	for _, g := range []string{"a", "b", "c", "d", "e"} {
		ev := exec(g, "", "/bin/true")
		en.Enrich(&ev)
	}
	if len(en.cur)+len(en.old) > 4 {
		t.Fatalf("cache grew to %d", len(en.cur)+len(en.old))
	}
}

type memStore struct{ n int }

func (m *memStore) Insert(_ context.Context, ev []store.Event) error { m.n += len(ev); return nil }

type memDetector struct {
	mu  sync.Mutex
	got []store.Event
}

func (d *memDetector) Process(_ context.Context, ev []store.Event) {
	d.mu.Lock()
	d.got = append(d.got, ev...)
	d.mu.Unlock()
}

func (d *memDetector) len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.got)
}

func TestRemoteDetector(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	det := &memDetector{}
	reloaded := false
	srv := httptest.NewServer(Handler(det, func(context.Context) error { reloaded = true; return nil }, "secret-token", log))
	defer srv.Close()

	// Without the token nothing is accepted.
	resp, err := http.Post(srv.URL+"/v1/events", "application/json", nil)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated post: %v %v", resp, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := NewRemote(srv.URL, "secret-token", log)
	go r.Run(ctx)
	p := &Pipeline{Store: &memStore{}, Enricher: &Enricher{}, Detector: r}
	rows, err := p.Ingest(ctx, Source{AgentID: "a1"}, []*xdrv1.Event{
		{Id: "1", Type: xdrv1.EventType_EVENT_TYPE_PROCESS_EXEC, TimestampUnixNano: time.Now().UnixNano(),
			Payload: &xdrv1.Event_Process{Process: &xdrv1.ProcessEvent{Exe: "/bin/sh"}}},
	})
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for det.len() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if det.len() != 1 || det.got[0].Exe != "/bin/sh" {
		t.Fatalf("detector got %+v", det.got)
	}
	r.Reload(ctx)
	if !reloaded {
		t.Fatal("reload not delivered")
	}
}

func TestNormalizeTelemetrySpecPayloads(t *testing.T) {
	src := Source{TenantID: "t", AgentID: "a", Hostname: "h"}
	dns := Normalize(src, &xdrv1.Event{
		Type:      xdrv1.EventType_EVENT_TYPE_DNS_QUERY,
		Collector: "dns",
		Payload: &xdrv1.Event_Dns{Dns: &xdrv1.DnsEvent{
			Query: "Example.COM.", QueryType: "A", ResponseCode: "NOERROR", Server: "1.1.1.1", ServerPort: 53,
			Answers: []*xdrv1.DnsAnswer{{Type: "A", Data: "93.184.216.34", Ttl: 60}}, Exe: "/usr/bin/curl", Pid: 7,
		}},
		Container: &xdrv1.ContainerContext{ContainerId: "0123456789abcdef0123", Name: "web"},
	})
	if dns.DNSQuery != "example.com" || dns.Outcome != "success" || len(dns.DNSAnswers) != 1 || dns.Collector != "dns" {
		t.Fatalf("dns row: %+v", dns)
	}
	if want := "pid 7 (curl) looked up example.com (A) → 93.184.216.34 in container web"; dns.Summary != want {
		t.Fatalf("summary %q, want %q", dns.Summary, want)
	}
	sudo := Normalize(src, &xdrv1.Event{
		Type: xdrv1.EventType_EVENT_TYPE_SUDO,
		Payload: &xdrv1.Event_Auth{Auth: &xdrv1.AuthEvent{
			Action: "sudo", User: "rutav", TargetUser: "root", Command: "/usr/bin/cat /etc/shadow", Success: true, Service: "sudo",
		}},
	})
	if sudo.Summary != "rutav ran sudo as root: /usr/bin/cat /etc/shadow" || sudo.Outcome != "success" || sudo.LoginUID != 4294967295 {
		t.Fatalf("sudo row: %+v", sudo)
	}
	p := Normalize(src, &xdrv1.Event{
		Type: xdrv1.EventType_EVENT_TYPE_PERSISTENCE,
		Payload: &xdrv1.Event_Persistence{Persistence: &xdrv1.PersistenceEvent{
			PersistenceType: "cron", Operation: "modified", Path: "/etc/crontab", NewValue: "+ * * * * * root /tmp/x",
		}},
	})
	if p.Category != "cron" || !strings.Contains(p.Summary, "modified cron persistence at /etc/crontab: + * * * * * root /tmp/x") {
		t.Fatalf("persistence row: %+v", p)
	}
}
