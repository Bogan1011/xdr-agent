package pam

import (
	"testing"
	"time"
)

var noon = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func TestDefaults(t *testing.T) {
	ps := DefaultPolicies(1)
	for i := range ps {
		ps[i].ID = int64(i + 1)
		if err := ps[i].Validate(); err != nil {
			t.Fatalf("%s: %v", ps[i].Name, err)
		}
	}
	admin := Decide(ps, Request{Username: "akshay", Role: "admin", Kind: Shell, Account: "root", AssetGroups: []int64{1}, Incident: "critical", Now: noon})
	if !admin.Allowed || admin.RequireApproval || admin.MaxMinutes != 480 {
		t.Fatalf("admin shell: %+v", admin)
	}
	op := Decide(ps, Request{Username: "bob", Role: "operator", Kind: JITSudo, Account: "bob", AssetGroups: []int64{1}, Now: noon})
	if !op.Allowed || !op.RequireApproval || op.Approvals != 1 || !op.RequireReason || op.Duration(600) != 2*time.Hour {
		t.Fatalf("operator sudo: %+v", op)
	}
	op = Decide(ps, Request{Username: "bob", Role: "operator", Kind: Shell, AssetGroups: []int64{1}, Incident: "high", Now: noon})
	if op.Allowed {
		t.Fatalf("operator during incident should be blocked: %+v", op)
	}
	if d := Decide(ps, Request{Role: "auditor", Kind: Shell, AssetGroups: []int64{1}, Now: noon}); d.Allowed {
		t.Fatalf("auditor has no policy: %+v", d)
	}
	host := Decide(ps, Request{Username: "alice", Role: "host", Kind: JITSudo, AssetGroups: []int64{1}, Now: noon})
	if !host.Allowed || host.PolicyID != 3 {
		t.Fatalf("host request: %+v", host)
	}
	if d := Decide(ps, Request{Username: "alice", Role: "host", Kind: Shell, AssetGroups: []int64{1}, Now: noon}); d.Allowed {
		t.Fatal("host users cannot get shells")
	}
}

func TestConditions(t *testing.T) {
	ps := []Policy{
		{ID: 1, Name: "deny prod root", Enabled: true, Priority: 1, Effect: "deny", SubjectRoles: []string{"analyst"},
			AssetGroups: []int64{2}, AccessTypes: []string{Shell}, Accounts: []string{"root"}},
		{ID: 2, Name: "office hours", Enabled: true, Priority: 5, Effect: "allow", SubjectUsers: []string{"carol"},
			AssetGroups: []int64{2}, AccessTypes: []string{Shell}, HoursFrom: 8, HoursTo: 18, RequireMFA: true, IncidentMode: IncidentApproval},
	}
	for i := range ps {
		if err := ps[i].Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if d := Decide(ps, Request{Username: "carol", Role: "analyst", Kind: Shell, Account: "root", AssetGroups: []int64{2}, Now: noon}); d.Allowed || d.PolicyID != 1 {
		t.Fatalf("deny should win: %+v", d)
	}
	d := Decide(ps, Request{Username: "carol", Role: "analyst", Kind: Shell, Account: "carol", AssetGroups: []int64{2}, Incident: "critical", Now: noon})
	if !d.Allowed || !d.RequireMFA || !d.RequireApproval || d.Approvals != 1 {
		t.Fatalf("incident should add approval: %+v", d)
	}
	if d := Decide(ps, Request{Username: "carol", Role: "analyst", Kind: Shell, Account: "carol", AssetGroups: []int64{2}, Now: noon.Add(9 * time.Hour)}); d.Allowed {
		t.Fatalf("21:00 is outside office hours: %+v", d)
	}
	if d := Decide(ps, Request{Username: "carol", Role: "analyst", Kind: Shell, Account: "carol", AssetGroups: []int64{3}, Now: noon}); d.Allowed {
		t.Fatal("other asset groups are not covered")
	}
	wrap := Policy{HoursFrom: 22, HoursTo: 6}
	if !wrap.inHours(noon.Add(11*time.Hour)) || wrap.inHours(noon) {
		t.Fatal("hours past midnight are wrong")
	}
}

func TestRisk(t *testing.T) {
	s, why := Risk(SessionFacts{Account: "root", Incident: "critical", AlertsDuring: 3, NewSource: true, Start: noon})
	if s != 95 || len(why) != 4 {
		t.Fatalf("got %d %v", s, why)
	}
	if s, _ := Risk(SessionFacts{Account: "bob", Start: noon}); s != 0 {
		t.Fatalf("quiet session scored %d", s)
	}
}
