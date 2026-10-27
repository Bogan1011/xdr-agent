// Package pam is the privileged access module: the access-policy engine that
// decides whether a person may open a shell or get JIT sudo on a server, and
// under which conditions, and the risk score of a privileged session. It is
// pure logic; the API and store wire it to users, assets and sessions.
package pam

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// Access types.
const (
	Shell   = "shell"    // browser terminal through the agent
	JITSudo = "jit_sudo" // time-boxed sudo for a local account
)

// Incident modes say what an open high or critical alert on the server does.
const (
	IncidentNone     = "none"
	IncidentApproval = "require_approval"
	IncidentDeny     = "deny"
)

// MaxDuration bounds every grant, whatever a policy says.
const MaxDuration = 8 * time.Hour

// Policy is one access policy. Subjects are roles or usernames; the pseudo
// role "host" stands for users asking on the server itself.
type Policy struct {
	ID              int64    `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Enabled         bool     `json:"enabled"`
	Priority        int      `json:"priority"`
	Effect          string   `json:"effect"` // allow or deny
	SubjectRoles    []string `json:"subject_roles"`
	SubjectUsers    []string `json:"subject_users"`
	AssetGroups     []int64  `json:"asset_groups"`
	AccessTypes     []string `json:"access_types"`
	Accounts        []string `json:"accounts"` // empty or "*" means any
	RequireApproval bool     `json:"require_approval"`
	Approvals       int      `json:"approvals"`
	RequireMFA      bool     `json:"require_mfa"`
	RequireTicket   bool     `json:"require_ticket"`
	MaxMinutes      int      `json:"max_minutes"`
	// HoursFrom and HoursTo bound the UTC hours access may start; 0 and 24
	// mean any time, and From > To wraps past midnight.
	HoursFrom    int    `json:"hours_from"`
	HoursTo      int    `json:"hours_to"`
	IncidentMode string `json:"incident_mode"`
}

// Validate normalises p and reports what is wrong with it.
func (p *Policy) Validate() error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 100 {
		return fmt.Errorf("a name of up to 100 characters is required")
	}
	if p.Effect == "" {
		p.Effect = "allow"
	}
	if p.Effect != "allow" && p.Effect != "deny" {
		return fmt.Errorf("effect must be allow or deny")
	}
	if len(p.SubjectRoles)+len(p.SubjectUsers) == 0 {
		return fmt.Errorf("pick at least one role or user")
	}
	if len(p.AssetGroups) == 0 {
		return fmt.Errorf("pick at least one asset group")
	}
	if len(p.AccessTypes) == 0 {
		return fmt.Errorf("pick at least one access type")
	}
	for _, t := range p.AccessTypes {
		if t != Shell && t != JITSudo {
			return fmt.Errorf("unknown access type %q", t)
		}
	}
	if p.Approvals < 1 {
		p.Approvals = 1
	}
	if p.Approvals > 3 {
		return fmt.Errorf("at most 3 approvals")
	}
	if p.MaxMinutes <= 0 || p.MaxMinutes > int(MaxDuration.Minutes()) {
		p.MaxMinutes = int(MaxDuration.Minutes())
	}
	if p.HoursFrom < 0 || p.HoursFrom > 24 || p.HoursTo < 0 || p.HoursTo > 24 {
		return fmt.Errorf("hours must be 0 to 24")
	}
	if p.HoursFrom == p.HoursTo {
		p.HoursFrom, p.HoursTo = 0, 24
	}
	switch p.IncidentMode {
	case "":
		p.IncidentMode = IncidentNone
	case IncidentNone, IncidentApproval, IncidentDeny:
	default:
		return fmt.Errorf("unknown incident mode %q", p.IncidentMode)
	}
	return nil
}

// Request is what is being asked: who, where, what.
type Request struct {
	Username string
	Role     string // console role id, or "host"
	Kind     string
	Account  string
	// AssetGroups are the ids of the groups the server is in.
	AssetGroups []int64
	// Incident is the highest severity of the server's open alerts, or "".
	Incident string
	Now      time.Time
}

// Decision is the engine's answer and the conditions attached to it.
type Decision struct {
	Allowed         bool     `json:"allowed"`
	PolicyID        int64    `json:"policy_id"`
	PolicyName      string   `json:"policy_name"`
	RequireApproval bool     `json:"require_approval"`
	Approvals       int      `json:"approvals"`
	RequireMFA      bool     `json:"require_mfa"`
	RequireTicket   bool     `json:"require_ticket"`
	RequireReason   bool     `json:"require_reason"`
	MaxMinutes      int      `json:"max_minutes"`
	Reasons         []string `json:"reasons"`
}

func (p *Policy) inHours(now time.Time) bool {
	from, to, h := p.HoursFrom, p.HoursTo, now.UTC().Hour()
	switch {
	case from == 0 && to == 24:
		return true
	case from < to:
		return h >= from && h < to
	default:
		return h >= from || h < to
	}
}

func (p *Policy) subject(r Request) bool {
	if slices.Contains(p.SubjectRoles, r.Role) {
		return true
	}
	// Console users never match the host pseudo-role and the reverse.
	return r.Role != "host" && slices.Contains(p.SubjectUsers, r.Username)
}

func (p *Policy) account(a string) bool {
	return len(p.Accounts) == 0 || slices.Contains(p.Accounts, "*") || slices.Contains(p.Accounts, a)
}

func (p *Policy) asset(groups []int64) bool {
	return slices.ContainsFunc(p.AssetGroups, func(g int64) bool { return slices.Contains(groups, g) })
}

// Decide evaluates policies in priority order (lowest number first) and
// applies the first that matches. Nothing matching means no access.
func Decide(policies []Policy, r Request) Decision {
	ps := slices.Clone(policies)
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].Priority < ps[j].Priority })
	var notes []string
	for _, p := range ps {
		if !p.Enabled || !slices.Contains(p.AccessTypes, r.Kind) || !p.subject(r) || !p.asset(r.AssetGroups) || !p.account(r.Account) {
			continue
		}
		if !p.inHours(r.Now) {
			notes = append(notes, fmt.Sprintf("%q only allows access between %02d:00 and %02d:00 UTC", p.Name, p.HoursFrom, p.HoursTo%24))
			continue
		}
		d := Decision{PolicyID: p.ID, PolicyName: p.Name}
		if p.Effect == "deny" {
			d.Reasons = append(notes, fmt.Sprintf("denied by policy %q", p.Name))
			return d
		}
		d.Allowed = true
		d.RequireApproval, d.Approvals = p.RequireApproval, p.Approvals
		d.RequireMFA, d.RequireTicket, d.MaxMinutes = p.RequireMFA, p.RequireTicket, p.MaxMinutes
		if d.MaxMinutes <= 0 || d.MaxMinutes > int(MaxDuration.Minutes()) {
			d.MaxMinutes = int(MaxDuration.Minutes())
		}
		if d.Approvals < 1 {
			d.Approvals = 1
		}
		if r.Incident == "high" || r.Incident == "critical" {
			switch p.IncidentMode {
			case IncidentDeny:
				d.Allowed = false
				d.Reasons = append(d.Reasons, fmt.Sprintf("the server has an open %s alert and %q blocks access during incidents", r.Incident, p.Name))
				return d
			case IncidentApproval:
				if !d.RequireApproval {
					d.RequireApproval = true
					d.Reasons = append(d.Reasons, fmt.Sprintf("approval needed: the server has an open %s alert", r.Incident))
				}
			}
		}
		if !d.RequireApproval {
			d.Approvals = 0
		}
		d.RequireReason = d.RequireApproval || r.Kind == JITSudo
		d.Reasons = append(d.Reasons, fmt.Sprintf("allowed by policy %q", p.Name))
		return d
	}
	return Decision{Reasons: append(notes, "no access policy allows this for you on this server")}
}

// Duration applies the decision's limit to the minutes asked for; zero asks
// for the default of an hour.
func (d Decision) Duration(minutes int) time.Duration {
	if minutes <= 0 {
		minutes = 60
	}
	if minutes < 5 {
		minutes = 5
	}
	if d.MaxMinutes > 0 && minutes > d.MaxMinutes {
		minutes = d.MaxMinutes
	}
	return time.Duration(minutes) * time.Minute
}

// DefaultPolicies are created on first start. They keep the console's
// behaviour from before policies existed for administrators, and make
// everyone else ask.
func DefaultPolicies(allServers int64) []Policy {
	all := []int64{allServers}
	return []Policy{
		{Name: "Administrators", Description: "Admins open shells and grant sudo on every server; every session is recorded.",
			Enabled: true, Priority: 10, Effect: "allow", SubjectRoles: []string{"admin"}, AssetGroups: all,
			AccessTypes: []string{Shell, JITSudo}, MaxMinutes: 480, HoursTo: 24, IncidentMode: IncidentNone},
		{Name: "Analysts and operators need approval", Description: "Shell or sudo for up to 2 hours after one approval; blocked while the server has an open high or critical alert.",
			Enabled: true, Priority: 20, Effect: "allow", SubjectRoles: []string{"analyst", "operator"}, AssetGroups: all,
			AccessTypes: []string{Shell, JITSudo}, RequireApproval: true, Approvals: 1, MaxMinutes: 120, HoursTo: 24, IncidentMode: IncidentDeny},
		{Name: "Sudo asked for on the host", Description: "xdr-agent elevate on a server needs one approval, up to 8 hours.",
			Enabled: true, Priority: 30, Effect: "allow", SubjectRoles: []string{"host"}, AssetGroups: all,
			AccessTypes: []string{JITSudo}, RequireApproval: true, Approvals: 1, MaxMinutes: 480, HoursTo: 24, IncidentMode: IncidentNone},
	}
}
