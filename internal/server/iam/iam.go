// Package iam is the console's identity and authorization model: built-in
// roles, permissions, the permission each API route needs, password hashing
// and TOTP for MFA. It holds no state; store persists users and roles.
package iam

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"unicode/utf8"
)

// Permissions. A role holds a list of them; "*" holds all.
const (
	All          = "*"
	View         = "view"             // read dashboards, endpoints, alerts, events and policies
	AlertsManage = "alerts.manage"    // triage alerts
	ResponseRun  = "response.run"     // kill, quarantine, isolate, scan
	Detection    = "detection.manage" // rules, IOCs and feeds
	Endpoints    = "endpoints.manage" // install, uninstall, revoke, update, tokens
	Policies     = "policies.manage"  // endpoint security policies and recording settings
	Secrets      = "secrets.view"     // maintenance tokens
	AccessReq    = "access.request"   // request and use shell or JIT sudo access
	AccessOK     = "access.approve"   // approve, deny and revoke access; grant JIT sudo
	SessionsView = "sessions.view"    // recordings, live shell watching, session timelines
	AuditView    = "audit.view"       // the audit log
	IAMManage    = "iam.manage"       // users, roles, asset groups and access policies
)

// Permission describes one permission for the console.
type Permission struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

var Permissions = []Permission{
	{View, "View dashboards, endpoints, alerts and events"},
	{AlertsManage, "Triage alerts"},
	{ResponseRun, "Run response actions"},
	{Detection, "Manage detection rules and threat intel"},
	{Endpoints, "Install, update and remove agents"},
	{Policies, "Manage endpoint security policies"},
	{Secrets, "Reveal agent maintenance tokens"},
	{AccessReq, "Request and use privileged access"},
	{AccessOK, "Approve and revoke privileged access"},
	{SessionsView, "View session recordings and watch live sessions"},
	{AuditView, "View the audit log"},
	{IAMManage, "Manage users, roles, asset groups and access policies"},
}

// ValidPermission reports whether p is a known permission.
func ValidPermission(p string) bool {
	return p == All || slices.ContainsFunc(Permissions, func(x Permission) bool { return x.ID == p })
}

// Role is a named set of permissions.
type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	Builtin     bool     `json:"builtin"`
}

// HostRole is the pseudo-role access policies use for users asking for JIT
// sudo on the host itself (xdr-agent elevate) rather than from the console.
const HostRole = "host"

// BuiltinRoles are kept in the database and refreshed on every start.
var BuiltinRoles = []Role{
	{ID: "admin", Name: "Administrator", Description: "Everything, including users, roles and access policies.",
		Permissions: []string{All}, Builtin: true},
	{ID: "analyst", Name: "SOC analyst", Description: "Investigates and responds; requests server access when needed.",
		Permissions: []string{View, AlertsManage, ResponseRun, Detection, AccessReq, SessionsView}, Builtin: true},
	{ID: "operator", Name: "Server operator", Description: "IT admin who requests shell or sudo access to servers.",
		Permissions: []string{View, AccessReq}, Builtin: true},
	{ID: "auditor", Name: "Auditor", Description: "Read-only, plus recordings and the audit log.",
		Permissions: []string{View, SessionsView, AuditView}, Builtin: true},
}

// Has reports whether perms grants p. An empty p needs only a login.
func Has(perms []string, p string) bool {
	return p == "" || slices.Contains(perms, All) || slices.Contains(perms, p)
}

// routePerms maps a route pattern to the permission it needs. Unlisted GET
// routes need View; any other unlisted route needs All, so a route added
// without thinking about permissions is admin-only.
var routePerms = map[string]string{
	"GET /api/v1/me":                            "",
	"POST /api/v1/me/password":                  "",
	"POST /api/v1/me/mfa/setup":                 "",
	"POST /api/v1/me/mfa/enable":                "",
	"POST /api/v1/me/mfa/disable":               "",
	"GET /api/v1/agents/{id}/maintenance-token": Secrets,

	"PATCH /api/v1/alerts/{id}":           AlertsManage,
	"POST /api/v1/agents/{id}/commands":   ResponseRun,
	"POST /api/v1/rules":                  Detection,
	"PUT /api/v1/rules/{id}":              Detection,
	"POST /api/v1/rules/{id}/enabled":     Detection,
	"DELETE /api/v1/rules/{id}":           Detection,
	"POST /api/v1/iocs":                   Detection,
	"DELETE /api/v1/iocs/{id}":            Detection,
	"POST /api/v1/ioc-feeds":              Detection,
	"POST /api/v1/ioc-feeds/{id}/refresh": Detection,
	"POST /api/v1/ioc-feeds/{id}/enabled": Detection,
	"DELETE /api/v1/ioc-feeds/{id}":       Detection,

	"POST /api/v1/agents/{id}/revoke":            Endpoints,
	"DELETE /api/v1/agents/{id}":                 Endpoints,
	"POST /api/v1/agents/{id}/uninstall":         Endpoints,
	"POST /api/v1/deploy-jobs":                   Endpoints,
	"POST /api/v1/enrollment-tokens":             Endpoints,
	"DELETE /api/v1/enrollment-tokens/{id}":      Endpoints,
	"POST /api/v1/agents/{id}/update":            Endpoints,
	"POST /api/v1/agents/update-all":             Endpoints,
	"POST /api/v1/agents/{id}/tamper-protection": Endpoints,
	"DELETE /api/v1/known-hosts/{host}/{port}":   Endpoints,
	"POST /api/v1/policies":                      Policies,
	"PUT /api/v1/policies/{id}":                  Policies,
	"DELETE /api/v1/policies/{id}":               Policies,
	"PUT /api/v1/policies/{id}/endpoints":        Policies,
	"PUT /api/v1/agents/{id}/policy":             Policies,
	"POST /api/v1/agents/{id}/pam/recording":     Policies,

	"GET /api/v1/pam/access/preview":         AccessReq,
	"POST /api/v1/pam/access":                AccessReq,
	"GET /api/v1/agents/{id}/shell":          AccessReq,
	"POST /api/v1/live/shells/{sid}/close":   AccessReq,
	"POST /api/v1/pam/requests/{id}/cancel":  AccessReq,
	"POST /api/v1/pam/requests/{id}/approve": AccessOK,
	"POST /api/v1/pam/requests/{id}/deny":    AccessOK,
	"POST /api/v1/pam/requests/{id}/revoke":  AccessOK,
	"POST /api/v1/agents/{id}/pam/grant":     AccessReq,
	"GET /api/v1/pam/sessions/{id}":          SessionsView,
	"GET /api/v1/pam/access-sessions/{id}":   SessionsView,
	"GET /api/v1/live/shells/{sid}/watch":    SessionsView,
	"GET /api/v1/audit":                      AuditView,
	"GET /api/v1/audit/verify":               AuditView,

	"GET /api/v1/users":                   IAMManage,
	"POST /api/v1/users":                  IAMManage,
	"PUT /api/v1/users/{id}":              IAMManage,
	"DELETE /api/v1/users/{id}":           IAMManage,
	"POST /api/v1/users/{id}/mfa/reset":   IAMManage,
	"POST /api/v1/roles":                  IAMManage,
	"PUT /api/v1/roles/{id}":              IAMManage,
	"DELETE /api/v1/roles/{id}":           IAMManage,
	"POST /api/v1/asset-groups":           IAMManage,
	"PUT /api/v1/asset-groups/{id}":       IAMManage,
	"DELETE /api/v1/asset-groups/{id}":    IAMManage,
	"POST /api/v1/access-policies":        IAMManage,
	"PUT /api/v1/access-policies/{id}":    IAMManage,
	"DELETE /api/v1/access-policies/{id}": IAMManage,
}

// RoutePermission returns the permission a request to pattern needs.
func RoutePermission(pattern string) string {
	if p, ok := routePerms[pattern]; ok {
		return p
	}
	if len(pattern) > 4 && pattern[:4] == http.MethodGet+" " {
		return View
	}
	return All
}

// Audited reports whether a request to pattern goes to the audit log: every
// change, and reads of secrets, recordings and live sessions.
func Audited(pattern string) bool {
	if len(pattern) < 4 || pattern[:4] != http.MethodGet+" " {
		return true
	}
	switch RoutePermission(pattern) {
	case Secrets, SessionsView:
		return true
	}
	return pattern == "GET /api/v1/agents/{id}/shell"
}

// --- passwords ---

const (
	passwordIterations = 210_000
	MinPassword        = 12
	maxPassword        = 256
)

// CheckPasswordPolicy enforces the console's password rules.
func CheckPasswordPolicy(pw string) error {
	if n := utf8.RuneCountInString(pw); n < MinPassword || n > maxPassword {
		return fmt.Errorf("passwords must be %d to %d characters", MinPassword, maxPassword)
	}
	return nil
}

// HashPassword returns a fresh salt and the PBKDF2-SHA256 hash, both hex.
func HashPassword(pw string) (salt, hash string, err error) {
	s := make([]byte, 16)
	_, _ = rand.Read(s)
	key, err := pbkdf2.Key(sha256.New, pw, s, passwordIterations, 32)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(s), hex.EncodeToString(key), nil
}

// PasswordMatches checks pw against a salt and hash from HashPassword.
func PasswordMatches(pw, saltHex, hashHex string) bool {
	salt, err := hex.DecodeString(saltHex)
	if pw == "" || err != nil || hashHex == "" {
		return false
	}
	key, err := pbkdf2.Key(sha256.New, pw, salt, passwordIterations, 32)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(key)), []byte(hashHex)) == 1
}
