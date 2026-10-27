package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Bogan1011/xdr-agent/internal/server/grpcsvc"
	"github.com/Bogan1011/xdr-agent/internal/server/iam"
	"github.com/Bogan1011/xdr-agent/internal/server/live"
	"github.com/Bogan1011/xdr-agent/internal/server/pam"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

var pamUser = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// noHostPolicy is the note grpcsvc leaves on a host request no policy allows.
const noHostPolicy = "no access policy allows sudo for host users on this server"

func (a *API) pamRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/pam/requests", a.auth(a.listElevations))
	mux.HandleFunc("GET /api/v1/pam/summary", a.auth(a.pamSummary))
	mux.HandleFunc("GET /api/v1/pam/access/preview", a.auth(a.previewAccess))
	mux.HandleFunc("POST /api/v1/pam/access", a.auth(a.requestAccess))
	mux.HandleFunc("POST /api/v1/pam/requests/{id}/approve", a.auth(a.approveElevation))
	mux.HandleFunc("POST /api/v1/pam/requests/{id}/deny", a.auth(a.denyElevation))
	mux.HandleFunc("POST /api/v1/pam/requests/{id}/cancel", a.auth(a.cancelElevation))
	mux.HandleFunc("POST /api/v1/pam/requests/{id}/revoke", a.auth(a.revokeElevation))
	mux.HandleFunc("POST /api/v1/agents/{id}/pam/grant", a.auth(a.grantElevation))
	mux.HandleFunc("POST /api/v1/agents/{id}/pam/recording", a.auth(a.setPamRecording))
	mux.HandleFunc("GET /api/v1/pam/accounts", a.auth(a.listPrivilegedAccounts))
	mux.HandleFunc("GET /api/v1/pam/sessions", a.auth(a.listSessions))
	mux.HandleFunc("GET /api/v1/pam/sessions/{id}", a.auth(a.getSession))
	mux.HandleFunc("GET /api/v1/pam/access-sessions", a.auth(a.listAccessSessions))
	mux.HandleFunc("GET /api/v1/pam/access-sessions/{id}", a.auth(a.getAccessSession))
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (a *API) listElevations(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	list, err := a.db.ListElevations(r.Context(), q.Get("agent_id"), q.Get("status"), 200)
	if a.fail(w, err) {
		return
	}
	ids := make([]string, len(list))
	for i, e := range list {
		ids[i] = e.ID
	}
	approvals, err := a.db.ListApprovals(r.Context(), ids)
	if a.fail(w, err) {
		return
	}
	for _, e := range list {
		e.Approvals = approvals[e.ID]
		if e.Approvals == nil {
			e.Approvals = []store.Approval{}
		}
	}
	writeJSON(w, list)
}

func (a *API) pamSummary(w http.ResponseWriter, r *http.Request) {
	n, err := a.db.PendingElevationCount(r.Context())
	if a.fail(w, err) {
		return
	}
	writeJSON(w, map[string]int{"pending": n})
}

// --- asking for access ---

type accessReq struct {
	AgentID         string `json:"agent_id"`
	Kind            string `json:"kind"`
	Account         string `json:"account"`
	Reason          string `json:"reason"`
	Ticket          string `json:"ticket"`
	DurationMinutes int    `json:"duration_minutes"`
	MFACode         string `json:"mfa_code"`
}

func (q *accessReq) normalise() string {
	q.Account, q.Reason, q.Ticket = strings.TrimSpace(q.Account), strings.TrimSpace(q.Reason), strings.TrimSpace(q.Ticket)
	if q.Kind == "" {
		q.Kind = pam.Shell
	}
	if q.Kind == pam.Shell && q.Account == "" {
		q.Account = "root"
	}
	switch {
	case q.Kind != pam.Shell && q.Kind != pam.JITSudo:
		return "kind must be shell or jit_sudo"
	case !pamUser.MatchString(q.Account):
		return "enter a local account name"
	case q.Kind == pam.JITSudo && q.Account == "root":
		return "root already has sudo; pick the account to elevate"
	case len(q.Reason) > 500 || len(q.Ticket) > 100:
		return "the reason is limited to 500 characters and the ticket to 100"
	}
	return ""
}

func (a *API) decide(ctx context.Context, u *requestUser, agentID string, q *accessReq) (pam.Decision, string, error) {
	return a.db.DecideAccess(ctx, u.TenantID, agentID, pam.Request{Username: u.Username, Role: u.RoleID, Kind: q.Kind, Account: q.Account})
}

// previewAccess tells the console what a request would need, so the form
// asks only for that.
func (a *API) previewAccess(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	q := &accessReq{AgentID: v.Get("agent_id"), Kind: v.Get("kind"), Account: v.Get("account")}
	if msg := q.normalise(); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	if _, err := a.db.GetAgent(r.Context(), q.AgentID); a.fail(w, err) {
		return
	}
	d, incident, err := a.decide(r.Context(), user(r), q.AgentID, q)
	if a.fail(w, err) {
		return
	}
	writeJSON(w, map[string]any{"decision": d, "incident": incident, "mfa_enabled": user(r).MFAEnabled})
}

func (a *API) requestAccess(w http.ResponseWriter, r *http.Request) {
	var q accessReq
	if !decode(w, r, &q, 8192) {
		return
	}
	e, d, code, msg := a.createAccess(r, &q)
	if code != 0 {
		writeJSONStatus(w, code, map[string]any{"error": msg, "decision": d})
		return
	}
	writeJSON(w, map[string]any{"request": e, "decision": d})
}

// createAccess runs a request through the policy engine and records it,
// granting at once when the policy needs no approval. A non-zero code is
// the HTTP error to answer with.
func (a *API) createAccess(r *http.Request, q *accessReq) (*store.Elevation, pam.Decision, int, string) {
	ctx, u := r.Context(), user(r)
	if msg := q.normalise(); msg != "" {
		return nil, pam.Decision{}, http.StatusBadRequest, msg
	}
	ag, err := a.db.GetAgent(ctx, q.AgentID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, pam.Decision{}, http.StatusNotFound, "unknown endpoint"
	}
	if err != nil {
		a.log.Error("access request", "err", err)
		return nil, pam.Decision{}, http.StatusInternalServerError, "internal error"
	}
	if ag.Revoked {
		return nil, pam.Decision{}, http.StatusConflict, "the agent is revoked"
	}
	d, incident, err := a.decide(ctx, u, ag.ID, q)
	if err != nil {
		a.log.Error("access decision", "err", err)
		return nil, d, http.StatusInternalServerError, "internal error"
	}
	switch {
	case !d.Allowed:
		a.audit(r, u.User, "pam.access.denied", "agent:"+ag.ID, "denied", map[string]any{"kind": q.Kind, "account": q.Account, "reasons": d.Reasons})
		return nil, d, http.StatusForbidden, strings.Join(d.Reasons, "; ")
	case d.RequireReason && q.Reason == "":
		return nil, d, http.StatusBadRequest, "a reason is required"
	case d.RequireTicket && q.Ticket == "":
		return nil, d, http.StatusBadRequest, "a ticket or change reference is required"
	case d.RequireMFA && !u.MFAEnabled:
		return nil, d, http.StatusForbidden, "this access needs MFA: turn it on under your profile first"
	case d.RequireMFA && !iam.VerifyTOTP(u.MFASecret, q.MFACode, time.Now()):
		return nil, d, http.StatusBadRequest, "enter a current code from your authenticator app"
	}
	dur := d.Duration(q.DurationMinutes)
	e := &store.Elevation{
		ID: newID(), AgentID: ag.ID, Hostname: ag.Hostname, Username: q.Account, Reason: q.Reason,
		DurationSeconds: int64(dur.Seconds()), RequestedBy: u.Username, RequesterID: u.ID, Kind: q.Kind, Ticket: q.Ticket,
		PolicyID: d.PolicyID, PolicyName: d.PolicyName, ApprovalsRequired: max(d.Approvals, 1), Incident: incident,
	}
	if err := a.db.CreateElevation(ctx, e); err != nil {
		a.log.Error("create access request", "err", err)
		return nil, d, http.StatusInternalServerError, "internal error"
	}
	if !d.RequireApproval {
		if err := a.grant(ctx, e, dur, "policy: "+d.PolicyName, false); err != nil {
			a.log.Error("grant access", "err", err)
			return nil, d, http.StatusInternalServerError, "internal error"
		}
	}
	a.log.Warn("access requested", "request_id", e.ID, "kind", e.Kind, "hostname", e.Hostname, "account", e.Username,
		"by", u.Username, "policy", d.PolicyName, "needs_approval", d.RequireApproval)
	if fresh, err := a.db.GetElevation(ctx, e.ID); err == nil {
		e = fresh
	}
	return e, d, 0, ""
}

// grant makes an access request effective: JIT sudo is sent to the agent,
// a shell becomes usable until it expires.
func (a *API) grant(ctx context.Context, e *store.Elevation, d time.Duration, by string, emergency bool) error {
	cmdID := ""
	if e.Kind != pam.Shell {
		c := &store.Command{AgentID: e.AgentID, Type: "grant_elevation", RequestedBy: by, Args: map[string]string{
			"request_id": e.ID, "user": e.Username, "duration_seconds": strconv.FormatInt(int64(d.Seconds()), 10),
		}}
		if err := a.detect.QueueCommand(ctx, c); err != nil {
			return err
		}
		cmdID = c.ID
	}
	return a.db.ApproveElevation(ctx, e.ID, by, d, cmdID, emergency)
}

// grantElevation is the console's "give sudo to a local account" form. It
// is an access request like any other, so policy may require approval.
func (a *API) grantElevation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User            string `json:"user"`
		DurationMinutes int    `json:"duration_minutes"`
		Reason          string `json:"reason"`
		Ticket          string `json:"ticket"`
		MFACode         string `json:"mfa_code"`
	}
	if !decode(w, r, &req, 4096) {
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		writeErr(w, http.StatusBadRequest, "a reason of up to 500 characters is required")
		return
	}
	e, d, code, msg := a.createAccess(r, &accessReq{AgentID: r.PathValue("id"), Kind: pam.JITSudo, Account: req.User,
		Reason: req.Reason, Ticket: req.Ticket, DurationMinutes: req.DurationMinutes, MFACode: req.MFACode})
	if code != 0 {
		writeJSONStatus(w, code, map[string]any{"error": msg, "decision": d})
		return
	}
	writeJSON(w, map[string]string{"id": e.ID, "status": e.Status})
}

// --- deciding ---

func (a *API) approveElevation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DurationMinutes int    `json:"duration_minutes"`
		Note            string `json:"note"`
		Emergency       bool   `json:"emergency"`
	}
	if !decode(w, r, &req, 4096) {
		return
	}
	u, note := user(r), truncateStr(strings.TrimSpace(req.Note), 500)
	e, err := a.db.GetElevation(r.Context(), r.PathValue("id"))
	if a.fail(w, err) {
		return
	}
	if e.Status != "pending" {
		writeErr(w, http.StatusConflict, "request is "+e.Status)
		return
	}
	if e.PolicyName == "" && e.Note == noHostPolicy {
		writeErr(w, http.StatusForbidden, noHostPolicy+"; add one under Access policies or deny it")
		return
	}
	own := e.RequesterID != "" && e.RequesterID == u.ID
	switch {
	case own && !req.Emergency:
		writeErr(w, http.StatusForbidden, "you cannot approve your own request; another approver has to, or use emergency access")
		return
	case req.Emergency && (!own || !iam.Has(u.Permissions, iam.All)):
		writeErr(w, http.StatusForbidden, "emergency access is for administrators approving their own request")
		return
	case req.Emergency && note == "":
		writeErr(w, http.StatusBadRequest, "emergency access needs a note saying why")
		return
	}
	n, err := a.db.AddApproval(r.Context(), e.ID, u.ID, u.Username, "approve", note, req.Emergency)
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "you already decided this request")
		return
	}
	if a.fail(w, err) {
		return
	}
	if !req.Emergency && n < e.ApprovalsRequired {
		a.log.Info("access approval recorded", "request_id", e.ID, "by", u.Username, "approvals", n, "required", e.ApprovalsRequired)
		writeJSON(w, map[string]any{"status": "pending", "approvals": n, "required": e.ApprovalsRequired})
		return
	}
	d := time.Duration(e.DurationSeconds) * time.Second
	if req.DurationMinutes > 0 {
		d = grpcsvc.ElevationDuration(uint64(req.DurationMinutes) * 60)
		if max := a.policyMax(r.Context(), u.TenantID, e.PolicyID); max > 0 && d > max {
			d = max
		}
	}
	err = a.grant(r.Context(), e, d, u.Username, req.Emergency)
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "request was decided meanwhile")
		return
	}
	if a.fail(w, err) {
		return
	}
	if note != "" {
		_ = a.db.SetElevationStatus(r.Context(), e.ID, []string{"approved"}, "approved", "", note)
	}
	a.log.Warn("access approved", "request_id", e.ID, "kind", e.Kind, "hostname", e.Hostname, "account", e.Username,
		"duration", d, "by", u.Username, "emergency", req.Emergency)
	writeJSON(w, map[string]any{"status": "approved", "approvals": n, "required": e.ApprovalsRequired})
}

func (a *API) policyMax(ctx context.Context, tenant string, id int64) time.Duration {
	ps, err := a.db.ListAccessPolicies(ctx, tenant)
	if err != nil {
		return 0
	}
	if i := slices.IndexFunc(ps, func(p pam.Policy) bool { return p.ID == id }); i >= 0 {
		return time.Duration(ps[i].MaxMinutes) * time.Minute
	}
	return 0
}

func (a *API) denyElevation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Note string `json:"note"`
	}
	if !decode(w, r, &req, 4096) {
		return
	}
	u, note := user(r), truncateStr(strings.TrimSpace(req.Note), 500)
	err := a.db.SetElevationStatus(r.Context(), r.PathValue("id"), []string{"pending"}, "denied", u.Username, note)
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "request is not pending")
		return
	}
	if a.fail(w, err) {
		return
	}
	_, _ = a.db.AddApproval(r.Context(), r.PathValue("id"), u.ID, u.Username, "deny", note, false)
	a.log.Info("access denied", "request_id", r.PathValue("id"), "by", u.Username)
	w.WriteHeader(http.StatusNoContent)
}

// cancelElevation withdraws your own pending request.
func (a *API) cancelElevation(w http.ResponseWriter, r *http.Request) {
	e, err := a.db.GetElevation(r.Context(), r.PathValue("id"))
	if a.fail(w, err) {
		return
	}
	if e.RequesterID != user(r).ID {
		writeErr(w, http.StatusForbidden, "only the requester can cancel a request")
		return
	}
	err = a.db.SetElevationStatus(r.Context(), e.ID, []string{"pending"}, "cancelled", user(r).Username, "cancelled by the requester")
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "request is not pending")
		return
	}
	if a.fail(w, err) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) revokeElevation(w http.ResponseWriter, r *http.Request) {
	by := actor(r)
	e, err := a.db.GetElevation(r.Context(), r.PathValue("id"))
	if a.fail(w, err) {
		return
	}
	if e.Status != "approved" && e.Status != "active" {
		writeErr(w, http.StatusConflict, "request is "+e.Status)
		return
	}
	if e.Kind == pam.Shell {
		a.closeRequestShells(e.ID)
	} else {
		c := &store.Command{AgentID: e.AgentID, Type: "revoke_elevation", RequestedBy: by,
			Args: map[string]string{"request_id": e.ID, "user": e.Username}}
		if a.fail(w, a.detect.QueueCommand(r.Context(), c)) {
			return
		}
	}
	err = a.db.SetElevationStatus(r.Context(), e.ID, []string{"approved", "active"}, "revoked", by, "revoked by "+by)
	if err != nil && !errors.Is(err, store.ErrConflict) && a.fail(w, err) {
		return
	}
	a.log.Warn("access revoked", "request_id", e.ID, "kind", e.Kind, "hostname", e.Hostname, "account", e.Username, "by", by)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) closeRequestShells(requestID string) {
	shells := a.live.Shells("")
	for i := range shells {
		if shells[i].RequestID == requestID {
			if sh, err := a.live.Get(shells[i].ID); err == nil {
				a.live.Close(sh)
			}
		}
	}
}

// --- settings, inventory and recordings ---

func (a *API) setPamRecording(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !decode(w, r, &req, 1024) {
		return
	}
	if a.fail(w, a.db.SetPamRecordAll(r.Context(), r.PathValue("id"), req.Enabled)) {
		return
	}
	a.log.Info("sudo session recording changed", "agent_id", r.PathValue("id"), "all_sessions", req.Enabled)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listPrivilegedAccounts(w http.ResponseWriter, r *http.Request) {
	inv, err := a.db.ListInventory(r.Context())
	if a.fail(w, err) {
		return
	}
	writeJSON(w, inv)
}

func (a *API) listSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	list, err := a.db.ListSessions(r.Context(), q.Get("agent_id"), q.Get("request_id"), 200)
	if a.fail(w, err) {
		return
	}
	writeJSON(w, list)
}

func (a *API) getSession(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(w, r)
	if !ok {
		return
	}
	s, err := a.db.GetSession(r.Context(), id)
	if a.fail(w, err) {
		return
	}
	a.log.Info("session recording viewed", "session", s.ID, "hostname", s.Hostname, "user", s.Username, "by", actor(r))
	writeJSON(w, map[string]any{"session": s, "output": strings.ToValidUTF8(string(s.Output), "�")})
}

// --- privileged sessions ---

func (a *API) listAccessSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	list, err := a.db.ListAccessSessions(r.Context(), q.Get("agent_id"), q.Get("user"), queryLimit(r, 200, 500))
	if a.fail(w, err) {
		return
	}
	writeJSON(w, list)
}

// getAccessSession is the session's story: who, under which approval, the
// alerts raised and the processes, files and connections it caused.
func (a *API) getAccessSession(w http.ResponseWriter, r *http.Request) {
	s, err := a.db.GetAccessSession(r.Context(), r.PathValue("id"))
	if a.fail(w, err) {
		return
	}
	from, to := s.StartedAt.Add(-time.Minute), s.EndedAt
	if to.IsZero() || to.Unix() <= 0 {
		to = time.Now()
	}
	to = to.Add(time.Minute)
	alerts, err := a.db.AlertsBetween(r.Context(), s.AgentID, from, to)
	if a.fail(w, err) {
		return
	}
	resp := map[string]any{"session": s, "alerts": alerts, "events": []store.Event{}}
	if s.RequestID != "" {
		if e, err := a.db.GetElevation(r.Context(), s.RequestID); err == nil {
			resp["request"] = e
			if ap, err := a.db.ListApprovals(r.Context(), []string{e.ID}); err == nil {
				resp["approvals"] = ap[e.ID]
			}
		}
	}
	if s.Protocol == "browser_shell" {
		evs, err := a.events.SessionEvents(r.Context(), s.AgentID, s.ID, from, to, 1000)
		if err != nil {
			a.log.Warn("session events", "session", s.ID, "err", err)
			resp["events_error"] = "telemetry is unavailable"
		} else {
			resp["events"] = evs
		}
	}
	writeJSON(w, resp)
}

// shellEnded closes the privileged session record once its recording is
// stored, and scores it.
func (a *API) shellEnded(sh *live.Shell, recordingID int64, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := a.db.GetAccessSession(ctx, sh.ID)
	if err != nil {
		return
	}
	f := pam.SessionFacts{Account: s.Account, Start: s.StartedAt}
	if e, err := a.db.GetElevation(ctx, s.RequestID); err == nil {
		f.Emergency, f.Incident = e.Emergency, e.Incident
	}
	if alerts, err := a.db.AlertsBetween(ctx, s.AgentID, s.StartedAt, time.Now()); err == nil {
		f.AlertsDuring = len(alerts)
	}
	if seen, err := a.db.SeenSource(ctx, s.UserID, s.SourceIP, s.ID); err == nil {
		f.NewSource = !seen
	}
	score, why := pam.Risk(f)
	if err := a.db.EndAccessSession(ctx, s.ID, recordingID, reason, score, why); err != nil {
		a.log.Error("end privileged session", "session", s.ID, "err", err)
	}
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
