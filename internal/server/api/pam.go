package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Bogan1011/xdr-agent/internal/server/grpcsvc"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

var pamUser = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

func (a *API) pamRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/pam/requests", a.auth(a.listElevations))
	mux.HandleFunc("GET /api/v1/pam/summary", a.auth(a.pamSummary))
	mux.HandleFunc("POST /api/v1/pam/requests/{id}/approve", a.auth(a.approveElevation))
	mux.HandleFunc("POST /api/v1/pam/requests/{id}/deny", a.auth(a.denyElevation))
	mux.HandleFunc("POST /api/v1/pam/requests/{id}/revoke", a.auth(a.revokeElevation))
	mux.HandleFunc("POST /api/v1/agents/{id}/pam/grant", a.auth(a.grantElevation))
	mux.HandleFunc("POST /api/v1/agents/{id}/pam/recording", a.auth(a.setPamRecording))
	mux.HandleFunc("GET /api/v1/pam/accounts", a.auth(a.listPrivilegedAccounts))
	mux.HandleFunc("GET /api/v1/pam/sessions", a.auth(a.listSessions))
	mux.HandleFunc("GET /api/v1/pam/sessions/{id}", a.auth(a.getSession))
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
	writeJSON(w, list)
}

func (a *API) pamSummary(w http.ResponseWriter, r *http.Request) {
	n, err := a.db.PendingElevationCount(r.Context())
	if a.fail(w, err) {
		return
	}
	writeJSON(w, map[string]int{"pending": n})
}

// sendGrant queues the grant command for an approved or admin-made request.
func (a *API) sendGrant(ctx context.Context, e *store.Elevation, d time.Duration) (string, error) {
	c := &store.Command{AgentID: e.AgentID, Type: "grant_elevation", RequestedBy: a.cfg.AdminUser, Args: map[string]string{
		"request_id": e.ID, "user": e.Username, "duration_seconds": strconv.FormatInt(int64(d.Seconds()), 10),
	}}
	if err := a.detect.QueueCommand(ctx, c); err != nil {
		return "", err
	}
	return c.ID, nil
}

func (a *API) approveElevation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DurationMinutes int    `json:"duration_minutes"`
		Note            string `json:"note"`
	}
	if !decode(w, r, &req, 4096) {
		return
	}
	e, err := a.db.GetElevation(r.Context(), r.PathValue("id"))
	if a.fail(w, err) {
		return
	}
	if e.Status != "pending" {
		writeErr(w, http.StatusConflict, "request is "+e.Status)
		return
	}
	d := time.Duration(e.DurationSeconds) * time.Second
	if req.DurationMinutes > 0 {
		d = grpcsvc.ElevationDuration(uint64(req.DurationMinutes) * 60)
	}
	cmdID, err := a.sendGrant(r.Context(), e, d)
	if a.fail(w, err) {
		return
	}
	err = a.db.ApproveElevation(r.Context(), e.ID, a.cfg.AdminUser, d, cmdID)
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "request was decided meanwhile")
		return
	}
	if a.fail(w, err) {
		return
	}
	if note := strings.TrimSpace(req.Note); note != "" {
		_ = a.db.SetElevationStatus(r.Context(), e.ID, []string{"approved"}, "approved", "", truncateStr(note, 500))
	}
	a.log.Warn("elevation approved", "request_id", e.ID, "hostname", e.Hostname, "user", e.Username, "duration", d, "by", a.cfg.AdminUser)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) denyElevation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Note string `json:"note"`
	}
	if !decode(w, r, &req, 4096) {
		return
	}
	err := a.db.SetElevationStatus(r.Context(), r.PathValue("id"), []string{"pending"}, "denied", a.cfg.AdminUser,
		truncateStr(strings.TrimSpace(req.Note), 500))
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "request is not pending")
		return
	}
	if a.fail(w, err) {
		return
	}
	a.log.Info("elevation denied", "request_id", r.PathValue("id"), "by", a.cfg.AdminUser)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) revokeElevation(w http.ResponseWriter, r *http.Request) {
	e, err := a.db.GetElevation(r.Context(), r.PathValue("id"))
	if a.fail(w, err) {
		return
	}
	if e.Status != "approved" && e.Status != "active" {
		writeErr(w, http.StatusConflict, "request is "+e.Status)
		return
	}
	c := &store.Command{AgentID: e.AgentID, Type: "revoke_elevation", RequestedBy: a.cfg.AdminUser,
		Args: map[string]string{"request_id": e.ID, "user": e.Username}}
	if a.fail(w, a.detect.QueueCommand(r.Context(), c)) {
		return
	}
	err = a.db.SetElevationStatus(r.Context(), e.ID, []string{"approved", "active"}, "revoked", a.cfg.AdminUser, "revoked by "+a.cfg.AdminUser)
	if err != nil && !errors.Is(err, store.ErrConflict) && a.fail(w, err) {
		return
	}
	a.log.Warn("elevation revoked", "request_id", e.ID, "hostname", e.Hostname, "user", e.Username, "by", a.cfg.AdminUser)
	w.WriteHeader(http.StatusNoContent)
}

// grantElevation gives a user sudo on a host without a request from the host.
func (a *API) grantElevation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User            string `json:"user"`
		DurationMinutes int    `json:"duration_minutes"`
		Reason          string `json:"reason"`
	}
	if !decode(w, r, &req, 4096) {
		return
	}
	req.User, req.Reason = strings.TrimSpace(req.User), strings.TrimSpace(req.Reason)
	if !pamUser.MatchString(req.User) || req.User == "root" {
		writeErr(w, http.StatusBadRequest, "enter a local account name other than root")
		return
	}
	if req.Reason == "" || len(req.Reason) > 500 {
		writeErr(w, http.StatusBadRequest, "a reason of up to 500 characters is required")
		return
	}
	ag, err := a.db.GetAgent(r.Context(), r.PathValue("id"))
	if a.fail(w, err) {
		return
	}
	if ag.Revoked {
		writeErr(w, http.StatusConflict, "agent is revoked")
		return
	}
	d := grpcsvc.ElevationDuration(uint64(max(req.DurationMinutes, 0)) * 60)
	e := &store.Elevation{ID: newID(), AgentID: ag.ID, Hostname: ag.Hostname, Username: req.User, Reason: req.Reason,
		DurationSeconds: int64(d.Seconds()), RequestedBy: a.cfg.AdminUser}
	if a.fail(w, a.db.CreateElevation(r.Context(), e)) {
		return
	}
	cmdID, err := a.sendGrant(r.Context(), e, d)
	if a.fail(w, err) {
		return
	}
	if a.fail(w, a.db.ApproveElevation(r.Context(), e.ID, a.cfg.AdminUser, d, cmdID)) {
		return
	}
	a.log.Warn("elevation granted from the console", "request_id", e.ID, "hostname", ag.Hostname, "user", req.User, "duration", d)
	writeJSON(w, map[string]string{"id": e.ID})
}

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
	a.log.Info("session recording viewed", "session", s.ID, "hostname", s.Hostname, "user", s.Username)
	writeJSON(w, map[string]any{"session": s, "output": strings.ToValidUTF8(string(s.Output), "�")})
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
