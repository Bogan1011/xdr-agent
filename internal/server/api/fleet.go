package api

import (
	"context"
	"net/http"
	"strconv"

	"github.com/Bogan1011/xdr-agent/internal/server/release"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

func (a *API) fleetRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/fleet", a.auth(a.fleet))
	mux.HandleFunc("POST /api/v1/agents/{id}/update", a.auth(a.updateAgent))
	mux.HandleFunc("POST /api/v1/agents/update-all", a.auth(a.updateAllAgents))
	mux.HandleFunc("POST /api/v1/agents/{id}/tamper-protection", a.auth(a.setTamperProtection))
	mux.HandleFunc("GET /api/v1/agents/{id}/maintenance-token", a.auth(a.maintenanceToken))
	mux.HandleFunc("GET /api/v1/known-hosts", a.auth(a.listKnownHosts))
	mux.HandleFunc("DELETE /api/v1/known-hosts/{host}/{port}", a.auth(a.forgetKnownHost))
}

// fleet reports the agent release this console offers.
func (a *API) fleet(w http.ResponseWriter, r *http.Request) {
	rel, err := release.Load(a.cfg.DownloadsDir)
	if err != nil {
		writeJSON(w, map[string]any{"version": "", "sha256": map[string]string{}, "error": err.Error()})
		return
	}
	writeJSON(w, rel)
}

// needsUpdate is true for a reachable agent that runs another version and
// has no update in flight.
func needsUpdate(ag *store.Agent, rel *release.Release) bool {
	return !ag.Revoked && !ag.Updating && ag.AgentVersion != rel.Version && rel.SHA256[ag.Arch] != ""
}

func (a *API) queueUpdate(ctx context.Context, by string, ag *store.Agent, rel *release.Release) error {
	c := &store.Command{AgentID: ag.ID, Type: "update_agent", RequestedBy: by,
		Args: map[string]string{"version": rel.Version, "sha256": rel.SHA256[ag.Arch]}}
	return a.detect.QueueCommand(ctx, c)
}

func (a *API) updateAgent(w http.ResponseWriter, r *http.Request) {
	rel, err := release.Load(a.cfg.DownloadsDir)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "no agent release available: "+err.Error())
		return
	}
	ag, err := a.db.GetAgent(r.Context(), r.PathValue("id"))
	if a.fail(w, err) {
		return
	}
	if !needsUpdate(ag, rel) {
		writeErr(w, http.StatusConflict, "agent is revoked, already on "+rel.Version+", already updating, or its architecture has no build")
		return
	}
	if a.fail(w, a.queueUpdate(r.Context(), actor(r), ag, rel)) {
		return
	}
	a.log.Info("agent update queued", "agent_id", ag.ID, "from", ag.AgentVersion, "to", rel.Version)
	w.WriteHeader(http.StatusNoContent)
}

// updateAllAgents queues an update for every agent that is behind.
func (a *API) updateAllAgents(w http.ResponseWriter, r *http.Request) {
	rel, err := release.Load(a.cfg.DownloadsDir)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "no agent release available: "+err.Error())
		return
	}
	agents, err := a.db.ListAgents(r.Context())
	if a.fail(w, err) {
		return
	}
	n := 0
	for _, ag := range agents {
		if !needsUpdate(ag, rel) || !ag.Online {
			continue
		}
		if err := a.queueUpdate(r.Context(), actor(r), ag, rel); err != nil {
			a.log.Error("queue agent update", "agent_id", ag.ID, "err", err)
			continue
		}
		n++
	}
	a.log.Info("fleet update queued", "agents", n, "version", rel.Version)
	writeJSON(w, map[string]int{"queued": n})
}

func (a *API) setTamperProtection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !decode(w, r, &req, 1024) {
		return
	}
	if a.fail(w, a.db.SetTamperProtection(r.Context(), r.PathValue("id"), req.Enabled)) {
		return
	}
	a.log.Info("tamper protection changed", "agent_id", r.PathValue("id"), "enabled", req.Enabled)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) maintenanceToken(w http.ResponseWriter, r *http.Request) {
	_, tok, err := a.db.TamperPolicy(r.Context(), r.PathValue("id"))
	if a.fail(w, err) {
		return
	}
	a.log.Info("maintenance token viewed", "agent_id", r.PathValue("id"), "remote", r.RemoteAddr)
	writeJSON(w, map[string]string{"token": tok})
}

func (a *API) listKnownHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := a.db.ListKnownHosts(r.Context())
	if a.fail(w, err) {
		return
	}
	writeJSON(w, hosts)
}

func (a *API) forgetKnownHost(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid port")
		return
	}
	if a.fail(w, a.db.ForgetHostKey(r.Context(), r.PathValue("host"), port)) {
		return
	}
	a.log.Info("pinned SSH host key forgotten", "host", r.PathValue("host"), "port", port)
	w.WriteHeader(http.StatusNoContent)
}
