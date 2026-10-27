package api

import (
	"net/http"

	"github.com/Bogan1011/xdr-agent/internal/server/store"
	"github.com/Bogan1011/xdr-agent/internal/server/storyline"
)

func (a *API) storylineRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/storyline", a.auth(a.getStoryline))
}

// getStoryline returns the process tree around one process, with the alerts
// raised in it.
func (a *API) getStoryline(w http.ResponseWriter, r *http.Request) {
	agentID, guid := r.URL.Query().Get("agent_id"), r.URL.Query().Get("guid")
	if agentID == "" || guid == "" {
		writeErr(w, http.StatusBadRequest, "agent_id and guid are required")
		return
	}
	st, err := storyline.Build(r.Context(), a.events, agentID, guid)
	if a.fail(w, err) {
		return
	}
	guids := []string{st.Root}
	for _, n := range st.Nodes {
		guids = append(guids, n.GUID)
	}
	alerts, err := a.db.ProcessAlerts(r.Context(), agentID, guids)
	if a.fail(w, err) {
		return
	}
	if alerts == nil {
		alerts = []*store.Alert{}
	}
	writeJSON(w, map[string]any{"storyline": st, "alerts": alerts})
}
