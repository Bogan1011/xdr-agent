package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/Bogan1011/xdr-agent/internal/policy"
	"github.com/Bogan1011/xdr-agent/internal/server/grpcsvc"
)

func (a *API) preventionRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/prevention/policy", a.auth(a.getGlobalPrevention))
	mux.HandleFunc("PUT /api/v1/prevention/policy", a.auth(a.setGlobalPrevention))
	mux.HandleFunc("GET /api/v1/agents/{id}/prevention", a.auth(a.getAgentPrevention))
	mux.HandleFunc("PUT /api/v1/agents/{id}/prevention", a.auth(a.setAgentPrevention))
}

const maxPolicyBytes = 256 << 10

// readPolicy parses and validates a policy from the request body.
func readPolicy(w http.ResponseWriter, raw json.RawMessage) ([]byte, bool) {
	p, err := policy.UnmarshalJSON(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid policy")
		return nil, false
	}
	if err := policy.Validate(p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return nil, false
	}
	return policy.MarshalJSON(p), true
}

func (a *API) getGlobalPrevention(w http.ResponseWriter, r *http.Request) {
	p, err := grpcsvc.GlobalPrevention(r.Context(), a.db)
	if a.fail(w, err) {
		return
	}
	_, _, blocked := a.detect.Content()
	writeJSON(w, map[string]any{"policy": json.RawMessage(policy.MarshalJSON(p)), "blocked_hashes": len(blocked) / 32})
}

func (a *API) setGlobalPrevention(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPolicyBytes))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	raw, ok := readPolicy(w, body)
	if !ok || a.fail(w, a.db.SetGlobalPrevention(r.Context(), raw)) {
		return
	}
	a.log.Info("fleet prevention policy changed", "remote", r.RemoteAddr)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) getAgentPrevention(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, custom, err := grpcsvc.ResolvePrevention(r.Context(), a.db, id)
	if a.fail(w, err) {
		return
	}
	_, state, err := a.db.AgentPrevention(r.Context(), id)
	if a.fail(w, err) {
		return
	}
	writeJSON(w, map[string]any{
		"custom": custom, "policy": json.RawMessage(policy.MarshalJSON(p)), "state": json.RawMessage(state),
	})
}

// setAgentPrevention gives the endpoint its own policy, or with custom false
// returns it to the fleet policy.
func (a *API) setAgentPrevention(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Custom bool            `json:"custom"`
		Policy json.RawMessage `json:"policy"`
	}
	if !decode(w, r, &req, maxPolicyBytes) {
		return
	}
	var raw []byte
	if req.Custom {
		var ok bool
		if raw, ok = readPolicy(w, req.Policy); !ok {
			return
		}
	}
	if a.fail(w, a.db.SetAgentPrevention(r.Context(), r.PathValue("id"), raw)) {
		return
	}
	a.log.Info("endpoint prevention policy changed", "agent_id", r.PathValue("id"), "custom", req.Custom)
	w.WriteHeader(http.StatusNoContent)
}
