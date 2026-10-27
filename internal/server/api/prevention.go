package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Bogan1011/xdr-agent/internal/policy"
	"github.com/Bogan1011/xdr-agent/internal/server/grpcsvc"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

func (a *API) preventionRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/policies", a.auth(a.listPolicies))
	mux.HandleFunc("POST /api/v1/policies", a.auth(a.createPolicy))
	mux.HandleFunc("GET /api/v1/policies/{id}", a.auth(a.getPolicy))
	mux.HandleFunc("PUT /api/v1/policies/{id}", a.auth(a.updatePolicy))
	mux.HandleFunc("DELETE /api/v1/policies/{id}", a.auth(a.deletePolicy))
	mux.HandleFunc("PUT /api/v1/policies/{id}/endpoints", a.auth(a.assignPolicy))
	mux.HandleFunc("GET /api/v1/agents/{id}/prevention", a.auth(a.getAgentPrevention))
	mux.HandleFunc("PUT /api/v1/agents/{id}/policy", a.auth(a.setAgentPolicy))
}

const maxPolicyBytes = 512 << 10

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
	if err := policy.SetPassword(p.SelfProtection); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return nil, false
	}
	p.Name = ""
	return policy.MarshalJSON(p), true
}

// policyName checks a policy name, writing the error when it is bad.
func policyName(w http.ResponseWriter, name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 {
		writeErr(w, http.StatusBadRequest, "name must be 1 to 80 characters")
		return "", false
	}
	return name, true
}

func (a *API) policyFail(w http.ResponseWriter, err error) bool {
	if errors.Is(err, store.ErrDuplicate) {
		writeErr(w, http.StatusConflict, "a policy with this name exists")
		return true
	}
	return a.fail(w, err)
}

func (a *API) listPolicies(w http.ResponseWriter, r *http.Request) {
	pols, err := a.db.ListPolicies(r.Context())
	if a.fail(w, err) {
		return
	}
	// The list shows which modules are on, not the whole policy.
	type row struct {
		*store.Policy
		Modules []string `json:"modules"`
	}
	out := make([]row, 0, len(pols))
	for _, pol := range pols {
		out = append(out, row{Policy: pol, Modules: modulesOn(pol.Policy)})
		pol.Policy = nil
	}
	writeJSON(w, out)
}

// modulesOn names the modules a policy has switched on.
func modulesOn(raw []byte) []string {
	p, err := policy.UnmarshalJSON(raw)
	if err != nil {
		return []string{}
	}
	out := []string{}
	for _, m := range []struct {
		name string
		on   bool
	}{
		{"anti_malware", p.AntiMalware.Enabled || p.AntiMalware.BlockKnownBad},
		{"web_reputation", p.WebReputation.Enabled},
		{"file_integrity", p.Fim.Enabled},
		{"firewall", p.Firewall.Enabled},
		{"intrusion_prevention", p.IntrusionPrevention.Enabled},
		{"device_control", p.DeviceControl.Enabled},
		{"activity_monitoring", p.ActivityMonitoring.Process || p.ActivityMonitoring.File || p.ActivityMonitoring.Network},
		{"application_control", p.ApplicationControl.Enabled},
	} {
		if m.on {
			out = append(out, m.name)
		}
	}
	return out
}

func (a *API) createPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		// CopyFrom starts from another policy's settings; 0 starts from the defaults.
		CopyFrom int64 `json:"copy_from"`
	}
	if !decode(w, r, &req, 8<<10) {
		return
	}
	name, ok := policyName(w, req.Name)
	if !ok {
		return
	}
	raw := policy.MarshalJSON(policy.Default())
	if req.CopyFrom != 0 {
		src, err := a.db.GetPolicy(r.Context(), req.CopyFrom)
		if a.fail(w, err) {
			return
		}
		raw = src.Policy
	}
	id, err := a.db.CreatePolicy(r.Context(), name, strings.TrimSpace(req.Description), raw)
	if a.policyFail(w, err) {
		return
	}
	a.log.Info("policy created", "policy_id", id, "name", name)
	writeJSON(w, map[string]int64{"id": id})
}

func (a *API) getPolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(w, r)
	if !ok {
		return
	}
	pol, err := a.db.GetPolicy(r.Context(), id)
	if a.fail(w, err) {
		return
	}
	p, err := policy.UnmarshalJSON(pol.Policy)
	if a.fail(w, err) {
		return
	}
	pol.Policy = policy.MarshalJSON(p)
	eps, err := a.db.PolicyEndpoints(r.Context(), id)
	if a.fail(w, err) {
		return
	}
	type ep struct {
		ID       string `json:"id"`
		Hostname string `json:"hostname"`
		Online   bool   `json:"online"`
	}
	list := make([]ep, 0, len(eps))
	for _, e := range eps {
		list = append(list, ep{e.ID, e.Hostname, e.Online})
	}
	c := a.detect.Content()
	writeJSON(w, map[string]any{
		"policy": pol, "endpoint_list": list,
		"intel": map[string]int{"hashes": len(c.Blocked) / 32, "ips": len(c.BadIPs), "domains": len(c.BadDomains)},
	})
}

func (a *API) updatePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(w, r)
	if !ok {
		return
	}
	var req struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Policy      json.RawMessage `json:"policy"`
	}
	if !decode(w, r, &req, maxPolicyBytes) {
		return
	}
	name, ok := policyName(w, req.Name)
	if !ok {
		return
	}
	raw, ok := readPolicy(w, req.Policy)
	if !ok || a.policyFail(w, a.db.UpdatePolicy(r.Context(), id, name, strings.TrimSpace(req.Description), raw)) {
		return
	}
	a.log.Info("policy changed", "policy_id", id, "name", name, "remote", r.RemoteAddr)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(w, r)
	if !ok {
		return
	}
	err := a.db.DeletePolicy(r.Context(), id)
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "the default policy cannot be deleted")
		return
	}
	if a.fail(w, err) {
		return
	}
	a.log.Info("policy deleted", "policy_id", id)
	w.WriteHeader(http.StatusNoContent)
}

// assignPolicy moves endpoints to the policy.
func (a *API) assignPolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(w, r)
	if !ok {
		return
	}
	var req struct {
		AgentIDs []string `json:"agent_ids"`
	}
	if !decode(w, r, &req, 256<<10) {
		return
	}
	if len(req.AgentIDs) == 0 {
		writeErr(w, http.StatusBadRequest, "no endpoints selected")
		return
	}
	if a.fail(w, a.db.SetAgentPolicy(r.Context(), id, req.AgentIDs...)) {
		return
	}
	a.log.Info("policy assigned", "policy_id", id, "endpoints", len(req.AgentIDs))
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) getAgentPrevention(w http.ResponseWriter, r *http.Request) {
	p, pol, state, err := grpcsvc.ResolvePrevention(r.Context(), a.db, r.PathValue("id"))
	if a.fail(w, err) {
		return
	}
	p.Name = ""
	writeJSON(w, map[string]any{
		"policy_id": pol.ID, "policy_name": pol.Name, "is_default": pol.IsDefault,
		"policy": json.RawMessage(policy.MarshalJSON(p)), "state": json.RawMessage(state),
	})
}

// setAgentPolicy assigns one endpoint; policy_id 0 is the default policy.
func (a *API) setAgentPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PolicyID int64 `json:"policy_id"`
	}
	if !decode(w, r, &req, 1<<10) {
		return
	}
	if a.fail(w, a.db.SetAgentPolicy(r.Context(), req.PolicyID, r.PathValue("id"))) {
		return
	}
	a.log.Info("endpoint policy changed", "agent_id", r.PathValue("id"), "policy_id", req.PolicyID)
	w.WriteHeader(http.StatusNoContent)
}
