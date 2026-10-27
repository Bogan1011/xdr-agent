package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Bogan1011/xdr-agent/internal/server/detect"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

func (a *API) detectionRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/alerts", a.auth(a.listAlerts))
	mux.HandleFunc("GET /api/v1/alerts/summary", a.auth(a.alertSummary))
	mux.HandleFunc("GET /api/v1/alerts/{id}", a.auth(a.getAlert))
	mux.HandleFunc("PATCH /api/v1/alerts/{id}", a.auth(a.updateAlert))

	mux.HandleFunc("GET /api/v1/agents/{id}/commands", a.auth(a.listCommands))
	mux.HandleFunc("POST /api/v1/agents/{id}/commands", a.auth(a.createCommand))

	mux.HandleFunc("GET /api/v1/rules", a.auth(a.listRules))
	mux.HandleFunc("POST /api/v1/rules", a.auth(a.saveRule))
	mux.HandleFunc("PUT /api/v1/rules/{id}", a.auth(a.saveRule))
	mux.HandleFunc("POST /api/v1/rules/{id}/enabled", a.auth(a.setRuleEnabled))
	mux.HandleFunc("DELETE /api/v1/rules/{id}", a.auth(a.deleteRule))

	mux.HandleFunc("GET /api/v1/iocs", a.auth(a.listIOCs))
	mux.HandleFunc("POST /api/v1/iocs", a.auth(a.addIOCs))
	mux.HandleFunc("DELETE /api/v1/iocs/{id}", a.auth(a.deleteIOC))
	mux.HandleFunc("GET /api/v1/ioc-feeds", a.auth(a.listFeeds))
	mux.HandleFunc("POST /api/v1/ioc-feeds", a.auth(a.createFeed))
	mux.HandleFunc("POST /api/v1/ioc-feeds/{id}/refresh", a.auth(a.refreshFeed))
	mux.HandleFunc("POST /api/v1/ioc-feeds/{id}/enabled", a.auth(a.setFeedEnabled))
	mux.HandleFunc("DELETE /api/v1/ioc-feeds/{id}", a.auth(a.deleteFeed))
}

func decode(w http.ResponseWriter, r *http.Request, v any, max int64) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, max)).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return false
	}
	return true
}

func pathInt(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return id, true
}

func queryLimit(r *http.Request, def, max int) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		return def
	}
	return min(n, max)
}

// --- alerts ---

func (a *API) listAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	alerts, err := a.db.ListAlerts(r.Context(), store.AlertQuery{
		AgentID: q.Get("agent_id"), Status: q.Get("status"), Severity: q.Get("severity"), Limit: queryLimit(r, 200, 1000),
	})
	if a.fail(w, err) {
		return
	}
	writeJSON(w, alerts)
}

func (a *API) alertSummary(w http.ResponseWriter, r *http.Request) {
	s, err := a.db.AlertSummary(r.Context())
	if a.fail(w, err) {
		return
	}
	writeJSON(w, s)
}

func (a *API) getAlert(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(w, r)
	if !ok {
		return
	}
	al, err := a.db.GetAlert(r.Context(), id)
	if a.fail(w, err) {
		return
	}
	cmds, err := a.db.ListCommands(r.Context(), "", id, 50)
	if a.fail(w, err) {
		return
	}
	writeJSON(w, map[string]any{"alert": al, "commands": cmds})
}

func (a *API) updateAlert(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(w, r)
	if !ok {
		return
	}
	var req struct{ Status, Note string }
	if !decode(w, r, &req, 16<<10) {
		return
	}
	if req.Status != "" && !slices.Contains(store.AlertStatuses, req.Status) {
		writeErr(w, http.StatusBadRequest, "invalid status")
		return
	}
	if a.fail(w, a.db.UpdateAlert(r.Context(), id, req.Status, req.Note)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- response ---

func (a *API) listCommands(w http.ResponseWriter, r *http.Request) {
	cmds, err := a.db.ListCommands(r.Context(), r.PathValue("id"), 0, queryLimit(r, 50, 500))
	if a.fail(w, err) {
		return
	}
	writeJSON(w, cmds)
}

func (a *API) createCommand(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type    string            `json:"type"`
		Args    map[string]string `json:"args"`
		AlertID int64             `json:"alert_id"`
	}
	if !decode(w, r, &req, 16<<10) {
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
	if strings.HasSuffix(req.Type, "_elevation") {
		writeErr(w, http.StatusBadRequest, "grant and revoke sudo from Privileged access")
		return
	}
	if err := detect.ValidateCommand(req.Type, req.Args); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	c := &store.Command{AgentID: ag.ID, Type: req.Type, Args: req.Args, AlertID: req.AlertID, RequestedBy: actor(r)}
	if a.fail(w, a.detect.QueueCommand(r.Context(), c)) {
		return
	}
	if req.AlertID != 0 {
		_ = a.db.UpdateAlert(r.Context(), req.AlertID, "in_progress", "")
	}
	writeJSON(w, c)
}

// --- rules ---

func (a *API) listRules(w http.ResponseWriter, r *http.Request) {
	rules, err := a.db.ListRules(r.Context())
	if a.fail(w, err) {
		return
	}
	writeJSON(w, map[string]any{"rules": rules, "fields": fieldNames(), "responses": detect.Responses})
}

func fieldNames() []string {
	out := make([]string, 0, len(detect.Fields))
	for k := range detect.Fields {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

var yaraIDRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)

func (a *API) saveRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind     string `json:"kind"`
		Source   string `json:"source"`
		Severity string `json:"severity"`
		Enabled  *bool  `json:"enabled"`
	}
	if !decode(w, r, &req, 256<<10) {
		return
	}
	var rule *store.Rule
	var err error
	switch req.Kind {
	case "sigma":
		rule, err = detect.RuleFromSigma(req.Source)
		if err == nil && r.PathValue("id") != "" && r.PathValue("id") != rule.ID {
			err = errors.New("the rule id in the source cannot change; create a new rule instead")
		}
	case "yara":
		id := r.PathValue("id")
		if id == "" {
			var b [6]byte
			_, _ = rand.Read(b[:])
			id = "custom-yara-" + hex.EncodeToString(b[:])
		}
		if !yaraIDRe.MatchString(id) {
			err = errors.New("invalid rule id")
			break
		}
		rule, err = detect.RuleFromYara(id, req.Source, req.Severity)
	default:
		err = errors.New("kind must be sigma or yara")
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rule.Enabled = req.Enabled == nil || *req.Enabled
	ctx := r.Context()
	if rule.Kind == "yara" {
		// Agents receive all enabled YARA rules as one file, so it must
		// still compile with this rule in it.
		all, err := a.db.ListRules(ctx)
		if a.fail(w, err) {
			return
		}
		all = slices.DeleteFunc(all, func(x store.Rule) bool { return x.ID == rule.ID })
		if _, _, err := detect.YaraBundle(append(all, *rule)); err != nil {
			writeErr(w, http.StatusBadRequest, "conflicts with the other YARA rules: "+err.Error())
			return
		}
	}
	if err := a.db.SaveRule(ctx, *rule); errors.Is(err, store.ErrBuiltin) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	} else if a.fail(w, err) {
		return
	}
	a.reloadDetection(ctx)
	writeJSON(w, rule)
}

func (a *API) setRuleEnabled(w http.ResponseWriter, r *http.Request) {
	var req struct{ Enabled bool }
	if !decode(w, r, &req, 1024) {
		return
	}
	ctx := r.Context()
	if req.Enabled {
		all, err := a.db.ListRules(ctx)
		if a.fail(w, err) {
			return
		}
		for i := range all {
			if all[i].ID == r.PathValue("id") {
				all[i].Enabled = true
			}
		}
		if _, _, err := detect.YaraBundle(all); err != nil {
			writeErr(w, http.StatusBadRequest, "conflicts with the other YARA rules: "+err.Error())
			return
		}
	}
	if a.fail(w, a.db.SetRuleEnabled(ctx, r.PathValue("id"), req.Enabled)) {
		return
	}
	a.reloadDetection(ctx)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) deleteRule(w http.ResponseWriter, r *http.Request) {
	if a.fail(w, a.db.DeleteRule(r.Context(), r.PathValue("id"))) {
		return
	}
	a.reloadDetection(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) reloadDetection(ctx context.Context) {
	if err := a.detect.Reload(ctx); err != nil {
		a.log.Error("reload detection content", "err", err)
	}
}

// --- IOCs ---

var severities = []string{"low", "medium", "high", "critical"}

func (a *API) listIOCs(w http.ResponseWriter, r *http.Request) {
	iocs, err := a.db.ListIOCs(r.Context(), strings.TrimSpace(r.URL.Query().Get("q")), queryLimit(r, 500, 2000))
	if a.fail(w, err) {
		return
	}
	writeJSON(w, iocs)
}

// addIOCs takes one indicator per line in values, all of one type.
func (a *API) addIOCs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type        string `json:"type"`
		Values      string `json:"values"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
	}
	if !decode(w, r, &req, 4<<20) {
		return
	}
	if req.Severity == "" {
		req.Severity = "high"
	}
	if !slices.Contains(severities, req.Severity) {
		writeErr(w, http.StatusBadRequest, "invalid severity")
		return
	}
	var iocs []store.IOC
	for _, line := range strings.Split(req.Values, "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		v, err := detect.NormalizeIOC(req.Type, line)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		iocs = append(iocs, store.IOC{Type: req.Type, Value: v, Description: req.Description, Severity: req.Severity})
	}
	if len(iocs) == 0 || len(iocs) > 50000 {
		writeErr(w, http.StatusBadRequest, "give between 1 and 50000 indicators, one per line")
		return
	}
	n, err := a.db.AddIOCs(r.Context(), iocs)
	if a.fail(w, err) {
		return
	}
	a.reloadDetection(r.Context())
	writeJSON(w, map[string]int{"added": n, "duplicates": len(iocs) - n})
}

func (a *API) deleteIOC(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(w, r)
	if !ok {
		return
	}
	if a.fail(w, a.db.DeleteIOC(r.Context(), id)) {
		return
	}
	a.reloadDetection(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listFeeds(w http.ResponseWriter, r *http.Request) {
	feeds, err := a.db.ListFeeds(r.Context())
	if a.fail(w, err) {
		return
	}
	writeJSON(w, feeds)
}

func (a *API) createFeed(w http.ResponseWriter, r *http.Request) {
	var f store.Feed
	if !decode(w, r, &f, 16<<10) {
		return
	}
	f.Name = strings.TrimSpace(f.Name)
	u, err := url.Parse(f.URL)
	switch {
	case f.Name == "":
		err = errors.New("name is required")
	case err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "":
		err = errors.New("url must be an http(s) URL")
	case f.Type != "sha256" && f.Type != "ip" && f.Type != "domain":
		err = errors.New("type must be sha256, ip or domain")
	}
	if f.Severity == "" {
		f.Severity = "high"
	}
	if err == nil && !slices.Contains(severities, f.Severity) {
		err = errors.New("invalid severity")
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	f.Enabled = true
	f.ID, err = a.db.CreateFeed(r.Context(), f)
	if a.fail(w, err) {
		return
	}
	// Download in the background; the UI polls the feed list for the result.
	go func() { _ = a.detect.RefreshFeed(context.WithoutCancel(r.Context()), f) }()
	writeJSON(w, f)
}

func (a *API) findFeed(w http.ResponseWriter, r *http.Request) (store.Feed, bool) {
	id, ok := pathInt(w, r)
	if !ok {
		return store.Feed{}, false
	}
	feeds, err := a.db.ListFeeds(r.Context())
	if a.fail(w, err) {
		return store.Feed{}, false
	}
	for _, f := range feeds {
		if f.ID == id {
			return f, true
		}
	}
	a.fail(w, store.ErrNotFound)
	return store.Feed{}, false
}

func (a *API) refreshFeed(w http.ResponseWriter, r *http.Request) {
	f, ok := a.findFeed(w, r)
	if !ok {
		return
	}
	if err := a.detect.RefreshFeed(r.Context(), f); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) setFeedEnabled(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(w, r)
	if !ok {
		return
	}
	var req struct{ Enabled bool }
	if !decode(w, r, &req, 1024) {
		return
	}
	if a.fail(w, a.db.SetFeedEnabled(r.Context(), id, req.Enabled)) {
		return
	}
	a.reloadDetection(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) deleteFeed(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(w, r)
	if !ok {
		return
	}
	if a.fail(w, a.db.DeleteFeed(r.Context(), id)) {
		return
	}
	a.reloadDetection(r.Context())
	w.WriteHeader(http.StatusNoContent)
}
