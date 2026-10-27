// Package api serves the dashboard's REST API, the dashboard itself, and
// the public files the agent installer downloads.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Bogan1011/xdr-agent/internal/server/deploy"
	"github.com/Bogan1011/xdr-agent/internal/server/detect"
	"github.com/Bogan1011/xdr-agent/internal/server/live"
	"github.com/Bogan1011/xdr-agent/internal/server/pki"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

const (
	sessionCookie = "xdr_session"
	sessionTTL    = 12 * time.Hour
)

type Config struct {
	// AdminUser is the break-glass administrator kept from the environment;
	// the server resets its password from XDR_ADMIN_PASSWORD on start.
	AdminUser string
	// PublicHost is the address agents use to reach this server.
	PublicHost   string
	EnrollPort   int
	AgentPort    int
	WebDir       string
	DownloadsDir string
}

type API struct {
	cfg    Config
	db     *store.Postgres
	events *store.ClickHouse
	ca     *pki.CA
	deploy *deploy.Deployer
	detect *detect.Service
	live   *live.Hub
	log    *slog.Logger

	mu       sync.Mutex
	sessions map[string]*loginSession
}

// loginSession is a signed-in browser.
type loginSession struct {
	userID  string
	expires time.Time
	// mfa is true when the login was confirmed with a second factor.
	mfa bool
}

func New(cfg Config, db *store.Postgres, events *store.ClickHouse, ca *pki.CA, dep *deploy.Deployer, det *detect.Service, log *slog.Logger) *API {
	a := &API{cfg: cfg, db: db, events: events, ca: ca, deploy: dep, detect: det, log: log, sessions: map[string]*loginSession{}}
	return a.WithLive(&live.Hub{Log: log})
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/login", a.login)
	mux.HandleFunc("POST /api/v1/logout", a.logout)
	a.iamRoutes(mux)

	mux.HandleFunc("GET /api/v1/agents", a.auth(a.listAgents))
	mux.HandleFunc("GET /api/v1/agents/{id}", a.auth(a.getAgent))
	mux.HandleFunc("POST /api/v1/agents/{id}/revoke", a.auth(a.revokeAgent))
	mux.HandleFunc("DELETE /api/v1/agents/{id}", a.auth(a.deleteAgent))
	mux.HandleFunc("POST /api/v1/agents/{id}/uninstall", a.auth(a.uninstallAgent))
	mux.HandleFunc("GET /api/v1/deploy-jobs", a.auth(a.listDeployJobs))
	mux.HandleFunc("POST /api/v1/deploy-jobs", a.auth(a.createDeployJobs))

	mux.HandleFunc("GET /api/v1/events", a.auth(a.queryEvents))
	mux.HandleFunc("GET /api/v1/stats", a.auth(a.stats))

	mux.HandleFunc("GET /api/v1/enrollment-tokens", a.auth(a.listTokens))
	mux.HandleFunc("POST /api/v1/enrollment-tokens", a.auth(a.createToken))
	mux.HandleFunc("DELETE /api/v1/enrollment-tokens/{id}", a.auth(a.revokeToken))
	mux.HandleFunc("GET /api/v1/install-info", a.auth(a.installInfo))
	a.detectionRoutes(mux)
	a.fleetRoutes(mux)
	a.pamRoutes(mux)
	a.preventionRoutes(mux)
	a.liveRoutes(mux)
	a.storylineRoutes(mux)

	// Public: the installer fetches these before the host has any identity.
	mux.HandleFunc("GET /pki/ca.crt", a.caCert)
	mux.HandleFunc("GET /install.sh", a.installScript)
	mux.HandleFunc("GET /uninstall.sh", a.uninstallScript)
	if a.cfg.DownloadsDir != "" {
		mux.Handle("GET /downloads/", http.StripPrefix("/downloads/", http.FileServer(http.Dir(a.cfg.DownloadsDir))))
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	if a.cfg.WebDir != "" {
		mux.Handle("GET /", spa(a.cfg.WebDir))
	}
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// spa serves the built dashboard, falling back to index.html for client routes.
func spa(dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := filepath.Join(dir, filepath.Clean("/"+r.URL.Path))
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			http.ServeFile(w, r, filepath.Join(dir, "index.html"))
			return
		}
		fs.ServeHTTP(w, r)
	})
}

// --- auth ---

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

// --- agents ---

func (a *API) listAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := a.db.ListAgents(r.Context())
	if a.fail(w, err) {
		return
	}
	writeJSON(w, agents)
}

func (a *API) getAgent(w http.ResponseWriter, r *http.Request) {
	ag, err := a.db.GetAgent(r.Context(), r.PathValue("id"))
	if a.fail(w, err) {
		return
	}
	writeJSON(w, ag)
}

func (a *API) revokeAgent(w http.ResponseWriter, r *http.Request) {
	if a.fail(w, a.db.SetRevoked(r.Context(), r.PathValue("id"), true)) {
		return
	}
	a.log.Info("agent revoked", "agent_id", r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) deleteAgent(w http.ResponseWriter, r *http.Request) {
	if a.fail(w, a.db.DeleteAgent(r.Context(), r.PathValue("id"))) {
		return
	}
	a.log.Info("agent deleted", "agent_id", r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) uninstallAgent(w http.ResponseWriter, r *http.Request) {
	if a.fail(w, a.db.RequestUninstall(r.Context(), r.PathValue("id"))) {
		return
	}
	a.log.Info("agent uninstall requested", "agent_id", r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

// --- remote install ---

func (a *API) listDeployJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := a.db.ListDeployJobs(r.Context(), 50)
	if a.fail(w, err) {
		return
	}
	writeJSON(w, jobs)
}

func (a *API) createDeployJobs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hosts      string `json:"hosts"`
		Port       int    `json:"port"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		PrivateKey string `json:"private_key"`
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	hosts := strings.FieldsFunc(req.Hosts, func(c rune) bool { return c == ',' || c == '\n' || c == ' ' || c == '\r' || c == '\t' })
	ids, err := a.deploy.Start(r.Context(), deploy.Request{
		Hosts: hosts, Port: req.Port, Username: req.Username, Password: req.Password,
		PrivateKey: req.PrivateKey, Passphrase: req.Passphrase,
		BaseURL: baseURL(r), CASHA256: a.ca.Fingerprint(),
	})
	if err != nil && len(ids) == 0 {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.log.Info("remote install started", "hosts", hosts, "user", req.Username)
	writeJSON(w, map[string]any{"job_ids": ids})
}

// --- events ---

func (a *API) queryEvents(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	q := store.EventQuery{
		AgentID: v.Get("agent_id"),
		Search:  strings.TrimSpace(v.Get("q")),
		SHA256:  v.Get("sha256"),
	}
	if t := v.Get("type"); t != "" {
		q.Types = strings.Split(t, ",")
	}
	q.ProcessGUID = v.Get("process_guid")
	if p, err := strconv.ParseUint(v.Get("pid"), 10, 32); err == nil {
		q.PID = uint32(p)
	}
	q.Limit, _ = strconv.Atoi(v.Get("limit"))
	var err error
	if q.From, err = parseTime(v.Get("from")); err != nil {
		writeErr(w, http.StatusBadRequest, "from: "+err.Error())
		return
	}
	if q.To, err = parseTime(v.Get("to")); err != nil {
		writeErr(w, http.StatusBadRequest, "to: "+err.Error())
		return
	}
	events, err := a.events.Query(r.Context(), q)
	if a.fail(w, err) {
		return
	}
	writeJSON(w, events)
}

// parseTime accepts RFC 3339 or a relative duration such as "15m" or "24h".
func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-d), nil
	}
	return time.Parse(time.RFC3339, s)
}

func (a *API) stats(w http.ResponseWriter, r *http.Request) {
	s, err := a.events.Stats(r.Context(), r.URL.Query().Get("agent_id"))
	if a.fail(w, err) {
		return
	}
	writeJSON(w, s)
}

// --- enrollment ---

func (a *API) listTokens(w http.ResponseWriter, r *http.Request) {
	t, err := a.db.ListEnrollmentTokens(r.Context())
	if a.fail(w, err) {
		return
	}
	writeJSON(w, t)
}

func (a *API) createToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Description string `json:"description"`
		TTLHours    int    `json:"ttl_hours"`
		MaxUses     int    `json:"max_uses"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.TTLHours <= 0 || req.TTLHours > 24*30 {
		req.TTLHours = 24
	}
	if req.MaxUses <= 0 || req.MaxUses > 10000 {
		req.MaxUses = 1
	}
	t, err := a.db.CreateEnrollmentToken(r.Context(), req.Description, time.Duration(req.TTLHours)*time.Hour, req.MaxUses)
	if a.fail(w, err) {
		return
	}
	writeJSON(w, t)
}

func (a *API) revokeToken(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if a.fail(w, a.db.RevokeEnrollmentToken(r.Context(), id)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) installInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"ca_sha256":   a.ca.Fingerprint(),
		"public_host": a.cfg.PublicHost,
		"enroll_port": a.cfg.EnrollPort,
		"agent_port":  a.cfg.AgentPort,
		"base_url":    baseURL(r),
	})
}

func baseURL(r *http.Request) string {
	scheme := "http"
	if isHTTPS(r) {
		scheme = "https"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	// The value is rendered into a shell script, so only allow host characters.
	if !validHost.MatchString(host) {
		host = "invalid-host"
	}
	return scheme + "://" + host
}

var validHost = regexp.MustCompile(`^[A-Za-z0-9.\-]+(:[0-9]+)?$|^\[[0-9A-Fa-f:.]+\](:[0-9]+)?$`)

func (a *API) caCert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(a.ca.CertPEM)
}

// --- helpers ---

func (a *API) fail(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not found")
		return true
	}
	a.log.Error("api error", "err", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
