package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"golang.org/x/net/websocket"

	"github.com/Bogan1011/xdr-agent/internal/server/iam"
	"github.com/Bogan1011/xdr-agent/internal/server/live"
	"github.com/Bogan1011/xdr-agent/internal/server/pam"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

var shellUser = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// WithLive enables remote shells and the live activity view.
func (a *API) WithLive(h *live.Hub) *API {
	a.live = h
	h.Ended = a.shellEnded
	return a
}

func (a *API) liveRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/agents/{id}/live", a.auth(a.agentLive))
	mux.HandleFunc("GET /api/v1/agents/{id}/shell", a.auth(a.openShell))
	mux.HandleFunc("GET /api/v1/live/shells", a.auth(a.listShells))
	mux.HandleFunc("GET /api/v1/live/shells/{sid}/watch", a.auth(a.watchShell))
	mux.HandleFunc("POST /api/v1/live/shells/{sid}/close", a.auth(a.closeShell))
}

// agentLive is what happens on the host right now: who is logged in, what
// they run, the busiest processes, and the console's remote shells.
func (a *API) agentLive(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	resp := map[string]any{"online": false, "shells": a.live.Shells(id)}
	act, err := a.live.Activity(r.Context(), id)
	switch {
	case err == nil:
		resp["online"] = true
		resp["activity"] = act
	case errors.Is(err, live.ErrOffline):
	default:
		resp["online"] = true
		resp["error"] = "the agent did not answer in time"
	}
	writeJSON(w, resp)
}

func (a *API) listShells(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.live.Shells(r.URL.Query().Get("agent_id")))
}

func (a *API) closeShell(w http.ResponseWriter, r *http.Request) {
	s, err := a.live.Get(r.PathValue("sid"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if u := user(r); s.Admin != u.Username && !iam.Has(u.Permissions, iam.AccessOK) {
		writeErr(w, http.StatusForbidden, "only the shell's owner or an approver can end it")
		return
	}
	a.log.Info("remote shell closed from the console", "session", s.ID, "hostname", s.Hostname, "by", actor(r))
	a.live.Close(s)
	w.WriteHeader(http.StatusNoContent)
}

// openShell upgrades to a WebSocket carrying a terminal on the agent. It
// needs an approved shell access request of the caller's for this agent
// (?request=), and the shell is closed when the grant expires.
// Browser to server: JSON text frames {"t":"i","d":"keys"} and
// {"t":"r","c":cols,"r":rows}. Server to browser: binary frames of terminal
// output, then a text frame {"t":"exit","msg":"why"}.
func (a *API) openShell(w http.ResponseWriter, r *http.Request) {
	id, q, u := r.PathValue("id"), r.URL.Query(), user(r)
	e, err := a.db.GetElevation(r.Context(), q.Get("request"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && (e.Kind != pam.Shell || e.AgentID != id || e.RequesterID != u.ID)) {
		writeErr(w, http.StatusForbidden, "request shell access to this endpoint first")
		return
	}
	if a.fail(w, err) {
		return
	}
	if e.Status != "approved" && e.Status != "active" {
		writeErr(w, http.StatusForbidden, "the access request is "+e.Status)
		return
	}
	if !shellUser.MatchString(e.Username) {
		writeErr(w, http.StatusBadRequest, "invalid user name")
		return
	}
	ag, err := a.db.GetAgent(r.Context(), id)
	if a.fail(w, err) {
		return
	}
	if ag.Revoked {
		writeErr(w, http.StatusConflict, "the agent is revoked")
		return
	}
	cols, _ := strconv.ParseUint(q.Get("cols"), 10, 16)
	rows, _ := strconv.ParseUint(q.Get("rows"), 10, 16)
	auth := "password"
	if u.mfa {
		auth = "password+totp"
	}
	a.socket(w, r, func(ws *websocket.Conn) {
		s, err := a.live.Open(id, e.Username, u.Username, e.ID, uint32(cols), uint32(rows))
		if err != nil {
			sendExit(ws, err.Error())
			return
		}
		_ = a.db.SetElevationStatus(r.Context(), e.ID, []string{"approved"}, "active", "", "")
		if err := a.db.StartAccessSession(r.Context(), &store.AccessSession{
			ID: s.ID, UserID: u.ID, Username: u.Username, AgentID: id, Hostname: s.Hostname, Protocol: "browser_shell",
			Account: e.Username, SourceIP: clientIP(r), UserAgent: truncateStr(r.UserAgent(), 300), AuthMethod: auth,
			RequestID: e.ID, PolicyName: e.PolicyName, Ticket: e.Ticket, StartedAt: s.Started,
		}); err != nil {
			a.log.Error("record privileged session", "session", s.ID, "err", err)
		}
		a.audit(r, u.User, "pam.shell.open", "agent:"+id, "ok", map[string]any{"session": s.ID, "account": e.Username, "request": e.ID})
		a.log.Info("remote shell started", "session", s.ID, "hostname", s.Hostname, "user", e.Username, "by", u.Username, "remote", r.RemoteAddr)
		expiry := time.AfterFunc(time.Until(e.ExpiresAt), func() {
			a.log.Info("remote shell access expired", "session", s.ID, "request_id", e.ID)
			a.live.Close(s)
		})
		defer expiry.Stop()
		go func() {
			for {
				var msg string
				if err := websocket.Message.Receive(ws, &msg); err != nil {
					// The browser tab closed: hang up like a closed terminal.
					a.live.Close(s)
					return
				}
				var m struct {
					T    string
					D    string
					C, R uint32
				}
				if json.Unmarshal([]byte(msg), &m) != nil {
					continue
				}
				switch m.T {
				case "i":
					s.Input([]byte(m.D))
				case "r":
					s.Resize(m.C, m.R)
				}
			}
		}()
		stream(ws, s)
	})
}

// watchShell streams a running remote shell read-only, for a second admin
// to see what is being done.
func (a *API) watchShell(w http.ResponseWriter, r *http.Request) {
	s, err := a.live.Get(r.PathValue("sid"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	a.socket(w, r, func(ws *websocket.Conn) {
		a.log.Info("remote shell watched", "session", s.ID, "hostname", s.Hostname, "remote", r.RemoteAddr)
		go func() {
			var discard string
			for websocket.Message.Receive(ws, &discard) == nil {
			}
			ws.Close()
		}()
		stream(ws, s)
	})
}

// stream copies shell output to the socket until the shell or socket ends.
func stream(ws *websocket.Conn, s *live.Shell) {
	replay, ch, cancel := s.Subscribe()
	defer cancel()
	if len(replay) > 0 && websocket.Message.Send(ws, replay) != nil {
		return
	}
	for data := range ch {
		if websocket.Message.Send(ws, data) != nil {
			return
		}
	}
	sendExit(ws, s.Reason())
}

func sendExit(ws *websocket.Conn, msg string) {
	raw, _ := json.Marshal(map[string]string{"t": "exit", "msg": msg})
	_ = websocket.Message.Send(ws, string(raw))
}

// socket upgrades to a WebSocket. The session cookie authenticates it; the
// origin must be this console, so another site cannot open a shell with it.
func (a *API) socket(w http.ResponseWriter, r *http.Request, h func(*websocket.Conn)) {
	srv := websocket.Server{
		Handshake: func(cfg *websocket.Config, req *http.Request) error {
			o, err := url.Parse(req.Header.Get("Origin"))
			if err != nil || o.Host != req.Host {
				return errors.New("cross-origin websocket refused")
			}
			cfg.Origin = o
			return nil
		},
		Handler: func(ws *websocket.Conn) {
			defer ws.Close()
			ws.PayloadType = websocket.BinaryFrame
			h(ws)
		},
	}
	srv.ServeHTTP(w, r)
}
