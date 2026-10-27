package api

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Bogan1011/xdr-agent/internal/server/iam"
	"github.com/Bogan1011/xdr-agent/internal/server/pam"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

var (
	validUsername = regexp.MustCompile(`^[A-Za-z0-9_.@-]{2,64}$`)
	validRoleID   = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,31}$`)
)

func (a *API) iamRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/login", a.login)
	mux.HandleFunc("POST /api/v1/logout", a.logout)
	mux.HandleFunc("GET /api/v1/me", a.auth(a.me))
	mux.HandleFunc("POST /api/v1/me/password", a.auth(a.changePassword))
	mux.HandleFunc("POST /api/v1/me/mfa/setup", a.auth(a.mfaSetup))
	mux.HandleFunc("POST /api/v1/me/mfa/enable", a.auth(a.mfaEnable))
	mux.HandleFunc("POST /api/v1/me/mfa/disable", a.auth(a.mfaDisable))

	mux.HandleFunc("GET /api/v1/users", a.auth(a.listUsers))
	mux.HandleFunc("POST /api/v1/users", a.auth(a.createUser))
	mux.HandleFunc("PUT /api/v1/users/{id}", a.auth(a.updateUser))
	mux.HandleFunc("DELETE /api/v1/users/{id}", a.auth(a.deleteUser))
	mux.HandleFunc("POST /api/v1/users/{id}/mfa/reset", a.auth(a.resetUserMFA))
	mux.HandleFunc("GET /api/v1/roles", a.auth(a.listRoles))
	mux.HandleFunc("POST /api/v1/roles", a.auth(a.saveRole))
	mux.HandleFunc("PUT /api/v1/roles/{id}", a.auth(a.saveRole))
	mux.HandleFunc("DELETE /api/v1/roles/{id}", a.auth(a.deleteRole))
	mux.HandleFunc("GET /api/v1/asset-groups", a.auth(a.listAssetGroups))
	mux.HandleFunc("POST /api/v1/asset-groups", a.auth(a.saveAssetGroup))
	mux.HandleFunc("PUT /api/v1/asset-groups/{id}", a.auth(a.saveAssetGroup))
	mux.HandleFunc("DELETE /api/v1/asset-groups/{id}", a.auth(a.deleteAssetGroup))
	mux.HandleFunc("GET /api/v1/access-policies", a.auth(a.listAccessPolicies))
	mux.HandleFunc("POST /api/v1/access-policies", a.auth(a.saveAccessPolicy))
	mux.HandleFunc("PUT /api/v1/access-policies/{id}", a.auth(a.saveAccessPolicy))
	mux.HandleFunc("DELETE /api/v1/access-policies/{id}", a.auth(a.deleteAccessPolicy))
	mux.HandleFunc("GET /api/v1/audit", a.auth(a.listAudit))
	mux.HandleFunc("GET /api/v1/audit/verify", a.auth(a.verifyAudit))
}

// --- sessions and the auth wrapper ---

type ctxKey int

const userKey ctxKey = 0

type requestUser struct {
	*store.User
	mfa bool // signed in with a second factor
}

// user is the signed-in user of a request that went through auth.
func user(r *http.Request) *requestUser {
	u, _ := r.Context().Value(userKey).(*requestUser)
	return u
}

// actor names the signed-in user for logs, commands and decisions.
func actor(r *http.Request) string {
	if u := user(r); u != nil {
		return u.Username
	}
	return "system"
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password, Code string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	u, err := a.db.UserByName(r.Context(), store.DefaultTenant, strings.TrimSpace(req.Username))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		a.fail(w, err)
		return
	}
	// Hash even for unknown users so timing does not reveal who exists.
	ok := iam.PasswordMatches(req.Password, "00", "00")
	if u != nil {
		ok = iam.PasswordMatches(req.Password, u.PasswordSalt, u.PasswordHash) && !u.Disabled
	}
	if !ok {
		a.log.Warn("failed dashboard login", "user", req.Username, "remote", r.RemoteAddr)
		a.audit(r, nil, "login", "user:"+truncateStr(req.Username, 64), "denied", map[string]any{"why": "bad password or disabled"})
		time.Sleep(500 * time.Millisecond)
		writeErr(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	if u.MFAEnabled {
		if req.Code == "" {
			writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": "enter the code from your authenticator app", "mfa_required": true})
			return
		}
		if !iam.VerifyTOTP(u.MFASecret, req.Code, time.Now()) {
			a.audit(r, u, "login", "user:"+u.Username, "denied", map[string]any{"why": "wrong MFA code"})
			time.Sleep(500 * time.Millisecond)
			writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": "wrong authenticator code", "mfa_required": true})
			return
		}
	}
	var b [32]byte
	_, _ = rand.Read(b[:])
	tok := hex.EncodeToString(b[:])
	a.mu.Lock()
	now := time.Now()
	for k, s := range a.sessions {
		if now.After(s.expires) {
			delete(a.sessions, k)
		}
	}
	a.sessions[tok] = &loginSession{userID: u.ID, expires: now.Add(sessionTTL), mfa: u.MFAEnabled}
	a.mu.Unlock()
	_ = a.db.TouchLogin(r.Context(), u.ID)
	a.audit(r, u, "login", "user:"+u.Username, "ok", map[string]any{"mfa": u.MFAEnabled})
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: isHTTPS(r), MaxAge: int(sessionTTL.Seconds()),
	})
	writeJSON(w, map[string]string{"username": u.Username})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

// endUserSessions signs a user out everywhere, after a disable or delete.
func (a *API) endUserSessions(userID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, s := range a.sessions {
		if s.userID == userID {
			delete(a.sessions, k)
		}
	}
}

// auth requires a signed-in, enabled user holding the permission the route
// needs (iam.RoutePermission), and writes changes and sensitive reads to the
// audit log.
func (a *API) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var sess *loginSession
		if c, err := r.Cookie(sessionCookie); err == nil {
			a.mu.Lock()
			if s, ok := a.sessions[c.Value]; ok && time.Now().Before(s.expires) {
				sess = s
			}
			a.mu.Unlock()
		}
		if sess == nil {
			writeErr(w, http.StatusUnauthorized, "login required")
			return
		}
		u, err := a.db.GetUser(r.Context(), sess.userID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && u.Disabled) {
			writeErr(w, http.StatusUnauthorized, "login required")
			return
		}
		if a.fail(w, err) {
			return
		}
		// Cookies are SameSite=Strict; requiring JSON on writes also
		// blocks simple cross-site form posts.
		if r.Method != http.MethodGet && r.Method != http.MethodDelete && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeErr(w, http.StatusUnsupportedMediaType, "content type must be application/json")
			return
		}
		perm := iam.RoutePermission(r.Pattern)
		if !iam.Has(u.Permissions, perm) {
			a.audit(r, u, r.Pattern, r.URL.Path, "forbidden", map[string]any{"needs": perm})
			writeErr(w, http.StatusForbidden, "your role does not allow this ("+perm+")")
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), userKey, &requestUser{User: u, mfa: sess.mfa}))
		if !iam.Audited(r.Pattern) {
			next(w, r)
			return
		}
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		next(sw, r)
		outcome := "ok"
		if sw.code >= 400 {
			outcome = "error " + http.StatusText(sw.code)
		}
		a.audit(r, u, r.Pattern, r.URL.Path, outcome, nil)
	}
}

// audit appends to the audit log; a failure is logged, not returned, so the
// log cannot be used to block the console.
func (a *API) audit(r *http.Request, u *store.User, action, target, outcome string, detail map[string]any) {
	e := &store.AuditEntry{Actor: "anonymous", Action: action, Target: target, Outcome: outcome, Remote: clientIP(r)}
	if u != nil {
		e.Actor, e.ActorID = u.Username, u.ID
	}
	if detail != nil {
		e.Detail, _ = json.Marshal(detail)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if err := a.db.Audit(ctx, e); err != nil {
		a.log.Error("write audit log", "action", action, "err", err)
	}
}

// statusWriter records the status code; it passes Hijack through for the
// WebSocket routes.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijacking not supported")
	}
	s.code = http.StatusSwitchingProtocols
	return h.Hijack()
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// --- me ---

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	u := user(r)
	writeJSON(w, map[string]any{
		"id": u.ID, "username": u.Username, "display_name": u.DisplayName, "role_id": u.RoleID,
		"permissions": u.Permissions, "mfa_enabled": u.MFAEnabled, "builtin": u.Builtin, "tenant_id": u.TenantID,
	})
}

func (a *API) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct{ Current, New string }
	if !decode(w, r, &req, 4096) {
		return
	}
	u := user(r)
	if u.Builtin {
		writeErr(w, http.StatusConflict, "this account's password comes from XDR_ADMIN_PASSWORD in deploy/.env")
		return
	}
	if !iam.PasswordMatches(req.Current, u.PasswordSalt, u.PasswordHash) {
		writeErr(w, http.StatusBadRequest, "the current password is wrong")
		return
	}
	if err := iam.CheckPasswordPolicy(req.New); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if a.fail(w, a.db.SetUserPassword(r.Context(), u.ID, req.New)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// mfaSetup stores a new secret, not yet enabled, and returns it once.
func (a *API) mfaSetup(w http.ResponseWriter, r *http.Request) {
	u := user(r)
	if u.MFAEnabled {
		writeErr(w, http.StatusConflict, "MFA is already on; turn it off first to change it")
		return
	}
	secret := iam.NewTOTPSecret()
	if a.fail(w, a.db.SetUserMFA(r.Context(), u.ID, secret, false)) {
		return
	}
	writeJSON(w, map[string]string{"secret": secret, "uri": iam.TOTPURI("XDR Console", u.Username, secret)})
}

func (a *API) mfaEnable(w http.ResponseWriter, r *http.Request) {
	var req struct{ Code string }
	if !decode(w, r, &req, 1024) {
		return
	}
	u := user(r)
	if u.MFASecret == "" || !iam.VerifyTOTP(u.MFASecret, req.Code, time.Now()) {
		writeErr(w, http.StatusBadRequest, "that code does not match; check the time on your phone")
		return
	}
	if a.fail(w, a.db.SetUserMFA(r.Context(), u.ID, u.MFASecret, true)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) mfaDisable(w http.ResponseWriter, r *http.Request) {
	var req struct{ Code string }
	if !decode(w, r, &req, 1024) {
		return
	}
	u := user(r)
	if !u.MFAEnabled || !iam.VerifyTOTP(u.MFASecret, req.Code, time.Now()) {
		writeErr(w, http.StatusBadRequest, "enter a current code to turn MFA off")
		return
	}
	if a.fail(w, a.db.SetUserMFA(r.Context(), u.ID, "", false)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- users ---

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	us, err := a.db.ListUsers(r.Context(), user(r).TenantID)
	if a.fail(w, err) {
		return
	}
	writeJSON(w, us)
}

type userReq struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	RoleID      string `json:"role_id"`
	Disabled    bool   `json:"disabled"`
	Password    string `json:"password"`
}

func (a *API) checkRole(w http.ResponseWriter, r *http.Request, role string) bool {
	ok, err := a.db.RoleExists(r.Context(), user(r).TenantID, role)
	if a.fail(w, err) {
		return false
	}
	if !ok {
		writeErr(w, http.StatusBadRequest, "unknown role")
	}
	return ok
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	var req userReq
	if !decode(w, r, &req, 8192) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if !validUsername.MatchString(req.Username) {
		writeErr(w, http.StatusBadRequest, "usernames are 2 to 64 letters, digits or . _ @ -")
		return
	}
	if err := iam.CheckPasswordPolicy(req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !a.checkRole(w, r, req.RoleID) {
		return
	}
	u := &store.User{TenantID: user(r).TenantID, Username: req.Username, DisplayName: truncateStr(strings.TrimSpace(req.DisplayName), 100),
		Email: truncateStr(strings.TrimSpace(req.Email), 200), RoleID: req.RoleID}
	err := a.db.CreateUser(r.Context(), u, req.Password)
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "that username is taken")
		return
	}
	if a.fail(w, err) {
		return
	}
	writeJSON(w, map[string]string{"id": u.ID})
}

func (a *API) tenantUser(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	u, err := a.db.GetUser(r.Context(), r.PathValue("id"))
	if err == nil && u.TenantID != user(r).TenantID {
		err = store.ErrNotFound
	}
	if a.fail(w, err) {
		return nil, false
	}
	return u, true
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	var req userReq
	if !decode(w, r, &req, 8192) {
		return
	}
	u, ok := a.tenantUser(w, r)
	if !ok {
		return
	}
	if u.Builtin && (req.RoleID != "admin" || req.Disabled) {
		writeErr(w, http.StatusConflict, "the built-in administrator stays an enabled admin")
		return
	}
	if u.ID == user(r).ID && (req.Disabled || req.RoleID != u.RoleID) {
		writeErr(w, http.StatusConflict, "you cannot disable yourself or change your own role")
		return
	}
	if !a.checkRole(w, r, req.RoleID) {
		return
	}
	u.DisplayName, u.Email = truncateStr(strings.TrimSpace(req.DisplayName), 100), truncateStr(strings.TrimSpace(req.Email), 200)
	u.RoleID, u.Disabled = req.RoleID, req.Disabled
	if a.fail(w, a.db.UpdateUser(r.Context(), u)) {
		return
	}
	if req.Password != "" {
		if u.Builtin {
			writeErr(w, http.StatusConflict, "the built-in administrator's password comes from deploy/.env")
			return
		}
		if err := iam.CheckPasswordPolicy(req.Password); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if a.fail(w, a.db.SetUserPassword(r.Context(), u.ID, req.Password)) {
			return
		}
	}
	if u.Disabled || req.Password != "" {
		a.endUserSessions(u.ID)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	u, ok := a.tenantUser(w, r)
	if !ok {
		return
	}
	if u.Builtin || u.ID == user(r).ID {
		writeErr(w, http.StatusConflict, "the built-in administrator and your own account cannot be deleted")
		return
	}
	if a.fail(w, a.db.DeleteUser(r.Context(), u.ID)) {
		return
	}
	a.endUserSessions(u.ID)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) resetUserMFA(w http.ResponseWriter, r *http.Request) {
	u, ok := a.tenantUser(w, r)
	if !ok || a.fail(w, a.db.SetUserMFA(r.Context(), u.ID, "", false)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- roles ---

func (a *API) listRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := a.db.ListRoles(r.Context(), user(r).TenantID)
	if a.fail(w, err) {
		return
	}
	writeJSON(w, map[string]any{"roles": roles, "permissions": iam.Permissions})
}

func (a *API) saveRole(w http.ResponseWriter, r *http.Request) {
	var req iam.Role
	if !decode(w, r, &req, 8192) {
		return
	}
	if id := r.PathValue("id"); id != "" {
		req.ID = id
	}
	req.Name = strings.TrimSpace(req.Name)
	if !validRoleID.MatchString(req.ID) || req.ID == iam.HostRole || req.Name == "" || len(req.Name) > 64 {
		writeErr(w, http.StatusBadRequest, "a role needs an id (lowercase letters, digits, - or _) and a name")
		return
	}
	for _, p := range req.Permissions {
		if !iam.ValidPermission(p) {
			writeErr(w, http.StatusBadRequest, "unknown permission "+p)
			return
		}
	}
	slices.Sort(req.Permissions)
	req.Permissions = slices.Compact(req.Permissions)
	if req.Permissions == nil {
		req.Permissions = []string{}
	}
	err := a.db.SaveRole(r.Context(), user(r).TenantID, req)
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "built-in roles cannot be changed")
		return
	}
	if a.fail(w, err) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) deleteRole(w http.ResponseWriter, r *http.Request) {
	err := a.db.DeleteRole(r.Context(), user(r).TenantID, r.PathValue("id"))
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "users still have this role")
		return
	}
	if a.fail(w, err) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- asset groups ---

func (a *API) listAssetGroups(w http.ResponseWriter, r *http.Request) {
	gs, err := a.db.ListAssetGroups(r.Context(), user(r).TenantID)
	if a.fail(w, err) {
		return
	}
	writeJSON(w, gs)
}

var (
	criticalities = []string{"low", "medium", "high", "critical"}
	environments  = []string{"production", "staging", "development", "other"}
)

func (a *API) saveAssetGroup(w http.ResponseWriter, r *http.Request) {
	var g store.AssetGroup
	if !decode(w, r, &g, 256*1024) {
		return
	}
	g.ID = 0
	if id := r.PathValue("id"); id != "" {
		n, err := store.ParseID(id)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid id")
			return
		}
		g.ID = n
	}
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" || len(g.Name) > 100 || !slices.Contains(criticalities, g.Criticality) || !slices.Contains(environments, g.Environment) {
		writeErr(w, http.StatusBadRequest, "a group needs a name, a criticality and an environment")
		return
	}
	g.Description = truncateStr(strings.TrimSpace(g.Description), 500)
	// The built-in group keeps every endpoint.
	if g.ID != 0 {
		gs, err := a.db.ListAssetGroups(r.Context(), user(r).TenantID)
		if a.fail(w, err) {
			return
		}
		for _, x := range gs {
			if x.ID == g.ID && x.AllAssets {
				g.AllAssets = true
			}
		}
	} else {
		g.AllAssets = false
	}
	err := a.db.SaveAssetGroup(r.Context(), user(r).TenantID, &g)
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "a group with that name exists")
		return
	}
	if a.fail(w, err) {
		return
	}
	writeJSON(w, map[string]int64{"id": g.ID})
}

func (a *API) deleteAssetGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(w, r)
	if !ok || a.fail(w, a.db.DeleteAssetGroup(r.Context(), user(r).TenantID, id)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- access policies ---

func (a *API) listAccessPolicies(w http.ResponseWriter, r *http.Request) {
	ps, err := a.db.ListAccessPolicies(r.Context(), user(r).TenantID)
	if a.fail(w, err) {
		return
	}
	writeJSON(w, ps)
}

func (a *API) saveAccessPolicy(w http.ResponseWriter, r *http.Request) {
	var p pam.Policy
	if !decode(w, r, &p, 64*1024) {
		return
	}
	p.ID = 0
	if id := r.PathValue("id"); id != "" {
		n, err := store.ParseID(id)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid id")
			return
		}
		p.ID = n
	}
	if err := p.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p.Description = truncateStr(strings.TrimSpace(p.Description), 500)
	err := a.db.SaveAccessPolicy(r.Context(), user(r).TenantID, &p)
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "a policy with that name exists")
		return
	}
	if a.fail(w, err) {
		return
	}
	writeJSON(w, map[string]int64{"id": p.ID})
}

func (a *API) deleteAccessPolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(w, r)
	if !ok || a.fail(w, a.db.DeleteAccessPolicy(r.Context(), user(r).TenantID, id)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- audit ---

func (a *API) listAudit(w http.ResponseWriter, r *http.Request) {
	list, err := a.db.ListAudit(r.Context(), strings.TrimSpace(r.URL.Query().Get("q")), queryLimit(r, 200, 1000))
	if a.fail(w, err) {
		return
	}
	writeJSON(w, list)
}

func (a *API) verifyAudit(w http.ResponseWriter, r *http.Request) {
	n, broken, err := a.db.VerifyAudit(r.Context())
	if a.fail(w, err) {
		return
	}
	writeJSON(w, map[string]any{"ok": broken == 0, "checked": n, "broken_at": broken})
}

func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
