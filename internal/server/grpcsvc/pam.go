package grpcsvc

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

const (
	defaultElevation = time.Hour
	// MaxElevation is the longest just-in-time grant a user can ask for or an
	// admin can approve.
	MaxElevation = 8 * time.Hour
	maxRecording = 4 << 20
)

// ElevationDuration applies the default and the bounds to a requested length.
func ElevationDuration(secs uint64) time.Duration {
	d := time.Duration(secs) * time.Second
	switch {
	case secs == 0:
		return defaultElevation
	case d < 5*time.Minute:
		return 5 * time.Minute
	case d > MaxElevation:
		return MaxElevation
	}
	return d
}

func elevationStatus(e *store.Elevation) *xdrv1.ElevationStatus {
	st := &xdrv1.ElevationStatus{Id: e.ID, Status: e.Status, Note: e.Note}
	if !e.ExpiresAt.IsZero() && e.ExpiresAt.Unix() > 0 {
		st.ExpiresUnix = e.ExpiresAt.Unix()
	}
	return st
}

func (s *Agents) RequestElevation(ctx context.Context, req *xdrv1.ElevationRequest) (*xdrv1.ElevationStatus, error) {
	a := fromCtx(ctx)
	reason := strings.TrimSpace(req.Reason)
	if req.User == "" || req.User == "root" || len(req.User) > 32 || reason == "" || len(reason) > 500 {
		return nil, status.Error(codes.InvalidArgument, "a user and a reason of up to 500 characters are required")
	}
	// One open request per user and host; asking again returns it.
	if e, err := s.DB.PendingElevation(ctx, a.id, req.User); err == nil {
		return elevationStatus(e), nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, status.Error(codes.Unavailable, "store unavailable")
	}
	e := &store.Elevation{
		ID: newAgentID(), AgentID: a.id, Hostname: a.hostname, Username: req.User, UID: int64(req.Uid),
		Reason: reason, DurationSeconds: int64(ElevationDuration(req.DurationSeconds).Seconds()), RequestedBy: req.User,
	}
	if err := s.DB.CreateElevation(ctx, e); err != nil {
		s.Log.Error("create elevation request", "agent_id", a.id, "err", err)
		return nil, status.Error(codes.Unavailable, "store unavailable")
	}
	s.Log.Info("elevation requested", "request_id", e.ID, "hostname", a.hostname, "user", e.Username, "reason", reason)
	e.Status = "pending"
	return elevationStatus(e), nil
}

func (s *Agents) GetElevation(ctx context.Context, req *xdrv1.GetElevationRequest) (*xdrv1.ElevationStatus, error) {
	e, err := s.DB.GetElevation(ctx, req.Id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && e.AgentID != fromCtx(ctx).id) {
		return nil, status.Error(codes.NotFound, "unknown request")
	}
	if err != nil {
		return nil, status.Error(codes.Unavailable, "store unavailable")
	}
	return elevationStatus(e), nil
}

// grantDone records whether the agent installed an approved grant.
func (s *Agents) grantDone(ctx context.Context, c *store.Command, ok bool) {
	id := c.Args["request_id"]
	var err error
	if ok {
		err = s.DB.SetElevationStatus(ctx, id, []string{"approved"}, "active", "", "")
	} else {
		err = s.DB.SetElevationStatus(ctx, id, []string{"approved"}, "failed", "", c.Message)
	}
	if err != nil && !errors.Is(err, store.ErrConflict) {
		s.Log.Error("update elevation after grant", "request_id", id, "err", err)
	}
}

func (s *Agents) ReportPrivilegedAccounts(ctx context.Context, req *xdrv1.PrivilegedAccounts) (*xdrv1.PrivilegedAccountsAck, error) {
	a := fromCtx(ctx)
	if len(req.Accounts) > 5000 {
		return nil, status.Error(codes.InvalidArgument, "too many accounts")
	}
	accts := make([]json.RawMessage, 0, len(req.Accounts))
	m := protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}
	for _, acc := range req.Accounts {
		raw, err := m.Marshal(acc)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "bad account")
		}
		accts = append(accts, raw)
	}
	raw, _ := json.Marshal(accts)
	prev, err := s.DB.SaveInventory(ctx, a.id, raw, int(req.InteractiveAccounts))
	if err != nil {
		s.Log.Error("save privileged accounts", "agent_id", a.id, "err", err)
		return nil, status.Error(codes.Unavailable, "store unavailable")
	}
	if prev != nil {
		s.alertNewPrivileged(ctx, a, prev, req.Accounts)
	}
	return &xdrv1.PrivilegedAccountsAck{}, nil
}

// NewPrivileged returns accounts that gained privileges since the previous
// report. Just-in-time grants are expected and left out.
func NewPrivileged(prev []byte, cur []*xdrv1.PrivilegedAccount) []*xdrv1.PrivilegedAccount {
	var old []struct {
		Name    string   `json:"name"`
		Sources []string `json:"sources"`
	}
	_ = json.Unmarshal(prev, &old)
	had := map[string][]string{}
	for _, o := range old {
		had[o.Name] = o.Sources
	}
	var out []*xdrv1.PrivilegedAccount
	for _, acc := range cur {
		for _, src := range acc.Sources {
			if src != "jit" && !slices.Contains(had[acc.Name], src) {
				out = append(out, acc)
				break
			}
		}
	}
	return out
}

func (s *Agents) alertNewPrivileged(ctx context.Context, a agentCtx, prev []byte, cur []*xdrv1.PrivilegedAccount) {
	for _, acc := range NewPrivileged(prev, cur) {
		ev := store.Event{
			Time: time.Now().UTC(), AgentID: a.id, Hostname: a.hostname, Type: "privileged_account",
			User: acc.Name, UID: acc.Uid, Args: strings.Join(acc.Sources, ", "),
		}
		raw, _ := json.Marshal(ev)
		al := &store.Alert{
			AgentID: a.id, Hostname: a.hostname, RuleID: "pam-new-privileged-account", RuleName: "New privileged account",
			Kind: "pam", Severity: "high", Tags: []string{"attack.privilege_escalation", "attack.t1078.003"},
			Detail: acc.Name + " can now act as root via " + strings.Join(acc.Sources, ", "), Event: raw,
		}
		if _, _, err := s.DB.RaiseAlert(ctx, al, acc.Name+"|"+strings.Join(acc.Sources, ",")); err != nil {
			s.Log.Error("raise privileged account alert", "err", err)
		}
	}
}

func (s *Agents) UploadSessionRecording(ctx context.Context, req *xdrv1.SessionRecording) (*xdrv1.SessionRecordingAck, error) {
	a := fromCtx(ctx)
	if req.SessionId == "" || len(req.Output) > maxRecording {
		return nil, status.Error(codes.InvalidArgument, "session id required and output at most 4 MiB")
	}
	start := time.Unix(req.StartUnix, 0).UTC()
	if req.StartUnix <= 0 {
		start = time.Now().UTC()
	}
	sess := &store.Session{
		AgentID: a.id, Hostname: a.hostname, SessionID: clean(req.SessionId, 300), Username: clean(req.User, 64),
		RunasUser: clean(req.RunasUser, 64), TTY: clean(req.Tty, 64), Cwd: clean(req.Cwd, 1000),
		Command: clean(req.Command, 4000), StartedAt: start, DurationMs: int64(req.DurationMs),
		Output: req.Output, Truncated: req.Truncated, RequestID: clean(req.RequestId, 64),
	}
	if sess.Output == nil {
		sess.Output = []byte{}
	}
	if err := s.DB.SaveSession(ctx, sess); err != nil {
		s.Log.Error("save session recording", "agent_id", a.id, "err", err)
		return nil, status.Error(codes.Unavailable, "store unavailable")
	}
	s.Log.Info("sudo session recorded", "hostname", a.hostname, "user", sess.Username, "command", sess.Command, "request_id", sess.RequestID)
	return &xdrv1.SessionRecordingAck{}, nil
}

// clean makes agent text storable in a Postgres TEXT column.
func clean(s string, n int) string {
	return strings.ToValidUTF8(strings.ReplaceAll(truncate(s, n), "\x00", ""), "")
}
