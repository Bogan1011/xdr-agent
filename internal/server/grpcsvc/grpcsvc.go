// Package grpcsvc implements the enrollment and agent gRPC services.
package grpcsvc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/server/pki"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

const maxBatch = 5000

type Enrollment struct {
	xdrv1.UnimplementedEnrollmentServiceServer
	CA  *pki.CA
	DB  *store.Postgres
	Log *slog.Logger
}

func (s *Enrollment) Enroll(ctx context.Context, req *xdrv1.EnrollRequest) (*xdrv1.EnrollResponse, error) {
	if req.Host == nil || req.Host.Hostname == "" {
		return nil, status.Error(codes.InvalidArgument, "host info is required")
	}
	ok, err := s.DB.ConsumeEnrollmentToken(ctx, req.EnrollmentToken)
	if err != nil {
		s.Log.Error("consume enrollment token", "err", err)
		return nil, status.Error(codes.Internal, "enrollment failed")
	}
	if !ok {
		s.Log.Warn("enrollment rejected: invalid, expired or used-up token", "hostname", req.Host.Hostname, "peer", peerAddr(ctx))
		return nil, status.Error(codes.PermissionDenied, "invalid enrollment token")
	}

	id := newAgentID()
	certPEM, cert, err := s.CA.SignAgent(req.CsrPem, id)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "bad csr: %v", err)
	}
	if err := s.DB.CreateAgent(ctx, id, hostUpdate(req.Host), cert.SerialNumber.Text(16), cert.NotAfter); err != nil {
		s.Log.Error("create agent", "err", err)
		return nil, status.Error(codes.Internal, "enrollment failed")
	}
	s.Log.Info("agent enrolled", "agent_id", id, "hostname", req.Host.Hostname, "peer", peerAddr(ctx))
	return &xdrv1.EnrollResponse{AgentId: id, CertificatePem: certPEM, CaPem: s.CA.CertPEM}, nil
}

type Agents struct {
	xdrv1.UnimplementedAgentServiceServer
	DB     *store.Postgres
	Events *store.ClickHouse
	Log    *slog.Logger
}

type ctxKey struct{}

type agentCtx struct{ id, hostname string }

// AuthInterceptor maps the verified client certificate to an enrolled,
// non-revoked agent and stores it in the context.
func (s *Agents) AuthInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.VerifiedChains) == 0 || len(ti.State.VerifiedChains[0]) == 0 {
		return nil, status.Error(codes.Unauthenticated, "client certificate required")
	}
	id := ti.State.VerifiedChains[0][0].Subject.CommonName
	host, revoked, err := s.DB.AgentHostname(ctx, id)
	if errors.Is(err, store.ErrNotFound) || revoked {
		return nil, status.Error(codes.PermissionDenied, "agent is not enrolled or has been revoked")
	}
	if err != nil {
		return nil, status.Error(codes.Unavailable, "lookup failed")
	}
	return handler(context.WithValue(ctx, ctxKey{}, agentCtx{id: id, hostname: host}), req)
}

func fromCtx(ctx context.Context) agentCtx { return ctx.Value(ctxKey{}).(agentCtx) }

func (s *Agents) Heartbeat(ctx context.Context, req *xdrv1.HeartbeatRequest) (*xdrv1.HeartbeatResponse, error) {
	a := fromCtx(ctx)
	if req.Host != nil {
		st := req.Stats
		if st == nil {
			st = &xdrv1.AgentStats{}
		}
		if err := s.DB.Heartbeat(ctx, a.id, hostUpdate(req.Host), st.EventsSent, st.EventsDropped, st.CpuPercent, st.RssBytes); err != nil {
			s.Log.Error("heartbeat update", "agent_id", a.id, "err", err)
			return nil, status.Error(codes.Unavailable, "store unavailable")
		}
	}
	resp := &xdrv1.HeartbeatResponse{ServerTimeUnix: time.Now().Unix()}
	cmd, err := s.DB.TakeCommand(ctx, a.id)
	if err != nil {
		s.Log.Error("take command", "agent_id", a.id, "err", err)
	}
	if cmd == "uninstall" {
		s.Log.Info("sending uninstall to agent", "agent_id", a.id, "hostname", a.hostname)
		resp.Commands = append(resp.Commands, &xdrv1.AgentCommand{Id: newAgentID(), Type: xdrv1.CommandType_COMMAND_TYPE_UNINSTALL})
	}
	return resp, nil
}

func (s *Agents) SendEvents(ctx context.Context, req *xdrv1.EventBatch) (*xdrv1.SendEventsResponse, error) {
	a := fromCtx(ctx)
	if len(req.Events) > maxBatch {
		return nil, status.Errorf(codes.InvalidArgument, "batch larger than %d events", maxBatch)
	}
	rows := make([]store.Event, 0, len(req.Events))
	for _, e := range req.Events {
		rows = append(rows, toRow(a, e))
	}
	if err := s.Events.Insert(ctx, rows); err != nil {
		s.Log.Error("insert events", "agent_id", a.id, "err", err)
		return nil, status.Error(codes.Unavailable, "event store unavailable")
	}
	_ = s.DB.Touch(ctx, a.id)
	return &xdrv1.SendEventsResponse{Accepted: uint64(len(rows))}, nil
}

// EventTypeName is the stored name of an event type, e.g. "process_exec".
func EventTypeName(t xdrv1.EventType) string {
	return strings.ToLower(strings.TrimPrefix(t.String(), "EVENT_TYPE_"))
}

func toRow(a agentCtx, e *xdrv1.Event) store.Event {
	r := store.Event{
		Time:     time.Unix(0, e.TimestampUnixNano).UTC(),
		AgentID:  a.id,
		Hostname: a.hostname,
		EventID:  e.Id,
		Type:     EventTypeName(e.Type),
	}
	// Agent clocks can be wrong; keep events inside a sane window so they
	// land in a valid partition.
	if now := time.Now(); r.Time.After(now.Add(time.Hour)) || r.Time.Before(now.AddDate(0, 0, -30)) {
		r.Time = now.UTC()
	}
	switch p := e.Payload.(type) {
	case *xdrv1.Event_Process:
		pe := p.Process
		r.PID, r.PPID, r.UID, r.User = pe.Pid, pe.Ppid, pe.Uid, pe.User
		r.Exe, r.Args, r.Cwd, r.SHA256 = pe.Exe, joinArgs(pe.Args), pe.Cwd, pe.Sha256
		r.ParentExe, r.ExitCode = pe.ParentExe, pe.ExitCode
	case *xdrv1.Event_File:
		fe := p.File
		r.Path, r.OldPath, r.Size, r.Mode, r.UID, r.SHA256 = fe.Path, fe.OldPath, fe.Size, fe.Mode, fe.Uid, fe.Sha256
	case *xdrv1.Event_Network:
		ne := p.Network
		r.Protocol, r.LocalAddr, r.LocalPort = ne.Protocol, ne.LocalAddr, ne.LocalPort
		r.RemoteAddr, r.RemotePort, r.PID, r.Exe, r.UID = ne.RemoteAddr, ne.RemotePort, ne.Pid, ne.Exe, ne.Uid
	}
	return r
}

// joinArgs renders argv as a shell-like string; arguments with spaces are quoted.
func joinArgs(args []string) string {
	var b strings.Builder
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		if a == "" || strings.ContainsAny(a, " \t\"'") {
			fmt.Fprintf(&b, "%q", a)
		} else {
			b.WriteString(a)
		}
	}
	return b.String()
}

func hostUpdate(h *xdrv1.HostInfo) store.HostUpdate {
	return store.HostUpdate{
		Hostname: h.Hostname, OS: h.Os, OSVersion: h.OsVersion, Kernel: h.Kernel, Arch: h.Arch,
		AgentVersion: h.AgentVersion, MachineID: h.MachineId, IPAddresses: h.IpAddresses,
	}
}

func newAgentID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func peerAddr(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return ""
}
