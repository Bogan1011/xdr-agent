// Package grpcsvc implements the enrollment and agent gRPC services.
package grpcsvc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/server/detect"
	"github.com/Bogan1011/xdr-agent/internal/server/pki"
	"github.com/Bogan1011/xdr-agent/internal/server/release"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

const (
	maxBatch = 5000
	// binaryChunk stays well under gRPC's default 4 MiB message limit.
	binaryChunk = 1 << 20
)

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
	Detect *detect.Service
	Log    *slog.Logger
	// DownloadsDir holds the agent binaries offered for self-update.
	DownloadsDir string
}

var commandTypes = map[string]xdrv1.CommandType{
	"kill_process":    xdrv1.CommandType_COMMAND_TYPE_KILL_PROCESS,
	"quarantine_file": xdrv1.CommandType_COMMAND_TYPE_QUARANTINE_FILE,
	"restore_file":    xdrv1.CommandType_COMMAND_TYPE_RESTORE_FILE,
	"isolate_host":    xdrv1.CommandType_COMMAND_TYPE_ISOLATE_HOST,
	"unisolate_host":  xdrv1.CommandType_COMMAND_TYPE_UNISOLATE_HOST,
	"scan_path":       xdrv1.CommandType_COMMAND_TYPE_SCAN_PATH,
	"update_agent":    xdrv1.CommandType_COMMAND_TYPE_UPDATE_AGENT,
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
	if err := s.DB.SetAgentState(ctx, a.id, req.Isolated, req.ContentVersion, req.TamperProtected); err != nil {
		s.Log.Warn("agent state update", "agent_id", a.id, "err", err)
	}
	resp := &xdrv1.HeartbeatResponse{ServerTimeUnix: time.Now().Unix()}
	resp.ContentVersion, _ = s.Detect.Content()
	if on, tok, err := s.DB.TamperPolicy(ctx, a.id); err == nil {
		sum := sha256.Sum256([]byte(tok))
		resp.Tamper = &xdrv1.TamperPolicy{Enabled: on, MaintenanceTokenSha256: hex.EncodeToString(sum[:])}
	} else {
		s.Log.Warn("tamper policy", "agent_id", a.id, "err", err)
	}
	cmds, err := s.DB.TakeCommands(ctx, a.id)
	if err != nil {
		s.Log.Error("take response commands", "agent_id", a.id, "err", err)
	}
	for _, c := range cmds {
		resp.Commands = append(resp.Commands, &xdrv1.AgentCommand{Id: c.ID, Type: commandTypes[c.Type], Args: c.Args})
	}
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
	s.Detect.Process(ctx, rows)
	return &xdrv1.SendEventsResponse{Accepted: uint64(len(rows))}, nil
}

func (s *Agents) GetDetectionContent(ctx context.Context, _ *xdrv1.DetectionContentRequest) (*xdrv1.DetectionContent, error) {
	v, src := s.Detect.Content()
	return &xdrv1.DetectionContent{Version: v, YaraRules: src}, nil
}

func (s *Agents) ReportCommandResult(ctx context.Context, req *xdrv1.CommandResult) (*xdrv1.CommandResultAck, error) {
	a := fromCtx(ctx)
	c, err := s.DB.FinishCommand(ctx, a.id, req.CommandId, req.Success, truncate(req.Message, 4000))
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Error(codes.NotFound, "unknown command")
	}
	if err != nil {
		s.Log.Error("finish command", "agent_id", a.id, "err", err)
		return nil, status.Error(codes.Unavailable, "store unavailable")
	}
	s.Log.Info("response command finished", "command_id", c.ID, "type", c.Type, "hostname", a.hostname,
		"success", req.Success, "message", c.Message)
	return &xdrv1.CommandResultAck{}, nil
}

func (s *Agents) GetAgentBinary(ctx context.Context, req *xdrv1.AgentBinaryRequest) (*xdrv1.AgentBinaryChunk, error) {
	rel, err := release.Load(s.DownloadsDir)
	if err != nil {
		s.Log.Error("load agent release", "err", err)
		return nil, status.Error(codes.Unavailable, "no agent release available")
	}
	path, err := rel.Path(req.Arch)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "agent binary unavailable")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, status.Error(codes.Unavailable, "agent binary unavailable")
	}
	if req.Offset > uint64(st.Size()) {
		return nil, status.Error(codes.OutOfRange, "offset past end of binary")
	}
	buf := make([]byte, binaryChunk)
	n, err := f.ReadAt(buf, int64(req.Offset))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, status.Error(codes.Unavailable, "read agent binary")
	}
	if req.Offset == 0 {
		s.Log.Info("agent downloading update", "agent_id", fromCtx(ctx).id, "version", rel.Version, "arch", req.Arch)
	}
	return &xdrv1.AgentBinaryChunk{Data: buf[:n], TotalSize: uint64(st.Size()), Version: rel.Version}, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
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
		r.PID, r.PPID, r.Exe, r.User = fe.Pid, fe.Ppid, fe.Exe, fe.User
	case *xdrv1.Event_Network:
		ne := p.Network
		r.Protocol, r.LocalAddr, r.LocalPort = ne.Protocol, ne.LocalAddr, ne.LocalPort
		r.RemoteAddr, r.RemotePort, r.PID, r.Exe, r.UID = ne.RemoteAddr, ne.RemotePort, ne.Pid, ne.Exe, ne.Uid
	case *xdrv1.Event_Yara:
		y := p.Yara
		r.Path, r.SHA256, r.Size, r.PID = y.Path, y.Sha256, y.Size, y.Pid
		// The matched rule names are kept in args.
		r.Args = strings.Join(y.Rules, ", ")
	case *xdrv1.Event_Tamper:
		t := p.Tamper
		// The action is kept in path so rules can match it exactly.
		r.Path, r.Args, r.PID, r.Exe = t.Action, t.Detail, t.Pid, t.Exe
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
