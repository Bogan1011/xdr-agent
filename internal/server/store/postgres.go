// Package store persists agents and configuration in Postgres and
// telemetry in ClickHouse.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OnlineWindow is how recently an agent must have checked in to count as online.
const OnlineWindow = 90 * time.Second

var ErrNotFound = errors.New("not found")

type Postgres struct{ pool *pgxpool.Pool }

func OpenPostgres(ctx context.Context, url string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	p := &Postgres{pool: pool}
	if err := p.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return p, nil
}

func (p *Postgres) Close() { p.pool.Close() }

func (p *Postgres) migrate(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS agents (
	id             TEXT PRIMARY KEY,
	hostname       TEXT NOT NULL,
	os             TEXT NOT NULL DEFAULT '',
	os_version     TEXT NOT NULL DEFAULT '',
	kernel         TEXT NOT NULL DEFAULT '',
	arch           TEXT NOT NULL DEFAULT '',
	ip_addresses   TEXT[] NOT NULL DEFAULT '{}',
	agent_version  TEXT NOT NULL DEFAULT '',
	machine_id     TEXT NOT NULL DEFAULT '',
	cert_serial    TEXT NOT NULL DEFAULT '',
	cert_expires   TIMESTAMPTZ,
	enrolled_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
	last_seen      TIMESTAMPTZ,
	events_sent    BIGINT NOT NULL DEFAULT 0,
	events_dropped BIGINT NOT NULL DEFAULT 0,
	cpu_percent    DOUBLE PRECISION NOT NULL DEFAULT 0,
	rss_bytes      BIGINT NOT NULL DEFAULT 0,
	revoked        BOOLEAN NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS enrollment_tokens (
	id          BIGSERIAL PRIMARY KEY,
	token_hash  TEXT NOT NULL UNIQUE,
	description TEXT NOT NULL DEFAULT '',
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	expires_at  TIMESTAMPTZ NOT NULL,
	max_uses    INT NOT NULL,
	uses        INT NOT NULL DEFAULT 0,
	revoked     BOOLEAN NOT NULL DEFAULT false
);
ALTER TABLE agents ADD COLUMN IF NOT EXISTS pending_command TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS uninstalled_at TIMESTAMPTZ;
CREATE TABLE IF NOT EXISTS deploy_jobs (
	id          BIGSERIAL PRIMARY KEY,
	host        TEXT NOT NULL,
	port        INT NOT NULL,
	username    TEXT NOT NULL,
	status      TEXT NOT NULL DEFAULT 'pending',
	host_key    TEXT NOT NULL DEFAULT '',
	log         TEXT NOT NULL DEFAULT '',
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	finished_at TIMESTAMPTZ
);
`)
	return err
}

type Agent struct {
	ID            string    `json:"id"`
	Hostname      string    `json:"hostname"`
	OS            string    `json:"os"`
	OSVersion     string    `json:"os_version"`
	Kernel        string    `json:"kernel"`
	Arch          string    `json:"arch"`
	IPAddresses   []string  `json:"ip_addresses"`
	AgentVersion  string    `json:"agent_version"`
	MachineID     string    `json:"machine_id"`
	CertExpires   time.Time `json:"cert_expires"`
	EnrolledAt    time.Time `json:"enrolled_at"`
	LastSeen      time.Time `json:"last_seen"`
	EventsSent    int64     `json:"events_sent"`
	EventsDropped int64     `json:"events_dropped"`
	CPUPercent    float64   `json:"cpu_percent"`
	RSSBytes      int64     `json:"rss_bytes"`
	Revoked       bool      `json:"revoked"`
	// PendingCommand is "uninstall" while an uninstall waits for the agent's next check-in.
	PendingCommand string    `json:"pending_command"`
	UninstalledAt  time.Time `json:"uninstalled_at"`
	Online         bool      `json:"online"`
}

const agentCols = `id, hostname, os, os_version, kernel, arch, ip_addresses, agent_version, machine_id,
	COALESCE(cert_expires, 'epoch'), enrolled_at, COALESCE(last_seen, 'epoch'), events_sent, events_dropped,
	cpu_percent, rss_bytes, revoked, pending_command, COALESCE(uninstalled_at, 'epoch')`

func scanAgent(row pgx.Row) (*Agent, error) {
	a := &Agent{}
	err := row.Scan(&a.ID, &a.Hostname, &a.OS, &a.OSVersion, &a.Kernel, &a.Arch, &a.IPAddresses, &a.AgentVersion,
		&a.MachineID, &a.CertExpires, &a.EnrolledAt, &a.LastSeen, &a.EventsSent, &a.EventsDropped,
		&a.CPUPercent, &a.RSSBytes, &a.Revoked, &a.PendingCommand, &a.UninstalledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.Online = !a.Revoked && time.Since(a.LastSeen) < OnlineWindow
	return a, nil
}

func (p *Postgres) ListAgents(ctx context.Context) ([]*Agent, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+agentCols+` FROM agents ORDER BY hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Agent{}
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *Postgres) GetAgent(ctx context.Context, id string) (*Agent, error) {
	return scanAgent(p.pool.QueryRow(ctx, `SELECT `+agentCols+` FROM agents WHERE id = $1`, id))
}

// AgentHostname returns an agent's hostname and revocation state, used to
// authenticate and label events on ingest.
func (p *Postgres) AgentHostname(ctx context.Context, id string) (string, bool, error) {
	var host string
	var revoked bool
	err := p.pool.QueryRow(ctx, `SELECT hostname, revoked FROM agents WHERE id = $1`, id).Scan(&host, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, ErrNotFound
	}
	return host, revoked, err
}

type HostUpdate struct {
	Hostname, OS, OSVersion, Kernel, Arch, AgentVersion, MachineID string
	IPAddresses                                                    []string
}

func (p *Postgres) CreateAgent(ctx context.Context, id string, h HostUpdate, serial string, expires time.Time) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO agents (id, hostname, os, os_version, kernel, arch, ip_addresses,
		agent_version, machine_id, cert_serial, cert_expires, last_seen)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, now())`,
		id, h.Hostname, h.OS, h.OSVersion, h.Kernel, h.Arch, nonNil(h.IPAddresses), h.AgentVersion, h.MachineID, serial, expires)
	return err
}

func (p *Postgres) Heartbeat(ctx context.Context, id string, h HostUpdate, sent, dropped uint64, cpu float64, rss uint64) error {
	_, err := p.pool.Exec(ctx, `UPDATE agents SET hostname=$2, os=$3, os_version=$4, kernel=$5, arch=$6,
		ip_addresses=$7, agent_version=$8, machine_id=$9, last_seen=now(), events_sent=$10, events_dropped=$11,
		cpu_percent=$12, rss_bytes=$13 WHERE id=$1`,
		id, h.Hostname, h.OS, h.OSVersion, h.Kernel, h.Arch, nonNil(h.IPAddresses), h.AgentVersion, h.MachineID,
		int64(sent), int64(dropped), cpu, int64(rss))
	return err
}

// RequestUninstall queues an uninstall for the agent's next heartbeat.
func (p *Postgres) RequestUninstall(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE agents SET pending_command = 'uninstall' WHERE id = $1 AND NOT revoked`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// TakeCommand returns and clears the agent's pending command. Delivering an
// uninstall also revokes the agent, so its certificate stops working.
func (p *Postgres) TakeCommand(ctx context.Context, id string) (string, error) {
	var cmd string
	err := p.pool.QueryRow(ctx, `UPDATE agents a SET pending_command = '',
		revoked = a.revoked OR a.pending_command = 'uninstall',
		uninstalled_at = CASE WHEN a.pending_command = 'uninstall' THEN now() ELSE a.uninstalled_at END
		FROM (SELECT id, pending_command FROM agents WHERE id = $1 FOR UPDATE) old
		WHERE a.id = old.id AND old.pending_command != ''
		RETURNING old.pending_command`, id).Scan(&cmd)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return cmd, err
}

func (p *Postgres) Touch(ctx context.Context, id string) error {
	_, err := p.pool.Exec(ctx, `UPDATE agents SET last_seen = now() WHERE id = $1`, id)
	return err
}

func (p *Postgres) SetRevoked(ctx context.Context, id string, revoked bool) error {
	tag, err := p.pool.Exec(ctx, `UPDATE agents SET revoked = $2 WHERE id = $1`, id, revoked)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) DeleteAgent(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

type EnrollmentToken struct {
	ID          int64     `json:"id"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	MaxUses     int       `json:"max_uses"`
	Uses        int       `json:"uses"`
	Revoked     bool      `json:"revoked"`
	// Token is only set when the token is created; only its hash is stored.
	Token string `json:"token,omitempty"`
}

func hashToken(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

func (p *Postgres) CreateEnrollmentToken(ctx context.Context, desc string, ttl time.Duration, maxUses int) (*EnrollmentToken, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	tok := "xdr_" + hex.EncodeToString(b[:])
	t := &EnrollmentToken{Description: desc, MaxUses: maxUses, Token: tok}
	err := p.pool.QueryRow(ctx, `INSERT INTO enrollment_tokens (token_hash, description, expires_at, max_uses)
		VALUES ($1, $2, now() + $3::interval, $4) RETURNING id, created_at, expires_at`,
		hashToken(tok), desc, fmt.Sprintf("%d seconds", int(ttl.Seconds())), maxUses).Scan(&t.ID, &t.CreatedAt, &t.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (p *Postgres) ListEnrollmentTokens(ctx context.Context) ([]*EnrollmentToken, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, description, created_at, expires_at, max_uses, uses, revoked
		FROM enrollment_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*EnrollmentToken{}
	for rows.Next() {
		t := &EnrollmentToken{}
		if err := rows.Scan(&t.ID, &t.Description, &t.CreatedAt, &t.ExpiresAt, &t.MaxUses, &t.Uses, &t.Revoked); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (p *Postgres) RevokeEnrollmentToken(ctx context.Context, id int64) error {
	tag, err := p.pool.Exec(ctx, `UPDATE enrollment_tokens SET revoked = true WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ConsumeEnrollmentToken atomically uses one enrollment from a valid token.
func (p *Postgres) ConsumeEnrollmentToken(ctx context.Context, tok string) (bool, error) {
	tag, err := p.pool.Exec(ctx, `UPDATE enrollment_tokens SET uses = uses + 1
		WHERE token_hash = $1 AND NOT revoked AND expires_at > now() AND uses < max_uses`, hashToken(tok))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type DeployJob struct {
	ID         int64     `json:"id"`
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	Username   string    `json:"username"`
	Status     string    `json:"status"`
	HostKey    string    `json:"host_key"`
	Log        string    `json:"log"`
	CreatedAt  time.Time `json:"created_at"`
	FinishedAt time.Time `json:"finished_at"`
}

func (p *Postgres) CreateDeployJob(ctx context.Context, host string, port int, user string) (int64, error) {
	var id int64
	err := p.pool.QueryRow(ctx, `INSERT INTO deploy_jobs (host, port, username) VALUES ($1, $2, $3) RETURNING id`,
		host, port, user).Scan(&id)
	return id, err
}

// UpdateDeployJob records progress; finished marks the job as done.
func (p *Postgres) UpdateDeployJob(ctx context.Context, id int64, status, hostKey, log string, finished bool) error {
	_, err := p.pool.Exec(ctx, `UPDATE deploy_jobs SET status = $2, host_key = $3, log = $4,
		finished_at = CASE WHEN $5 THEN now() ELSE finished_at END WHERE id = $1`, id, status, hostKey, log, finished)
	return err
}

func (p *Postgres) ListDeployJobs(ctx context.Context, limit int) ([]*DeployJob, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, host, port, username, status, host_key, log, created_at,
		COALESCE(finished_at, 'epoch') FROM deploy_jobs ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*DeployJob{}
	for rows.Next() {
		j := &DeployJob{}
		if err := rows.Scan(&j.ID, &j.Host, &j.Port, &j.Username, &j.Status, &j.HostKey, &j.Log, &j.CreatedAt, &j.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// FailStaleDeployJobs marks jobs left running by a server restart as failed.
func (p *Postgres) FailStaleDeployJobs(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, `UPDATE deploy_jobs SET status = 'failed', log = log || E'\nserver restarted during the job',
		finished_at = now() WHERE status IN ('pending', 'running')`)
	return err
}
