package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrConflict means the record is not in a state that allows the change.
var ErrConflict = errors.New("conflict")

func (p *Postgres) migratePAM(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, `
ALTER TABLE agents ADD COLUMN IF NOT EXISTS pam_record_all BOOLEAN NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS pam_requests (
	id               TEXT PRIMARY KEY,
	agent_id         TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	hostname         TEXT NOT NULL,
	username         TEXT NOT NULL,
	uid              BIGINT NOT NULL DEFAULT 0,
	reason           TEXT NOT NULL DEFAULT '',
	duration_seconds BIGINT NOT NULL,
	status           TEXT NOT NULL DEFAULT 'pending',
	requested_by     TEXT NOT NULL DEFAULT '',
	decided_by       TEXT NOT NULL DEFAULT '',
	note             TEXT NOT NULL DEFAULT '',
	command_id       TEXT NOT NULL DEFAULT '',
	created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	decided_at       TIMESTAMPTZ,
	expires_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS pam_requests_created ON pam_requests (created_at DESC);
CREATE TABLE IF NOT EXISTS pam_accounts (
	agent_id     TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
	accounts     JSONB NOT NULL,
	interactive  INT NOT NULL DEFAULT 0,
	collected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS pam_sessions (
	id          BIGSERIAL PRIMARY KEY,
	agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	hostname    TEXT NOT NULL,
	session_id  TEXT NOT NULL,
	username    TEXT NOT NULL,
	runas_user  TEXT NOT NULL DEFAULT '',
	tty         TEXT NOT NULL DEFAULT '',
	cwd         TEXT NOT NULL DEFAULT '',
	command     TEXT NOT NULL DEFAULT '',
	started_at  TIMESTAMPTZ NOT NULL,
	duration_ms BIGINT NOT NULL DEFAULT 0,
	output      BYTEA NOT NULL,
	truncated   BOOLEAN NOT NULL DEFAULT false,
	request_id  TEXT NOT NULL DEFAULT '',
	uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE (agent_id, session_id)
);
CREATE INDEX IF NOT EXISTS pam_sessions_started ON pam_sessions (started_at DESC);
`)
	return err
}

// Elevation is a just-in-time sudo request and, once decided, its grant.
type Elevation struct {
	ID              string `json:"id"`
	AgentID         string `json:"agent_id"`
	Hostname        string `json:"hostname"`
	Username        string `json:"username"`
	UID             int64  `json:"uid"`
	Reason          string `json:"reason"`
	DurationSeconds int64  `json:"duration_seconds"`
	// Status is pending, approved (grant sent), active (agent confirmed),
	// denied, expired, revoked or failed.
	Status      string    `json:"status"`
	RequestedBy string    `json:"requested_by"`
	DecidedBy   string    `json:"decided_by"`
	Note        string    `json:"note"`
	CommandID   string    `json:"command_id"`
	CreatedAt   time.Time `json:"created_at"`
	DecidedAt   time.Time `json:"decided_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

const elevationCols = `id, agent_id, hostname, username, uid, reason, duration_seconds, status, requested_by,
	decided_by, note, command_id, created_at, COALESCE(decided_at, 'epoch'), COALESCE(expires_at, 'epoch')`

func scanElevation(row pgx.CollectableRow) (*Elevation, error) {
	e := &Elevation{}
	err := row.Scan(&e.ID, &e.AgentID, &e.Hostname, &e.Username, &e.UID, &e.Reason, &e.DurationSeconds, &e.Status,
		&e.RequestedBy, &e.DecidedBy, &e.Note, &e.CommandID, &e.CreatedAt, &e.DecidedAt, &e.ExpiresAt)
	return e, err
}

// expireElevations moves grants past their end, and requests nobody decided
// within a day, to expired.
func (p *Postgres) expireElevations(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, `
UPDATE pam_requests SET status='expired' WHERE status IN ('approved', 'active') AND expires_at < now();
UPDATE pam_requests SET status='expired', note='nobody decided within 24 hours'
	WHERE status='pending' AND created_at < now() - interval '24 hours';`)
	return err
}

func (p *Postgres) CreateElevation(ctx context.Context, e *Elevation) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO pam_requests (id, agent_id, hostname, username, uid, reason, duration_seconds, requested_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, e.ID, e.AgentID, e.Hostname, e.Username, e.UID, e.Reason, e.DurationSeconds, e.RequestedBy)
	return err
}

func (p *Postgres) GetElevation(ctx context.Context, id string) (*Elevation, error) {
	if err := p.expireElevations(ctx); err != nil {
		return nil, err
	}
	rows, err := p.pool.Query(ctx, `SELECT `+elevationCols+` FROM pam_requests WHERE id=$1`, id)
	if err != nil {
		return nil, err
	}
	e, err := pgx.CollectExactlyOneRow(rows, scanElevation)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

// PendingElevation returns the user's open request on an agent, if any.
func (p *Postgres) PendingElevation(ctx context.Context, agentID, user string) (*Elevation, error) {
	if err := p.expireElevations(ctx); err != nil {
		return nil, err
	}
	rows, err := p.pool.Query(ctx, `SELECT `+elevationCols+` FROM pam_requests
		WHERE agent_id=$1 AND username=$2 AND status='pending' LIMIT 1`, agentID, user)
	if err != nil {
		return nil, err
	}
	e, err := pgx.CollectExactlyOneRow(rows, scanElevation)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

func (p *Postgres) ListElevations(ctx context.Context, agentID, status string, limit int) ([]*Elevation, error) {
	if err := p.expireElevations(ctx); err != nil {
		return nil, err
	}
	rows, err := p.pool.Query(ctx, `SELECT `+elevationCols+` FROM pam_requests
		WHERE ($1 = '' OR agent_id = $1) AND ($2 = '' OR status = $2)
		ORDER BY (status = 'pending') DESC, created_at DESC LIMIT $3`, agentID, status, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanElevation)
}

// ApproveElevation records the decision and the grant command that carries it.
func (p *Postgres) ApproveElevation(ctx context.Context, id, by string, duration time.Duration, commandID string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE pam_requests SET status='approved', decided_by=$2, decided_at=now(),
		duration_seconds=$3, expires_at=now() + $3::bigint * interval '1 second', command_id=$4
		WHERE id=$1 AND status='pending'`, id, by, int64(duration.Seconds()), commandID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

// SetElevationStatus moves a request to status if it is in one of from.
func (p *Postgres) SetElevationStatus(ctx context.Context, id string, from []string, status, by, note string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE pam_requests SET status=$3,
		decided_by=CASE WHEN $4 = '' THEN decided_by ELSE $4 END,
		decided_at=CASE WHEN $4 = '' THEN decided_at ELSE now() END,
		note=CASE WHEN $5 = '' THEN note ELSE $5 END
		WHERE id=$1 AND status = ANY($2)`, id, from, status, by, note)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

func (p *Postgres) PendingElevationCount(ctx context.Context) (int, error) {
	if err := p.expireElevations(ctx); err != nil {
		return 0, err
	}
	var n int
	err := p.pool.QueryRow(ctx, `SELECT count(*) FROM pam_requests WHERE status='pending'`).Scan(&n)
	return n, err
}

// --- privileged accounts ---

type Inventory struct {
	AgentID     string          `json:"agent_id"`
	Hostname    string          `json:"hostname"`
	Accounts    json.RawMessage `json:"accounts"`
	Interactive int             `json:"interactive"`
	CollectedAt time.Time       `json:"collected_at"`
}

// SaveInventory replaces an agent's privileged accounts and returns the
// previous list, or nil when this is the first report.
func (p *Postgres) SaveInventory(ctx context.Context, agentID string, accounts []byte, interactive int) ([]byte, error) {
	var prev []byte
	err := p.pool.QueryRow(ctx, `SELECT accounts FROM pam_accounts WHERE agent_id=$1`, agentID).Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO pam_accounts (agent_id, accounts, interactive, collected_at) VALUES ($1,$2,$3,now())
		ON CONFLICT (agent_id) DO UPDATE SET accounts=EXCLUDED.accounts, interactive=EXCLUDED.interactive, collected_at=now()`,
		agentID, accounts, interactive)
	return prev, err
}

func (p *Postgres) ListInventory(ctx context.Context) ([]*Inventory, error) {
	rows, err := p.pool.Query(ctx, `SELECT i.agent_id, a.hostname, i.accounts, i.interactive, i.collected_at
		FROM pam_accounts i JOIN agents a ON a.id = i.agent_id ORDER BY a.hostname`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (*Inventory, error) {
		i := &Inventory{}
		err := row.Scan(&i.AgentID, &i.Hostname, &i.Accounts, &i.Interactive, &i.CollectedAt)
		return i, err
	})
}

// --- session recordings ---

type Session struct {
	ID         int64     `json:"id"`
	AgentID    string    `json:"agent_id"`
	Hostname   string    `json:"hostname"`
	SessionID  string    `json:"session_id"`
	Username   string    `json:"username"`
	RunasUser  string    `json:"runas_user"`
	TTY        string    `json:"tty"`
	Cwd        string    `json:"cwd"`
	Command    string    `json:"command"`
	StartedAt  time.Time `json:"started_at"`
	DurationMs int64     `json:"duration_ms"`
	Size       int64     `json:"size"`
	Truncated  bool      `json:"truncated"`
	RequestID  string    `json:"request_id"`
	// Output is only filled when one session is fetched.
	Output []byte `json:"-"`
}

func (p *Postgres) SaveSession(ctx context.Context, s *Session) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO pam_sessions (agent_id, hostname, session_id, username, runas_user, tty, cwd,
		command, started_at, duration_ms, output, truncated, request_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (agent_id, session_id) DO NOTHING`,
		s.AgentID, s.Hostname, s.SessionID, s.Username, s.RunasUser, s.TTY, s.Cwd, s.Command, s.StartedAt,
		s.DurationMs, s.Output, s.Truncated, s.RequestID)
	return err
}

const sessionCols = `id, agent_id, hostname, session_id, username, runas_user, tty, cwd, command, started_at,
	duration_ms, length(output), truncated, request_id`

func scanSession(row pgx.CollectableRow) (*Session, error) {
	s := &Session{}
	err := row.Scan(&s.ID, &s.AgentID, &s.Hostname, &s.SessionID, &s.Username, &s.RunasUser, &s.TTY, &s.Cwd,
		&s.Command, &s.StartedAt, &s.DurationMs, &s.Size, &s.Truncated, &s.RequestID)
	return s, err
}

func (p *Postgres) ListSessions(ctx context.Context, agentID, requestID string, limit int) ([]*Session, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+sessionCols+` FROM pam_sessions
		WHERE ($1 = '' OR agent_id = $1) AND ($2 = '' OR request_id = $2) ORDER BY started_at DESC LIMIT $3`,
		agentID, requestID, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanSession)
}

func (p *Postgres) GetSession(ctx context.Context, id int64) (*Session, error) {
	var s *Session
	var out []byte
	rows, err := p.pool.Query(ctx, `SELECT `+sessionCols+`, output FROM pam_sessions WHERE id=$1`, id)
	if err != nil {
		return nil, err
	}
	s, err = pgx.CollectExactlyOneRow(rows, func(row pgx.CollectableRow) (*Session, error) {
		s := &Session{}
		err := row.Scan(&s.ID, &s.AgentID, &s.Hostname, &s.SessionID, &s.Username, &s.RunasUser, &s.TTY, &s.Cwd,
			&s.Command, &s.StartedAt, &s.DurationMs, &s.Size, &s.Truncated, &s.RequestID, &out)
		return s, err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if s != nil {
		s.Output = out
	}
	return s, err
}

// --- policy ---

func (p *Postgres) PamRecordAll(ctx context.Context, agentID string) (bool, error) {
	var on bool
	err := p.pool.QueryRow(ctx, `SELECT pam_record_all FROM agents WHERE id=$1`, agentID).Scan(&on)
	return on, err
}

func (p *Postgres) SetPamRecordAll(ctx context.Context, agentID string, on bool) error {
	tag, err := p.pool.Exec(ctx, `UPDATE agents SET pam_record_all=$2 WHERE id=$1`, agentID, on)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
