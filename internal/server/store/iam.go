package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Bogan1011/xdr-agent/internal/server/iam"
	"github.com/Bogan1011/xdr-agent/internal/server/pam"
)

// migrateIAM adds the identity and access model: users, roles, asset
// groups, access policies, approvals, privileged sessions and the audit log.
// It runs after tenancy so every table can reference tenants.
func (p *Postgres) migrateIAM(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS roles (
	tenant_id   TEXT NOT NULL DEFAULT 'default' REFERENCES tenants(id),
	id          TEXT NOT NULL,
	name        TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	permissions TEXT[] NOT NULL DEFAULT '{}',
	builtin     BOOLEAN NOT NULL DEFAULT false,
	PRIMARY KEY (tenant_id, id)
);
CREATE TABLE IF NOT EXISTS users (
	id            TEXT PRIMARY KEY,
	tenant_id     TEXT NOT NULL DEFAULT 'default' REFERENCES tenants(id),
	username      TEXT NOT NULL,
	display_name  TEXT NOT NULL DEFAULT '',
	email         TEXT NOT NULL DEFAULT '',
	role_id       TEXT NOT NULL,
	password_salt TEXT NOT NULL,
	password_hash TEXT NOT NULL,
	builtin       BOOLEAN NOT NULL DEFAULT false,
	disabled      BOOLEAN NOT NULL DEFAULT false,
	mfa_secret    TEXT NOT NULL DEFAULT '',
	mfa_enabled   BOOLEAN NOT NULL DEFAULT false,
	created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
	last_login    TIMESTAMPTZ,
	UNIQUE (tenant_id, username)
);
CREATE TABLE IF NOT EXISTS asset_groups (
	id          BIGSERIAL PRIMARY KEY,
	tenant_id   TEXT NOT NULL DEFAULT 'default' REFERENCES tenants(id),
	name        TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	criticality TEXT NOT NULL DEFAULT 'medium',
	environment TEXT NOT NULL DEFAULT 'production',
	all_assets  BOOLEAN NOT NULL DEFAULT false,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE (tenant_id, name)
);
CREATE TABLE IF NOT EXISTS asset_group_members (
	group_id BIGINT NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
	agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	PRIMARY KEY (group_id, agent_id)
);
CREATE TABLE IF NOT EXISTS access_policies (
	id               BIGSERIAL PRIMARY KEY,
	tenant_id        TEXT NOT NULL DEFAULT 'default' REFERENCES tenants(id),
	name             TEXT NOT NULL,
	description      TEXT NOT NULL DEFAULT '',
	enabled          BOOLEAN NOT NULL DEFAULT true,
	priority         INT NOT NULL DEFAULT 100,
	effect           TEXT NOT NULL DEFAULT 'allow',
	subject_roles    TEXT[] NOT NULL DEFAULT '{}',
	subject_users    TEXT[] NOT NULL DEFAULT '{}',
	asset_groups     BIGINT[] NOT NULL DEFAULT '{}',
	access_types     TEXT[] NOT NULL DEFAULT '{}',
	accounts         TEXT[] NOT NULL DEFAULT '{}',
	require_approval BOOLEAN NOT NULL DEFAULT false,
	approvals        INT NOT NULL DEFAULT 1,
	require_mfa      BOOLEAN NOT NULL DEFAULT false,
	require_ticket   BOOLEAN NOT NULL DEFAULT false,
	max_minutes      INT NOT NULL DEFAULT 60,
	hours_from       INT NOT NULL DEFAULT 0,
	hours_to         INT NOT NULL DEFAULT 24,
	incident_mode    TEXT NOT NULL DEFAULT 'none',
	updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE (tenant_id, name)
);
-- Access requests: pam_requests now holds both JIT sudo and shell requests.
ALTER TABLE pam_requests ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'jit_sudo';
ALTER TABLE pam_requests ADD COLUMN IF NOT EXISTS requester_id TEXT NOT NULL DEFAULT '';
ALTER TABLE pam_requests ADD COLUMN IF NOT EXISTS ticket TEXT NOT NULL DEFAULT '';
ALTER TABLE pam_requests ADD COLUMN IF NOT EXISTS policy_id BIGINT NOT NULL DEFAULT 0;
ALTER TABLE pam_requests ADD COLUMN IF NOT EXISTS policy_name TEXT NOT NULL DEFAULT '';
ALTER TABLE pam_requests ADD COLUMN IF NOT EXISTS approvals_required INT NOT NULL DEFAULT 1;
ALTER TABLE pam_requests ADD COLUMN IF NOT EXISTS emergency BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE pam_requests ADD COLUMN IF NOT EXISTS incident TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS approvals (
	id          BIGSERIAL PRIMARY KEY,
	tenant_id   TEXT NOT NULL DEFAULT 'default' REFERENCES tenants(id),
	request_id  TEXT NOT NULL REFERENCES pam_requests(id) ON DELETE CASCADE,
	approver_id TEXT NOT NULL,
	approver    TEXT NOT NULL,
	decision    TEXT NOT NULL,
	note        TEXT NOT NULL DEFAULT '',
	emergency   BOOLEAN NOT NULL DEFAULT false,
	at          TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE (request_id, approver_id)
);
-- A privileged session is a first-class security object: who, where, how,
-- under which approval, and what it was scored.
CREATE TABLE IF NOT EXISTS access_sessions (
	id           TEXT PRIMARY KEY,
	tenant_id    TEXT NOT NULL DEFAULT 'default' REFERENCES tenants(id),
	user_id      TEXT NOT NULL DEFAULT '',
	username     TEXT NOT NULL,
	agent_id     TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	hostname     TEXT NOT NULL,
	protocol     TEXT NOT NULL,
	account      TEXT NOT NULL DEFAULT '',
	source_ip    TEXT NOT NULL DEFAULT '',
	user_agent   TEXT NOT NULL DEFAULT '',
	auth_method  TEXT NOT NULL DEFAULT '',
	request_id   TEXT NOT NULL DEFAULT '',
	policy_name  TEXT NOT NULL DEFAULT '',
	ticket       TEXT NOT NULL DEFAULT '',
	recording_id BIGINT NOT NULL DEFAULT 0,
	started_at   TIMESTAMPTZ NOT NULL,
	ended_at     TIMESTAMPTZ,
	end_reason   TEXT NOT NULL DEFAULT '',
	risk_score   INT NOT NULL DEFAULT 0,
	risk_reasons TEXT[] NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS access_sessions_started ON access_sessions (started_at DESC);
CREATE TABLE IF NOT EXISTS audit_log (
	id        BIGSERIAL PRIMARY KEY,
	tenant_id TEXT NOT NULL DEFAULT 'default' REFERENCES tenants(id),
	at        TIMESTAMPTZ NOT NULL DEFAULT now(),
	actor     TEXT NOT NULL,
	actor_id  TEXT NOT NULL DEFAULT '',
	action    TEXT NOT NULL,
	target    TEXT NOT NULL DEFAULT '',
	outcome   TEXT NOT NULL DEFAULT '',
	remote    TEXT NOT NULL DEFAULT '',
	detail    JSONB NOT NULL DEFAULT '{}',
	prev_hash TEXT NOT NULL,
	hash      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_at ON audit_log (at DESC);
INSERT INTO asset_groups (name, description, criticality, all_assets)
	VALUES ('All servers', 'Every enrolled endpoint.', 'medium', true) ON CONFLICT DO NOTHING;
`)
	if err != nil {
		return err
	}
	for _, r := range iam.BuiltinRoles {
		if _, err := p.pool.Exec(ctx, `INSERT INTO roles (id, name, description, permissions, builtin) VALUES ($1,$2,$3,$4,true)
			ON CONFLICT (tenant_id, id) DO UPDATE SET name=$2, description=$3, permissions=$4, builtin=true`,
			r.ID, r.Name, r.Description, r.Permissions); err != nil {
			return err
		}
	}
	var n int
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM access_policies`).Scan(&n); err != nil || n > 0 {
		return err
	}
	var all int64
	if err := p.pool.QueryRow(ctx, `SELECT id FROM asset_groups WHERE tenant_id='default' AND all_assets`).Scan(&all); err != nil {
		return err
	}
	for _, pol := range pam.DefaultPolicies(all) {
		if err := p.SaveAccessPolicy(ctx, DefaultTenant, &pol); err != nil {
			return err
		}
	}
	return nil
}

// --- users ---

type User struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email"`
	RoleID      string    `json:"role_id"`
	Builtin     bool      `json:"builtin"`
	Disabled    bool      `json:"disabled"`
	MFAEnabled  bool      `json:"mfa_enabled"`
	CreatedAt   time.Time `json:"created_at"`
	LastLogin   time.Time `json:"last_login"`

	PasswordSalt string `json:"-"`
	PasswordHash string `json:"-"`
	MFASecret    string `json:"-"`
	// Permissions are the role's, filled when the user is loaded.
	Permissions []string `json:"permissions"`
}

const userCols = `u.id, u.tenant_id, u.username, u.display_name, u.email, u.role_id, u.builtin, u.disabled, u.mfa_enabled,
	u.created_at, COALESCE(u.last_login, 'epoch'), u.password_salt, u.password_hash, u.mfa_secret, COALESCE(r.permissions, '{}')`

func scanUser(row pgx.CollectableRow) (*User, error) {
	u := &User{}
	err := row.Scan(&u.ID, &u.TenantID, &u.Username, &u.DisplayName, &u.Email, &u.RoleID, &u.Builtin, &u.Disabled,
		&u.MFAEnabled, &u.CreatedAt, &u.LastLogin, &u.PasswordSalt, &u.PasswordHash, &u.MFASecret, &u.Permissions)
	return u, err
}

func (p *Postgres) users(ctx context.Context, where string, args ...any) ([]*User, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+userCols+` FROM users u
		LEFT JOIN roles r ON r.tenant_id = u.tenant_id AND r.id = u.role_id WHERE `+where+` ORDER BY u.username`, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanUser)
}

func (p *Postgres) oneUser(ctx context.Context, where string, args ...any) (*User, error) {
	us, err := p.users(ctx, where, args...)
	if err != nil {
		return nil, err
	}
	if len(us) == 0 {
		return nil, ErrNotFound
	}
	return us[0], nil
}

func (p *Postgres) GetUser(ctx context.Context, id string) (*User, error) {
	return p.oneUser(ctx, `u.id = $1`, id)
}

func (p *Postgres) UserByName(ctx context.Context, tenant, username string) (*User, error) {
	return p.oneUser(ctx, `u.tenant_id = $1 AND u.username = $2`, tenant, username)
}

func (p *Postgres) ListUsers(ctx context.Context, tenant string) ([]*User, error) {
	return p.users(ctx, `u.tenant_id = $1`, tenant)
}

// EnsureBootstrapAdmin keeps the break-glass administrator from the server's
// environment: created on first start, its password and role reset on every
// start so the .env credentials always work.
func (p *Postgres) EnsureBootstrapAdmin(ctx context.Context, username, password string) error {
	salt, hash, err := iam.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO users (id, username, display_name, role_id, password_salt, password_hash, builtin)
		VALUES ($1,$2,$2,'admin',$3,$4,true)
		ON CONFLICT (tenant_id, username) DO UPDATE SET password_salt=$3, password_hash=$4, role_id='admin', builtin=true, disabled=false`,
		newToken()[:24], username, salt, hash)
	if err != nil {
		return err
	}
	// A renamed break-glass account must not keep working.
	_, err = p.pool.Exec(ctx, `UPDATE users SET builtin=false, disabled=true WHERE builtin AND username<>$1`, username)
	return err
}

func (p *Postgres) CreateUser(ctx context.Context, u *User, password string) error {
	salt, hash, err := iam.HashPassword(password)
	if err != nil {
		return err
	}
	u.ID = newToken()[:24]
	_, err = p.pool.Exec(ctx, `INSERT INTO users (id, tenant_id, username, display_name, email, role_id, password_salt, password_hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, u.ID, u.TenantID, u.Username, u.DisplayName, u.Email, u.RoleID, salt, hash)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

func (p *Postgres) UpdateUser(ctx context.Context, u *User) error {
	tag, err := p.pool.Exec(ctx, `UPDATE users SET display_name=$2, email=$3, role_id=$4, disabled=$5 WHERE id=$1`,
		u.ID, u.DisplayName, u.Email, u.RoleID, u.Disabled)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) SetUserPassword(ctx context.Context, id, password string) error {
	salt, hash, err := iam.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `UPDATE users SET password_salt=$2, password_hash=$3 WHERE id=$1`, id, salt, hash)
	return err
}

// SetUserMFA stores a secret; enabled turns it on once the user proved it.
func (p *Postgres) SetUserMFA(ctx context.Context, id, secret string, enabled bool) error {
	_, err := p.pool.Exec(ctx, `UPDATE users SET mfa_secret=$2, mfa_enabled=$3 WHERE id=$1`, id, secret, enabled)
	return err
}

func (p *Postgres) TouchLogin(ctx context.Context, id string) error {
	_, err := p.pool.Exec(ctx, `UPDATE users SET last_login=now() WHERE id=$1`, id)
	return err
}

func (p *Postgres) DeleteUser(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM users WHERE id=$1 AND NOT builtin`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// --- roles ---

func (p *Postgres) ListRoles(ctx context.Context, tenant string) ([]iam.Role, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, name, description, permissions, builtin FROM roles WHERE tenant_id=$1
		ORDER BY builtin DESC, name`, tenant)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (iam.Role, error) {
		var r iam.Role
		err := row.Scan(&r.ID, &r.Name, &r.Description, &r.Permissions, &r.Builtin)
		return r, err
	})
}

func (p *Postgres) RoleExists(ctx context.Context, tenant, id string) (bool, error) {
	var ok bool
	err := p.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM roles WHERE tenant_id=$1 AND id=$2)`, tenant, id).Scan(&ok)
	return ok, err
}

// SaveRole creates or updates a custom role; built-in roles are fixed.
func (p *Postgres) SaveRole(ctx context.Context, tenant string, r iam.Role) error {
	tag, err := p.pool.Exec(ctx, `INSERT INTO roles (tenant_id, id, name, description, permissions) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (tenant_id, id) DO UPDATE SET name=$3, description=$4, permissions=$5 WHERE NOT roles.builtin`,
		tenant, r.ID, r.Name, r.Description, r.Permissions)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

func (p *Postgres) DeleteRole(ctx context.Context, tenant, id string) error {
	var used bool
	if err := p.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE tenant_id=$1 AND role_id=$2)`, tenant, id).Scan(&used); err != nil {
		return err
	}
	if used {
		return ErrConflict
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM roles WHERE tenant_id=$1 AND id=$2 AND NOT builtin`, tenant, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// --- asset groups ---

type AssetGroup struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Criticality string   `json:"criticality"`
	Environment string   `json:"environment"`
	AllAssets   bool     `json:"all_assets"`
	AgentIDs    []string `json:"agent_ids"`
}

func (p *Postgres) ListAssetGroups(ctx context.Context, tenant string) ([]*AssetGroup, error) {
	rows, err := p.pool.Query(ctx, `SELECT g.id, g.name, g.description, g.criticality, g.environment, g.all_assets,
		COALESCE(array_agg(m.agent_id) FILTER (WHERE m.agent_id IS NOT NULL), '{}')
		FROM asset_groups g LEFT JOIN asset_group_members m ON m.group_id = g.id
		WHERE g.tenant_id=$1 GROUP BY g.id ORDER BY g.all_assets DESC, g.name`, tenant)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (*AssetGroup, error) {
		g := &AssetGroup{}
		err := row.Scan(&g.ID, &g.Name, &g.Description, &g.Criticality, &g.Environment, &g.AllAssets, &g.AgentIDs)
		return g, err
	})
}

// SaveAssetGroup creates (ID 0) or updates a group and replaces its members.
func (p *Postgres) SaveAssetGroup(ctx context.Context, tenant string, g *AssetGroup) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if g.ID == 0 {
		err = tx.QueryRow(ctx, `INSERT INTO asset_groups (tenant_id, name, description, criticality, environment)
			VALUES ($1,$2,$3,$4,$5) RETURNING id`, tenant, g.Name, g.Description, g.Criticality, g.Environment).Scan(&g.ID)
	} else {
		var tag interface{ RowsAffected() int64 }
		tag, err = tx.Exec(ctx, `UPDATE asset_groups SET name=$3, description=$4, criticality=$5, environment=$6
			WHERE id=$1 AND tenant_id=$2`, g.ID, tenant, g.Name, g.Description, g.Criticality, g.Environment)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
	}
	if isUnique(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM asset_group_members WHERE group_id=$1`, g.ID); err != nil {
		return err
	}
	if !g.AllAssets && len(g.AgentIDs) > 0 {
		if _, err := tx.Exec(ctx, `INSERT INTO asset_group_members (group_id, agent_id)
			SELECT $1, id FROM agents WHERE id = ANY($2) ON CONFLICT DO NOTHING`, g.ID, g.AgentIDs); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (p *Postgres) DeleteAssetGroup(ctx context.Context, tenant string, id int64) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM asset_groups WHERE id=$1 AND tenant_id=$2 AND NOT all_assets`, id, tenant)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err == nil {
		_, err = p.pool.Exec(ctx, `UPDATE access_policies SET asset_groups = array_remove(asset_groups, $1)`, id)
	}
	return err
}

// AssetContext is what access decisions need about a server: its groups,
// and the highest severity of its open alerts.
func (p *Postgres) AssetContext(ctx context.Context, tenant, agentID string) (groups []int64, incident string, err error) {
	err = p.pool.QueryRow(ctx, `SELECT COALESCE(array_agg(g.id), '{}') FROM asset_groups g
		WHERE g.tenant_id=$1 AND (g.all_assets OR EXISTS (SELECT 1 FROM asset_group_members m WHERE m.group_id=g.id AND m.agent_id=$2))`,
		tenant, agentID).Scan(&groups)
	if err != nil {
		return nil, "", err
	}
	err = p.pool.QueryRow(ctx, `SELECT COALESCE((SELECT severity FROM alerts WHERE agent_id=$1 AND status IN ('new','in_progress')
		ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC LIMIT 1), '')`,
		agentID).Scan(&incident)
	return groups, incident, err
}

// --- access policies ---

const accessPolicyCols = `id, name, description, enabled, priority, effect, subject_roles, subject_users, asset_groups, access_types,
	accounts, require_approval, approvals, require_mfa, require_ticket, max_minutes, hours_from, hours_to, incident_mode`

func (p *Postgres) ListAccessPolicies(ctx context.Context, tenant string) ([]pam.Policy, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+accessPolicyCols+` FROM access_policies WHERE tenant_id=$1 ORDER BY priority, id`, tenant)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (pam.Policy, error) {
		var x pam.Policy
		err := row.Scan(&x.ID, &x.Name, &x.Description, &x.Enabled, &x.Priority, &x.Effect, &x.SubjectRoles, &x.SubjectUsers,
			&x.AssetGroups, &x.AccessTypes, &x.Accounts, &x.RequireApproval, &x.Approvals, &x.RequireMFA, &x.RequireTicket,
			&x.MaxMinutes, &x.HoursFrom, &x.HoursTo, &x.IncidentMode)
		return x, err
	})
}

// SaveAccessPolicy creates (ID 0) or updates a policy.
func (p *Postgres) SaveAccessPolicy(ctx context.Context, tenant string, x *pam.Policy) error {
	nz := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	args := []any{tenant, x.Name, x.Description, x.Enabled, x.Priority, x.Effect, nz(x.SubjectRoles), nz(x.SubjectUsers),
		x.AssetGroups, x.AccessTypes, nz(x.Accounts), x.RequireApproval, x.Approvals, x.RequireMFA, x.RequireTicket,
		x.MaxMinutes, x.HoursFrom, x.HoursTo, x.IncidentMode}
	var err error
	if x.ID == 0 {
		err = p.pool.QueryRow(ctx, `INSERT INTO access_policies (tenant_id, name, description, enabled, priority, effect,
			subject_roles, subject_users, asset_groups, access_types, accounts, require_approval, approvals, require_mfa,
			require_ticket, max_minutes, hours_from, hours_to, incident_mode)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) RETURNING id`, args...).Scan(&x.ID)
	} else {
		var tag interface{ RowsAffected() int64 }
		tag, err = p.pool.Exec(ctx, `UPDATE access_policies SET name=$2, description=$3, enabled=$4, priority=$5, effect=$6,
			subject_roles=$7, subject_users=$8, asset_groups=$9, access_types=$10, accounts=$11, require_approval=$12,
			approvals=$13, require_mfa=$14, require_ticket=$15, max_minutes=$16, hours_from=$17, hours_to=$18,
			incident_mode=$19, updated_at=now() WHERE tenant_id=$1 AND id=$20`, append(args, x.ID)...)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
	}
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

func (p *Postgres) DeleteAccessPolicy(ctx context.Context, tenant string, id int64) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM access_policies WHERE tenant_id=$1 AND id=$2`, tenant, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// --- approvals ---

type Approval struct {
	RequestID string    `json:"request_id"`
	Approver  string    `json:"approver"`
	Decision  string    `json:"decision"`
	Note      string    `json:"note"`
	Emergency bool      `json:"emergency"`
	At        time.Time `json:"at"`
}

// AddApproval records one approver's decision and returns how many distinct
// approvals the request now has. Each approver counts once.
func (p *Postgres) AddApproval(ctx context.Context, requestID, approverID, approver, decision, note string, emergency bool) (int, error) {
	_, err := p.pool.Exec(ctx, `INSERT INTO approvals (request_id, approver_id, approver, decision, note, emergency)
		VALUES ($1,$2,$3,$4,$5,$6)`, requestID, approverID, approver, decision, note, emergency)
	if isUnique(err) {
		return 0, ErrConflict
	}
	if err != nil {
		return 0, err
	}
	var n int
	err = p.pool.QueryRow(ctx, `SELECT count(*) FROM approvals WHERE request_id=$1 AND decision='approve'`, requestID).Scan(&n)
	return n, err
}

func (p *Postgres) ListApprovals(ctx context.Context, requestIDs []string) (map[string][]Approval, error) {
	out := map[string][]Approval{}
	rows, err := p.pool.Query(ctx, `SELECT request_id, approver, decision, note, emergency, at FROM approvals
		WHERE request_id = ANY($1) ORDER BY at`, requestIDs)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Approval, error) {
		var a Approval
		err := row.Scan(&a.RequestID, &a.Approver, &a.Decision, &a.Note, &a.Emergency, &a.At)
		return a, err
	})
	for _, a := range list {
		out[a.RequestID] = append(out[a.RequestID], a)
	}
	return out, err
}

// --- privileged sessions ---

type AccessSession struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Username    string    `json:"username"`
	AgentID     string    `json:"agent_id"`
	Hostname    string    `json:"hostname"`
	Protocol    string    `json:"protocol"` // browser_shell or sudo
	Account     string    `json:"account"`
	SourceIP    string    `json:"source_ip"`
	UserAgent   string    `json:"user_agent"`
	AuthMethod  string    `json:"auth_method"`
	RequestID   string    `json:"request_id"`
	PolicyName  string    `json:"policy_name"`
	Ticket      string    `json:"ticket"`
	RecordingID int64     `json:"recording_id"`
	StartedAt   time.Time `json:"started_at"`
	EndedAt     time.Time `json:"ended_at"`
	EndReason   string    `json:"end_reason"`
	RiskScore   int       `json:"risk_score"`
	RiskReasons []string  `json:"risk_reasons"`
}

func (p *Postgres) StartAccessSession(ctx context.Context, s *AccessSession) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO access_sessions (id, user_id, username, agent_id, hostname, protocol, account,
		source_ip, user_agent, auth_method, request_id, policy_name, ticket, recording_id, started_at, ended_at, end_reason,
		risk_score, risk_reasons) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NULLIF($16,'epoch'::timestamptz),$17,$18,$19)
		ON CONFLICT (id) DO NOTHING`,
		s.ID, s.UserID, s.Username, s.AgentID, s.Hostname, s.Protocol, s.Account, s.SourceIP, s.UserAgent, s.AuthMethod,
		s.RequestID, s.PolicyName, s.Ticket, s.RecordingID, s.StartedAt, epochIfZero(s.EndedAt), s.EndReason, s.RiskScore,
		nonNil(s.RiskReasons))
	return err
}

func (p *Postgres) EndAccessSession(ctx context.Context, id string, recordingID int64, reason string, risk int, why []string) error {
	_, err := p.pool.Exec(ctx, `UPDATE access_sessions SET ended_at=now(), recording_id=$2, end_reason=$3, risk_score=$4,
		risk_reasons=$5 WHERE id=$1`, id, recordingID, reason, risk, nonNil(why))
	return err
}

// SeenSource reports whether the user had a session from ip before.
func (p *Postgres) SeenSource(ctx context.Context, userID, ip, except string) (bool, error) {
	var ok bool
	err := p.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM access_sessions WHERE user_id=$1 AND source_ip=$2 AND id<>$3)`,
		userID, ip, except).Scan(&ok)
	return ok, err
}

// AlertsBetween counts alerts first seen on an agent in a time window.
func (p *Postgres) AlertsBetween(ctx context.Context, agentID string, from, to time.Time) ([]*Alert, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+alertCols+` FROM alerts WHERE agent_id=$1 AND first_seen BETWEEN $2 AND $3
		ORDER BY first_seen LIMIT 100`, agentID, from, to)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAlert)
}

const accessSessionCols = `id, user_id, username, agent_id, hostname, protocol, account, source_ip, user_agent, auth_method,
	request_id, policy_name, ticket, recording_id, started_at, COALESCE(ended_at, 'epoch'), end_reason, risk_score, risk_reasons`

func scanAccessSession(row pgx.CollectableRow) (*AccessSession, error) {
	s := &AccessSession{}
	err := row.Scan(&s.ID, &s.UserID, &s.Username, &s.AgentID, &s.Hostname, &s.Protocol, &s.Account, &s.SourceIP, &s.UserAgent,
		&s.AuthMethod, &s.RequestID, &s.PolicyName, &s.Ticket, &s.RecordingID, &s.StartedAt, &s.EndedAt, &s.EndReason,
		&s.RiskScore, &s.RiskReasons)
	return s, err
}

func (p *Postgres) ListAccessSessions(ctx context.Context, agentID, username string, limit int) ([]*AccessSession, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+accessSessionCols+` FROM access_sessions
		WHERE ($1 = '' OR agent_id = $1) AND ($2 = '' OR username = $2) ORDER BY started_at DESC LIMIT $3`, agentID, username, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAccessSession)
}

func (p *Postgres) GetAccessSession(ctx context.Context, id string) (*AccessSession, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+accessSessionCols+` FROM access_sessions WHERE id=$1`, id)
	if err != nil {
		return nil, err
	}
	s, err := pgx.CollectExactlyOneRow(rows, scanAccessSession)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return s, err
}

// --- audit ---

type AuditEntry struct {
	ID       int64           `json:"id"`
	At       time.Time       `json:"at"`
	Actor    string          `json:"actor"`
	ActorID  string          `json:"actor_id"`
	Action   string          `json:"action"`
	Target   string          `json:"target"`
	Outcome  string          `json:"outcome"`
	Remote   string          `json:"remote"`
	Detail   json.RawMessage `json:"detail"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
}

func auditHash(e *AuditEntry) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s|%s|%s|%s|%s", e.PrevHash, e.At.UTC().Format(time.RFC3339Nano), e.Actor, e.ActorID,
		e.Action, e.Target, e.Outcome, e.Remote, e.Detail)
	return hex.EncodeToString(h.Sum(nil))
}

// Audit appends to the audit log. Each entry hashes the one before, so an
// edited or deleted row breaks the chain VerifyAudit walks.
func (p *Postgres) Audit(ctx context.Context, e *AuditEntry) error {
	if len(e.Detail) == 0 {
		e.Detail = json.RawMessage(`{}`)
	}
	// Postgres normalises JSONB, so hash what it will hand back.
	var norm []byte
	if err := p.pool.QueryRow(ctx, `SELECT $1::jsonb::text`, string(e.Detail)).Scan(&norm); err != nil {
		return err
	}
	e.Detail = norm
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7262021)`); err != nil {
		return err
	}
	e.PrevHash = ""
	err = tx.QueryRow(ctx, `SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&e.PrevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	e.At = time.Now().UTC().Truncate(time.Microsecond)
	e.Hash = auditHash(e)
	if err := tx.QueryRow(ctx, `INSERT INTO audit_log (at, actor, actor_id, action, target, outcome, remote, detail, prev_hash, hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`, e.At, e.Actor, e.ActorID, e.Action, e.Target, e.Outcome, e.Remote,
		string(e.Detail), e.PrevHash, e.Hash).Scan(&e.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const auditCols = `id, at, actor, actor_id, action, target, outcome, remote, detail::text, prev_hash, hash`

func scanAudit(row pgx.CollectableRow) (*AuditEntry, error) {
	e := &AuditEntry{}
	var detail string
	err := row.Scan(&e.ID, &e.At, &e.Actor, &e.ActorID, &e.Action, &e.Target, &e.Outcome, &e.Remote, &detail, &e.PrevHash, &e.Hash)
	e.Detail = json.RawMessage(detail)
	return e, err
}

func (p *Postgres) ListAudit(ctx context.Context, search string, limit int) ([]*AuditEntry, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+auditCols+` FROM audit_log WHERE $1 = '' OR actor ILIKE '%'||$1||'%'
		OR action ILIKE '%'||$1||'%' OR target ILIKE '%'||$1||'%' ORDER BY id DESC LIMIT $2`, search, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAudit)
}

// VerifyAudit walks the whole chain and returns the number of entries and
// the id of the first one that does not match, or 0.
func (p *Postgres) VerifyAudit(ctx context.Context) (checked int, brokenAt int64, err error) {
	rows, err := p.pool.Query(ctx, `SELECT `+auditCols+` FROM audit_log ORDER BY id`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return checked, 0, err
		}
		checked++
		if e.PrevHash != prev || auditHash(e) != e.Hash {
			return checked, e.ID, nil
		}
		prev = e.Hash
	}
	return checked, 0, rows.Err()
}

// --- helpers ---

func epochIfZero(t time.Time) time.Time {
	if t.IsZero() {
		return time.Unix(0, 0).UTC()
	}
	return t
}

// ParseID parses a numeric path id.
func ParseID(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }

func newToken() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func isUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// DecideAccess runs the access-policy engine for a request on agentID,
// filling in the server's asset groups and incident state.
func (p *Postgres) DecideAccess(ctx context.Context, tenant, agentID string, r pam.Request) (pam.Decision, string, error) {
	groups, incident, err := p.AssetContext(ctx, tenant, agentID)
	if err != nil {
		return pam.Decision{}, "", err
	}
	policies, err := p.ListAccessPolicies(ctx, tenant)
	if err != nil {
		return pam.Decision{}, "", err
	}
	r.AssetGroups, r.Incident, r.Now = groups, incident, time.Now()
	return pam.Decide(policies, r), incident, nil
}
