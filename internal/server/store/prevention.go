package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Bogan1011/xdr-agent/internal/policy"
)

// ErrDuplicate means a record with the same name exists.
var ErrDuplicate = errors.New("duplicate")

func (p *Postgres) migratePrevention(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS settings (
	key        TEXT PRIMARY KEY,
	value      JSONB NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Before named policies: an endpoint's own policy, NULL for the fleet policy.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS prevention JSONB;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS prevention_state JSONB NOT NULL DEFAULT '{}';
CREATE TABLE IF NOT EXISTS policies (
	id          BIGSERIAL PRIMARY KEY,
	name        TEXT NOT NULL UNIQUE,
	description TEXT NOT NULL DEFAULT '',
	is_default  BOOLEAN NOT NULL DEFAULT false,
	policy      JSONB NOT NULL,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS policies_one_default ON policies (is_default) WHERE is_default;
-- NULL follows the default policy.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS policy_id BIGINT REFERENCES policies(id) ON DELETE SET NULL;
`)
	if err != nil {
		return err
	}
	return p.migrateNamedPolicies(ctx)
}

// migrateNamedPolicies turns the fleet policy into the default policy and
// each endpoint's own policy into a named policy assigned to it.
func (p *Postgres) migrateNamedPolicies(ctx context.Context) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM policies WHERE is_default`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT value FROM settings WHERE key='prevention_policy'`).Scan(&raw)
		if errors.Is(err, pgx.ErrNoRows) {
			raw, err = policy.MarshalJSON(policy.Default()), nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO policies (name, description, is_default, policy)
			VALUES ('Default', 'Applies to every endpoint without another policy.', true, $1)`, raw); err != nil {
			return err
		}
	}
	rows, err := tx.Query(ctx, `SELECT id, hostname, prevention FROM agents WHERE prevention IS NOT NULL AND policy_id IS NULL`)
	if err != nil {
		return err
	}
	type own struct {
		id, host string
		raw      []byte
	}
	var owns []own
	for rows.Next() {
		var o own
		if err := rows.Scan(&o.id, &o.host, &o.raw); err != nil {
			return err
		}
		owns = append(owns, o)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, o := range owns {
		var pid int64
		name := fmt.Sprintf("%s (custom %s)", o.host, o.id[:min(8, len(o.id))])
		if err := tx.QueryRow(ctx, `INSERT INTO policies (name, description, policy) VALUES ($1, $2, $3) RETURNING id`,
			name, "Made from the endpoint's own policy.", o.raw).Scan(&pid); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE agents SET policy_id=$2, prevention=NULL WHERE id=$1`, o.id, pid); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

type Policy struct {
	ID          int64           `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	IsDefault   bool            `json:"is_default"`
	Policy      json.RawMessage `json:"policy,omitempty"`
	Endpoints   int             `json:"endpoints"`
	Version     int64           `json:"version"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// effectivePolicy is the policy id an agents row follows.
const effectivePolicy = `COALESCE(agents.policy_id, (SELECT id FROM policies WHERE is_default))`

const policyCols = `p.id, p.name, p.description, p.is_default, p.policy, p.updated_at, p.version,
	(SELECT count(*) FROM agents WHERE NOT revoked AND ` + effectivePolicy + ` = p.id)`

func scanPolicy(row pgx.Row) (*Policy, error) {
	pol := &Policy{}
	err := row.Scan(&pol.ID, &pol.Name, &pol.Description, &pol.IsDefault, &pol.Policy, &pol.UpdatedAt, &pol.Version, &pol.Endpoints)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return pol, err
}

func (p *Postgres) ListPolicies(ctx context.Context) ([]*Policy, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+policyCols+` FROM policies p ORDER BY NOT p.is_default, lower(p.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Policy{}
	for rows.Next() {
		pol, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, pol)
	}
	return out, rows.Err()
}

func (p *Postgres) GetPolicy(ctx context.Context, id int64) (*Policy, error) {
	return scanPolicy(p.pool.QueryRow(ctx, `SELECT `+policyCols+` FROM policies p WHERE p.id=$1`, id))
}

func uniqueErr(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return ErrDuplicate
	}
	return err
}

func (p *Postgres) CreatePolicy(ctx context.Context, name, desc string, raw []byte) (int64, error) {
	var id int64
	err := p.pool.QueryRow(ctx, `INSERT INTO policies (name, description, policy) VALUES ($1,$2,$3) RETURNING id`,
		name, desc, raw).Scan(&id)
	return id, uniqueErr(err)
}

func (p *Postgres) UpdatePolicy(ctx context.Context, id int64, name, desc string, raw []byte) error {
	tag, err := p.pool.Exec(ctx, `UPDATE policies SET name=$2, description=$3, policy=$4, updated_at=now(), version=version+1 WHERE id=$1`,
		id, name, desc, raw)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return uniqueErr(err)
}

// DeletePolicy removes a policy; its endpoints return to the default policy.
// The default policy cannot be deleted (ErrConflict).
func (p *Postgres) DeletePolicy(ctx context.Context, id int64) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM policies WHERE id=$1 AND NOT is_default`, id)
	if err == nil && tag.RowsAffected() == 0 {
		if _, gerr := p.GetPolicy(ctx, id); gerr != nil {
			return gerr
		}
		return ErrConflict
	}
	return err
}

// PolicyEndpoints lists the endpoints that follow a policy.
func (p *Postgres) PolicyEndpoints(ctx context.Context, id int64) ([]*Agent, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+agentCols+` FROM agents WHERE NOT revoked AND `+effectivePolicy+` = $1
		ORDER BY hostname`, id)
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

// AgentPolicy returns the policy an endpoint follows and its last reported
// prevention state.
func (p *Postgres) AgentPolicy(ctx context.Context, agentID string) (*Policy, []byte, error) {
	var state []byte
	pol := &Policy{}
	err := p.pool.QueryRow(ctx, `SELECT p.id, p.name, p.description, p.is_default, p.policy, p.updated_at, p.version, a.prevention_state
		FROM agents a JOIN policies p ON p.id = COALESCE(a.policy_id, (SELECT id FROM policies WHERE is_default))
		WHERE a.id=$1`, agentID).Scan(&pol.ID, &pol.Name, &pol.Description, &pol.IsDefault, &pol.Policy, &pol.UpdatedAt, &pol.Version, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	return pol, state, err
}

// SetAgentPolicy assigns endpoints to a policy; 0 is the default policy.
func (p *Postgres) SetAgentPolicy(ctx context.Context, policyID int64, agentIDs ...string) error {
	var v any
	if policyID != 0 {
		pol, err := p.GetPolicy(ctx, policyID)
		if err != nil {
			return err
		}
		if !pol.IsDefault {
			v = policyID
		}
	}
	tag, err := p.pool.Exec(ctx, `UPDATE agents SET policy_id=$2 WHERE id = ANY($1)`, agentIDs, v)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) SetPreventionState(ctx context.Context, id string, raw []byte) error {
	_, err := p.pool.Exec(ctx, `UPDATE agents SET prevention_state=$2 WHERE id=$1`, id, raw)
	return err
}
