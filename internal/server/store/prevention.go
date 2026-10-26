package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

func (p *Postgres) migratePrevention(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS settings (
	key        TEXT PRIMARY KEY,
	value      JSONB NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- NULL follows the fleet-wide policy in settings.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS prevention JSONB;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS prevention_state JSONB NOT NULL DEFAULT '{}';
`)
	return err
}

const preventionKey = "prevention_policy"

// GlobalPrevention is the fleet-wide policy as JSON, nil when never saved.
func (p *Postgres) GlobalPrevention(ctx context.Context) ([]byte, error) {
	var raw []byte
	err := p.pool.QueryRow(ctx, `SELECT value FROM settings WHERE key=$1`, preventionKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return raw, err
}

func (p *Postgres) SetGlobalPrevention(ctx context.Context, raw []byte) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, preventionKey, raw)
	return err
}

// AgentPrevention returns the endpoint's own policy (nil when it follows
// the fleet policy) and its last reported prevention state.
func (p *Postgres) AgentPrevention(ctx context.Context, id string) (custom, state []byte, err error) {
	err = p.pool.QueryRow(ctx, `SELECT prevention, prevention_state FROM agents WHERE id=$1`, id).Scan(&custom, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	return custom, state, err
}

// SetAgentPrevention stores an endpoint's own policy; nil returns it to the
// fleet policy.
func (p *Postgres) SetAgentPrevention(ctx context.Context, id string, raw []byte) error {
	var v any
	if raw != nil {
		v = json.RawMessage(raw)
	}
	tag, err := p.pool.Exec(ctx, `UPDATE agents SET prevention=$2 WHERE id=$1`, id, v)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) SetPreventionState(ctx context.Context, id string, raw []byte) error {
	_, err := p.pool.Exec(ctx, `UPDATE agents SET prevention_state=$2 WHERE id=$1`, id, raw)
	return err
}
