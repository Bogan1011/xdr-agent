package store

import (
	"context"
	"time"
)

// DefaultTenant owns everything until multi-tenancy reaches the console.
const DefaultTenant = "default"

// tenantTables are the configuration tables that carry tenant_id. Settings
// and pinned SSH host keys stay server-wide.
var tenantTables = []string{
	"agents", "enrollment_tokens", "deploy_jobs", "policies", "detection_rules", "ioc_feeds",
	"iocs", "alerts", "commands", "pam_requests", "pam_accounts", "pam_sessions",
}

// migrateTenancy makes the data model tenant and version aware. Existing
// rows join the default tenant.
func (p *Postgres) migrateTenancy(ctx context.Context) error {
	sql := `
CREATE TABLE IF NOT EXISTS tenants (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO tenants (id, name) VALUES ('default', 'Default') ON CONFLICT DO NOTHING;
`
	for _, t := range tenantTables {
		sql += `ALTER TABLE ` + t + ` ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default' REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS ` + t + `_tenant_idx ON ` + t + ` (tenant_id);
`
	}
	sql += `
-- Policies are versioned so agents and the console can tell which revision applies.
ALTER TABLE policies ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 1;
-- A certificate only authenticates the host; the agents row decides ownership
-- and authorization. Each issued certificate is recorded so it can be revoked
-- on its own.
CREATE TABLE IF NOT EXISTS agent_certificates (
	serial      TEXT PRIMARY KEY,
	agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	tenant_id   TEXT NOT NULL DEFAULT 'default' REFERENCES tenants(id),
	issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
	expires_at  TIMESTAMPTZ NOT NULL,
	revoked_at  TIMESTAMPTZ
);
INSERT INTO agent_certificates (serial, agent_id, tenant_id, issued_at, expires_at)
	SELECT cert_serial, id, tenant_id, enrolled_at, COALESCE(cert_expires, enrolled_at + interval '1 year')
	FROM agents WHERE cert_serial != '' ON CONFLICT DO NOTHING;
`
	_, err := p.pool.Exec(ctx, sql)
	return err
}

func (p *Postgres) recordCertificate(ctx context.Context, agentID, tenant, serial string, expires time.Time) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO agent_certificates (serial, agent_id, tenant_id, expires_at)
		VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, serial, agentID, tenant, expires)
	return err
}
