package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

func (p *Postgres) migrateDetection(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, `
ALTER TABLE agents ADD COLUMN IF NOT EXISTS isolated BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS content_version TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS detection_rules (
	id          TEXT PRIMARY KEY,
	kind        TEXT NOT NULL,
	name        TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	severity    TEXT NOT NULL,
	enabled     BOOLEAN NOT NULL DEFAULT true,
	builtin     BOOLEAN NOT NULL DEFAULT false,
	source      TEXT NOT NULL,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ioc_feeds (
	id           BIGSERIAL PRIMARY KEY,
	name         TEXT NOT NULL,
	url          TEXT NOT NULL,
	type         TEXT NOT NULL,
	severity     TEXT NOT NULL DEFAULT 'high',
	enabled      BOOLEAN NOT NULL DEFAULT true,
	last_fetched TIMESTAMPTZ,
	last_error   TEXT NOT NULL DEFAULT '',
	ioc_count    INT NOT NULL DEFAULT 0,
	created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS iocs (
	id          BIGSERIAL PRIMARY KEY,
	type        TEXT NOT NULL,
	value       TEXT NOT NULL,
	feed_id     BIGINT NOT NULL DEFAULT 0,
	description TEXT NOT NULL DEFAULT '',
	severity    TEXT NOT NULL DEFAULT 'high',
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE (type, value, feed_id)
);
CREATE TABLE IF NOT EXISTS alerts (
	id          BIGSERIAL PRIMARY KEY,
	agent_id    TEXT NOT NULL,
	hostname    TEXT NOT NULL,
	rule_id     TEXT NOT NULL,
	rule_name   TEXT NOT NULL,
	kind        TEXT NOT NULL,
	severity    TEXT NOT NULL,
	tags        TEXT[] NOT NULL DEFAULT '{}',
	detail      TEXT NOT NULL DEFAULT '',
	status      TEXT NOT NULL DEFAULT 'new',
	dedupe_key  TEXT NOT NULL,
	count       INT NOT NULL DEFAULT 1,
	event       JSONB NOT NULL,
	note        TEXT NOT NULL DEFAULT '',
	first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
	last_seen   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS alerts_open_dedupe ON alerts (agent_id, rule_id, dedupe_key)
	WHERE status IN ('new', 'in_progress');
CREATE INDEX IF NOT EXISTS alerts_last_seen ON alerts (last_seen DESC);
CREATE TABLE IF NOT EXISTS commands (
	id          TEXT PRIMARY KEY,
	agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	type        TEXT NOT NULL,
	args        JSONB NOT NULL DEFAULT '{}',
	alert_id    BIGINT NOT NULL DEFAULT 0,
	requested_by TEXT NOT NULL DEFAULT '',
	status      TEXT NOT NULL DEFAULT 'pending',
	message     TEXT NOT NULL DEFAULT '',
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	sent_at     TIMESTAMPTZ,
	finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS commands_agent ON commands (agent_id, created_at DESC);
`)
	return err
}

// --- rules ---

type Rule struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"` // sigma or yara
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Enabled     bool      `json:"enabled"`
	Builtin     bool      `json:"builtin"`
	Source      string    `json:"source"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// SeedRules installs or refreshes shipped rules, keeping their enabled flag.
func (p *Postgres) SeedRules(ctx context.Context, rules []Rule) error {
	b := &pgx.Batch{}
	for _, r := range rules {
		b.Queue(`INSERT INTO detection_rules (id, kind, name, description, severity, enabled, builtin, source)
			VALUES ($1,$2,$3,$4,$5,true,true,$6)
			ON CONFLICT (id) DO UPDATE SET kind=$2, name=$3, description=$4, severity=$5, source=$6, builtin=true,
				updated_at = CASE WHEN detection_rules.source = $6 THEN detection_rules.updated_at ELSE now() END`,
			r.ID, r.Kind, r.Name, r.Description, r.Severity, r.Source)
	}
	return p.pool.SendBatch(ctx, b).Close()
}

func (p *Postgres) ListRules(ctx context.Context) ([]Rule, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, kind, name, description, severity, enabled, builtin, source, updated_at
		FROM detection_rules ORDER BY kind, name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Rule, error) {
		var r Rule
		err := row.Scan(&r.ID, &r.Kind, &r.Name, &r.Description, &r.Severity, &r.Enabled, &r.Builtin, &r.Source, &r.UpdatedAt)
		return r, err
	})
}

// SaveRule creates or replaces a custom rule. Built-in rules cannot be edited.
func (p *Postgres) SaveRule(ctx context.Context, r Rule) error {
	tag, err := p.pool.Exec(ctx, `INSERT INTO detection_rules (id, kind, name, description, severity, enabled, source)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (id) DO UPDATE SET kind=$2, name=$3, description=$4, severity=$5, enabled=$6, source=$7, updated_at=now()
		WHERE NOT detection_rules.builtin`,
		r.ID, r.Kind, r.Name, r.Description, r.Severity, r.Enabled, r.Source)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrBuiltin
	}
	return err
}

var ErrBuiltin = errors.New("built-in rules can only be enabled or disabled")

func (p *Postgres) SetRuleEnabled(ctx context.Context, id string, enabled bool) error {
	tag, err := p.pool.Exec(ctx, `UPDATE detection_rules SET enabled=$2, updated_at=now() WHERE id=$1`, id, enabled)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) DeleteRule(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM detection_rules WHERE id=$1 AND NOT builtin`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// --- IOCs ---

type IOC struct {
	ID          int64     `json:"id"`
	Type        string    `json:"type"` // sha256, ip, domain
	Value       string    `json:"value"`
	FeedID      int64     `json:"feed_id"`
	Source      string    `json:"source"` // feed name, or empty for manual entries
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CreatedAt   time.Time `json:"created_at"`
}

const iocCols = `i.id, i.type, i.value, i.feed_id, COALESCE(f.name, ''), i.description, i.severity, i.created_at`

func scanIOC(row pgx.CollectableRow) (IOC, error) {
	var i IOC
	err := row.Scan(&i.ID, &i.Type, &i.Value, &i.FeedID, &i.Source, &i.Description, &i.Severity, &i.CreatedAt)
	return i, err
}

// AllIOCs loads every indicator for the detection engine.
func (p *Postgres) AllIOCs(ctx context.Context) ([]IOC, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+iocCols+` FROM iocs i LEFT JOIN ioc_feeds f ON f.id = i.feed_id
		WHERE i.feed_id = 0 OR f.enabled`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanIOC)
}

// ListIOCs returns manual indicators and, when q is set, any matching value.
func (p *Postgres) ListIOCs(ctx context.Context, q string, limit int) ([]IOC, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+iocCols+` FROM iocs i LEFT JOIN ioc_feeds f ON f.id = i.feed_id
		WHERE ($1 = '' AND i.feed_id = 0) OR ($1 != '' AND (i.value ILIKE '%' || $1 || '%' OR i.description ILIKE '%' || $1 || '%'))
		ORDER BY i.created_at DESC LIMIT $2`, q, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanIOC)
}

// AddIOCs inserts manual indicators, ignoring duplicates, and returns how many were new.
func (p *Postgres) AddIOCs(ctx context.Context, iocs []IOC) (int, error) {
	b := &pgx.Batch{}
	for _, i := range iocs {
		b.Queue(`INSERT INTO iocs (type, value, description, severity) VALUES ($1,$2,$3,$4)
			ON CONFLICT (type, value, feed_id) DO NOTHING`, i.Type, i.Value, i.Description, i.Severity)
	}
	br := p.pool.SendBatch(ctx, b)
	defer br.Close()
	n := 0
	for range iocs {
		tag, err := br.Exec()
		if err != nil {
			return n, err
		}
		n += int(tag.RowsAffected())
	}
	return n, nil
}

func (p *Postgres) DeleteIOC(ctx context.Context, id int64) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM iocs WHERE id=$1 AND feed_id = 0`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

type Feed struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Enabled     bool      `json:"enabled"`
	LastFetched time.Time `json:"last_fetched"`
	LastError   string    `json:"last_error"`
	IOCCount    int       `json:"ioc_count"`
}

func (p *Postgres) ListFeeds(ctx context.Context) ([]Feed, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, name, url, type, severity, enabled, COALESCE(last_fetched, 'epoch'),
		last_error, ioc_count FROM ioc_feeds ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Feed, error) {
		var f Feed
		err := row.Scan(&f.ID, &f.Name, &f.URL, &f.Type, &f.Severity, &f.Enabled, &f.LastFetched, &f.LastError, &f.IOCCount)
		return f, err
	})
}

func (p *Postgres) CreateFeed(ctx context.Context, f Feed) (int64, error) {
	var id int64
	err := p.pool.QueryRow(ctx, `INSERT INTO ioc_feeds (name, url, type, severity, enabled) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		f.Name, f.URL, f.Type, f.Severity, f.Enabled).Scan(&id)
	return id, err
}

func (p *Postgres) SetFeedEnabled(ctx context.Context, id int64, enabled bool) error {
	tag, err := p.pool.Exec(ctx, `UPDATE ioc_feeds SET enabled=$2 WHERE id=$1`, id, enabled)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) DeleteFeed(ctx context.Context, id int64) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM iocs WHERE feed_id=$1`, id); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM ioc_feeds WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

// ReplaceFeedIOCs swaps a feed's indicators for a fresh download.
func (p *Postgres) ReplaceFeedIOCs(ctx context.Context, f Feed, values []string) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM iocs WHERE feed_id=$1`, f.ID); err != nil {
		return err
	}
	rows := make([][]any, len(values))
	for i, v := range values {
		rows[i] = []any{f.Type, v, f.ID, f.Severity}
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"iocs"}, []string{"type", "value", "feed_id", "severity"}, pgx.CopyFromRows(rows)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE ioc_feeds SET last_fetched=now(), last_error='', ioc_count=$2 WHERE id=$1`, f.ID, len(values)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *Postgres) SetFeedError(ctx context.Context, id int64, msg string) error {
	_, err := p.pool.Exec(ctx, `UPDATE ioc_feeds SET last_fetched=now(), last_error=$2 WHERE id=$1`, id, msg)
	return err
}

// --- alerts ---

type Alert struct {
	ID        int64           `json:"id"`
	AgentID   string          `json:"agent_id"`
	Hostname  string          `json:"hostname"`
	RuleID    string          `json:"rule_id"`
	RuleName  string          `json:"rule_name"`
	Kind      string          `json:"kind"`
	Severity  string          `json:"severity"`
	Tags      []string        `json:"tags"`
	Detail    string          `json:"detail"`
	Status    string          `json:"status"`
	Count     int             `json:"count"`
	Event     json.RawMessage `json:"event"`
	Note      string          `json:"note"`
	FirstSeen time.Time       `json:"first_seen"`
	LastSeen  time.Time       `json:"last_seen"`
}

// AlertStatuses are the states an analyst moves an alert through.
var AlertStatuses = []string{"new", "in_progress", "resolved", "false_positive"}

// RaiseAlert opens an alert or, if the same detection is already open,
// counts the repeat. It reports whether a new alert was created.
func (p *Postgres) RaiseAlert(ctx context.Context, a *Alert, dedupeKey string) (int64, bool, error) {
	var id int64
	var inserted bool
	err := p.pool.QueryRow(ctx, `INSERT INTO alerts (agent_id, hostname, rule_id, rule_name, kind, severity, tags, detail, dedupe_key, event)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (agent_id, rule_id, dedupe_key) WHERE status IN ('new', 'in_progress')
		DO UPDATE SET count = alerts.count + 1, last_seen = now(), event = EXCLUDED.event
		RETURNING id, xmax = 0`,
		a.AgentID, a.Hostname, a.RuleID, a.RuleName, a.Kind, a.Severity, nonNil(a.Tags), a.Detail, dedupeKey, a.Event).Scan(&id, &inserted)
	return id, inserted, err
}

type AlertQuery struct {
	AgentID  string
	Status   string // empty: open (new + in_progress); "all": everything
	Severity string
	Limit    int
}

const alertCols = `id, agent_id, hostname, rule_id, rule_name, kind, severity, tags, detail, status, count, event, note, first_seen, last_seen`

func scanAlert(row pgx.CollectableRow) (*Alert, error) {
	a := &Alert{}
	err := row.Scan(&a.ID, &a.AgentID, &a.Hostname, &a.RuleID, &a.RuleName, &a.Kind, &a.Severity, &a.Tags, &a.Detail,
		&a.Status, &a.Count, &a.Event, &a.Note, &a.FirstSeen, &a.LastSeen)
	return a, err
}

func (p *Postgres) ListAlerts(ctx context.Context, q AlertQuery) ([]*Alert, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+alertCols+` FROM alerts
		WHERE ($1 = '' OR agent_id = $1)
		AND (($2 = '' AND status IN ('new', 'in_progress')) OR $2 = 'all' OR status = $2)
		AND ($3 = '' OR severity = $3)
		ORDER BY last_seen DESC LIMIT $4`, q.AgentID, q.Status, q.Severity, q.Limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAlert)
}

func (p *Postgres) GetAlert(ctx context.Context, id int64) (*Alert, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+alertCols+` FROM alerts WHERE id=$1`, id)
	if err != nil {
		return nil, err
	}
	a, err := pgx.CollectExactlyOneRow(rows, scanAlert)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func (p *Postgres) UpdateAlert(ctx context.Context, id int64, status, note string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE alerts SET status = COALESCE(NULLIF($2, ''), status),
		note = COALESCE(NULLIF($3, ''), note) WHERE id=$1`, id, status, note)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

type AlertSummary struct {
	Open       int            `json:"open"`
	BySeverity map[string]int `json:"by_severity"`
	Last24h    int            `json:"last_24h"`
}

func (p *Postgres) AlertSummary(ctx context.Context) (*AlertSummary, error) {
	s := &AlertSummary{BySeverity: map[string]int{}}
	rows, err := p.pool.Query(ctx, `SELECT severity, count(*) FROM alerts WHERE status IN ('new', 'in_progress') GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return nil, err
		}
		s.BySeverity[sev] = n
		s.Open += n
	}
	rows.Close()
	err = p.pool.QueryRow(ctx, `SELECT count(*) FROM alerts WHERE first_seen > now() - interval '24 hours'`).Scan(&s.Last24h)
	return s, err
}

// --- response commands ---

type Command struct {
	ID          string            `json:"id"`
	AgentID     string            `json:"agent_id"`
	Type        string            `json:"type"`
	Args        map[string]string `json:"args"`
	AlertID     int64             `json:"alert_id"`
	RequestedBy string            `json:"requested_by"`
	Status      string            `json:"status"` // pending, sent, succeeded, failed
	Message     string            `json:"message"`
	CreatedAt   time.Time         `json:"created_at"`
	FinishedAt  time.Time         `json:"finished_at"`
}

func (p *Postgres) CreateCommand(ctx context.Context, c *Command) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO commands (id, agent_id, type, args, alert_id, requested_by)
		VALUES ($1,$2,$3,$4,$5,$6)`, c.ID, c.AgentID, c.Type, c.Args, c.AlertID, c.RequestedBy)
	return err
}

const commandCols = `id, agent_id, type, args, alert_id, requested_by, status, message, created_at, COALESCE(finished_at, 'epoch')`

func scanCommand(row pgx.CollectableRow) (*Command, error) {
	c := &Command{}
	err := row.Scan(&c.ID, &c.AgentID, &c.Type, &c.Args, &c.AlertID, &c.RequestedBy, &c.Status, &c.Message, &c.CreatedAt, &c.FinishedAt)
	return c, err
}

// TakeCommands marks the agent's pending commands as sent and returns them.
// Commands older than an hour expire instead of running late.
func (p *Postgres) TakeCommands(ctx context.Context, agentID string) ([]*Command, error) {
	if _, err := p.pool.Exec(ctx, `UPDATE commands SET status='failed', message='expired before the agent checked in',
		finished_at=now() WHERE agent_id=$1 AND status='pending' AND created_at < now() - interval '1 hour'`, agentID); err != nil {
		return nil, err
	}
	rows, err := p.pool.Query(ctx, `UPDATE commands SET status='sent', sent_at=now()
		WHERE agent_id=$1 AND status='pending' RETURNING `+commandCols, agentID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanCommand)
}

// FinishCommand records an agent's result for one of its own commands.
func (p *Postgres) FinishCommand(ctx context.Context, agentID, id string, ok bool, msg string) (*Command, error) {
	status := "failed"
	if ok {
		status = "succeeded"
	}
	rows, err := p.pool.Query(ctx, `UPDATE commands SET status=$3, message=$4, finished_at=now()
		WHERE id=$1 AND agent_id=$2 RETURNING `+commandCols, id, agentID, status, msg)
	if err != nil {
		return nil, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, scanCommand)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

func (p *Postgres) ListCommands(ctx context.Context, agentID string, alertID int64, limit int) ([]*Command, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+commandCols+` FROM commands
		WHERE ($1 = '' OR agent_id = $1) AND ($2 = 0 OR alert_id = $2) ORDER BY created_at DESC LIMIT $3`, agentID, alertID, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanCommand)
}

// SetAgentState records the isolation state and content version the agent reports.
func (p *Postgres) SetAgentState(ctx context.Context, id string, isolated bool, contentVersion string) error {
	_, err := p.pool.Exec(ctx, `UPDATE agents SET isolated=$2, content_version=$3 WHERE id=$1`, id, isolated, contentVersion)
	return err
}
