package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

type ClickHouse struct{ conn driver.Conn }

type ClickHouseOptions struct {
	Addr, Database, User, Password string
	TTLDays                        int
}

func OpenClickHouse(ctx context.Context, o ClickHouseOptions) (*ClickHouse, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{o.Addr},
		Auth: clickhouse.Auth{Database: o.Database, Username: o.User, Password: o.Password},
		Settings: clickhouse.Settings{
			// Let ClickHouse coalesce many small agent batches into large parts,
			// while still acknowledging each insert only once it is written.
			"async_insert":          1,
			"wait_for_async_insert": 1,
		},
		Compression: &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
		DialTimeout: 10 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	if err := conn.Ping(ctx); err != nil {
		return nil, err
	}
	c := &ClickHouse{conn: conn}
	if err := c.migrate(ctx, o.TTLDays); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return c, nil
}

func (c *ClickHouse) Close() error { return c.conn.Close() }

// eventsV0Columns are the columns of the events table before schema
// version 1, copied over when an older table is upgraded.
const eventsV0Columns = `ts, agent_id, hostname, event_id, type, pid, ppid, uid, user, exe, args, cwd,
	sha256, parent_exe, exit_code, path, old_path, size, mode, protocol, local_addr, local_port,
	remote_addr, remote_port`

func (c *ClickHouse) migrate(ctx context.Context, ttlDays int) error {
	// The sort key leads with tenant_id, which an existing table cannot gain,
	// so a pre-v1 table is renamed, recreated and its rows copied.
	var legacy, upgraded uint64
	if err := c.conn.QueryRow(ctx, `SELECT countIf(name = 'event_id'), countIf(name = 'tenant_id')
		FROM system.columns WHERE database = currentDatabase() AND table = 'events'`).Scan(&legacy, &upgraded); err != nil {
		return err
	}
	if legacy > 0 && upgraded == 0 {
		if err := c.conn.Exec(ctx, `RENAME TABLE events TO events_v0`); err != nil {
			return err
		}
	}
	// ReplacingMergeTree drops rows an agent re-sent after a lost
	// acknowledgement, since the event_id repeats.
	if err := c.conn.Exec(ctx, fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS events (
	ts          DateTime64(9, 'UTC'),
	tenant_id   LowCardinality(String) DEFAULT 'default',
	agent_id    LowCardinality(String),
	endpoint_id LowCardinality(String) DEFAULT '',
	hostname    LowCardinality(String),
	event_id    String,
	schema_version UInt16 DEFAULT 0,
	type        LowCardinality(String),
	priority    LowCardinality(String) DEFAULT '',
	pid         UInt32,
	ppid        UInt32,
	uid         UInt32,
	user        LowCardinality(String),
	exe         String,
	args        String,
	cwd         String,
	sha256      String,
	parent_exe  String,
	exit_code   Int32,
	process_guid        String DEFAULT '',
	parent_process_guid String DEFAULT '',
	parent_args         String DEFAULT '',
	parent_user         LowCardinality(String) DEFAULT '',
	parent_sha256       String DEFAULT '',
	process_start       DateTime64(9, 'UTC') DEFAULT 0,
	storyline_guid      String DEFAULT '',
	path        String,
	old_path    String,
	size        UInt64,
	mode        UInt32,
	protocol    LowCardinality(String),
	local_addr  String,
	local_port  UInt32,
	remote_addr String,
	remote_port UInt32,
	metadata    Map(LowCardinality(String), String),
	INDEX idx_sha256 sha256 TYPE bloom_filter GRANULARITY 4,
	INDEX idx_remote remote_addr TYPE bloom_filter GRANULARITY 4,
	INDEX idx_guid process_guid TYPE bloom_filter GRANULARITY 4,
	INDEX idx_parent_guid parent_process_guid TYPE bloom_filter GRANULARITY 4,
	INDEX idx_storyline storyline_guid TYPE bloom_filter GRANULARITY 4
) ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (tenant_id, agent_id, type, ts, event_id)
TTL toDateTime(ts) + INTERVAL %d DAY`, ttlDays)); err != nil {
		return err
	}
	// Added in 0.9: the storyline (process tree) an event belongs to.
	for _, q := range []string{
		`ALTER TABLE events ADD COLUMN IF NOT EXISTS storyline_guid String DEFAULT '' AFTER process_start`,
		`ALTER TABLE events ADD INDEX IF NOT EXISTS idx_storyline storyline_guid TYPE bloom_filter GRANULARITY 4`,
	} {
		if err := c.conn.Exec(ctx, q); err != nil {
			return err
		}
	}
	if legacy > 0 && upgraded == 0 {
		if err := c.conn.Exec(ctx, `INSERT INTO events (`+eventsV0Columns+`) SELECT `+eventsV0Columns+` FROM events_v0`); err != nil {
			return fmt.Errorf("copy events to the v1 table (old rows stay in events_v0): %w", err)
		}
		return c.conn.Exec(ctx, `DROP TABLE events_v0`)
	}
	return nil
}

type Event struct {
	Time          time.Time         `json:"ts" ch:"ts"`
	TenantID      string            `json:"tenant_id" ch:"tenant_id"`
	AgentID       string            `json:"agent_id" ch:"agent_id"`
	EndpointID    string            `json:"endpoint_id" ch:"endpoint_id"`
	Hostname      string            `json:"hostname" ch:"hostname"`
	EventID       string            `json:"event_id" ch:"event_id"`
	SchemaVersion uint16            `json:"schema_version" ch:"schema_version"`
	Type          string            `json:"type" ch:"type"`
	Priority      string            `json:"priority" ch:"priority"`
	PID           uint32            `json:"pid" ch:"pid"`
	PPID          uint32            `json:"ppid" ch:"ppid"`
	UID           uint32            `json:"uid" ch:"uid"`
	User          string            `json:"user" ch:"user"`
	Exe           string            `json:"exe" ch:"exe"`
	Args          string            `json:"args" ch:"args"`
	Cwd           string            `json:"cwd" ch:"cwd"`
	SHA256        string            `json:"sha256" ch:"sha256"`
	ParentExe     string            `json:"parent_exe" ch:"parent_exe"`
	ExitCode      int32             `json:"exit_code" ch:"exit_code"`
	ProcessGUID   string            `json:"process_guid" ch:"process_guid"`
	ParentGUID    string            `json:"parent_process_guid" ch:"parent_process_guid"`
	ParentArgs    string            `json:"parent_args" ch:"parent_args"`
	ParentUser    string            `json:"parent_user" ch:"parent_user"`
	ParentSHA256  string            `json:"parent_sha256" ch:"parent_sha256"`
	ProcessStart  time.Time         `json:"process_start" ch:"process_start"`
	StorylineGUID string            `json:"storyline_guid" ch:"storyline_guid"`
	Path          string            `json:"path" ch:"path"`
	OldPath       string            `json:"old_path" ch:"old_path"`
	Size          uint64            `json:"size" ch:"size"`
	Mode          uint32            `json:"mode" ch:"mode"`
	Protocol      string            `json:"protocol" ch:"protocol"`
	LocalAddr     string            `json:"local_addr" ch:"local_addr"`
	LocalPort     uint32            `json:"local_port" ch:"local_port"`
	RemoteAddr    string            `json:"remote_addr" ch:"remote_addr"`
	RemotePort    uint32            `json:"remote_port" ch:"remote_port"`
	Metadata      map[string]string `json:"metadata,omitempty" ch:"metadata"`
}

func (c *ClickHouse) Insert(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	b, err := c.conn.PrepareBatch(ctx, "INSERT INTO events")
	if err != nil {
		return err
	}
	for i := range events {
		if err := b.AppendStruct(&events[i]); err != nil {
			b.Abort()
			return err
		}
	}
	return b.Send()
}

type EventQuery struct {
	AgentID string
	Types   []string
	Search  string
	SHA256  string
	PID     uint32
	// ProcessGUID matches the process and its direct children.
	ProcessGUID string
	From, To    time.Time
	Limit       int
}

func (c *ClickHouse) Query(ctx context.Context, q EventQuery) ([]Event, error) {
	where := []string{"1"}
	args := []any{}
	add := func(cond string, v ...any) {
		where = append(where, cond)
		args = append(args, v...)
	}
	if q.AgentID != "" {
		add("agent_id = ?", q.AgentID)
	}
	if len(q.Types) > 0 {
		add("type IN ?", q.Types)
	}
	if q.SHA256 != "" {
		add("sha256 = ?", strings.ToLower(q.SHA256))
	}
	if q.PID != 0 {
		add("(pid = ? OR ppid = ?)", q.PID, q.PID)
	}
	if q.ProcessGUID != "" {
		add("(process_guid = ? OR parent_process_guid = ?)", q.ProcessGUID, q.ProcessGUID)
	}
	if !q.From.IsZero() {
		add("ts >= ?", q.From)
	}
	if !q.To.IsZero() {
		add("ts <= ?", q.To)
	}
	if q.Search != "" {
		add(`(positionCaseInsensitive(exe, ?) > 0 OR positionCaseInsensitive(args, ?) > 0
			OR positionCaseInsensitive(path, ?) > 0 OR positionCaseInsensitive(remote_addr, ?) > 0
			OR positionCaseInsensitive(user, ?) > 0 OR positionCaseInsensitive(hostname, ?) > 0)`,
			q.Search, q.Search, q.Search, q.Search, q.Search, q.Search)
	}
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	var out []Event
	err := c.conn.Select(ctx, &out,
		"SELECT * FROM events WHERE "+strings.Join(where, " AND ")+fmt.Sprintf(" ORDER BY ts DESC LIMIT %d", q.Limit),
		args...)
	if out == nil {
		out = []Event{}
	}
	return out, err
}

// maxTreeQuery bounds each process tree query.
const maxTreeQuery = 2000

// Processes returns the process_exec events of the given processes.
func (c *ClickHouse) Processes(ctx context.Context, agentID string, guids []string) ([]Event, error) {
	return c.treeQuery(ctx, "type = 'process_exec' AND process_guid IN ?", agentID, guids, maxTreeQuery)
}

// Children returns the process_exec events of the children of the given
// processes.
func (c *ClickHouse) Children(ctx context.Context, agentID string, parents []string, limit int) ([]Event, error) {
	return c.treeQuery(ctx, "type = 'process_exec' AND parent_process_guid IN ?", agentID, parents, limit)
}

// Activity returns what the given processes did besides starting: file,
// network, policy and exit events, newest first.
func (c *ClickHouse) Activity(ctx context.Context, agentID string, guids []string, limit int) ([]Event, error) {
	return c.treeQuery(ctx, "type != 'process_exec' AND process_guid IN ?", agentID, guids, limit)
}

func (c *ClickHouse) treeQuery(ctx context.Context, cond, agentID string, guids []string, limit int) ([]Event, error) {
	out := []Event{}
	if len(guids) == 0 {
		return out, nil
	}
	if limit <= 0 || limit > maxTreeQuery {
		limit = maxTreeQuery
	}
	err := c.conn.Select(ctx, &out, "SELECT * FROM events WHERE agent_id = ? AND "+cond+
		fmt.Sprintf(" ORDER BY ts DESC LIMIT %d", limit), agentID, guids)
	return out, err
}

type TypeCount struct {
	Type  string `json:"type" ch:"type"`
	Count uint64 `json:"count" ch:"c"`
}

type Bucket struct {
	Time  time.Time `json:"ts" ch:"t"`
	Type  string    `json:"type" ch:"type"`
	Count uint64    `json:"count" ch:"c"`
}

type TopItem struct {
	Value string `json:"value" ch:"v"`
	Count uint64 `json:"count" ch:"c"`
}

type Stats struct {
	ByType        []TypeCount `json:"by_type"`
	Timeline      []Bucket    `json:"timeline"`
	TopProcesses  []TopItem   `json:"top_processes"`
	TopRemoteAddr []TopItem   `json:"top_remote_addrs"`
}

// Stats summarises the last 24 hours, optionally for one agent.
func (c *ClickHouse) Stats(ctx context.Context, agentID string) (*Stats, error) {
	cond, args := "ts > now() - INTERVAL 24 HOUR", []any{}
	if agentID != "" {
		cond += " AND agent_id = ?"
		args = append(args, agentID)
	}
	s := &Stats{ByType: []TypeCount{}, Timeline: []Bucket{}, TopProcesses: []TopItem{}, TopRemoteAddr: []TopItem{}}
	if err := c.conn.Select(ctx, &s.ByType, "SELECT type, count() AS c FROM events WHERE "+cond+" GROUP BY type ORDER BY c DESC", args...); err != nil {
		return nil, err
	}
	if err := c.conn.Select(ctx, &s.Timeline, "SELECT toStartOfHour(ts) AS t, type, count() AS c FROM events WHERE "+cond+" GROUP BY t, type ORDER BY t", args...); err != nil {
		return nil, err
	}
	if err := c.conn.Select(ctx, &s.TopProcesses, "SELECT exe AS v, count() AS c FROM events WHERE "+cond+" AND type = 'process_exec' AND exe != '' GROUP BY v ORDER BY c DESC LIMIT 10", args...); err != nil {
		return nil, err
	}
	if err := c.conn.Select(ctx, &s.TopRemoteAddr, "SELECT remote_addr AS v, count() AS c FROM events WHERE "+cond+" AND type = 'net_connect' AND remote_addr NOT IN ('', '127.0.0.1', '::1') GROUP BY v ORDER BY c DESC LIMIT 10", args...); err != nil {
		return nil, err
	}
	return s, nil
}
