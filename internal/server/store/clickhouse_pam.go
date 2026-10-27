package store

import (
	"context"
	"fmt"
	"time"
)

// SessionEvents returns what happened on a server during a console shell:
// the events of every process the shell started. Agents that tag processes
// with the console session (the console_session column) are matched
// exactly; otherwise the shells the agent started in the window (su -l
// under xdr-agent, then the login shell's storyline) are used, which can
// mix two shells open at the same time.
func (c *ClickHouse) SessionEvents(ctx context.Context, agentID, sessionID string, from, to time.Time, limit int) ([]Event, error) {
	if limit <= 0 || limit > maxTreeQuery {
		limit = maxTreeQuery
	}
	out := []Event{}
	if sessionID != "" {
		err := c.conn.Select(ctx, &out, "SELECT * FROM events WHERE agent_id = ? AND console_session = ?"+
			fmt.Sprintf(" ORDER BY ts LIMIT %d", limit), agentID, sessionID)
		if err == nil && len(out) > 0 {
			return out, nil
		}
		out = []Event{}
	}
	err := c.conn.Select(ctx, &out, `SELECT * FROM events WHERE agent_id = ? AND ts BETWEEN ? AND ? AND storyline_guid IN (
		SELECT storyline_guid FROM events WHERE agent_id = ? AND ts BETWEEN ? AND ? AND type = 'process_exec' AND storyline_guid != ''
			AND (process_guid IN (SELECT process_guid FROM events WHERE agent_id = ? AND ts BETWEEN ? AND ?
				AND type = 'process_exec' AND positionCaseInsensitive(parent_exe, 'xdr-agent') > 0)
			OR parent_process_guid IN (SELECT process_guid FROM events WHERE agent_id = ? AND ts BETWEEN ? AND ?
				AND type = 'process_exec' AND positionCaseInsensitive(parent_exe, 'xdr-agent') > 0)))`+
		fmt.Sprintf(" ORDER BY ts LIMIT %d", limit),
		agentID, from, to, agentID, from, to, agentID, from, to, agentID, from, to)
	return out, err
}
