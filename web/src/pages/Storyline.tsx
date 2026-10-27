import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Alert, StoryNode, api, categoryOf } from "../api";
import { usePoll } from "../hooks";
import EventTable from "../components/EventTable";
import { SeverityBadge } from "../components/Response";

const sevRank = { low: 0, medium: 1, high: 2, critical: 3 };

function base(exe: string): string {
  return exe ? exe.split("/").pop() || exe : "unknown process";
}

// The process tree around one process: what started it, what it started, and
// what each process did.
export default function Storyline() {
  const { agentId = "", guid = "" } = useParams();
  const d = usePoll(() => api.storyline(agentId, guid), 15000, [agentId, guid]);
  const [selected, setSelected] = useState(guid);
  const st = d.data?.storyline;
  const alerts = d.data?.alerts ?? [];

  const byProcess = new Map<string, Alert[]>();
  for (const a of alerts) {
    const k = a.process_guid || a.storyline_guid;
    byProcess.set(k, [...(byProcess.get(k) ?? []), a]);
  }
  const events = st ? st.events.filter((e) => e.process_guid === selected) : [];
  const node = st?.nodes.find((n) => n.guid === selected);
  const host = st?.events[0]?.hostname ?? alerts[0]?.hostname ?? "";

  return (
    <>
      <header className="page-head">
        <h1>Storyline</h1>
        {host && (
          <Link to={`/endpoints/${agentId}`} className="muted">
            {host}
          </Link>
        )}
      </header>
      {d.error && <div className="error">{d.error}</div>}
      {st && (
        <section className="card">
          <div className="card-head">
            <h2>Process tree</h2>
            <span className="muted">
              {st.nodes.length} processes · {alerts.length} alerts
              {st.truncated ? " · showing the first part" : ""}
            </span>
          </div>
          {st.session && (
            <div className="story-session muted">
              Started by {base(st.session.exe)}
              {st.session.pid ? ` (pid ${st.session.pid})` : ""}
            </div>
          )}
          <div className="story-tree">
            {st.nodes.map((n) => (
              <TreeRow
                key={n.guid}
                n={n}
                alerts={byProcess.get(n.guid) ?? []}
                focus={n.guid === st.focus}
                selected={n.guid === selected}
                onSelect={() => setSelected(n.guid)}
              />
            ))}
          </div>
        </section>
      )}
      {node && (
        <section className="card">
          <div className="card-head">
            <h2 className="mono">{base(node.exe)}</h2>
            <span className="muted">
              pid {node.pid} · {node.user || "?"}
              {node.exited ? ` · exited ${node.exit_code}` : ""}
            </span>
          </div>
          <dl className="detail">
            <dt>Command line</dt>
            <dd className="mono">{node.args || node.exe}</dd>
            {node.images && node.images.length > 0 && (
              <>
                <dt>Earlier images</dt>
                <dd className="mono">{node.images.join(" → ")}</dd>
              </>
            )}
            {node.sha256 && (
              <>
                <dt>SHA-256</dt>
                <dd className="mono">{node.sha256}</dd>
              </>
            )}
            <dt>Process GUID</dt>
            <dd className="mono">{node.guid}</dd>
          </dl>
          {(byProcess.get(node.guid) ?? []).map((a) => (
            <div key={a.id} className="story-alert">
              <SeverityBadge severity={a.severity} /> <Link to={`/alerts?id=${a.id}`}>{a.rule_name}</Link>
            </div>
          ))}
          <h3>Activity</h3>
          <EventTable events={events} showHost={false} />
        </section>
      )}
    </>
  );
}

function TreeRow({ n, alerts, focus, selected, onSelect }: {
  n: StoryNode; alerts: Alert[]; focus: boolean; selected: boolean; onSelect: () => void;
}) {
  const worst = alerts.reduce<Alert | undefined>((w, a) => (!w || sevRank[a.severity] > sevRank[w.severity] ? a : w), undefined);
  const counts = { file: 0, network: 0 };
  for (const [t, c] of Object.entries(n.counts)) {
    if (t === "process_exit") continue;
    const cat = categoryOf(t);
    if (cat === "file" || cat === "network") counts[cat] += c;
  }
  return (
    <div
      className={`story-row clickable${selected ? " selected" : ""}${focus ? " focus" : ""}`}
      style={{ paddingLeft: 8 + n.depth * 20 }}
      onClick={onSelect}
      title={n.args || n.exe}
    >
      <span className="story-branch">{n.depth > 0 ? "└" : "●"}</span>
      <span className="mono story-name">{base(n.exe)}</span>
      <span className="mono muted truncate story-args">{n.args && n.args !== n.exe ? n.args : ""}</span>
      <span className="muted nowrap">{n.user}</span>
      <span className="muted nowrap">pid {n.pid || "?"}</span>
      {counts.file > 0 && <span className="chip chip-file">{counts.file} file</span>}
      {counts.network > 0 && <span className="chip chip-network">{counts.network} net</span>}
      {worst && <SeverityBadge severity={worst.severity} />}
      {alerts.length > 1 && <span className="muted">×{alerts.length}</span>}
    </div>
  );
}
