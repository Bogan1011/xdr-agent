import { useMemo, useRef, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { Alert, Storyline as StorylineData, api } from "../api";
import { usePoll } from "../hooks";
import EventTable from "../components/EventTable";
import ProcessGraph, { base } from "../components/ProcessGraph";
import { SeverityBadge } from "../components/Response";

// Storyline is the workbench for one process tree: the alert on the left,
// the process graph on the right, and the activity of the process picked in
// the graph below.
export default function Storyline() {
  const { agentId = "", guid = "" } = useParams();
  const [params] = useSearchParams();
  const alertId = Number(params.get("alert") ?? 0);
  const d = usePoll(() => api.storyline(agentId, guid), 15000, [agentId, guid]);
  const alertReq = usePoll(() => (alertId ? api.alert(alertId) : Promise.resolve(undefined)), 0, [alertId]);
  const agent = usePoll(() => api.agent(agentId), 0, [agentId]);
  const [selected, setSelected] = useState(guid);
  const activity = useRef<HTMLElement>(null);

  const st = d.data?.storyline;
  const alerts = useMemo(() => d.data?.alerts ?? [], [d.data]);
  const alert = alertReq.data?.alert ?? alerts.find((a) => a.process_guid === guid) ?? alerts[0];
  const byProcess = useMemo(() => {
    const m = new Map<string, Alert[]>();
    for (const a of alerts) {
      const k = a.process_guid || a.storyline_guid;
      m.set(k, [...(m.get(k) ?? []), a]);
    }
    return m;
  }, [alerts]);
  const node = st?.nodes.find((n) => n.guid === selected);
  const events = st ? st.events.filter((e) => e.process_guid === selected) : [];
  const host = agent.data?.hostname ?? alert?.hostname ?? st?.events[0]?.hostname ?? "endpoint";
  const ip = agent.data?.ip_addresses?.[0] ?? "";

  return (
    <>
      <header className="page-head">
        <h1>Workbench</h1>
        <span className="muted">
          <Link to="/alerts">Alerts</Link> / {alert ? alert.rule_name : "Storyline"}
        </span>
      </header>
      {d.error && <div className="error">{d.error}</div>}
      <div className="workbench">
        <aside className="card wb-summary">
          <Summary alert={alert} st={st} alerts={alerts} host={host} ip={ip} agentId={agentId} />
        </aside>
        <section className="card wb-graph">
          {st ? (
            <ProcessGraph
              st={st}
              host={host}
              ip={ip}
              byProcess={byProcess}
              selected={selected}
              onSelect={setSelected}
              onShowActivity={() => activity.current?.scrollIntoView({ behavior: "smooth" })}
            />
          ) : (
            <div className="empty">Loading the process tree…</div>
          )}
        </section>
      </div>
      {node && (
        <section className="card" ref={activity}>
          <div className="card-head">
            <h2>
              Activity of <span className="mono">{base(node.exe)}</span>
            </h2>
            <span className="muted">pid {node.pid || "?"} · {node.user || "?"}</span>
          </div>
          <EventTable events={events} showHost={false} />
        </section>
      )}
    </>
  );
}

function Summary({ alert, st, alerts, host, ip, agentId }: {
  alert?: Alert; st?: StorylineData; alerts: Alert[]; host: string; ip: string; agentId: string;
}) {
  const users = new Set((st?.nodes ?? []).map((n) => n.user).filter(Boolean));
  const e = alert?.event;
  const techniques = (alert?.tags ?? [])
    .map((t) => /^attack\.(t\d{4}(?:\.\d{3})?)$/i.exec(t)?.[1]?.toUpperCase())
    .filter((t): t is string => !!t);
  const highlights: [string, string][] = [];
  if (e) {
    highlights.push(["endpointHostName", host]);
    if (ip) highlights.push(["endpointIp", ip]);
    if (e.args) highlights.push(["objectCmd", e.args]);
    if (e.exe) highlights.push(["processFilePath", e.exe]);
    if (e.parent_exe) highlights.push(["parentFilePath", e.parent_exe]);
    if (e.user) highlights.push(["user", e.user]);
    if (e.path) highlights.push(["objectFilePath", e.path]);
    if (e.sha256) highlights.push(["objectSha256", e.sha256]);
    if (e.remote_addr) highlights.push(["remoteIp", `${e.remote_addr}:${e.remote_port}`]);
  }

  return (
    <>
      <h2 className="wb-title">Summary</h2>
      {alert ? (
        <>
          <div className="wb-alert-name">{alert.rule_name}</div>
          {alert.detail && <p className="muted wb-desc">{alert.detail}</p>}
          <dl className="wb-facts">
            <dt>Severity</dt>
            <dd><SeverityBadge severity={alert.severity} /></dd>
            <dt>Status</dt>
            <dd>{alert.status.replace("_", " ")}</dd>
            <dt>Impact scope</dt>
            <dd>
              1 endpoint · {users.size || 1} user{users.size === 1 ? "" : "s"}
            </dd>
            <dt>Created</dt>
            <dd>{new Date(alert.first_seen).toLocaleString()}</dd>
            {alert.count > 1 && (
              <>
                <dt>Occurrences</dt>
                <dd>{alert.count}</dd>
              </>
            )}
          </dl>
          <h3>Highlights</h3>
          {techniques.length > 0 && (
            <div className="wb-technique">
              Technique:{" "}
              {techniques.map((t) => (
                <a key={t} href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`} target="_blank" rel="noreferrer">
                  {t}{" "}
                </a>
              ))}
            </div>
          )}
          <ul className="wb-highlights">
            {highlights.map(([k, v]) => (
              <li key={k}>
                <span className="muted">({k})</span> <span className="mono">{v}</span>
              </li>
            ))}
          </ul>
          <div className="wb-links">
            <Link to={`/alerts?id=${alert.id}`}>Respond to alert →</Link>
            <Link to={`/endpoints/${agentId}`}>Open endpoint →</Link>
          </div>
        </>
      ) : (
        <p className="muted">No alert in this storyline. Pick a process in the graph to see what it did.</p>
      )}
      {alerts.length > (alert ? 1 : 0) && (
        <>
          <h3>Alerts in this storyline</h3>
          <ul className="wb-alerts">
            {alerts.map((a) => (
              <li key={a.id}>
                <SeverityBadge severity={a.severity} />{" "}
                <Link to={`/storyline/${agentId}/${a.process_guid || st?.focus}?alert=${a.id}`}>{a.rule_name}</Link>
              </li>
            ))}
          </ul>
        </>
      )}
    </>
  );
}
