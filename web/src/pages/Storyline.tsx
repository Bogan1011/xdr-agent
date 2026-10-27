import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { Alert, Severity, StoryNode, Storyline as StorylineData, api, categoryOf } from "../api";
import { usePoll } from "../hooks";
import EventTable from "../components/EventTable";
import { SeverityBadge } from "../components/Response";

const sevRank: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const shells = new Set(["bash", "sh", "dash", "zsh", "ksh", "fish", "-bash", "-sh", "-zsh"]);

function base(exe: string): string {
  return exe ? exe.split("/").pop() || exe : "unknown process";
}

function clip(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

// Storyline is the workbench for one process tree: the alert on the left,
// the graph of user, endpoint and processes on the right, and the activity
// of the process picked in the graph below.
export default function Storyline() {
  const { agentId = "", guid = "" } = useParams();
  const [params] = useSearchParams();
  const alertId = Number(params.get("alert") ?? 0);
  const d = usePoll(() => api.storyline(agentId, guid), 15000, [agentId, guid]);
  const alertReq = usePoll(() => (alertId ? api.alert(alertId) : Promise.resolve(undefined)), 0, [alertId]);
  const agent = usePoll(() => api.agent(agentId), 0, [agentId]);
  const [selected, setSelected] = useState(guid);

  const st = d.data?.storyline;
  const alerts = d.data?.alerts ?? [];
  const alert = alertReq.data?.alert ?? alerts.find((a) => a.process_guid === guid) ?? alerts[0];
  const byProcess = new Map<string, Alert[]>();
  for (const a of alerts) {
    const k = a.process_guid || a.storyline_guid;
    byProcess.set(k, [...(byProcess.get(k) ?? []), a]);
  }
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
            <Graph
              st={st}
              host={host}
              ip={ip}
              byProcess={byProcess}
              selected={selected}
              onSelect={setSelected}
            />
          ) : (
            <div className="empty">Loading the process tree…</div>
          )}
        </section>
      </div>
      {node && (
        <section className="card">
          <div className="card-head">
            <h2 className="mono">{base(node.exe)}</h2>
            <span className="muted">
              pid {node.pid || "?"} · {node.user || "?"}
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
            {node.started && node.known && (
              <>
                <dt>Started</dt>
                <dd>{new Date(node.started).toLocaleString()}</dd>
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

// --- graph ---

const COL = 170;
const ROW = 120;
const R = 24;
const PAD_X = 70;
const PAD_Y = 60;

type Kind = "user" | "host" | "session" | "shell" | "process";

interface GNode {
  id: string;
  kind: Kind;
  label: string;
  sub?: string;
  x: number;
  y: number;
  node?: StoryNode;
}

function layout(st: StorylineData, host: string, ip: string) {
  const kids = new Map<string, StoryNode[]>();
  const byId = new Map(st.nodes.map((n) => [n.guid, n]));
  for (const n of st.nodes) {
    if (n.guid === st.root || !byId.has(n.parent_guid)) continue;
    kids.set(n.parent_guid, [...(kids.get(n.parent_guid) ?? []), n]);
  }
  // Processes that are not under the root (seen only by their activity) hang
  // off the endpoint next to the root.
  const tops = st.nodes.filter((n) => n.guid === st.root || !byId.has(n.parent_guid));
  const offset = st.session ? 3 : 2;

  const g: GNode[] = [];
  const edges: [string, string][] = [];
  let slot = 0;
  const place = (n: StoryNode, depth: number): number => {
    const children = kids.get(n.guid) ?? [];
    let y: number;
    if (children.length === 0) {
      y = slot++;
    } else {
      const ys = children.map((c) => place(c, depth + 1));
      y = (ys[0] + ys[ys.length - 1]) / 2;
      for (const c of children) edges.push([n.guid, c.guid]);
    }
    const name = base(n.exe);
    g.push({
      id: n.guid, kind: shells.has(name) ? "shell" : "process", label: name,
      sub: n.args && n.args !== n.exe ? n.args : "", x: (offset + depth) * COL, y, node: n,
    });
    return y;
  };
  const topYs = tops.map((t) => place(t, 0));
  const mid = topYs.length ? (Math.min(...topYs) + Math.max(...topYs)) / 2 : 0;

  const rootUser = (st.nodes.find((n) => n.guid === st.root) ?? st.nodes[0])?.user || "unknown user";
  g.push({ id: "#user", kind: "user", label: rootUser, x: 0, y: mid });
  g.push({ id: "#host", kind: "host", label: host, sub: ip, x: COL, y: mid });
  edges.push(["#user", "#host"]);
  const parentOfTops = st.session ? "#session" : "#host";
  if (st.session) {
    g.push({ id: "#session", kind: "session", label: base(st.session.exe), x: 2 * COL, y: mid, node: st.session });
    edges.push(["#host", "#session"]);
  }
  for (const t of tops) edges.push([parentOfTops, t.guid]);

  for (const n of g) {
    n.x = PAD_X + n.x;
    n.y = PAD_Y + n.y * ROW;
  }
  const width = Math.max(...g.map((n) => n.x)) + PAD_X + 60;
  const height = Math.max(...g.map((n) => n.y)) + PAD_Y + 20;
  return { g, edges, width, height };
}

function Icon({ kind }: { kind: Kind }) {
  const p = { fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  switch (kind) {
    case "user":
      return (
        <g {...p}>
          <circle cx={0} cy={-5} r={5} />
          <path d="M-9 10c1-6 5-8 9-8s8 2 9 8" />
        </g>
      );
    case "host":
      return (
        <g {...p}>
          <rect x={-9} y={-10} width={18} height={8} rx={1.5} />
          <rect x={-9} y={2} width={18} height={8} rx={1.5} />
          <path d="M-5 -6h4M-5 6h4" />
        </g>
      );
    case "session":
      return (
        <g {...p}>
          <circle r={4} />
          <path d="M0 -10v3M0 7v3M-10 0h3M7 0h3M-7 -7l2 2M5 5l2 2M-7 7l2 -2M5 -5l2 -2" />
        </g>
      );
    case "shell":
      return (
        <g {...p}>
          <rect x={-10} y={-8} width={20} height={16} rx={2} />
          <path d="M-6 -3l4 3-4 3M1 4h5" />
        </g>
      );
    default:
      return (
        <g {...p}>
          <rect x={-8} y={-8} width={16} height={16} rx={3} />
          <path d="M-4 -2h8M-4 2h5" />
        </g>
      );
  }
}

function Graph({ st, host, ip, byProcess, selected, onSelect }: {
  st: StorylineData; host: string; ip: string; byProcess: Map<string, Alert[]>; selected: string; onSelect: (g: string) => void;
}) {
  const { g, edges, width, height } = layout(st, host, ip);
  const pos = new Map(g.map((n) => [n.id, n]));
  // The path from the endpoint to the focus process is drawn highlighted.
  const onPath = new Set<string>(["#user", "#host", "#session"]);
  const parents = new Map(st.nodes.map((n) => [n.guid, n.parent_guid]));
  for (let cur: string | undefined = st.focus; cur && !onPath.has(cur); cur = parents.get(cur)) onPath.add(cur);

  return (
    <div className="wb-canvas">
      <svg width={width} height={height} role="img" aria-label="Process tree">
        {edges.map(([a, b]) => {
          const p = pos.get(a);
          const q = pos.get(b);
          if (!p || !q) return null;
          const mx = (p.x + q.x) / 2;
          const hot = onPath.has(a) && onPath.has(b);
          return (
            <path
              key={a + b}
              d={`M${p.x + R} ${p.y} C${mx} ${p.y} ${mx} ${q.y} ${q.x - R} ${q.y}`}
              className={hot ? "wb-edge hot" : "wb-edge"}
            />
          );
        })}
        {g.map((n) => {
          const al = n.node ? byProcess.get(n.id) ?? [] : [];
          const worst = al.reduce<Alert | undefined>((w, a) => (!w || sevRank[a.severity] > sevRank[w.severity] ? a : w), undefined);
          const clickable = !!n.node && n.kind !== "session";
          const counts = { file: 0, network: 0 };
          for (const [t, c] of Object.entries(n.node?.counts ?? {})) {
            const cat = categoryOf(t);
            if (t !== "process_exit" && (cat === "file" || cat === "network")) counts[cat] += c;
          }
          const cls = [
            "wb-node",
            `wb-${n.kind}`,
            worst ? `alert sev-ring-${worst.severity}` : "",
            n.id === selected ? "selected" : "",
            n.id === st.focus ? "focus" : "",
            clickable ? "clickable" : "",
          ].join(" ");
          return (
            <g key={n.id} transform={`translate(${n.x},${n.y})`} className={cls} onClick={clickable ? () => onSelect(n.id) : undefined}>
              <title>{n.node ? `${n.node.args || n.node.exe}\npid ${n.node.pid} · ${n.node.user}` : n.label}</title>
              <circle r={R} className="wb-disc" />
              <Icon kind={n.kind} />
              {worst && <circle cx={R * 0.7} cy={-R * 0.7} r={6} className={`wb-badge sev-fill-${worst.severity}`} />}
              <text y={R + 16} textAnchor="middle" className="wb-label">{clip(n.label, 22)}</text>
              {n.sub && (
                <text y={R + 30} textAnchor="middle" className="wb-sub">{clip(n.sub, 26)}</text>
              )}
              {(counts.file > 0 || counts.network > 0) && (
                <text y={R + (n.sub ? 44 : 30)} textAnchor="middle" className="wb-sub wb-counts">
                  {[counts.file ? `${counts.file} file` : "", counts.network ? `${counts.network} net` : ""].filter(Boolean).join(" · ")}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      {st.truncated && <div className="muted wb-note">Large tree: showing the first part.</div>}
    </div>
  );
}
