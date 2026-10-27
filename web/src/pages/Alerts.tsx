import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Alert, AlertStatus, api, statusLabels, timeAgo } from "../api";
import { usePoll } from "../hooks";
import { CommandList, SeverityBadge, useSend } from "../components/Response";

export default function Alerts() {
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "";
  const severity = params.get("severity") ?? "";
  const selected = Number(params.get("id") ?? 0);
  const alerts = usePoll(() => api.alerts({ status, severity }), 10000, [status, severity]);

  function set(k: string, v: string) {
    const p = new URLSearchParams(params);
    if (v) p.set(k, v);
    else p.delete(k);
    setParams(p, { replace: true });
  }

  return (
    <>
      <header className="page-head">
        <h1>Alerts</h1>
      </header>
      <div className="filters">
        <select value={status} onChange={(e) => set("status", e.target.value)}>
          <option value="">Open</option>
          <option value="new">New</option>
          <option value="in_progress">In progress</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False positive</option>
          <option value="all">All</option>
        </select>
        <select value={severity} onChange={(e) => set("severity", e.target.value)}>
          <option value="">Any severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>
      {alerts.error && <div className="error">{alerts.error}</div>}
      {selected > 0 && (
        <AlertDetail key={selected} id={selected} onClose={() => set("id", "")} onChange={alerts.refresh} />
      )}
      <section className="card">
        {alerts.data && <AlertTable alerts={alerts.data} onSelect={(id) => set("id", String(id))} />}
      </section>
    </>
  );
}

export function AlertTable({ alerts, onSelect, showHost = true }: { alerts: Alert[]; onSelect: (id: number) => void; showHost?: boolean }) {
  if (alerts.length === 0) return <div className="empty">No alerts.</div>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Last seen</th>
            <th>Severity</th>
            <th>Detection</th>
            {showHost && <th>Endpoint</th>}
            <th>Target</th>
            <th>Count</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => (
            <tr key={a.id} className="clickable" onClick={() => onSelect(a.id)}>
              <td className="nowrap" title={new Date(a.last_seen).toLocaleString()}>{timeAgo(a.last_seen)}</td>
              <td><SeverityBadge severity={a.severity} /></td>
              <td>{a.rule_name}</td>
              {showHost && <td className="nowrap">{a.hostname}</td>}
              <td className="mono truncate">{target(a)}</td>
              <td>{a.count}</td>
              <td className="nowrap">{statusLabels[a.status]}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function target(a: Alert): string {
  const e = a.event;
  if (e.type === "net_connect") return `${e.exe || "?"} → ${e.remote_addr}:${e.remote_port}`;
  if (e.type === "net_accept") return `${e.exe || "?"} ← ${e.remote_addr}:${e.remote_port}`;
  if (e.type.startsWith("file") || e.type === "yara_match") return e.path;
  return e.args || e.exe;
}

function AlertDetail({ id, onClose, onChange }: { id: number; onClose: () => void; onChange: () => void }) {
  const d = usePoll(() => api.alert(id), 5000, [id]);
  const [err, setErr] = useState("");
  const a = d.data?.alert;
  const { send, error, busy } = useSend(a?.agent_id ?? "", id, () => {
    d.refresh();
    onChange();
  });
  if (d.error) return <div className="error">{d.error}</div>;
  if (!a) return null;
  const e = a.event;

  async function setStatus(s: AlertStatus) {
    try {
      await api.updateAlert(id, s);
      d.refresh();
      onChange();
    } catch (x) {
      setErr((x as Error).message);
    }
  }

  const file = e.type === "yara_match" || (e.type.startsWith("file") && e.type !== "file_delete") ? e.path : e.exe;
  const rows: [string, string][] = [
    ["Endpoint", a.hostname],
    ["First / last seen", `${new Date(a.first_seen).toLocaleString()} / ${new Date(a.last_seen).toLocaleString()}`],
    ["Occurrences", String(a.count)],
    ["Detection", `${a.kind.toUpperCase()} · ${a.rule_id}`],
  ];
  if (a.detail) rows.push(["Matched", a.detail]);
  if (a.tags.length) rows.push(["MITRE ATT&CK", a.tags.join(", ")]);
  if (e.exe) rows.push(["Process", `${e.exe}${e.pid ? ` (pid ${e.pid})` : ""}`]);
  if (e.args) rows.push([e.type === "yara_match" ? "YARA rules" : "Command line", e.args]);
  if (e.parent_exe) rows.push(["Parent", e.parent_exe]);
  if (e.user) rows.push(["User", e.user]);
  if (e.path) rows.push(["File", e.path]);
  if (e.sha256) rows.push(["SHA-256", e.sha256]);
  if (e.remote_addr) rows.push(["Remote", `${e.remote_addr}:${e.remote_port}`]);

  return (
    <section className="card highlight">
      <div className="card-head">
        <h2>
          <SeverityBadge severity={a.severity} /> {a.rule_name}
        </h2>
        <button className="link" onClick={onClose}>Close</button>
      </div>
      {(err || error) && <div className="error">{err || error}</div>}
      <dl className="detail">
        {rows.map(([k, v]) => (
          <div key={k} style={{ display: "contents" }}>
            <dt>{k}</dt>
            <dd className={k === "SHA-256" || k === "Command line" ? "mono" : ""}>{v}</dd>
          </div>
        ))}
      </dl>
      <div className="filters" style={{ marginTop: 12 }}>
        <span className="muted">Respond:</span>
        {e.pid > 1 && e.type !== "process_exit" && (
          <button
            disabled={busy}
            onClick={() => send("kill_process", { pid: String(e.pid), exe: e.exe }, `Kill ${e.exe} (pid ${e.pid}) on ${a.hostname}?`)}
          >
            Kill process
          </button>
        )}
        {file && (
          <button disabled={busy} onClick={() => send("quarantine_file", { path: file }, `Quarantine ${file} on ${a.hostname}?`)}>
            Quarantine file
          </button>
        )}
        <button
          className="danger"
          disabled={busy}
          onClick={() =>
            send("isolate_host", {}, `Isolate ${a.hostname}? All traffic except to this console is blocked, including SSH.`)
          }
        >
          Isolate host
        </button>
        {(a.process_guid || e.process_guid) && (
          <Link to={`/storyline/${a.agent_id}/${a.process_guid || e.process_guid}?alert=${a.id}`}>Investigate in Workbench →</Link>
        )}
        <Link to={`/endpoints/${a.agent_id}`}>Open endpoint →</Link>
        <span style={{ flex: 1 }} />
        <span className="muted">Status:</span>
        <select value={a.status} onChange={(ev) => setStatus(ev.target.value as AlertStatus)}>
          {Object.entries(statusLabels).map(([k, v]) => (
            <option key={k} value={k}>{v}</option>
          ))}
        </select>
      </div>
      {d.data && d.data.commands.length > 0 && (
        <>
          <h3>Response actions</h3>
          <CommandList commands={d.data.commands} onChange={d.refresh} />
        </>
      )}
    </section>
  );
}
