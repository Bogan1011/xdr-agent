import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, formatBytes, timeAgo } from "../api";
import { usePoll } from "../hooks";
import EventTable from "../components/EventTable";
import Timeline from "../components/Timeline";
import { StatusBadge, isSet } from "./Endpoints";

export default function EndpointDetail() {
  const { id = "" } = useParams();
  const nav = useNavigate();
  const agent = usePoll(() => api.agent(id), 10000, [id]);
  const stats = usePoll(() => api.stats(id), 30000, [id]);
  const [type, setType] = useState("");
  const events = usePoll(() => api.events({ agent_id: id, type, limit: 100 }), 10000, [id, type]);

  const a = agent.data;
  if (agent.error) return <div className="error">{agent.error}</div>;
  if (!a) return null;

  async function revoke() {
    if (!confirm(`Revoke ${a!.hostname}? It will no longer be able to send telemetry.`)) return;
    await api.revokeAgent(id);
    agent.refresh();
  }
  async function uninstall() {
    if (!confirm(`Uninstall the agent from ${a!.hostname}? It removes itself at its next check-in (within 30 seconds).`)) return;
    await api.uninstallAgent(id);
    agent.refresh();
  }
  async function remove() {
    if (!confirm(`Delete ${a!.hostname} from the console? Its events are kept until they expire.`)) return;
    await api.deleteAgent(id);
    nav("/endpoints");
  }

  return (
    <>
      <header className="page-head">
        <div>
          <Link to="/endpoints" className="muted">← Endpoints</Link>
          <h1>{a.hostname}</h1>
        </div>
        <div className="actions">
          {!a.revoked && !a.pending_command && <button onClick={uninstall}>Uninstall</button>}
          {!a.revoked && <button onClick={revoke}>Revoke</button>}
          <button className="danger" onClick={remove}>Delete</button>
        </div>
      </header>

      <section className="card">
        <dl className="facts">
          <div><dt>Status</dt><dd><StatusBadge online={a.online} revoked={a.revoked} uninstalled={isSet(a.uninstalled_at)} uninstalling={a.pending_command === "uninstall"} /></dd></div>
          <div><dt>Last seen</dt><dd>{timeAgo(a.last_seen)}</dd></div>
          <div><dt>OS</dt><dd>{a.os_version}</dd></div>
          <div><dt>Kernel</dt><dd className="mono">{a.kernel} ({a.arch})</dd></div>
          <div><dt>IP addresses</dt><dd className="mono">{a.ip_addresses.join(", ")}</dd></div>
          <div><dt>Agent version</dt><dd className="mono">{a.agent_version}</dd></div>
          <div><dt>Agent CPU / memory</dt><dd>{a.cpu_percent.toFixed(1)}% · {formatBytes(a.rss_bytes)}</dd></div>
          <div><dt>Events sent / dropped</dt><dd>{a.events_sent.toLocaleString()} / {a.events_dropped.toLocaleString()}</dd></div>
          <div><dt>Enrolled</dt><dd>{new Date(a.enrolled_at).toLocaleString()}</dd></div>
          <div><dt>Certificate expires</dt><dd>{new Date(a.cert_expires).toLocaleDateString()}</dd></div>
          <div className="wide"><dt>Agent ID</dt><dd className="mono">{a.id}</dd></div>
        </dl>
      </section>

      <section className="card">
        <h2>Event volume</h2>
        {stats.data && <Timeline stats={stats.data} />}
      </section>

      <section className="card">
        <div className="card-head">
          <h2>Activity</h2>
          <select value={type} onChange={(e) => setType(e.target.value)}>
            <option value="">All events</option>
            <option value="process_exec,process_exit">Process</option>
            <option value="file_create,file_modify,file_delete,file_rename,file_attrib">File</option>
            <option value="net_connect,net_listen">Network</option>
          </select>
        </div>
        {events.data && <EventTable events={events.data} showHost={false} />}
      </section>
    </>
  );
}
