import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { PreventionState, api, formatBytes, timeAgo } from "../api";
import { usePoll } from "../hooks";
import EventTable from "../components/EventTable";
import Timeline from "../components/Timeline";
import { ProtectionBadge, StatusBadge, VersionCell, isOutdated, isSet } from "./Endpoints";
import { CommandList, EndpointResponse } from "../components/Response";
import { AlertTable } from "./Alerts";
import PreventionForm from "../components/PreventionForm";

export default function EndpointDetail() {
  const { id = "" } = useParams();
  const nav = useNavigate();
  const agent = usePoll(() => api.agent(id), 10000, [id]);
  const stats = usePoll(() => api.stats(id), 30000, [id]);
  const [type, setType] = useState("");
  const events = usePoll(() => api.events({ agent_id: id, type, limit: 100 }), 10000, [id, type]);
  const alerts = usePoll(() => api.alerts({ agent_id: id, limit: 50 }), 15000, [id]);
  const commands = usePoll(() => api.commands(id), 5000, [id]);
  const fleet = usePoll(api.fleet, 60000);
  const prevention = usePoll(() => api.agentPrevention(id), 15000, [id]);
  const [token, setToken] = useState("");

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
  async function update() {
    if (!confirm(`Update ${a!.hostname} from ${a!.agent_version} to ${fleet.data!.version}? The agent restarts, and rolls back on its own if the new version cannot reach the console.`)) return;
    await api.updateAgent(id);
    agent.refresh();
    commands.refresh();
  }
  async function toggleProtection() {
    const on = !a!.tamper_protection;
    if (!on && !confirm(`Turn tamper protection off on ${a!.hostname}? Anyone with root on the host can then stop or remove the agent.`)) return;
    await api.setTamperProtection(id, on);
    agent.refresh();
  }
  async function toggleRecording() {
    await api.setPamRecording(id, !a!.pam_record_all);
    agent.refresh();
  }
  async function showToken() {
    setToken(token ? "" : (await api.maintenanceToken(id)).token);
  }
  async function setCustomPrevention(custom: boolean) {
    if (!custom && !confirm(`Return ${a!.hostname} to the fleet prevention policy? Its own policy is discarded.`)) return;
    await api.setAgentPrevention(id, custom, custom ? prevention.data!.policy : undefined);
    prevention.refresh();
  }
  async function rebaseline() {
    if (!confirm(`Accept the current state of the monitored files on ${a!.hostname} as the new FIM baseline?`)) return;
    await api.sendCommand(id, "fim_rebaseline");
    commands.refresh();
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
          {!a.revoked && !a.updating && isOutdated(a, fleet.data) && <button onClick={update}>Update to {fleet.data!.version}</button>}
          {!a.revoked && !a.pending_command && <button onClick={uninstall}>Uninstall</button>}
          {!a.revoked && <button onClick={revoke}>Revoke</button>}
          <button className="danger" onClick={remove}>Delete</button>
        </div>
      </header>

      <section className="card">
        <dl className="facts">
          <div><dt>Status</dt><dd><StatusBadge online={a.online} revoked={a.revoked} uninstalled={isSet(a.uninstalled_at)} uninstalling={a.pending_command === "uninstall"} />{a.isolated && <span className="status status-critical"> · Network isolated</span>}</dd></div>
          <div><dt>Last seen</dt><dd>{timeAgo(a.last_seen)}</dd></div>
          <div><dt>OS</dt><dd>{a.os_version}</dd></div>
          <div><dt>Kernel</dt><dd className="mono">{a.kernel} ({a.arch})</dd></div>
          <div><dt>IP addresses</dt><dd className="mono">{a.ip_addresses.join(", ")}</dd></div>
          <div><dt>Agent version</dt><dd><VersionCell agent={a} fleet={fleet.data} /></dd></div>
          <div>
            <dt>Tamper protection</dt>
            <dd>
              <ProtectionBadge agent={a} />{" "}
              {!a.revoked && <button className="link" onClick={toggleProtection}>{a.tamper_protection ? "Turn off" : "Turn on"}</button>}{" "}
              <button className="link" onClick={showToken}>{token ? "Hide maintenance token" : "Show maintenance token"}</button>
            </dd>
          </div>
          {token && (
            <div className="wide">
              <dt>Maintenance token</dt>
              <dd>
                <code className="mono">{token}</code>
                <div className="muted">
                  Unlocks the agent on the host without the console: <code>sudo xdr-agent maintenance --token {token}</code>, or
                  uninstall with <code>curl -fsSL {location.origin}/uninstall.sh | sudo bash -s -- --token {token}</code>
                </div>
              </dd>
            </div>
          )}
          <div>
            <dt>Sudo session recording</dt>
            <dd>
              {a.pam_record_all ? "All sessions" : "Just-in-time grants"}{" "}
              {!a.revoked && <button className="link" onClick={toggleRecording}>{a.pam_record_all ? "Record grants only" : "Record all"}</button>}{" "}
              <Link to="/pam">Privileged access</Link>
            </dd>
          </div>
          <div><dt>Agent CPU / memory</dt><dd>{a.cpu_percent.toFixed(1)}% · {formatBytes(a.rss_bytes)}</dd></div>
          <div><dt>Events sent / dropped</dt><dd>{a.events_sent.toLocaleString()} / {a.events_dropped.toLocaleString()}</dd></div>
          <div><dt>Enrolled</dt><dd>{new Date(a.enrolled_at).toLocaleString()}</dd></div>
          <div><dt>Certificate expires</dt><dd>{new Date(a.cert_expires).toLocaleDateString()}</dd></div>
          <div><dt>YARA rules version</dt><dd className="mono">{a.content_version || "none"}</dd></div>
          <div className="wide"><dt>Agent ID</dt><dd className="mono">{a.id}</dd></div>
        </dl>
      </section>

      <section className="card">
        <h2>Open alerts</h2>
        {alerts.data && <AlertTable alerts={alerts.data} showHost={false} onSelect={(aid) => nav(`/alerts?id=${aid}`)} />}
      </section>

      {!a.revoked && prevention.data && (
        <section className="card">
          <div className="card-head">
            <h2>Prevention</h2>
            <div className="actions">
              {prevention.data.state.fim_active && <button onClick={rebaseline}>Accept changes as FIM baseline</button>}
              <button onClick={() => setCustomPrevention(!prevention.data!.custom)}>
                {prevention.data.custom ? "Use fleet policy" : "Customize for this endpoint"}
              </button>
            </div>
          </div>
          <PreventionStatus state={prevention.data.state} />
          {prevention.data.custom ? (
            <PreventionForm
              policy={prevention.data.policy}
              onSave={async (p) => {
                await api.setAgentPrevention(id, true, p);
                prevention.refresh();
              }}
            />
          ) : (
            <div className="muted small">Follows the <Link to="/prevention">fleet prevention policy</Link>.</div>
          )}
        </section>
      )}

      {!a.revoked && (
        <section className="card">
          <h2>Response</h2>
          <EndpointResponse
            agentId={id}
            hostname={a.hostname}
            isolated={a.isolated}
            onSent={() => {
              commands.refresh();
              agent.refresh();
            }}
          />
          <h3>Action history</h3>
          {commands.data && <CommandList commands={commands.data} onChange={commands.refresh} />}
        </section>
      )}

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
            <option value="agent_tamper">Agent tamper</option>
            <option value="exec_blocked,fim_change">Prevention</option>
          </select>
        </div>
        {events.data && <EventTable events={events.data} showHost={false} />}
      </section>
    </>
  );
}

function PreventionStatus({ state: s }: { state: PreventionState }) {
  return (
    <>
      {s.error && <div className="error">{s.error}</div>}
      <dl className="facts">
        <div>
          <dt>Exec blocking</dt>
          <dd>{s.exec_blocking ? <span className="status status-good">Active</span> : "Off"} · {(s.blocked_hashes ?? 0).toLocaleString()} hashes</dd>
        </div>
        <div>
          <dt>File integrity</dt>
          <dd>{s.fim_active ? <span className="status status-good">Monitoring {(s.fim_files ?? 0).toLocaleString()} files</span> : "Off"}</dd>
        </div>
        <div>
          <dt>Host firewall</dt>
          <dd>{s.firewall_applied ? <span className="status status-good">Applied</span> : "Off"}</dd>
        </div>
      </dl>
    </>
  );
}
