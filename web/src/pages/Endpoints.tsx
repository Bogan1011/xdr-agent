import { useState } from "react";
import { Link } from "react-router-dom";
import { Agent, Fleet, api, timeAgo } from "../api";
import { usePoll } from "../hooks";

export function StatusBadge({ online, revoked, uninstalled, uninstalling }: {
  online: boolean; revoked: boolean; uninstalled?: boolean; uninstalling?: boolean;
}) {
  if (uninstalled) return <span className="status status-critical"><span aria-hidden>■</span> Uninstalled</span>;
  if (uninstalling) return <span className="status status-warn"><span aria-hidden>▲</span> Uninstalling…</span>;
  if (revoked) return <span className="status status-critical"><span aria-hidden>■</span> Revoked</span>;
  if (online) return <span className="status status-good"><span aria-hidden>●</span> Online</span>;
  return <span className="status status-warn"><span aria-hidden>▲</span> Offline</span>;
}

export const isSet = (iso: string) => new Date(iso).getTime() > 1000;

export const isOutdated = (a: Agent, fleet?: Fleet | null) =>
  !!fleet?.version && !a.revoked && a.agent_version !== fleet.version;

export function VersionCell({ agent, fleet }: { agent: Agent; fleet?: Fleet | null }) {
  return (
    <span className="mono">
      {agent.agent_version}
      {agent.updating && <span className="status status-warn"> · updating…</span>}
      {!agent.updating && isOutdated(agent, fleet) && <span className="status status-warn"> · update to {fleet!.version}</span>}
    </span>
  );
}

export function ProtectionBadge({ agent }: { agent: Agent }) {
  if (agent.revoked) return <span className="muted">—</span>;
  if (!agent.tamper_protection) return <span className="status status-warn"><span aria-hidden>▲</span> Off</span>;
  if (!agent.tamper_protected) return <span className="status status-warn"><span aria-hidden>▲</span> Pending</span>;
  return <span className="status status-good"><span aria-hidden>●</span> On</span>;
}

export default function Endpoints() {
  const { data, error, refresh } = usePoll(api.agents, 10000);
  const fleet = usePoll(api.fleet, 60000);
  const [msg, setMsg] = useState("");
  const outdated = (data ?? []).filter((a) => a.online && !a.updating && isOutdated(a, fleet.data));

  async function updateAll() {
    if (!confirm(`Update ${outdated.length} online agent(s) to ${fleet.data!.version}? Each one restarts and rolls back on its own if the new version fails.`)) return;
    try {
      const r = await api.updateAllAgents();
      setMsg(`Update queued for ${r.queued} agent(s).`);
      refresh();
    } catch (e) {
      setMsg(String(e));
    }
  }

  return (
    <>
      <header className="page-head">
        <h1>Endpoints</h1>
        <div className="actions">
          {outdated.length > 0 && <button onClick={updateAll}>Update {outdated.length} to {fleet.data!.version}</button>}
          <Link to="/deploy" className="button primary">Deploy agent</Link>
        </div>
      </header>
      {error && <div className="error">{error}</div>}
      {msg && <div className="notice">{msg}</div>}
      {fleet.data && (
        <p className="muted">
          Console offers agent {fleet.data.version || "(unknown)"}
          {data && ` · ${data.filter((a) => !a.revoked && a.agent_version === fleet.data!.version).length} of ${data.filter((a) => !a.revoked).length} endpoints on it`}
          {data && ` · tamper protection on ${data.filter((a) => a.tamper_protected).length}`}
        </p>
      )}
      <section className="card">
        {data && data.length === 0 && (
          <div className="empty">
            No endpoints yet. <Link to="/deploy">Deploy your first agent</Link>.
          </div>
        )}
        {data && data.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Endpoint</th>
                  <th>Status</th>
                  <th>OS</th>
                  <th>IP addresses</th>
                  <th>Agent</th>
                  <th>Protection</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {data.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <Link to={`/endpoints/${a.id}`}>{a.hostname}</Link>
                    </td>
                    <td>
                      <StatusBadge online={a.online} revoked={a.revoked} uninstalled={isSet(a.uninstalled_at)} uninstalling={a.pending_command === "uninstall"} />
                    </td>
                    <td>{a.os_version || a.os}</td>
                    <td className="mono">{a.ip_addresses.join(", ")}</td>
                    <td><VersionCell agent={a} fleet={fleet.data} /></td>
                    <td><ProtectionBadge agent={a} /></td>
                    <td>{timeAgo(a.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
