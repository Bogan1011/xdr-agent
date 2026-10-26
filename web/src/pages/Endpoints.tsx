import { Link } from "react-router-dom";
import { api, timeAgo } from "../api";
import { usePoll } from "../hooks";

export function StatusBadge({ online, revoked }: { online: boolean; revoked: boolean }) {
  if (revoked) return <span className="status status-critical"><span aria-hidden>■</span> Revoked</span>;
  if (online) return <span className="status status-good"><span aria-hidden>●</span> Online</span>;
  return <span className="status status-warn"><span aria-hidden>▲</span> Offline</span>;
}

export default function Endpoints() {
  const { data, error } = usePoll(api.agents, 10000);
  return (
    <>
      <header className="page-head">
        <h1>Endpoints</h1>
        <Link to="/deploy" className="button primary">Deploy agent</Link>
      </header>
      {error && <div className="error">{error}</div>}
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
                      <StatusBadge online={a.online} revoked={a.revoked} />
                    </td>
                    <td>{a.os_version || a.os}</td>
                    <td className="mono">{a.ip_addresses.join(", ")}</td>
                    <td className="mono">{a.agent_version}</td>
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
