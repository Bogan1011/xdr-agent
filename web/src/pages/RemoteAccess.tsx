import { FormEvent, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, socketUrl, timeAgo } from "../api";
import { usePoll } from "../hooks";
import Terminal from "../components/Terminal";

// RemoteAccess lists every endpoint with one-click shell access, and the
// remote shells open right now.
export default function RemoteAccess() {
  const agents = usePoll(api.agents, 15000);
  const shells = usePoll(api.liveShells, 5000);
  const [q, setQ] = useState("");
  const list = (agents.data ?? []).filter((a) => !a.revoked && a.hostname.toLowerCase().includes(q.toLowerCase()));

  async function end(sid: string, host: string) {
    if (!confirm(`End the remote shell on ${host}?`)) return;
    await api.closeShell(sid);
    shells.refresh();
  }

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Remote access</h1>
          <p className="muted small">
            Open a shell on any endpoint from the browser. It runs through the agent's own connection, so the host needs no SSH
            port open, and every session is recorded under Privileged access.
          </p>
        </div>
      </header>

      <section className="card">
        <h2>Open now</h2>
        {shells.data && shells.data.length === 0 && <div className="empty">No remote shells are open.</div>}
        {shells.data && shells.data.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Endpoint</th><th>User</th><th>Opened by</th><th>Started</th><th>Watching</th><th /></tr>
              </thead>
              <tbody>
                {shells.data.map((s) => (
                  <tr key={s.id}>
                    <td><Link to={`/endpoints/${s.agent_id}`}>{s.hostname}</Link></td>
                    <td className="mono">{s.user}</td>
                    <td>{s.admin}</td>
                    <td className="nowrap">{timeAgo(s.started_at)}</td>
                    <td>{s.viewers}</td>
                    <td className="nowrap actions">
                      <Link className="button" to={`/remote/watch/${s.id}`}>Watch live</Link>
                      <button className="danger" onClick={() => end(s.id, s.hostname)}>End</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-head">
          <h2>Endpoints</h2>
          <input placeholder="Search hostname" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Endpoint</th><th>Status</th><th>OS</th><th>IP</th><th /></tr>
            </thead>
            <tbody>
              {list.map((a) => (
                <tr key={a.id}>
                  <td><Link to={`/endpoints/${a.id}`}>{a.hostname}</Link></td>
                  <td>{a.online ? <span className="status status-good"><span>●</span> Online</span> : <span className="muted">Offline</span>}</td>
                  <td>{a.os_version}</td>
                  <td className="mono">{a.ip_addresses[0]}</td>
                  <td className="nowrap actions">
                    <Link className="button" to={`/endpoints/${a.id}`}>Live view</Link>
                    <Link className={"button" + (a.online ? " primary" : "")} to={`/remote/${a.id}`}>Connect</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

// RemoteShell is a full-page terminal on one endpoint.
export function RemoteShell() {
  const { id = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const agent = usePoll(() => api.agent(id), 0, [id]);
  const user = params.get("user") || "";
  const [pick, setPick] = useState("root");
  // A new key reconnects after the shell ends.
  const [n, setN] = useState(0);
  const [ended, setEnded] = useState(false);

  function connect(e: FormEvent) {
    e.preventDefault();
    setEnded(false);
    setN(n + 1);
    setParams({ user: pick.trim() || "root" });
  }

  return (
    <>
      <header className="page-head">
        <div>
          <Link to={`/endpoints/${id}`} className="muted">← {agent.data?.hostname ?? "Endpoint"}</Link>
          <h1>Remote shell{agent.data ? ` · ${agent.data.hostname}` : ""}</h1>
        </div>
        <form className="actions" onSubmit={connect}>
          <input className="mono" value={pick} onChange={(e) => setPick(e.target.value)} placeholder="root" aria-label="Log in as" />
          <button className="primary">{user && !ended ? "Reconnect" : "Connect"}</button>
        </form>
      </header>
      {user ? (
        <section className="card">
          <p className="muted small">
            Logged in as <code>{user}</code>. This session is recorded and listed under <Link to="/pam">Privileged access</Link>.
          </p>
          <Terminal
            key={`${user}-${n}`}
            url={socketUrl(`/api/v1/agents/${encodeURIComponent(id)}/shell?user=${encodeURIComponent(user)}`)}
            onEnd={() => setEnded(true)}
          />
        </section>
      ) : (
        <section className="card">
          <div className="empty">Pick the account to log in as and press Connect. Root is the default.</div>
        </section>
      )}
    </>
  );
}

// WatchShell shows a remote shell someone else is using, read-only.
export function WatchShell() {
  const { sid = "" } = useParams();
  const nav = useNavigate();
  return (
    <>
      <header className="page-head">
        <div>
          <Link to="/remote" className="muted">← Remote access</Link>
          <h1>Watching a remote shell</h1>
        </div>
        <div className="actions">
          <button onClick={() => nav("/remote")}>Stop watching</button>
        </div>
      </header>
      <section className="card">
        <Terminal readOnly url={socketUrl(`/api/v1/live/shells/${encodeURIComponent(sid)}/watch`)} />
      </section>
    </>
  );
}
