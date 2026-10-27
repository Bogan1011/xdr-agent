import { FormEvent, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { AccessKind, Elevation, api, socketUrl, timeAgo } from "../api";
import { useMe } from "../me";
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
            port open. Access policies decide who may connect and whether it needs approval; every session is recorded.
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

// RemoteShell is a full-page terminal on one endpoint. Opening one is an
// access request: the access policy decides whether it needs approval, MFA
// or a ticket, and the shell closes when the grant expires.
export function RemoteShell() {
  const { id = "" } = useParams();
  const me = useMe();
  const [params, setParams] = useSearchParams();
  const agent = usePoll(() => api.agent(id), 0, [id]);
  const requests = usePoll(() => api.elevations(id), 5000, [id]);
  const rid = params.get("request") || "";
  // A new key reconnects after the shell ends.
  const [n, setN] = useState(0);
  const [ended, setEnded] = useState(false);

  const mine = (requests.data ?? []).filter(
    (r) => r.kind === "shell" && r.requester_id === me?.id && ["pending", "approved", "active"].includes(r.status),
  );
  const current = (requests.data ?? []).find((r) => r.id === rid);
  const usable = current && (current.status === "approved" || current.status === "active");

  return (
    <>
      <header className="page-head">
        <div>
          <Link to={`/endpoints/${id}`} className="muted">← {agent.data?.hostname ?? "Endpoint"}</Link>
          <h1>Remote shell{agent.data ? ` · ${agent.data.hostname}` : ""}</h1>
        </div>
        {usable && (
          <div className="actions">
            <button className="primary" onClick={() => { setEnded(false); setN(n + 1); }}>{ended ? "Reconnect" : "Restart"}</button>
            <button onClick={() => setParams({})}>New request</button>
          </div>
        )}
      </header>
      {usable ? (
        <section className="card">
          <p className="muted small">
            Logged in as <code>{current.username}</code> until {new Date(current.expires_at).toLocaleTimeString()} under policy{" "}
            <b>{current.policy_name || "—"}</b>. This session is recorded and listed under <Link to="/pam">Privileged access</Link>.
          </p>
          <Terminal
            key={`${rid}-${n}`}
            url={socketUrl(`/api/v1/agents/${encodeURIComponent(id)}/shell?request=${encodeURIComponent(rid)}`)}
            onEnd={() => setEnded(true)}
          />
        </section>
      ) : current && current.status === "pending" ? (
        <section className="card">
          <h2>Waiting for approval</h2>
          <p>
            Your request to log in as <code>{current.username}</code> needs {current.approvals_required} approval
            {current.approvals_required > 1 ? "s" : ""} ({current.approvals?.filter((a) => a.decision === "approve").length ?? 0} so far).
            An approver sees it under <Link to="/pam">Privileged access</Link>; this page connects once it is approved.
          </p>
          <button onClick={() => api.cancelElevation(current.id).then(() => { setParams({}); requests.refresh(); })}>Cancel request</button>
        </section>
      ) : (
        <>
          {current && <div className="notice">Request {current.id.slice(0, 8)} is {current.status}. {current.note}</div>}
          {mine.length > 0 && (
            <section className="card">
              <h2>Your open access</h2>
              <div className="stack">
                {mine.map((r) => (
                  <div key={r.id} className="actions">
                    <span>
                      <code>{r.username}</code> · {r.status}
                      {r.status !== "pending" && ` until ${new Date(r.expires_at).toLocaleTimeString()}`}
                    </span>
                    <button className="primary" onClick={() => setParams({ request: r.id })}>{r.status === "pending" ? "View" : "Use"}</button>
                  </div>
                ))}
              </div>
            </section>
          )}
          <AccessForm agentId={id} kind="shell" onCreated={(r) => { requests.refresh(); setParams({ request: r.id }); }} />
        </>
      )}
    </>
  );
}

const lengths = [15, 30, 60, 120, 240, 480];

// AccessForm asks for shell or JIT sudo access. It previews the policy so it
// only asks for what the policy needs.
export function AccessForm({ agentId, kind, onCreated }: { agentId: string; kind: AccessKind; onCreated: (r: Elevation) => void }) {
  const [account, setAccount] = useState(kind === "shell" ? "root" : "");
  const [checked, setChecked] = useState(kind === "shell" ? "root" : "");
  const preview = usePoll(
    () => (agentId && checked ? api.previewAccess(agentId, kind, checked) : Promise.resolve(undefined)),
    0,
    [agentId, kind, checked],
  );
  const [reason, setReason] = useState("");
  const [ticket, setTicket] = useState("");
  const [len, setLen] = useState(60);
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const d = preview.data?.decision;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    if (account.trim() !== checked) {
      setChecked(account.trim());
      return;
    }
    try {
      const r = await api.requestAccess({ agent_id: agentId, kind, account: checked, reason, ticket, duration_minutes: len, mfa_code: code });
      setCode("");
      onCreated(r.request);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <section className="card">
      <h2>{kind === "shell" ? "Request shell access" : "Request sudo"}</h2>
      <form className="stack" onSubmit={submit}>
        <div className="filters">
          <input
            className="mono"
            value={account}
            onChange={(e) => setAccount(e.target.value)}
            onBlur={() => setChecked(account.trim())}
            placeholder={kind === "shell" ? "root" : "local account"}
            aria-label="Local account"
            required
          />
          <select value={len} onChange={(e) => setLen(Number(e.target.value))} aria-label="Length">
            {lengths.filter((m) => !d || m <= d.max_minutes).map((m) => (
              <option key={m} value={m}>{m >= 60 ? `${m / 60} h` : `${m} min`}</option>
            ))}
          </select>
          {d?.allowed && (
            <>
              <input className="grow" placeholder={d.require_reason ? "Reason (required)" : "Reason (optional)"} value={reason}
                onChange={(e) => setReason(e.target.value)} required={d.require_reason} />
              {d.require_ticket && (
                <input placeholder="Ticket / change ref" value={ticket} onChange={(e) => setTicket(e.target.value)} required />
              )}
              {d.require_mfa && (
                <input className="mono narrow" inputMode="numeric" placeholder="MFA code" value={code}
                  onChange={(e) => setCode(e.target.value)} required />
              )}
            </>
          )}
          <button className="primary" disabled={!!d && !d.allowed}>
            {account.trim() !== checked ? "Check access" : d?.require_approval ? "Ask for approval" : "Connect"}
          </button>
        </div>
        {preview.error && <div className="error">{preview.error}</div>}
        {d && (
          <div className={d.allowed ? "muted small" : "error"}>
            {d.allowed
              ? [
                  `Policy "${d.policy_name}"`,
                  d.require_approval ? `${d.approvals} approval${d.approvals > 1 ? "s" : ""} needed` : "no approval needed",
                  d.require_mfa && "MFA code needed",
                  `up to ${d.max_minutes >= 60 ? `${d.max_minutes / 60} h` : `${d.max_minutes} min`}`,
                  "recorded",
                ].filter(Boolean).join(" · ")
              : d.reasons.join("; ")}
            {d.allowed && d.reasons.length > 1 && <div>{d.reasons.slice(0, -1).join("; ")}</div>}
            {d.require_mfa && preview.data && !preview.data.mfa_enabled && (
              <div>Turn on MFA in your <Link to="/profile">profile</Link> first.</div>
            )}
          </div>
        )}
        {error && <div className="error">{error}</div>}
      </form>
    </section>
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
