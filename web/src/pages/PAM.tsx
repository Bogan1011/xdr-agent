import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { AccessSession, Elevation, ElevationStatus, Inventory, PamSession, api, can, formatBytes, timeAgo } from "../api";
import { usePoll } from "../hooks";
import { useMe } from "../me";
import { AccessForm } from "./RemoteAccess";

const statusClass: Record<ElevationStatus, string> = {
  pending: "status-warn",
  approved: "status-warn",
  active: "status-good",
  denied: "muted",
  expired: "muted",
  revoked: "muted",
  failed: "status-critical",
  cancelled: "muted",
};

const durations = [15, 30, 60, 120, 240, 480];

function minutes(n: number) {
  return n >= 60 ? `${n / 60} h` : `${n} min`;
}

export default function PAM() {
  const requests = usePoll(() => api.elevations(), 5000);
  const accounts = usePoll(api.privilegedAccounts, 30000);
  const sessions = usePoll(() => api.pamSessions(), 15000);
  const privileged = usePoll(() => api.accessSessions(), 15000);
  const me = useMe();

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Privileged access</h1>
          <p className="muted small">
            Every shell and sudo grant is an access request decided by the <Link to="/admin/access">access policies</Link>:
            who, which servers, approval, MFA and how long. Sessions are recorded and scored.
          </p>
        </div>
      </header>
      <section className="card">
        <h2>Access requests</h2>
        <p className="muted small">
          Shell requests come from Remote access; sudo from the form below or on the host with{" "}
          <code>xdr-agent elevate -reason "…" -duration 30m</code>. Grants end when they expire or are revoked, and open
          shells and sudo sessions are closed.
        </p>
        {requests.error && <div className="error">{requests.error}</div>}
        {requests.data && <RequestTable requests={requests.data} onChange={() => { requests.refresh(); sessions.refresh(); }} />}
      </section>
      {can(me, "access.request") && <GrantForm onDone={requests.refresh} />}
      <section className="card">
        <h2>Privileged sessions</h2>
        <p className="muted small">Who connected where, under which approval, and how risky it looked.</p>
        {privileged.data && <PrivilegedSessions sessions={privileged.data} />}
      </section>
      <section className="card">
        <h2>Privileged accounts</h2>
        {accounts.data && <AccountTable inventory={accounts.data} />}
      </section>
      <section className="card">
        <h2>Session recordings</h2>
        <p className="muted small">
          Terminal output of sudo sessions, uploaded when each session ends. Turn on recording of every sudo session per host on
          the endpoint's page.
        </p>
        {sessions.data && <SessionTable sessions={sessions.data} />}
      </section>
    </>
  );
}

function RequestTable({ requests, onChange }: { requests: Elevation[]; onChange: () => void }) {
  const me = useMe();
  const [length, setLength] = useState<Record<string, number>>({});
  const [error, setError] = useState("");
  if (requests.length === 0) return <div className="empty">No requests yet.</div>;

  async function act(f: () => Promise<void>) {
    setError("");
    try {
      await f();
      onChange();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <>
      {error && <div className="error">{error}</div>}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Requested</th>
              <th>Access</th>
              <th>Host</th>
              <th>Account</th>
              <th>Reason</th>
              <th>Length</th>
              <th>Approvals</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {requests.map((r) => {
              const asked = Math.round(r.duration_seconds / 60);
              const pick = length[r.id] ?? asked;
              return (
                <tr key={r.id}>
                  <td className="nowrap" title={new Date(r.created_at).toLocaleString()}>{timeAgo(r.created_at)}</td>
                  <td className="nowrap">{r.kind === "shell" ? "Shell" : "Sudo"}</td>
                  <td><Link to={`/endpoints/${r.agent_id}`}>{r.hostname}</Link></td>
                  <td className="mono">{r.username}</td>
                  <td>
                    {r.reason || <span className="muted">—</span>}
                    {r.ticket && <div className="small mono">{r.ticket}</div>}
                    {r.requested_by !== r.username && <div className="muted small">by {r.requested_by}</div>}
                    {r.note && <div className="muted small">{r.note}</div>}
                    {r.incident && <div className="status status-critical small">open {r.incident} alert</div>}
                  </td>
                  <td className="nowrap">{minutes(asked)}</td>
                  <td className="nowrap small">
                    {(r.approvals ?? []).filter((a) => a.decision === "approve").length}/{r.approvals_required}
                    {r.policy_name && <div className="muted">{r.policy_name}</div>}
                    {(r.approvals ?? []).map((a) => (
                      <div key={a.approver} className="muted">
                        {a.decision === "approve" ? "✓" : "✗"} {a.approver}{a.emergency ? " (emergency)" : ""}
                      </div>
                    ))}
                  </td>
                  <td className="nowrap">
                    <span className={`status ${statusClass[r.status]}`}>{r.status}</span>
                    {(r.status === "active" || r.status === "approved") && can(me, "access.approve") && (
                      <div className="muted small">until {new Date(r.expires_at).toLocaleTimeString()}</div>
                    )}
                    {r.decided_by && r.status !== "pending" && <div className="muted small">by {r.decided_by}</div>}
                  </td>
                  <td className="nowrap">
                    {r.status === "pending" && r.requester_id === me?.id && (
                      <div className="actions">
                        <button onClick={() => act(() => api.cancelElevation(r.id))}>Cancel</button>
                        {can(me, "*") && (
                          <button
                            className="danger"
                            title="Break-glass: approve your own request. Logged and raises the session's risk."
                            onClick={() => {
                              const note = prompt("Emergency access: why can't this wait for another approver?");
                              if (note) act(() => api.approveElevation(r.id, pick, note, true).then(() => undefined));
                            }}
                          >
                            Emergency
                          </button>
                        )}
                      </div>
                    )}
                    {r.status === "pending" && r.requester_id !== me?.id && can(me, "access.approve") && (
                      <div className="actions">
                        <select value={pick} onChange={(e) => setLength({ ...length, [r.id]: Number(e.target.value) })}>
                          {[...new Set([asked, ...durations])].sort((a, b) => a - b).map((m) => (
                            <option key={m} value={m}>{minutes(m)}</option>
                          ))}
                        </select>
                        <button className="primary" onClick={() => act(() => api.approveElevation(r.id, pick).then(() => undefined))}>Approve</button>
                        <button
                          onClick={() => {
                            const note = prompt(`Deny access for ${r.username} on ${r.hostname}? Optional note for the requester:`);
                            if (note !== null) act(() => api.denyElevation(r.id, note));
                          }}
                        >
                          Deny
                        </button>
                      </div>
                    )}
                    {(r.status === "active" || r.status === "approved") && (
                      <button
                        className="danger"
                        onClick={() => {
                          if (confirm(`Revoke access for ${r.username} on ${r.hostname} now? Open shells and sudo sessions are ended.`))
                            act(() => api.revokeElevation(r.id));
                        }}
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

function GrantForm({ onDone }: { onDone: () => void }) {
  const agents = usePoll(api.agents, 60000);
  const [agent, setAgent] = useState("");
  const [msg, setMsg] = useState("");
  return (
    <>
      <section className="card">
        <div className="card-head">
          <h2>Sudo for a local account</h2>
          <select value={agent} onChange={(e) => { setAgent(e.target.value); setMsg(""); }} required aria-label="Host">
            <option value="">Pick a host…</option>
            {(agents.data ?? []).filter((a) => !a.revoked).map((a) => (
              <option key={a.id} value={a.id}>{a.hostname}{a.online ? "" : " (offline)"}</option>
            ))}
          </select>
        </div>
        {msg && <div className="notice">{msg}</div>}
        {!agent && <div className="muted small">Pick a host to see what its access policy needs.</div>}
      </section>
      {agent && (
        <AccessForm
          key={agent}
          agentId={agent}
          kind="jit_sudo"
          onCreated={(r) => {
            setMsg(r.status === "pending" ? `Request sent; it needs ${r.approvals_required} approval(s).` : `Sudo sent to ${r.username}; it is active once the agent checks in.`);
            onDone();
          }}
        />
      )}
    </>
  );
}

function riskClass(n: number) {
  return n >= 50 ? "status-critical" : n >= 20 ? "status-warn" : "status-good";
}

function PrivilegedSessions({ sessions }: { sessions: AccessSession[] }) {
  if (sessions.length === 0) return <div className="empty">No privileged sessions yet.</div>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr><th>Started</th><th>Who</th><th>Host</th><th>How</th><th>Approval</th><th>Length</th><th>Risk</th></tr>
        </thead>
        <tbody>
          {sessions.map((s) => {
            const end = s.ended_at && new Date(s.ended_at).getTime() > 0 ? new Date(s.ended_at).getTime() : 0;
            return (
              <tr key={s.id}>
                <td className="nowrap"><Link to={`/pam/sessions/${encodeURIComponent(s.id)}`}>{timeAgo(s.started_at)}</Link></td>
                <td>{s.username}<div className="muted small mono">{s.source_ip}</div></td>
                <td><Link to={`/endpoints/${s.agent_id}`}>{s.hostname}</Link></td>
                <td className="small">
                  {s.protocol === "browser_shell" ? "Browser shell" : "sudo"} as <code>{s.account || "root"}</code>
                  <div className="muted">{s.auth_method}</div>
                </td>
                <td className="small">{s.policy_name || (s.request_id ? s.request_id.slice(0, 8) : <span className="muted">standing</span>)}</td>
                <td className="nowrap">{end ? `${Math.max(1, Math.round((end - new Date(s.started_at).getTime()) / 60000))} min` : <span className="status status-good">open</span>}</td>
                <td className="nowrap" title={s.risk_reasons.join("\n")}><span className={`status ${riskClass(s.risk_score)}`}>{s.risk_score}</span></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function sinceUnix(v: string | number) {
  const n = Number(v);
  return n > 0 ? timeAgo(new Date(n * 1000).toISOString()) : "never";
}

function AccountTable({ inventory }: { inventory: Inventory[] }) {
  const rows = inventory.flatMap((i) => i.accounts.map((a) => ({ inv: i, a })));
  if (rows.length === 0) return <div className="empty">No reports yet. Agents send their privileged accounts within a minute of starting.</div>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Host</th>
            <th>Account</th>
            <th>Root via</th>
            <th>Risks</th>
            <th>Password</th>
            <th>SSH keys</th>
            <th>Last login</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ inv, a }) => {
            const risks = [
              a.nopasswd && "sudo without password",
              a.password === "empty" && "empty password",
              a.uid === 0 && a.name !== "root" && "extra uid 0",
              a.sources.some((s) => s.startsWith("group:")) && "root-equivalent group",
            ].filter(Boolean);
            return (
              <tr key={inv.agent_id + a.name}>
                <td><Link to={`/endpoints/${inv.agent_id}`}>{inv.hostname}</Link></td>
                <td className="mono">{a.name} <span className="muted">({a.uid})</span></td>
                <td className="mono small">{a.sources.join(", ")}</td>
                <td>{risks.map((r) => <div key={String(r)} className="status status-critical small">{r}</div>)}</td>
                <td>{a.password || "—"}</td>
                <td>{a.ssh_keys}</td>
                <td className="nowrap">
                  {sinceUnix(a.last_login_unix)}
                  {a.last_login_from && <div className="muted small mono">{a.last_login_from}</div>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// plainText renders a terminal transcript as text: escape sequences are
// dropped and backspaces and carriage returns applied per line.
function plainText(s: string) {
  const noEsc = s
    // eslint-disable-next-line no-control-regex
    .replace(/\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g, "")
    // eslint-disable-next-line no-control-regex
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "")
    // eslint-disable-next-line no-control-regex
    .replace(/\x1b[()][A-Za-z0-9]|\x1b[=>78]/g, "");
  return noEsc
    .split("\n")
    .map((line) => {
      line = line.replace(/\r+$/, "");
      line = line.slice(line.lastIndexOf("\r") + 1);
      let out = "";
      for (const ch of line) out = ch === "\b" ? out.slice(0, -1) : out + ch;
      return out;
    })
    .join("\n");
}

function SessionTable({ sessions }: { sessions: PamSession[] }) {
  const [open, setOpen] = useState<number | null>(null);
  const [text, setText] = useState("");
  if (sessions.length === 0) return <div className="empty">No recorded sessions yet.</div>;

  async function toggle(id: number) {
    if (open === id) {
      setOpen(null);
      return;
    }
    setOpen(id);
    setText("Loading…");
    try {
      setText(plainText((await api.pamSession(id)).output) || "(no terminal output)");
    } catch (e) {
      setText((e as Error).message);
    }
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Started</th>
            <th>Host</th>
            <th>User</th>
            <th>Command</th>
            <th>Length</th>
            <th>Output</th>
            <th>Grant</th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((s) => (
            <Fragment key={s.id}>
              <tr className="clickable" onClick={() => toggle(s.id)}>
                <td className="nowrap" title={new Date(s.started_at).toLocaleString()}>{timeAgo(s.started_at)}</td>
                <td>{s.hostname}</td>
                <td className="mono nowrap">{s.username} → {s.runas_user || "root"}</td>
                <td className="mono truncate" title={s.command}>{s.command}</td>
                <td className="nowrap">{Math.round(s.duration_ms / 1000)} s</td>
                <td className="nowrap">{formatBytes(s.size)}{s.truncated && " (cut)"}</td>
                <td className="mono small">{s.request_id ? s.request_id.slice(0, 8) : <span className="muted">standing</span>}</td>
              </tr>
              {open === s.id && (
                <tr className="detail-row">
                  <td colSpan={7}>
                    <div className="muted small">{s.tty} · {s.cwd}</div>
                    <pre className="code terminal">{text}</pre>
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}
