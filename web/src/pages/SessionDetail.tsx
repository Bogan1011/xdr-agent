import { Link, useParams } from "react-router-dom";
import { api, timeAgo } from "../api";
import { usePoll } from "../hooks";
import EventTable from "../components/EventTable";

// SessionDetail is one privileged session as a security story: who, from
// where, under which approval, the alerts raised while it ran and every
// process, file and connection its shell caused.
export default function SessionDetail() {
  const { id = "" } = useParams();
  const d = usePoll(() => api.accessSession(id), 15000, [id]);
  const s = d.data?.session;
  const ended = s && new Date(s.ended_at).getTime() > 0;
  const execs = (d.data?.events ?? []).filter((e) => e.type === "process_exec").length;

  return (
    <>
      <header className="page-head">
        <div>
          <Link to="/pam" className="muted">← Privileged access</Link>
          <h1>Privileged session{s ? ` · ${s.hostname}` : ""}</h1>
        </div>
      </header>
      {d.error && <div className="error">{d.error}</div>}
      {s && (
        <section className="card">
          <dl className="facts">
            <div><dt className="muted small">Who</dt><dd>{s.username} as <code>{s.account || "root"}</code></dd></div>
            <div><dt className="muted small">Host</dt><dd><Link to={`/endpoints/${s.agent_id}`}>{s.hostname}</Link></dd></div>
            <div><dt className="muted small">How</dt><dd>{s.protocol === "browser_shell" ? "Browser shell" : "sudo on the host"} · {s.auth_method}</dd></div>
            <div><dt className="muted small">From</dt><dd className="mono">{s.source_ip || "—"}</dd></div>
            <div><dt className="muted small">Started</dt><dd title={new Date(s.started_at).toLocaleString()}>{timeAgo(s.started_at)}</dd></div>
            <div><dt className="muted small">Ended</dt><dd>{ended ? `${timeAgo(s.ended_at)} · ${s.end_reason}` : "still open"}</dd></div>
            <div><dt className="muted small">Policy</dt><dd>{s.policy_name || "—"}{s.ticket && <> · <span className="mono">{s.ticket}</span></>}</dd></div>
            <div>
              <dt className="muted small">Risk</dt>
              <dd>
                <b>{ended ? s.risk_score : "scored when it ends"}</b>
                {s.risk_reasons.map((r) => <div key={r} className="muted small">{r}</div>)}
              </dd>
            </div>
          </dl>
          {d.data?.request && (
            <p className="muted small">
              Request {d.data.request.id.slice(0, 8)}: “{d.data.request.reason || "no reason"}”
              {(d.data.approvals ?? []).map((a) => ` · ${a.decision === "approve" ? "approved" : "denied"} by ${a.approver}${a.emergency ? " (emergency)" : ""}`)}
              {s.recording_id > 0 && <> · <Link to="/pam">recording #{s.recording_id}</Link></>}
            </p>
          )}
        </section>
      )}
      <section className="card">
        <h2>Alerts during the session</h2>
        {d.data && d.data.alerts.length === 0 && <div className="empty">No alerts on the host while it ran.</div>}
        {d.data && d.data.alerts.length > 0 && (
          <div className="stack">
            {d.data.alerts.map((a) => (
              <div key={a.id}>
                <span className={`sev sev-${a.severity}`}>{a.severity}</span> <Link to="/alerts">{a.rule_name}</Link>{" "}
                <span className="muted small">{timeAgo(a.first_seen)} · {a.detail}</span>
              </div>
            ))}
          </div>
        )}
      </section>
      {s?.protocol === "browser_shell" && (
        <section className="card">
          <h2>What the session did</h2>
          <p className="muted small">
            {execs} commands and what they touched, from the host's telemetry. Agents that tag console sessions are matched
            exactly; older agents are matched by the shell they started in this window.
          </p>
          {d.data?.events_error && <div className="error">{d.data.events_error}</div>}
          {d.data && <EventTable events={d.data.events} showHost={false} />}
        </section>
      )}
    </>
  );
}
