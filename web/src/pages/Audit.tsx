import { useState } from "react";
import { api, timeAgo } from "../api";
import { usePoll } from "../hooks";

// Audit is the tamper-evident log of everything done in the console.
export default function Audit() {
  const [q, setQ] = useState("");
  const list = usePoll(() => api.audit(q), 15000, [q]);
  const [verify, setVerify] = useState("");

  async function check() {
    setVerify("Checking…");
    try {
      const v = await api.verifyAudit();
      setVerify(v.ok ? `Chain intact: ${v.checked} entries verified.` : `Chain broken at entry ${v.broken_at}; the log was edited.`);
    } catch (e) {
      setVerify((e as Error).message);
    }
  }

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Audit log</h1>
          <p className="muted small">Sign-ins, every change, access decisions, shells and recording views. Each entry is hash-chained to the one before.</p>
        </div>
        <div className="actions">
          <input placeholder="Search user, action, target" value={q} onChange={(e) => setQ(e.target.value)} />
          <button onClick={check}>Verify chain</button>
        </div>
      </header>
      {verify && <div className="notice">{verify}</div>}
      <section className="card">
        {list.error && <div className="error">{list.error}</div>}
        {list.data && list.data.length === 0 && <div className="empty">Nothing logged yet.</div>}
        {list.data && list.data.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>Outcome</th><th>From</th></tr>
              </thead>
              <tbody>
                {list.data.map((e) => (
                  <tr key={e.id}>
                    <td className="nowrap" title={new Date(e.at).toLocaleString()}>{timeAgo(e.at)}</td>
                    <td>{e.actor}</td>
                    <td className="mono small">{e.action}</td>
                    <td className="mono small truncate" title={JSON.stringify(e.detail)}>{e.target}</td>
                    <td className={e.outcome === "ok" ? "" : "status status-critical"}>{e.outcome}</td>
                    <td className="mono small">{e.remote}</td>
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
