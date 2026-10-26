import { FormEvent, Fragment, useState } from "react";
import { DeployJob, api, timeAgo } from "../api";
import { usePoll } from "../hooks";

const statusClass: Record<DeployJob["status"], string> = {
  pending: "status-warn",
  running: "status-warn",
  succeeded: "status-good",
  failed: "status-critical",
};

// RemoteInstall installs the agent on hosts over SSH. Credentials are sent
// once with the request and are not stored by the server.
export default function RemoteInstall() {
  const [hosts, setHosts] = useState("");
  const [port, setPort] = useState(22);
  const [username, setUsername] = useState("root");
  const [useKey, setUseKey] = useState(false);
  const [password, setPassword] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<number | null>(null);
  const jobs = usePoll(api.deployJobs, 2000);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const r = await api.remoteInstall({
        hosts, port, username,
        password: useKey ? "" : password,
        private_key: useKey ? privateKey : "",
        passphrase: useKey ? passphrase : "",
      });
      setPassword("");
      setPassphrase("");
      setOpen(r.job_ids[0] ?? null);
      jobs.refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <section className="card">
        <h2>Remote install over SSH</h2>
        <p className="muted">
          The console connects to each host over SSH and runs the installer with a fresh one-time token.
          Credentials are used once and never stored. Non-root users need sudo rights.
        </p>
        <form className="stack" onSubmit={submit}>
          <label>
            Hosts (IP or hostname, one per line or comma separated)
            <textarea rows={3} value={hosts} onChange={(e) => setHosts(e.target.value)} placeholder={"192.168.1.118\n192.168.1.120"} required />
          </label>
          <div className="filters">
            <label>
              SSH user
              <input value={username} onChange={(e) => setUsername(e.target.value)} required />
            </label>
            <label>
              Port
              <input type="number" className="narrow" min={1} max={65535} value={port} onChange={(e) => setPort(Number(e.target.value))} />
            </label>
            <label>
              <input type="radio" checked={!useKey} onChange={() => setUseKey(false)} /> Password
            </label>
            <label>
              <input type="radio" checked={useKey} onChange={() => setUseKey(true)} /> Private key
            </label>
          </div>
          {!useKey && (
            <label>
              Password
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="off" required />
            </label>
          )}
          {useKey && (
            <>
              <label>
                Private key (PEM / OpenSSH)
                <textarea rows={5} className="mono" value={privateKey} onChange={(e) => setPrivateKey(e.target.value)} required />
              </label>
              <label>
                Key passphrase (optional)
                <input type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} autoComplete="off" />
              </label>
            </>
          )}
          {error && <div className="error">{error}</div>}
          <div>
            <button className="primary" disabled={busy}>{busy ? "Starting…" : "Install agent"}</button>
          </div>
        </form>
      </section>

      <section className="card">
        <h2>Install jobs</h2>
        {jobs.data && jobs.data.length === 0 && <div className="empty">No remote installs yet.</div>}
        {jobs.data && jobs.data.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Host</th><th>User</th><th>Status</th><th>Started</th><th>Host key</th></tr>
              </thead>
              <tbody>
                {jobs.data.map((j) => (
                  <Fragment key={j.id}>
                    <tr className="clickable" onClick={() => setOpen(open === j.id ? null : j.id)}>
                      <td className="mono">{j.host}:{j.port}</td>
                      <td>{j.username}</td>
                      <td><span className={`status ${statusClass[j.status]}`}>{j.status}</span></td>
                      <td>{timeAgo(j.created_at)}</td>
                      <td className="mono truncate" title={j.host_key}>{j.host_key}</td>
                    </tr>
                    {open === j.id && (
                      <tr className="detail-row">
                        <td colSpan={5}><pre className="code">{j.log || "Waiting…"}</pre></td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
