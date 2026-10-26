import { FormEvent, useState } from "react";
import { EnrollmentToken, api, timeAgo } from "../api";
import { usePoll } from "../hooks";

export default function Deploy() {
  const info = usePoll(api.installInfo, 0);
  const tokens = usePoll(api.tokens, 0);
  const [desc, setDesc] = useState("");
  const [maxUses, setMaxUses] = useState(1);
  const [ttl, setTtl] = useState(24);
  const [created, setCreated] = useState<EnrollmentToken | null>(null);
  const [error, setError] = useState("");

  async function create(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      const t = await api.createToken(desc, ttl, maxUses);
      setCreated(t);
      setDesc("");
      tokens.refresh();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function revoke(id: number) {
    await api.revokeToken(id);
    tokens.refresh();
  }

  const base = info.data?.base_url ?? window.location.origin;
  const cmd =
    created && info.data
      ? `curl -fsSL ${base}/install.sh | sudo bash -s -- --token ${created.token} --ca-sha256 ${info.data.ca_sha256}`
      : "";

  return (
    <>
      <header className="page-head">
        <h1>Deploy agents</h1>
      </header>

      <section className="card">
        <h2>1. Create an enrollment token</h2>
        <p className="muted">
          A token lets new hosts enroll. Only its hash is stored, so copy the install command right away.
        </p>
        <form className="filters" onSubmit={create}>
          <input className="grow" placeholder="Description, e.g. ubuntu web servers" value={desc} onChange={(e) => setDesc(e.target.value)} />
          <label>
            Hosts
            <input type="number" min={1} max={10000} value={maxUses} onChange={(e) => setMaxUses(Number(e.target.value))} className="narrow" />
          </label>
          <label>
            Valid for (h)
            <input type="number" min={1} max={720} value={ttl} onChange={(e) => setTtl(Number(e.target.value))} className="narrow" />
          </label>
          <button className="primary">Create token</button>
        </form>
        {error && <div className="error">{error}</div>}
      </section>

      {created && (
        <section className="card highlight">
          <h2>2. Run this on each Linux host as root</h2>
          <pre className="code">{cmd}</pre>
          <CopyButton text={cmd} />
          <p className="muted small">
            The installer checks that the CA certificate it downloads matches the fingerprint in this command before trusting the server.
            Remote install from the console (over SSH) arrives in step 3.
          </p>
        </section>
      )}

      <section className="card">
        <h2>Uninstall</h2>
        <pre className="code">curl -fsSL {base}/uninstall.sh | sudo bash</pre>
        <p className="muted small">Then revoke or delete the endpoint on its page.</p>
      </section>

      <section className="card">
        <h2>Enrollment tokens</h2>
        {tokens.data && tokens.data.length === 0 && <div className="empty">No tokens yet.</div>}
        {tokens.data && tokens.data.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Description</th><th>Used</th><th>Created</th><th>Expires</th><th>State</th><th /></tr>
              </thead>
              <tbody>
                {tokens.data.map((t) => {
                  const expired = new Date(t.expires_at).getTime() < Date.now();
                  const state = t.revoked ? "Revoked" : expired ? "Expired" : t.uses >= t.max_uses ? "Used up" : "Active";
                  return (
                    <tr key={t.id}>
                      <td>{t.description || <span className="muted">—</span>}</td>
                      <td>{t.uses} / {t.max_uses}</td>
                      <td>{timeAgo(t.created_at)}</td>
                      <td>{new Date(t.expires_at).toLocaleString()}</td>
                      <td>{state}</td>
                      <td>{state === "Active" && <button className="link" onClick={() => revoke(t.id)}>Revoke</button>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

// CopyButton falls back to execCommand because the console is often served
// over plain HTTP, where navigator.clipboard is unavailable.
function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }
  return <button onClick={copy}>{copied ? "Copied" : "Copy command"}</button>;
}
