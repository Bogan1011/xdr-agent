import { useState } from "react";
import { Feed, IOC, Severity, api, timeAgo } from "../api";
import { usePoll } from "../hooks";
import { SeverityBadge } from "../components/Response";

const typeLabels: Record<IOC["type"], string> = { sha256: "SHA-256 hash", ip: "IP / CIDR", domain: "Domain" };

export default function IOCs() {
  const [q, setQ] = useState("");
  const iocs = usePoll(() => api.iocs(q), 0, [q]);
  const feeds = usePoll(api.feeds, 10000);

  return (
    <>
      <header className="page-head">
        <h1>Threat intelligence</h1>
      </header>
      <p className="muted">
        Indicators are matched against every event: hashes against executed and written files, IPs against outbound
        connections, and domains against command lines.
      </p>
      <div className="grid-2">
        <AddIOCs onAdded={iocs.refresh} />
        <AddFeed onAdded={feeds.refresh} />
      </div>
      <section className="card">
        <h2>Feeds</h2>
        {feeds.error && <div className="error">{feeds.error}</div>}
        {feeds.data && <FeedTable feeds={feeds.data} onChange={feeds.refresh} />}
      </section>
      <section className="card">
        <div className="card-head">
          <h2>Indicators</h2>
          <input placeholder="Search all indicators, including feeds" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        {iocs.error && <div className="error">{iocs.error}</div>}
        {iocs.data && <IOCTable iocs={iocs.data} onChange={iocs.refresh} />}
      </section>
    </>
  );
}

function AddIOCs({ onAdded }: { onAdded: () => void }) {
  const [type, setType] = useState<IOC["type"]>("sha256");
  const [values, setValues] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<Severity>("high");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setMsg("");
    try {
      const r = await api.addIOCs(type, values, description, severity);
      setMsg(`Added ${r.added}${r.duplicates ? `, ${r.duplicates} already present` : ""}.`);
      setValues("");
      onAdded();
    } catch (x) {
      setErr((x as Error).message);
    }
  }

  return (
    <form className="card stack" onSubmit={submit}>
      <h2>Add indicators</h2>
      {err && <div className="error">{err}</div>}
      {msg && <div className="notice">{msg}</div>}
      <div className="filters">
        <select value={type} onChange={(e) => setType(e.target.value as IOC["type"])}>
          {Object.entries(typeLabels).map(([k, v]) => (
            <option key={k} value={k}>{v}</option>
          ))}
        </select>
        <SeveritySelect value={severity} onChange={setSeverity} />
      </div>
      <textarea rows={5} placeholder="One per line" value={values} onChange={(e) => setValues(e.target.value)} required />
      <input placeholder="Description (optional)" value={description} onChange={(e) => setDescription(e.target.value)} />
      <div className="actions">
        <button className="primary">Add</button>
      </div>
    </form>
  );
}

function AddFeed({ onAdded }: { onAdded: () => void }) {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [type, setType] = useState<IOC["type"]>("ip");
  const [severity, setSeverity] = useState<Severity>("high");
  const [err, setErr] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    try {
      await api.createFeed({ name, url, type, severity });
      setName("");
      setUrl("");
      onAdded();
    } catch (x) {
      setErr((x as Error).message);
    }
  }

  return (
    <form className="card stack" onSubmit={submit}>
      <h2>Subscribe to a feed</h2>
      {err && <div className="error">{err}</div>}
      <p className="muted small">
        Plain-text or CSV lists, refreshed every 6 hours. Examples: abuse.ch Feodo Tracker IPs
        (https://feodotracker.abuse.ch/downloads/ipblocklist.txt), URLhaus hosts (https://urlhaus.abuse.ch/downloads/text_online/,
        type domain), MalwareBazaar recent SHA-256 (https://bazaar.abuse.ch/export/txt/sha256/recent/).
      </p>
      <input placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} required />
      <input placeholder="https://…" value={url} onChange={(e) => setUrl(e.target.value)} required />
      <div className="filters">
        <select value={type} onChange={(e) => setType(e.target.value as IOC["type"])}>
          {Object.entries(typeLabels).map(([k, v]) => (
            <option key={k} value={k}>{v}</option>
          ))}
        </select>
        <SeveritySelect value={severity} onChange={setSeverity} />
        <button className="primary">Subscribe</button>
      </div>
    </form>
  );
}

function SeveritySelect({ value, onChange }: { value: Severity; onChange: (s: Severity) => void }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value as Severity)} aria-label="Severity">
      <option value="low">Low</option>
      <option value="medium">Medium</option>
      <option value="high">High</option>
      <option value="critical">Critical</option>
    </select>
  );
}

function FeedTable({ feeds, onChange }: { feeds: Feed[]; onChange: () => void }) {
  const [busy, setBusy] = useState(0);
  const [err, setErr] = useState("");
  if (feeds.length === 0) return <div className="empty">No feeds yet.</div>;
  async function refresh(f: Feed) {
    setBusy(f.id);
    setErr("");
    try {
      await api.refreshFeed(f.id);
    } catch (x) {
      setErr((x as Error).message);
    } finally {
      setBusy(0);
      onChange();
    }
  }
  return (
    <div className="table-wrap">
      {err && <div className="error">{err}</div>}
      <table>
        <thead>
          <tr>
            <th>Enabled</th>
            <th>Feed</th>
            <th>Type</th>
            <th>Indicators</th>
            <th>Last update</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {feeds.map((f) => (
            <tr key={f.id}>
              <td>
                <input type="checkbox" checked={f.enabled} onChange={() => api.setFeedEnabled(f.id, !f.enabled).then(onChange)} />
              </td>
              <td>
                <div>{f.name} <SeverityBadge severity={f.severity} /></div>
                <div className="muted small mono" style={{ wordBreak: "break-all" }}>{f.url}</div>
                {f.last_error && <div className="status-critical small">{f.last_error}</div>}
              </td>
              <td>{typeLabels[f.type]}</td>
              <td>{f.ioc_count.toLocaleString()}</td>
              <td className="nowrap">{timeAgo(f.last_fetched)}</td>
              <td className="nowrap">
                <button className="link" disabled={busy === f.id} onClick={() => refresh(f)}>
                  {busy === f.id ? "Updating…" : "Update now"}
                </button>
                {" · "}
                <button
                  className="link"
                  onClick={() => confirm(`Delete feed ${f.name} and its indicators?`) && api.deleteFeed(f.id).then(onChange)}
                >
                  Delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function IOCTable({ iocs, onChange }: { iocs: IOC[]; onChange: () => void }) {
  if (iocs.length === 0) return <div className="empty">No indicators.</div>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Type</th>
            <th>Value</th>
            <th>Severity</th>
            <th>Source</th>
            <th>Description</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {iocs.map((i) => (
            <tr key={i.id}>
              <td className="nowrap">{typeLabels[i.type]}</td>
              <td className="mono">{i.value}</td>
              <td><SeverityBadge severity={i.severity} /></td>
              <td>{i.source || "Manual"}</td>
              <td>{i.description}</td>
              <td>
                {i.feed_id === 0 && (
                  <button className="link" onClick={() => api.deleteIOC(i.id).then(onChange)}>Delete</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
