import { FormEvent, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import { usePoll } from "../hooks";
import EventTable from "../components/EventTable";

const typeOptions: [string, string][] = [
  ["", "All event types"],
  ["process_exec", "Process start"],
  ["process_exit", "Process exit"],
  ["process_exec,process_exit", "Any process"],
  ["shell_command", "Shell command"],
  ["file_create,file_modify,file_delete,file_rename,file_attrib", "Any file"],
  ["file_modify", "File modified"],
  ["file_delete", "File deleted"],
  ["net_connect", "Connection"],
  ["net_accept", "Inbound connection"],
  ["net_listen", "Listening port"],
];

const ranges: [string, string][] = [
  ["15m", "Last 15 minutes"],
  ["1h", "Last hour"],
  ["24h", "Last 24 hours"],
  ["168h", "Last 7 days"],
  ["720h", "Last 30 days"],
];

export default function Events() {
  const [params, setParams] = useSearchParams();
  const q = params.get("q") ?? "";
  const type = params.get("type") ?? "";
  const from = params.get("from") ?? "24h";
  const sha256 = params.get("sha256") ?? "";
  const [draft, setDraft] = useState(q);
  const [live, setLive] = useState(true);

  const { data, error } = usePoll(
    () => api.events({ q, type, from, sha256, limit: 500 }),
    live ? 5000 : 0,
    [q, type, from, sha256, live],
  );

  function set(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    set("q", draft.trim());
  }

  return (
    <>
      <header className="page-head">
        <h1>Event search</h1>
      </header>
      <form className="filters" onSubmit={submit}>
        <input
          className="grow"
          placeholder="Search process, command line, file path, IP, user, host…"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
        />
        <select value={type} onChange={(e) => set("type", e.target.value)}>
          {typeOptions.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
        <select value={from} onChange={(e) => set("from", e.target.value)}>
          {ranges.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
        <label className="toggle">
          <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} /> Live
        </label>
        <button className="primary">Search</button>
      </form>
      {sha256 && (
        <div className="notice">
          Filtering by SHA-256 <span className="mono">{sha256}</span>{" "}
          <button className="link" onClick={() => set("sha256", "")}>clear</button>
        </div>
      )}
      {error && <div className="error">{error}</div>}
      <section className="card">
        {data && <div className="muted small">{data.length === 500 ? "Showing the newest 500 matches" : `${data.length} matches`}</div>}
        {data && <EventTable events={data} />}
      </section>
    </>
  );
}
