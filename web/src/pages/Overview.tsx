import { Link, useNavigate } from "react-router-dom";
import { api, categoryOf } from "../api";
import { usePoll } from "../hooks";
import Timeline from "../components/Timeline";
import EventTable from "../components/EventTable";
import { AlertTable } from "./Alerts";

export default function Overview() {
  const agents = usePoll(api.agents, 15000);
  const stats = usePoll(() => api.stats(), 30000);
  const recent = usePoll(() => api.events({ type: "process_exec", limit: 15 }), 10000);
  const summary = usePoll(api.alertSummary, 15000);
  const openAlerts = usePoll(() => api.alerts({ limit: 8 }), 15000);
  const nav = useNavigate();
  const sev = summary.data?.by_severity ?? {};

  const total = agents.data?.length ?? 0;
  const online = agents.data?.filter((a) => a.online).length ?? 0;
  const byCat = { process: 0, file: 0, network: 0 };
  for (const t of stats.data?.by_type ?? []) byCat[categoryOf(t.type)] += t.count;
  const events24h = byCat.process + byCat.file + byCat.network;

  return (
    <>
      <header className="page-head">
        <h1>Overview</h1>
        <span className="muted">Last 24 hours</span>
      </header>
      {(agents.error || stats.error) && <div className="error">{agents.error || stats.error}</div>}

      <section className="tiles">
        <div className="tile">
          <div className="tile-label">Endpoints online</div>
          <div className="tile-value">
            {online}
            <span className="tile-of"> / {total}</span>
          </div>
          {total > online && (
            <div className="tile-note status-warn">
              <span aria-hidden>▲</span> {total - online} offline
            </div>
          )}
        </div>
        <div className="tile">
          <div className="tile-label">Events collected</div>
          <div className="tile-value">{events24h.toLocaleString()}</div>
        </div>
        <div className="tile">
          <div className="tile-label">Process starts</div>
          <div className="tile-value">
            {(stats.data?.by_type.find((t) => t.type === "process_exec")?.count ?? 0).toLocaleString()}
          </div>
        </div>
        <Link to="/alerts" className="tile tile-link">
          <div className="tile-label">Open alerts</div>
          <div className="tile-value">{summary.data?.open ?? 0}</div>
          <div className="tile-note">
            {(sev.critical ?? 0) > 0 && <span className="sev sev-critical">{sev.critical} critical</span>}{" "}
            {(sev.high ?? 0) > 0 && <span className="sev sev-high">{sev.high} high</span>}{" "}
            <span className="muted">{summary.data?.last_24h ?? 0} new in 24h</span>
          </div>
        </Link>
      </section>

      <section className="card">
        <div className="card-head">
          <h2>Open alerts</h2>
          <Link to="/alerts">All alerts →</Link>
        </div>
        {openAlerts.data && <AlertTable alerts={openAlerts.data} onSelect={(id) => nav(`/alerts?id=${id}`)} />}
      </section>

      <section className="card">
        <h2>Event volume</h2>
        {stats.data ? <Timeline stats={stats.data} /> : <div className="empty">Loading…</div>}
      </section>

      <div className="grid-2">
        <section className="card">
          <h2>Most executed programs</h2>
          <TopList items={stats.data?.top_processes ?? []} link={(v) => `/events?q=${encodeURIComponent(v)}&type=process_exec`} />
        </section>
        <section className="card">
          <h2>Top remote addresses</h2>
          <TopList items={stats.data?.top_remote_addrs ?? []} link={(v) => `/events?q=${encodeURIComponent(v)}&type=net_connect`} />
        </section>
      </div>

      <section className="card">
        <div className="card-head">
          <h2>Latest process activity</h2>
          <Link to="/events">Open event search →</Link>
        </div>
        {recent.data && <EventTable events={recent.data} />}
      </section>
    </>
  );
}

function TopList({ items, link }: { items: { value: string; count: number }[]; link: (v: string) => string }) {
  if (items.length === 0) return <div className="empty">Nothing yet.</div>;
  const max = items[0].count;
  return (
    <ol className="toplist">
      {items.map((it) => (
        <li key={it.value}>
          <Link to={link(it.value)} className="mono truncate" title={it.value}>
            {it.value}
          </Link>
          <span className="bar">
            <span style={{ width: `${(it.count / max) * 100}%` }} />
          </span>
          <span className="num">{it.count.toLocaleString()}</span>
        </li>
      ))}
    </ol>
  );
}
