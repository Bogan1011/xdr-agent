import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { LiveProcess, TerminalSession, api, formatBytes } from "../api";
import { usePoll } from "../hooks";

function duration(secs: number) {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
  return `${Math.floor(secs / 86400)}d ${Math.floor((secs % 86400) / 3600)}h`;
}

const since = (unix?: number) => (unix ? duration(Math.max(0, Math.round(Date.now() / 1000 - unix))) : "");

// LiveView shows what is happening on a host right now: who is logged in,
// what each of them is running, and the busiest processes.
export default function LiveView({ agentId }: { agentId: string }) {
  const live = usePoll(() => api.agentLive(agentId), 3000, [agentId]);
  const d = live.data;
  const act = d?.activity;
  const terminals = act?.terminals ?? [];
  const memUsed = act?.mem_total_bytes ? act.mem_total_bytes - (act.mem_available_bytes ?? 0) : 0;

  return (
    <section className="card highlight">
      <div className="card-head">
        <h2>
          Live view{" "}
          {d && (d.online ? <span className="status status-good small"><span>●</span> Live</span> : <span className="muted small">Agent not connected</span>)}
        </h2>
        <div className="actions">
          <Link className="button primary" to={`/remote/${agentId}`}>Open remote shell</Link>
        </div>
      </div>
      {live.error && <div className="error">{live.error}</div>}
      {d?.error && <div className="error">{d.error}</div>}
      {act && (
        <>
          <dl className="facts">
            <div><dt>Logged in now</dt><dd>{terminals.length === 0 ? "Nobody" : `${terminals.length} terminal${terminals.length > 1 ? "s" : ""}`}</dd></div>
            <div><dt>Load</dt><dd>{(act.load1 ?? 0).toFixed(2)}</dd></div>
            <div><dt>Memory</dt><dd>{formatBytes(memUsed)} of {formatBytes(act.mem_total_bytes ?? 0)}</dd></div>
            <div><dt>Up</dt><dd>{duration(act.uptime_seconds ?? 0)}</dd></div>
          </dl>
          <h3>Who is doing what</h3>
          {terminals.length === 0 ? (
            <div className="empty">Nobody is logged in.</div>
          ) : (
            <TerminalTable terminals={terminals} shells={d!.shells} />
          )}
          <h3>Busiest processes</h3>
          <ProcessTable procs={act.top ?? []} />
        </>
      )}
    </section>
  );
}

function TerminalTable({ terminals, shells }: { terminals: TerminalSession[]; shells: { id: string; user: string }[] }) {
  const [open, setOpen] = useState<string>("");
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr><th>User</th><th>From</th><th>Terminal</th><th>Logged in</th><th>Idle</th><th>Running now</th><th /></tr>
        </thead>
        <tbody>
          {terminals.map((t) => (
            <Fragment key={t.tty}>
              <tr>
                <td className="mono">{t.user}</td>
                <td className="mono">{t.console ? <span className="status status-warn">XDR console</span> : t.from || "local"}</td>
                <td className="mono">{t.tty}</td>
                <td className="nowrap">{since(t.login_unix)} ago</td>
                <td className="nowrap">{t.idle_seconds ? duration(t.idle_seconds) : "active"}</td>
                <td className="mono">{t.current || <span className="muted">shell prompt</span>}</td>
                <td className="nowrap">
                  <button className="link" onClick={() => setOpen(open === t.tty ? "" : t.tty)}>
                    {open === t.tty ? "Hide" : `${t.processes?.length ?? 0} processes`}
                  </button>
                  {t.console && shells.length > 0 && (
                    <>
                      {" · "}
                      <Link to="/remote">Watch</Link>
                    </>
                  )}
                </td>
              </tr>
              {open === t.tty && (
                <tr>
                  <td colSpan={7}>
                    <ProcessTable procs={t.processes ?? []} />
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

function ProcessTable({ procs }: { procs: LiveProcess[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr><th>PID</th><th>User</th><th>CPU</th><th>Memory</th><th>Started</th><th>Command</th></tr>
        </thead>
        <tbody>
          {procs.map((p) => (
            <tr key={p.pid}>
              <td className="mono">{p.pid}</td>
              <td className="mono">{p.user}</td>
              <td className="nowrap">{(p.cpu_percent ?? 0).toFixed(1)}%</td>
              <td className="nowrap">{formatBytes(p.rss_bytes ?? 0)}</td>
              <td className="nowrap">{since(p.start_unix)} ago</td>
              <td className="mono wrap">{p.command}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
