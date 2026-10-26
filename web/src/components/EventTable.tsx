import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { XdrEvent, categoryOf, formatBytes, typeLabels } from "../api";

function summary(e: XdrEvent): string {
  switch (categoryOf(e.type)) {
    case "process":
      return e.type === "process_exit" ? `${e.exe} exited (${e.exit_code})` : e.args || e.exe;
    case "file":
      if (e.type === "yara_match") return `${e.path} matched ${e.args}`;
      const what = e.type === "file_rename" ? `${e.old_path} → ${e.path}` : e.path;
      return e.exe ? `${what} by ${e.exe}` : what;
    default:
      if (e.type === "net_listen") return `${e.exe || "?"} listening on ${e.local_addr}:${e.local_port}`;
      if (e.type === "net_accept") return `${e.exe || "?"} ← ${e.remote_addr}:${e.remote_port}`;
      return `${e.exe || "?"} → ${e.remote_addr}:${e.remote_port}`;
  }
}

function Detail({ e }: { e: XdrEvent }) {
  const rows: [string, string | number][] = [
    ["Time", new Date(e.ts).toLocaleString()],
    ["Event ID", e.event_id],
    ["Host", e.hostname],
  ];
  const cat = categoryOf(e.type);
  if (cat === "process") {
    rows.push(["PID / PPID", `${e.pid} / ${e.ppid}`], ["User", `${e.user} (uid ${e.uid})`], ["Executable", e.exe]);
    if (e.args) rows.push(["Command line", e.args]);
    if (e.cwd) rows.push(["Working dir", e.cwd]);
    if (e.parent_exe) rows.push(["Parent", e.parent_exe]);
    if (e.type === "process_exit") rows.push(["Exit code", e.exit_code]);
  } else if (cat === "file") {
    rows.push(["Path", e.path]);
    if (e.type === "yara_match") rows.push(["YARA rules", e.args], ["SHA-256", e.sha256]);
    if (e.old_path) rows.push(["Old path", e.old_path]);
    // Only the eBPF collector knows which process made the change.
    if (e.pid) {
      rows.push(["Process", `${e.exe || "unknown"} (pid ${e.pid}, ppid ${e.ppid})`], ["By user", e.user]);
    }
    // A deleted file can no longer be stat'ed, so it has no size or mode.
    if (e.type !== "file_delete") {
      rows.push(["Size", formatBytes(e.size)], ["Mode", (e.mode & 0o7777).toString(8).padStart(4, "0")], ["Owner uid", e.uid]);
    }
  } else {
    rows.push(
      ["Protocol", e.protocol],
      ["Local", `${e.local_addr}:${e.local_port}`],
      ["Remote", `${e.remote_addr}:${e.remote_port}`],
      ["Process", `${e.exe || "unknown"} (pid ${e.pid})`],
    );
  }
  if (e.sha256) rows.push(["SHA-256", e.sha256]);
  return (
    <dl className="detail">
      {rows.map(([k, v]) => (
        <Fragment key={k}>
          <dt>{k}</dt>
          <dd className="mono">{v}</dd>
        </Fragment>
      ))}
    </dl>
  );
}

export default function EventTable({ events, showHost = true }: { events: XdrEvent[]; showHost?: boolean }) {
  const [open, setOpen] = useState<string | null>(null);
  if (events.length === 0) return <div className="empty">No events match.</div>;
  return (
    <div className="table-wrap">
      <table className="events">
        <thead>
          <tr>
            <th>Time</th>
            {showHost && <th>Endpoint</th>}
            <th>Type</th>
            <th>User</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <Fragment key={e.event_id}>
              <tr className="clickable" onClick={() => setOpen(open === e.event_id ? null : e.event_id)}>
                <td className="nowrap">{new Date(e.ts).toLocaleTimeString()}</td>
                {showHost && (
                  <td>
                    <Link to={`/endpoints/${e.agent_id}`} onClick={(ev) => ev.stopPropagation()}>
                      {e.hostname}
                    </Link>
                  </td>
                )}
                <td className="nowrap">
                  <span className={`chip chip-${categoryOf(e.type)}`}>{typeLabels[e.type] ?? e.type}</span>
                </td>
                <td>{e.user}</td>
                <td className="mono truncate" title={summary(e)}>
                  {summary(e)}
                </td>
              </tr>
              {open === e.event_id && (
                <tr className="detail-row">
                  <td colSpan={showHost ? 5 : 4}>
                    <Detail e={e} />
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
