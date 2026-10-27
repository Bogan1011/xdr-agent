import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { XdrEvent, categoryOf, formatBytes, typeLabels } from "../api";

// Policy module events keep the action in path and the detail in args.
const policyTypes = new Set(["web_reputation", "intrusion", "device_control", "app_control"]);

function summary(e: XdrEvent): string {
  if (policyTypes.has(e.type)) {
    const what = e.type === "app_control" ? e.exe : e.remote_addr || "";
    return `${e.path[0]?.toUpperCase() ?? ""}${e.path.slice(1)}${what ? ` ${what}` : ""}: ${e.args}`;
  }
  if (e.type === "agent_tamper") return `${e.path}: ${e.args}`;
  if (e.type === "exec_blocked") return `Blocked ${e.exe}${e.parent_exe ? ` (run by ${e.parent_exe})` : ""}`;
  if (e.type === "fim_change") return `${e.path}: ${e.args.split(" ")[0]}`;
  if (e.type === "shell_command") return `${e.user || "?"}$ ${e.args}`;
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
  if (policyTypes.has(e.type)) {
    rows.push(["Action", e.path], ["Detail", e.args]);
    if (e.remote_addr) rows.push(["Remote address", e.remote_addr]);
    if (e.exe) rows.push(["Process", `${e.exe}${e.pid ? ` (pid ${e.pid})` : ""}`]);
    if (e.user) rows.push(["User", e.user]);
  } else if (cat === "process") {
    rows.push(["PID / PPID", `${e.pid} / ${e.ppid}`], ["User", `${e.user} (uid ${e.uid})`], ["Executable", e.exe]);
    if (e.args) rows.push([e.type === "shell_command" ? "Command" : "Command line", e.args]);
    if (e.type === "shell_command") rows.push(["Typed or run", e.path === "interactive" ? "Typed at a prompt" : "String run by bash (bash -c, eval, trap)"]);
    if (e.cwd) rows.push(["Working dir", e.cwd]);
    if (e.parent_exe) rows.push(["Parent", e.parent_exe]);
    if (e.type === "process_exit") rows.push(["Exit code", e.exit_code]);
  } else if (cat === "file") {
    rows.push(["Path", e.path]);
    if (e.type === "yara_match") rows.push(["YARA rules", e.args], ["SHA-256", e.sha256]);
    if (e.type === "fim_change") rows.push(["Change", e.args]);
    if (e.old_path) rows.push(["Old path", e.old_path]);
    // Only the eBPF collector knows which process made the change.
    if (e.pid) {
      rows.push(["Process", `${e.exe || "unknown"} (pid ${e.pid}, ppid ${e.ppid})`], ["By user", e.user]);
    }
    // A deleted file can no longer be stat'ed, so it has no size or mode.
    if (e.type !== "file_delete" && !(e.type === "fim_change" && e.args.startsWith("removed"))) {
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
      {e.process_guid && (
        <>
          <dt>Process tree</dt>
          <dd>
            <Link to={`/storyline/${e.agent_id}/${e.process_guid}`}>Open storyline →</Link>
          </dd>
        </>
      )}
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
