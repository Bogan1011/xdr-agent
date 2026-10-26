import { useState } from "react";
import { Command, CommandType, Severity, api, commandLabels, timeAgo } from "../api";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`sev sev-${severity}`}>{severity}</span>;
}

function describe(c: Command): string {
  const a = c.args;
  switch (c.type) {
    case "kill_process":
      return `pid ${a.pid}${a.exe ? ` (${a.exe})` : ""}`;
    case "quarantine_file":
    case "scan_path":
      return a.path;
    case "restore_file":
      return a.quarantine_id;
    case "isolate_host":
      return a.allow ? `also allow ${a.allow}` : "console only";
    case "update_agent":
      return `to ${a.version}`;
    default:
      return "";
  }
}

export function CommandList({ commands, onChange }: { commands: Command[]; onChange?: () => void }) {
  if (commands.length === 0) return <div className="empty">No response actions yet.</div>;
  async function restore(c: Command) {
    await api.sendCommand(c.agent_id, "restore_file", { quarantine_id: c.message }, c.alert_id);
    onChange?.();
  }
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Requested</th>
            <th>Action</th>
            <th>Target</th>
            <th>By</th>
            <th>Status</th>
            <th>Result</th>
          </tr>
        </thead>
        <tbody>
          {commands.map((c) => (
            <tr key={c.id}>
              <td className="nowrap" title={new Date(c.created_at).toLocaleString()}>{timeAgo(c.created_at)}</td>
              <td className="nowrap">{commandLabels[c.type]}</td>
              <td className="mono truncate">{describe(c)}</td>
              <td>{c.requested_by}</td>
              <td className={`nowrap cmd-${c.status}`}>{c.status}</td>
              <td className="mono">
                {c.type === "quarantine_file" && c.status === "succeeded" ? (
                  <>
                    id {c.message}{" "}
                    <button className="link" onClick={() => restore(c)}>Restore</button>
                  </>
                ) : (
                  c.message
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// useSend wraps a response command with a confirmation and error state.
export function useSend(agentId: string, alertId = 0, onSent?: () => void) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function send(type: CommandType, args: Record<string, string>, confirmText: string) {
    if (!confirm(confirmText)) return;
    setBusy(true);
    setError("");
    try {
      await api.sendCommand(agentId, type, args, alertId);
      onSent?.();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return { send, error, busy };
}

// EndpointResponse is the manual response panel on an endpoint page.
export function EndpointResponse({
  agentId,
  hostname,
  isolated,
  onSent,
}: {
  agentId: string;
  hostname: string;
  isolated: boolean;
  onSent: () => void;
}) {
  const { send, error, busy } = useSend(agentId, 0, onSent);
  const [pid, setPid] = useState("");
  const [path, setPath] = useState("");
  const [scan, setScan] = useState("/tmp");
  const [allow, setAllow] = useState("");

  return (
    <div className="response">
      {error && <div className="error">{error}</div>}
      <div className="response-grid">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            send("kill_process", { pid }, `Kill process ${pid} on ${hostname}?`);
          }}
        >
          <label>Kill process</label>
          <div className="row">
            <input placeholder="PID" value={pid} onChange={(e) => setPid(e.target.value)} inputMode="numeric" required />
            <button disabled={busy}>Kill</button>
          </div>
        </form>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            send("quarantine_file", { path }, `Quarantine ${path} on ${hostname}? The file is moved to the agent's quarantine folder.`);
          }}
        >
          <label>Quarantine file</label>
          <div className="row">
            <input placeholder="/absolute/path" value={path} onChange={(e) => setPath(e.target.value)} required />
            <button disabled={busy}>Quarantine</button>
          </div>
        </form>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            send("scan_path", { path: scan }, `Scan ${scan} on ${hostname} with the YARA rules?`);
          }}
        >
          <label>YARA scan</label>
          <div className="row">
            <input placeholder="/path/to/scan" value={scan} onChange={(e) => setScan(e.target.value)} required />
            <button disabled={busy}>Scan</button>
          </div>
        </form>
        {isolated ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              send("unisolate_host", {}, `Restore network access on ${hostname}?`);
            }}
          >
            <label>Network isolation</label>
            <div className="row">
              <span className="status status-critical">Isolated</span>
              <button className="primary" disabled={busy}>End isolation</button>
            </div>
          </form>
        ) : (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              send(
                "isolate_host",
                { allow },
                `Isolate ${hostname}? All network traffic except to this console${allow ? ` and ${allow}` : ""} is blocked, including SSH.`,
              );
            }}
          >
            <label>Isolate host (blocks all traffic except the console)</label>
            <div className="row">
              <input placeholder="Also allow, e.g. 192.168.1.10, 10.0.0.0/24" value={allow} onChange={(e) => setAllow(e.target.value)} />
              <button className="danger" disabled={busy}>Isolate</button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
