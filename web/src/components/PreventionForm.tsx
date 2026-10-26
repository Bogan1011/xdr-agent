import { useEffect, useState } from "react";
import { FirewallRule, PreventionPolicy } from "../api";

const lines = (s: string) => s.split("\n").map((l) => l.trim()).filter(Boolean);

const newRule = (): FirewallRule => ({ direction: "in", action: "allow", protocol: "tcp", ports: "", cidr: "", comment: "" });

// PreventionForm edits a prevention policy; onSave gets the edited copy.
export default function PreventionForm({
  policy,
  blockedHashes,
  onSave,
}: {
  policy: PreventionPolicy;
  blockedHashes?: number;
  onSave: (p: PreventionPolicy) => Promise<void>;
}) {
  const [p, setP] = useState(policy);
  const [paths, setPaths] = useState(policy.fim.paths.join("\n"));
  const [exclude, setExclude] = useState(policy.fim.exclude.join("\n"));
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");

  useEffect(() => {
    setP(policy);
    setPaths(policy.fim.paths.join("\n"));
    setExclude(policy.fim.exclude.join("\n"));
  }, [policy]);

  const fim = (f: Partial<PreventionPolicy["fim"]>) => setP({ ...p, fim: { ...p.fim, ...f } });
  const fw = (f: Partial<PreventionPolicy["firewall"]>) => setP({ ...p, firewall: { ...p.firewall, ...f } });
  const rule = (i: number, r: Partial<FirewallRule>) =>
    fw({ rules: p.firewall.rules.map((x, j) => (j === i ? { ...x, ...r } : x)) });

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setMsg("");
    const out = { ...p, fim: { ...p.fim, paths: lines(paths), exclude: lines(exclude) } };
    if (out.firewall.enabled && out.firewall.default_deny_inbound &&
      !out.firewall.rules.some((r) => r.direction === "in" && r.action === "allow" && r.ports.split(",").map((x) => x.trim()).includes("22")) &&
      !confirm("Inbound traffic will be denied by default and no rule allows SSH (port 22). Only the console and established connections stay reachable. Save anyway?"))
      return;
    try {
      await onSave(out);
      setMsg("Saved. Endpoints apply it at their next check-in (within 15 seconds).");
    } catch (x) {
      setErr((x as Error).message);
    }
  }

  return (
    <form className="stack" onSubmit={submit}>
      {err && <div className="error">{err}</div>}
      {msg && <div className="notice">{msg}</div>}

      <h3>Malware prevention</h3>
      <label className="toggle">
        <input type="checkbox" checked={p.block_exec} onChange={(e) => setP({ ...p, block_exec: e.target.checked })} /> Block execution of
        files whose SHA-256 is a hash IOC
      </label>
      <div className="muted small">
        {blockedHashes !== undefined && <>{blockedHashes.toLocaleString()} hashes on the block list today (manual and feed IOCs on the Threat intel page). </>}
        Uses fanotify, Linux 5.0 or later. Blocked attempts raise a high alert.
      </div>

      <h3>File integrity monitoring</h3>
      <label className="toggle">
        <input type="checkbox" checked={p.fim.enabled} onChange={(e) => fim({ enabled: e.target.checked })} /> Record a baseline and alert on
        changes
      </label>
      <div className="grid-2">
        <label className="stack">
          Monitored files and directories (one per line)
          <textarea rows={8} className="mono" value={paths} onChange={(e) => setPaths(e.target.value)} />
        </label>
        <label className="stack">
          Exclude (path prefixes or globs, one per line)
          <textarea rows={8} className="mono" value={exclude} onChange={(e) => setExclude(e.target.value)} />
        </label>
      </div>
      <label className="filters">
        Full rescan every
        <input type="number" className="narrow" min={5} value={p.fim.interval_minutes} onChange={(e) => fim({ interval_minutes: Number(e.target.value) })} />
        minutes (changes seen by file events are reported within seconds)
      </label>

      <h3>Host firewall</h3>
      <label className="toggle">
        <input type="checkbox" checked={p.firewall.enabled} onChange={(e) => fw({ enabled: e.target.checked })} /> Apply firewall rules with
        nftables
      </label>
      <label className="toggle">
        <input type="checkbox" checked={p.firewall.default_deny_inbound} onChange={(e) => fw({ default_deny_inbound: e.target.checked })} /> Deny new
        inbound connections no rule allows
      </label>
      <div className="muted small">Loopback, established connections, DHCP and the console are always allowed. Rules match top to bottom; the first match wins.</div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Direction</th>
              <th>Action</th>
              <th>Protocol</th>
              <th>Ports</th>
              <th>Remote IP / CIDR</th>
              <th>Comment</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {p.firewall.rules.map((r, i) => (
              <tr key={i}>
                <td>
                  <select value={r.direction} onChange={(e) => rule(i, { direction: e.target.value as FirewallRule["direction"] })}>
                    <option value="in">Inbound</option>
                    <option value="out">Outbound</option>
                  </select>
                </td>
                <td>
                  <select value={r.action} onChange={(e) => rule(i, { action: e.target.value as FirewallRule["action"] })}>
                    <option value="allow">Allow</option>
                    <option value="deny">Deny</option>
                  </select>
                </td>
                <td>
                  <select value={r.protocol} onChange={(e) => rule(i, { protocol: e.target.value as FirewallRule["protocol"] })}>
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                    <option value="icmp">ICMP</option>
                    <option value="any">Any</option>
                  </select>
                </td>
                <td><input className="mono" placeholder="22, 80-90" value={r.ports} onChange={(e) => rule(i, { ports: e.target.value })} /></td>
                <td><input className="mono" placeholder="any" value={r.cidr} onChange={(e) => rule(i, { cidr: e.target.value })} /></td>
                <td><input value={r.comment} onChange={(e) => rule(i, { comment: e.target.value })} /></td>
                <td>
                  <button type="button" className="link" onClick={() => fw({ rules: p.firewall.rules.filter((_, j) => j !== i) })}>Remove</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="actions">
        <button type="button" onClick={() => fw({ rules: [...p.firewall.rules, newRule()] })}>Add rule</button>
        <button className="primary">Save policy</button>
      </div>
    </form>
  );
}
