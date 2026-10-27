import { useState } from "react";
import { FirewallRule, ModuleKey, PolicyDetail, PreventionPolicy } from "../api";

type Set = (p: PreventionPolicy) => void;
type Intel = PolicyDetail["intel"];

const lines = (s: string) => s.split("\n").map((l) => l.trim()).filter(Boolean);

// ListField edits a list one item per line; it keeps its own text so blank
// lines survive while typing. Remount it (key) to load another policy.
function ListField({ label, value, onChange, rows = 6, placeholder }: {
  label: string;
  value: string[];
  onChange: (v: string[]) => void;
  rows?: number;
  placeholder?: string;
}) {
  const [text, setText] = useState(value.join("\n"));
  return (
    <label className="stack">
      {label}
      <textarea
        rows={rows}
        className="mono"
        placeholder={placeholder}
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          onChange(lines(e.target.value));
        }}
      />
    </label>
  );
}

function Check({ checked, onChange, children }: { checked: boolean; onChange: (v: boolean) => void; children: React.ReactNode }) {
  return (
    <label className="toggle">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} /> {children}
    </label>
  );
}

// Switch is the module's main on/off control.
function Switch({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="tabs" role="group" aria-label="Module state">
      <button type="button" className={on ? "active" : ""} onClick={() => onChange(true)}>On</button>
      <button type="button" className={on ? "" : "active"} onClick={() => onChange(false)}>Off</button>
    </div>
  );
}

export function moduleOn(p: PreventionPolicy, m: ModuleKey): boolean {
  switch (m) {
    case "anti_malware": return p.anti_malware.enabled || p.anti_malware.block_known_bad;
    case "web_reputation": return p.web_reputation.enabled;
    case "file_integrity": return p.fim.enabled;
    case "firewall": return p.firewall.enabled;
    case "intrusion_prevention": return p.intrusion_prevention.enabled;
    case "device_control": return p.device_control.enabled;
    case "activity_monitoring": return p.activity_monitoring.process || p.activity_monitoring.file || p.activity_monitoring.network;
    case "application_control": return p.application_control.enabled;
  }
}

const about: Record<ModuleKey, string> = {
  anti_malware: "Scans new and changed files and every program that starts with the YARA rules, and stops known-bad files from running.",
  web_reputation: "Stops or reports connections to known-bad IP addresses and domains, from threat intel and your own list.",
  file_integrity: "Records a baseline of critical files and raises an alert when one changes.",
  firewall: "Host firewall rules applied with nftables.",
  intrusion_prevention: "Detects SSH brute force and bans the attacking address for a while.",
  device_control: "Controls USB storage devices (USB sticks, external disks).",
  activity_monitoring: "Chooses which activity the agent records for threat hunting and behaviour rules.",
  application_control: "Stops or reports programs by path or SHA-256, locks a server down to an allow-list, and stops scripts run from temp folders.",
};

export function ModuleForm({ m, p, set, intel }: { m: ModuleKey; p: PreventionPolicy; set: Set; intel?: Intel }) {
  const body = (() => {
    switch (m) {
      case "anti_malware": return <AntiMalware p={p} set={set} intel={intel} />;
      case "web_reputation": return <WebReputation p={p} set={set} intel={intel} />;
      case "file_integrity": return <FileIntegrity p={p} set={set} />;
      case "firewall": return <Firewall p={p} set={set} />;
      case "intrusion_prevention": return <Intrusion p={p} set={set} />;
      case "device_control": return <DeviceControl p={p} set={set} />;
      case "activity_monitoring": return <Activity p={p} set={set} />;
      case "application_control": return <AppControl p={p} set={set} />;
    }
  })();
  return (
    <div className="stack">
      <p className="muted" style={{ margin: 0 }}>{about[m]}</p>
      {body}
    </div>
  );
}

function AntiMalware({ p, set, intel }: { p: PreventionPolicy; set: Set; intel?: Intel }) {
  const am = p.anti_malware;
  const up = (v: Partial<typeof am>) => set({ ...p, anti_malware: { ...am, ...v } });
  return (
    <>
      <Switch on={am.enabled} onChange={(enabled) => up({ enabled })} />
      <Check checked={am.enabled} onChange={(enabled) => up({ enabled })}>Real-time scan (YARA rules on new files and started programs)</Check>
      <Check checked={am.block_known_bad} onChange={(block_known_bad) => up({ block_known_bad })}>
        Block programs whose SHA-256 is a hash IOC{intel ? ` (${intel.hashes.toLocaleString()} on the list today)` : ""}
      </Check>
      <Check checked={am.auto_quarantine} onChange={(auto_quarantine) => up({ auto_quarantine })}>Quarantine files that match a YARA rule</Check>
      <div className="muted small">Blocking uses fanotify (Linux 5.0 or later). Quarantined files can be restored from the endpoint's Response panel.</div>
    </>
  );
}

function WebReputation({ p, set, intel }: { p: PreventionPolicy; set: Set; intel?: Intel }) {
  const wr = p.web_reputation;
  const up = (v: Partial<typeof wr>) => set({ ...p, web_reputation: { ...wr, ...v } });
  return (
    <>
      <Switch on={wr.enabled} onChange={(enabled) => up({ enabled })} />
      <label className="filters">
        Action
        <select value={wr.block ? "block" : "detect"} onChange={(e) => up({ block: e.target.value === "block" })}>
          <option value="block">Block and alert</option>
          <option value="detect">Alert only</option>
        </select>
      </label>
      <Check checked={wr.use_threat_intel} onChange={(use_threat_intel) => up({ use_threat_intel })}>
        Use threat intel IP and domain IOCs{intel ? ` (${intel.ips.toLocaleString()} IPs, ${intel.domains.toLocaleString()} domains)` : ""}
      </Check>
      <div className="grid-2">
        <ListField label="Blocked domains (one per line, subdomains included)" value={wr.blocked_domains} placeholder="bad-site.example" onChange={(blocked_domains) => up({ blocked_domains })} />
        <ListField label="Always allowed domains" value={wr.allowed_domains} onChange={(allowed_domains) => up({ allowed_domains })} />
      </div>
      <div className="muted small">Domains are resolved by the agent every 10 minutes and their addresses blocked with nftables (also for containers). The console's address is never blocked.</div>
    </>
  );
}

function FileIntegrity({ p, set }: { p: PreventionPolicy; set: Set }) {
  const f = p.fim;
  const up = (v: Partial<typeof f>) => set({ ...p, fim: { ...f, ...v } });
  return (
    <>
      <Switch on={f.enabled} onChange={(enabled) => up({ enabled })} />
      <div className="grid-2">
        <ListField label="Monitored files and directories" rows={10} value={f.paths} onChange={(paths) => up({ paths })} />
        <ListField label="Exclude (path prefixes or globs)" rows={10} value={f.exclude} onChange={(exclude) => up({ exclude })} />
      </div>
      <label className="filters">
        Full rescan every
        <input type="number" className="narrow" min={5} value={f.interval_minutes} onChange={(e) => up({ interval_minutes: Number(e.target.value) })} />
        minutes (changes seen by file events are reported within seconds)
      </label>
    </>
  );
}

const newRule = (): FirewallRule => ({ direction: "in", action: "allow", protocol: "tcp", ports: "", cidr: "", comment: "" });

function Firewall({ p, set }: { p: PreventionPolicy; set: Set }) {
  const fw = p.firewall;
  const up = (v: Partial<typeof fw>) => set({ ...p, firewall: { ...fw, ...v } });
  const rule = (i: number, r: Partial<FirewallRule>) => up({ rules: fw.rules.map((x, j) => (j === i ? { ...x, ...r } : x)) });
  return (
    <>
      <Switch on={fw.enabled} onChange={(enabled) => up({ enabled })} />
      <Check checked={fw.default_deny_inbound} onChange={(default_deny_inbound) => up({ default_deny_inbound })}>Deny new inbound connections no rule allows</Check>
      <div className="muted small">Loopback, established connections, DHCP and the console are always allowed. Rules match top to bottom; the first match wins.</div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr><th>Direction</th><th>Action</th><th>Protocol</th><th>Ports</th><th>Remote IP / CIDR</th><th>Comment</th><th /></tr>
          </thead>
          <tbody>
            {fw.rules.map((r, i) => (
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
                <td><button type="button" className="link" onClick={() => up({ rules: fw.rules.filter((_, j) => j !== i) })}>Remove</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div><button type="button" onClick={() => up({ rules: [...fw.rules, newRule()] })}>Add rule</button></div>
    </>
  );
}

function Intrusion({ p, set }: { p: PreventionPolicy; set: Set }) {
  const ips = p.intrusion_prevention;
  const up = (v: Partial<typeof ips>) => set({ ...p, intrusion_prevention: { ...ips, ...v } });
  return (
    <>
      <Switch on={ips.enabled} onChange={(enabled) => up({ enabled })} />
      <label className="filters">
        Action
        <select value={ips.prevent ? "prevent" : "detect"} onChange={(e) => up({ prevent: e.target.value === "prevent" })}>
          <option value="prevent">Prevent: ban the address and alert</option>
          <option value="detect">Detect: alert only</option>
        </select>
      </label>
      <div className="filters">
        <label>After <input type="number" className="narrow" min={2} max={100} value={ips.max_failures} onChange={(e) => up({ max_failures: Number(e.target.value) })} /> failed SSH logins</label>
        <label>within <input type="number" className="narrow" min={10} value={ips.window_seconds} onChange={(e) => up({ window_seconds: Number(e.target.value) })} /> seconds,</label>
        <label>ban for <input type="number" className="narrow" min={1} value={ips.ban_minutes} onChange={(e) => up({ ban_minutes: Number(e.target.value) })} /> minutes</label>
      </div>
      <ListField label="Never ban (IPs or CIDRs, one per line)" rows={4} value={ips.allow} placeholder="192.168.1.0/24" onChange={(allow) => up({ allow })} />
      <div className="muted small">Reads sshd's log (journald, or /var/log/auth.log). A wrong password and an unknown username both count. The console is never banned.</div>
    </>
  );
}

function DeviceControl({ p, set }: { p: PreventionPolicy; set: Set }) {
  const dc = p.device_control;
  const up = (v: Partial<typeof dc>) => set({ ...p, device_control: { ...dc, ...v } });
  return (
    <>
      <Switch on={dc.enabled} onChange={(enabled) => up({ enabled })} />
      <label className="filters">
        USB storage
        <select value={dc.usb_storage} onChange={(e) => up({ usb_storage: e.target.value as "allow" | "block" })}>
          <option value="allow">Allow (report each device)</option>
          <option value="block">Block</option>
        </select>
      </label>
      <ListField label="Always allowed devices (vendor:product, e.g. 0781:5583)" rows={4} value={dc.allowed_devices} onChange={(allowed_devices) => up({ allowed_devices })} />
      <div className="muted small">Find a device's ID with <span className="mono">lsusb</span>. Keyboards, mice and other USB devices are never affected.</div>
    </>
  );
}

function Activity({ p, set }: { p: PreventionPolicy; set: Set }) {
  const am = p.activity_monitoring;
  const up = (v: Partial<typeof am>) => set({ ...p, activity_monitoring: { ...am, ...v } });
  return (
    <>
      <Check checked={am.process} onChange={(process) => up({ process })}>Process activity (programs started and stopped)</Check>
      <Check checked={am.file} onChange={(file) => up({ file })}>File activity (created, changed, deleted)</Check>
      <Check checked={am.network} onChange={(network) => up({ network })}>Network activity (connections and listening ports)</Check>
      <div className="muted small">Turning a kind off saves bandwidth and storage, but behaviour rules on it stop working. Alerts and prevention events are always sent.</div>
    </>
  );
}

const DEFAULT_ALLOWED = ["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/opt", "/snap", "/etc", "/var/lib/docker", "/var/lib/containerd", "/var/lib/snapd"];
const DEFAULT_SCRIPT_DIRS = ["/tmp", "/var/tmp", "/dev/shm"];

function AppControl({ p, set }: { p: PreventionPolicy; set: Set }) {
  const ac = p.application_control;
  const up = (v: Partial<typeof ac>) => set({ ...p, application_control: { ...ac, ...v } });
  return (
    <>
      <Switch on={ac.enabled} onChange={(enabled) => up({ enabled })} />
      <label className="filters">
        Action
        <select value={ac.block ? "block" : "detect"} onChange={(e) => up({ block: e.target.value === "block" })}>
          <option value="block">Block and alert</option>
          <option value="detect">Alert only</option>
        </select>
      </label>
      <div className="grid-2">
        <ListField label="Blocked paths (prefixes or globs)" value={ac.blocked_paths} placeholder={"/tmp/*\n/opt/games"} onChange={(blocked_paths) => up({ blocked_paths })} />
        <ListField label="Blocked SHA-256 hashes" value={ac.blocked_sha256} onChange={(blocked_sha256) => up({ blocked_sha256 })} />
      </div>
      <Check
        checked={ac.lockdown}
        onChange={(lockdown) => up({ lockdown, allowed_paths: lockdown && !ac.allowed_paths?.length ? DEFAULT_ALLOWED : ac.allowed_paths })}
      >
        Lockdown: only allow-listed programs may run
      </Check>
      {ac.lockdown && (
        <>
          <div className="grid-2">
            <ListField label="Allowed paths" value={ac.allowed_paths ?? []} onChange={(allowed_paths) => up({ allowed_paths })} />
            <ListField label="Allowed SHA-256 hashes" value={ac.allowed_sha256 ?? []} onChange={(allowed_sha256) => up({ allowed_sha256 })} />
          </div>
          <div className="muted small">Start with "Alert only" for a few days and check the Application control events before switching to block. The block lists still win over the allow-list.</div>
        </>
      )}
      <Check
        checked={ac.block_scripts}
        onChange={(block_scripts) => up({ block_scripts, script_paths: block_scripts && !ac.script_paths?.length ? DEFAULT_SCRIPT_DIRS : ac.script_paths })}
      >
        Stop scripts (bash, python, perl...) run from temp folders
      </Check>
      {ac.block_scripts && (
        <ListField label="Script folders" rows={3} value={ac.script_paths ?? []} onChange={(script_paths) => up({ script_paths })} />
      )}
    </>
  );
}
