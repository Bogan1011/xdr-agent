export interface Agent {
  id: string;
  hostname: string;
  os: string;
  os_version: string;
  kernel: string;
  arch: string;
  ip_addresses: string[];
  agent_version: string;
  machine_id: string;
  cert_expires: string;
  enrolled_at: string;
  last_seen: string;
  events_sent: number;
  events_dropped: number;
  cpu_percent: number;
  rss_bytes: number;
  revoked: boolean;
  online: boolean;
  pending_command: string;
  uninstalled_at: string;
  isolated: boolean;
  content_version: string;
  tamper_protection: boolean;
  tamper_protected: boolean;
  updating: boolean;
  pam_record_all: boolean;
  policy_id: number;
  policy_name: string;
}

export interface Fleet {
  version: string;
  sha256: Record<string, string>;
  error?: string;
}

export interface KnownHost {
  host: string;
  port: number;
  fingerprint: string;
  first_seen: string;
}

export type Severity = "low" | "medium" | "high" | "critical";
export type AlertStatus = "new" | "in_progress" | "resolved" | "false_positive";

export interface Alert {
  id: number;
  agent_id: string;
  hostname: string;
  rule_id: string;
  rule_name: string;
  kind: "sigma" | "ioc" | "yara" | "pam" | "correlation";
  severity: Severity;
  tags: string[];
  detail: string;
  status: AlertStatus;
  count: number;
  event: XdrEvent;
  note: string;
  first_seen: string;
  last_seen: string;
  process_guid: string;
  storyline_guid: string;
}

export interface AlertSummary {
  open: number;
  by_severity: Partial<Record<Severity, number>>;
  last_24h: number;
}

export type CommandType =
  | "kill_process"
  | "quarantine_file"
  | "restore_file"
  | "isolate_host"
  | "unisolate_host"
  | "scan_path"
  | "update_agent"
  | "grant_elevation"
  | "revoke_elevation"
  | "fim_rebaseline";

export interface Command {
  id: string;
  agent_id: string;
  type: CommandType;
  args: Record<string, string>;
  alert_id: number;
  requested_by: string;
  status: "pending" | "sent" | "succeeded" | "failed";
  message: string;
  created_at: string;
  finished_at: string;
}

export interface Rule {
  id: string;
  kind: "sigma" | "yara";
  name: string;
  description: string;
  severity: Severity;
  enabled: boolean;
  builtin: boolean;
  source: string;
  updated_at: string;
}

export interface IOC {
  id: number;
  type: "sha256" | "ip" | "domain";
  value: string;
  feed_id: number;
  source: string;
  description: string;
  severity: Severity;
  created_at: string;
}

export interface Feed {
  id: number;
  name: string;
  url: string;
  type: IOC["type"];
  severity: Severity;
  enabled: boolean;
  last_fetched: string;
  last_error: string;
  ioc_count: number;
}

export interface DeployJob {
  id: number;
  host: string;
  port: number;
  username: string;
  status: "pending" | "running" | "succeeded" | "failed";
  host_key: string;
  log: string;
  created_at: string;
  finished_at: string;
}

export interface RemoteInstall {
  hosts: string;
  port: number;
  username: string;
  password: string;
  private_key: string;
  passphrase: string;
}

export interface XdrEvent {
  ts: string;
  agent_id: string;
  hostname: string;
  event_id: string;
  type: string;
  pid: number;
  ppid: number;
  uid: number;
  user: string;
  exe: string;
  args: string;
  cwd: string;
  sha256: string;
  parent_exe: string;
  exit_code: number;
  path: string;
  old_path: string;
  size: number;
  mode: number;
  protocol: string;
  local_addr: string;
  local_port: number;
  remote_addr: string;
  remote_port: number;
  process_guid?: string;
  parent_process_guid?: string;
  storyline_guid?: string;
}

export interface StoryNode {
  guid: string;
  parent_guid: string;
  depth: number;
  pid: number;
  ppid: number;
  exe: string;
  args: string;
  user: string;
  sha256: string;
  started: string;
  images?: string[];
  exited: boolean;
  exit_code: number;
  counts: Record<string, number>;
  known: boolean;
}

export interface Storyline {
  agent_id: string;
  root: string;
  focus: string;
  session?: StoryNode;
  nodes: StoryNode[];
  events: XdrEvent[];
  truncated: boolean;
}

export interface Stats {
  by_type: { type: string; count: number }[];
  timeline: { ts: string; type: string; count: number }[];
  top_processes: { value: string; count: number }[];
  top_remote_addrs: { value: string; count: number }[];
}

export interface EnrollmentToken {
  id: number;
  description: string;
  created_at: string;
  expires_at: string;
  max_uses: number;
  uses: number;
  revoked: boolean;
  token?: string;
}

export interface InstallInfo {
  ca_sha256: string;
  public_host: string;
  enroll_port: number;
  agent_port: number;
  base_url: string;
}

export type ElevationStatus = "pending" | "approved" | "active" | "denied" | "expired" | "revoked" | "failed";

export interface Elevation {
  id: string;
  agent_id: string;
  hostname: string;
  username: string;
  uid: number;
  reason: string;
  duration_seconds: number;
  status: ElevationStatus;
  requested_by: string;
  decided_by: string;
  note: string;
  created_at: string;
  decided_at: string;
  expires_at: string;
}

export interface PrivilegedAccount {
  name: string;
  uid: number;
  shell: string;
  home: string;
  sources: string[];
  groups: string[];
  nopasswd: boolean;
  password: "set" | "locked" | "empty" | "none" | "";
  password_changed_unix: string | number;
  ssh_keys: number;
  last_login_unix: string | number;
  last_login_from: string;
}

export interface Inventory {
  agent_id: string;
  hostname: string;
  accounts: PrivilegedAccount[];
  interactive: number;
  collected_at: string;
}

export interface PamSession {
  id: number;
  agent_id: string;
  hostname: string;
  username: string;
  runas_user: string;
  tty: string;
  cwd: string;
  command: string;
  started_at: string;
  duration_ms: number;
  size: number;
  truncated: boolean;
  request_id: string;
}

export interface FirewallRule {
  direction: "in" | "out";
  action: "allow" | "deny";
  protocol: "tcp" | "udp" | "icmp" | "any";
  ports: string;
  cidr: string;
  comment: string;
}

export interface PreventionPolicy {
  anti_malware: { enabled: boolean; block_known_bad: boolean; auto_quarantine: boolean };
  web_reputation: { enabled: boolean; block: boolean; use_threat_intel: boolean; blocked_domains: string[]; allowed_domains: string[] };
  fim: { enabled: boolean; paths: string[]; exclude: string[]; interval_minutes: number };
  firewall: { enabled: boolean; default_deny_inbound: boolean; rules: FirewallRule[] };
  intrusion_prevention: {
    enabled: boolean;
    prevent: boolean;
    max_failures: number;
    window_seconds: number;
    ban_minutes: number;
    allow: string[];
  };
  device_control: { enabled: boolean; usb_storage: "allow" | "block"; allowed_devices: string[] };
  activity_monitoring: { process: boolean; file: boolean; network: boolean };
  application_control: {
    enabled: boolean;
    block: boolean;
    blocked_paths: string[];
    blocked_sha256: string[];
    lockdown: boolean;
    allowed_paths: string[];
    allowed_sha256: string[];
    block_scripts: boolean;
    script_paths: string[];
  };
}

export interface PreventionState {
  exec_blocking?: boolean;
  blocked_hashes?: number;
  fim_active?: boolean;
  fim_files?: number;
  firewall_applied?: boolean;
  error?: string;
  policy_name?: string;
  realtime_scan?: boolean;
  web_reputation_addrs?: number;
  web_reputation_blocking?: boolean;
  intrusion_prevention?: boolean;
  banned_addrs?: number;
  device_control?: boolean;
  blocked_devices?: number;
  app_control?: boolean;
  script_blocking?: boolean;
}

export interface PolicySummary {
  id: number;
  name: string;
  description: string;
  is_default: boolean;
  endpoints: number;
  updated_at: string;
  modules: string[];
}

export interface PolicyDetail {
  policy: PolicySummary & { policy: PreventionPolicy };
  endpoint_list: { id: string; hostname: string; online: boolean }[];
  intel: { hashes: number; ips: number; domains: number };
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401 && path !== "/api/v1/login") {
    window.dispatchEvent(new Event("xdr:unauthorized"));
  }
  if (!res.ok) {
    let msg = res.statusText;
    try {
      msg = (await res.json()).error ?? msg;
    } catch {
      // keep statusText
    }
    throw new ApiError(res.status, msg);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

export interface EventFilter {
  agent_id?: string;
  type?: string;
  q?: string;
  sha256?: string;
  from?: string;
  limit?: number;
}

export const api = {
  login: (username: string, password: string) =>
    request<{ username: string }>("POST", "/api/v1/login", { username, password }),
  logout: () => request<void>("POST", "/api/v1/logout", {}),
  me: () => request<{ username: string }>("GET", "/api/v1/me"),
  agents: () => request<Agent[]>("GET", "/api/v1/agents"),
  agent: (id: string) => request<Agent>("GET", `/api/v1/agents/${encodeURIComponent(id)}`),
  revokeAgent: (id: string) => request<void>("POST", `/api/v1/agents/${encodeURIComponent(id)}/revoke`, {}),
  uninstallAgent: (id: string) => request<void>("POST", `/api/v1/agents/${encodeURIComponent(id)}/uninstall`, {}),
  fleet: () => request<Fleet>("GET", "/api/v1/fleet"),
  updateAgent: (id: string) => request<void>("POST", `/api/v1/agents/${encodeURIComponent(id)}/update`, {}),
  updateAllAgents: () => request<{ queued: number }>("POST", "/api/v1/agents/update-all", {}),
  setTamperProtection: (id: string, enabled: boolean) =>
    request<void>("POST", `/api/v1/agents/${encodeURIComponent(id)}/tamper-protection`, { enabled }),
  maintenanceToken: (id: string) =>
    request<{ token: string }>("GET", `/api/v1/agents/${encodeURIComponent(id)}/maintenance-token`),
  knownHosts: () => request<KnownHost[]>("GET", "/api/v1/known-hosts"),
  forgetKnownHost: (host: string, port: number) =>
    request<void>("DELETE", `/api/v1/known-hosts/${encodeURIComponent(host)}/${port}`),
  deployJobs: () => request<DeployJob[]>("GET", "/api/v1/deploy-jobs"),
  remoteInstall: (r: RemoteInstall) => request<{ job_ids: number[] }>("POST", "/api/v1/deploy-jobs", r),
  deleteAgent: (id: string) => request<void>("DELETE", `/api/v1/agents/${encodeURIComponent(id)}`),
  events: (f: EventFilter) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(f)) if (v !== undefined && v !== "") p.set(k, String(v));
    return request<XdrEvent[]>("GET", `/api/v1/events?${p}`);
  },
  stats: (agentId?: string) =>
    request<Stats>("GET", `/api/v1/stats${agentId ? `?agent_id=${encodeURIComponent(agentId)}` : ""}`),
  tokens: () => request<EnrollmentToken[]>("GET", "/api/v1/enrollment-tokens"),
  createToken: (description: string, ttl_hours: number, max_uses: number) =>
    request<EnrollmentToken>("POST", "/api/v1/enrollment-tokens", { description, ttl_hours, max_uses }),
  revokeToken: (id: number) => request<void>("DELETE", `/api/v1/enrollment-tokens/${id}`),
  installInfo: () => request<InstallInfo>("GET", "/api/v1/install-info"),

  alerts: (f: { agent_id?: string; status?: string; severity?: string; limit?: number }) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(f)) if (v !== undefined && v !== "") p.set(k, String(v));
    return request<Alert[]>("GET", `/api/v1/alerts?${p}`);
  },
  alertSummary: () => request<AlertSummary>("GET", "/api/v1/alerts/summary"),
  alert: (id: number) => request<{ alert: Alert; commands: Command[] }>("GET", `/api/v1/alerts/${id}`),
  storyline: (agentId: string, guid: string) =>
    request<{ storyline: Storyline; alerts: Alert[] }>(
      "GET",
      `/api/v1/storyline?agent_id=${encodeURIComponent(agentId)}&guid=${encodeURIComponent(guid)}`,
    ),
  updateAlert: (id: number, status: AlertStatus, note = "") =>
    request<void>("PATCH", `/api/v1/alerts/${id}`, { status, note }),
  commands: (agentId: string) => request<Command[]>("GET", `/api/v1/agents/${encodeURIComponent(agentId)}/commands`),
  sendCommand: (agentId: string, type: CommandType, args: Record<string, string> = {}, alert_id = 0) =>
    request<Command>("POST", `/api/v1/agents/${encodeURIComponent(agentId)}/commands`, { type, args, alert_id }),
  rules: () => request<{ rules: Rule[]; fields: string[]; responses: string[] }>("GET", "/api/v1/rules"),
  saveRule: (kind: Rule["kind"], source: string, severity = "", id = "") =>
    request<Rule>(id ? "PUT" : "POST", id ? `/api/v1/rules/${encodeURIComponent(id)}` : "/api/v1/rules", {
      kind,
      source,
      severity,
    }),
  setRuleEnabled: (id: string, enabled: boolean) =>
    request<void>("POST", `/api/v1/rules/${encodeURIComponent(id)}/enabled`, { enabled }),
  deleteRule: (id: string) => request<void>("DELETE", `/api/v1/rules/${encodeURIComponent(id)}`),
  iocs: (q = "") => request<IOC[]>("GET", `/api/v1/iocs${q ? `?q=${encodeURIComponent(q)}` : ""}`),
  addIOCs: (type: IOC["type"], values: string, description: string, severity: Severity) =>
    request<{ added: number; duplicates: number }>("POST", "/api/v1/iocs", { type, values, description, severity }),
  deleteIOC: (id: number) => request<void>("DELETE", `/api/v1/iocs/${id}`),
  feeds: () => request<Feed[]>("GET", "/api/v1/ioc-feeds"),
  createFeed: (f: { name: string; url: string; type: IOC["type"]; severity: Severity }) =>
    request<Feed>("POST", "/api/v1/ioc-feeds", f),
  refreshFeed: (id: number) => request<void>("POST", `/api/v1/ioc-feeds/${id}/refresh`, {}),
  setFeedEnabled: (id: number, enabled: boolean) => request<void>("POST", `/api/v1/ioc-feeds/${id}/enabled`, { enabled }),
  deleteFeed: (id: number) => request<void>("DELETE", `/api/v1/ioc-feeds/${id}`),

  elevations: (agentId = "") =>
    request<Elevation[]>("GET", `/api/v1/pam/requests${agentId ? `?agent_id=${encodeURIComponent(agentId)}` : ""}`),
  pamSummary: () => request<{ pending: number }>("GET", "/api/v1/pam/summary"),
  approveElevation: (id: string, duration_minutes: number) =>
    request<void>("POST", `/api/v1/pam/requests/${encodeURIComponent(id)}/approve`, { duration_minutes }),
  denyElevation: (id: string, note: string) =>
    request<void>("POST", `/api/v1/pam/requests/${encodeURIComponent(id)}/deny`, { note }),
  revokeElevation: (id: string) => request<void>("POST", `/api/v1/pam/requests/${encodeURIComponent(id)}/revoke`, {}),
  grantElevation: (agentId: string, user: string, duration_minutes: number, reason: string) =>
    request<{ id: string }>("POST", `/api/v1/agents/${encodeURIComponent(agentId)}/pam/grant`, { user, duration_minutes, reason }),
  setPamRecording: (agentId: string, enabled: boolean) =>
    request<void>("POST", `/api/v1/agents/${encodeURIComponent(agentId)}/pam/recording`, { enabled }),
  privilegedAccounts: () => request<Inventory[]>("GET", "/api/v1/pam/accounts"),
  pamSessions: (agentId = "") =>
    request<PamSession[]>("GET", `/api/v1/pam/sessions${agentId ? `?agent_id=${encodeURIComponent(agentId)}` : ""}`),
  policies: () => request<PolicySummary[]>("GET", "/api/v1/policies"),
  policy: (id: number) => request<PolicyDetail>("GET", `/api/v1/policies/${id}`),
  createPolicy: (name: string, description: string, copy_from: number) =>
    request<{ id: number }>("POST", "/api/v1/policies", { name, description, copy_from }),
  updatePolicy: (id: number, name: string, description: string, policy: PreventionPolicy) =>
    request<void>("PUT", `/api/v1/policies/${id}`, { name, description, policy }),
  deletePolicy: (id: number) => request<void>("DELETE", `/api/v1/policies/${id}`),
  assignPolicy: (id: number, agent_ids: string[]) => request<void>("PUT", `/api/v1/policies/${id}/endpoints`, { agent_ids }),
  agentPrevention: (agentId: string) =>
    request<{ policy_id: number; policy_name: string; is_default: boolean; policy: PreventionPolicy; state: PreventionState }>(
      "GET",
      `/api/v1/agents/${encodeURIComponent(agentId)}/prevention`,
    ),
  setAgentPolicy: (agentId: string, policy_id: number) =>
    request<void>("PUT", `/api/v1/agents/${encodeURIComponent(agentId)}/policy`, { policy_id }),
  pamSession: (id: number) => request<{ session: PamSession; output: string }>("GET", `/api/v1/pam/sessions/${id}`),
  agentLive: (agentId: string) => request<LiveInfo>("GET", `/api/v1/agents/${encodeURIComponent(agentId)}/live`),
  liveShells: () => request<RemoteShell[]>("GET", "/api/v1/live/shells"),
  closeShell: (sid: string) => request<void>("POST", `/api/v1/live/shells/${encodeURIComponent(sid)}/close`, {}),
};

export interface LiveProcess {
  pid: number;
  ppid?: number;
  user: string;
  tty?: string;
  command: string;
  cpu_percent?: number;
  rss_bytes?: number;
  start_unix?: number;
}

export interface TerminalSession {
  tty: string;
  user: string;
  from?: string;
  login_unix?: number;
  idle_seconds?: number;
  current?: string;
  processes?: LiveProcess[];
  console?: boolean;
}

export interface Activity {
  terminals?: TerminalSession[];
  top?: LiveProcess[];
  load1?: number;
  mem_total_bytes?: number;
  mem_available_bytes?: number;
  uptime_seconds?: number;
}

export interface RemoteShell {
  id: string;
  agent_id: string;
  hostname: string;
  user: string;
  admin: string;
  started_at: string;
  viewers: number;
}

export interface LiveInfo {
  online: boolean;
  error?: string;
  activity?: Activity;
  shells: RemoteShell[];
}

// socketUrl is a WebSocket URL on this console for an API path.
export function socketUrl(path: string): string {
  return `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}${path}`;
}

export const commandLabels: Record<CommandType, string> = {
  kill_process: "Kill process",
  quarantine_file: "Quarantine file",
  restore_file: "Restore file",
  isolate_host: "Isolate host",
  unisolate_host: "End isolation",
  scan_path: "YARA scan",
  update_agent: "Update agent",
  grant_elevation: "Grant sudo",
  revoke_elevation: "Revoke sudo",
  fim_rebaseline: "New FIM baseline",
};

export const statusLabels: Record<AlertStatus, string> = {
  new: "New",
  in_progress: "In progress",
  resolved: "Resolved",
  false_positive: "False positive",
};

export type Category = "process" | "file" | "network";

export function categoryOf(type: string): Category {
  if (type.startsWith("process") || type === "exec_blocked" || type === "app_control") return "process";
  if (type.startsWith("file") || type === "yara_match" || type === "fim_change") return "file";
  return "network";
}

export const typeLabels: Record<string, string> = {
  process_exec: "Process start",
  process_exit: "Process exit",
  file_create: "File created",
  file_modify: "File modified",
  file_delete: "File deleted",
  file_rename: "File renamed",
  file_attrib: "File permissions",
  net_connect: "Connection",
  net_accept: "Inbound connection",
  net_listen: "Listening port",
  yara_match: "YARA match",
  agent_tamper: "Agent tamper",
  exec_blocked: "Exec blocked",
  fim_change: "Integrity drift",
  web_reputation: "Web reputation",
  intrusion: "Intrusion prevention",
  device_control: "Device control",
  app_control: "Application control",
};

// The policy modules in the order the console shows them.
export const policyModules = [
  { key: "anti_malware", label: "Anti-malware" },
  { key: "web_reputation", label: "Web reputation" },
  { key: "file_integrity", label: "File integrity" },
  { key: "firewall", label: "Firewall" },
  { key: "intrusion_prevention", label: "Intrusion prevention" },
  { key: "device_control", label: "Device control" },
  { key: "activity_monitoring", label: "Activity monitoring" },
  { key: "application_control", label: "Application control" },
] as const;

export type ModuleKey = (typeof policyModules)[number]["key"];

export function timeAgo(iso: string): string {
  const t = new Date(iso).getTime();
  if (!t || t < 1000) return "never";
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}
