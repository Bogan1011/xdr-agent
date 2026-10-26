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
};

export type Category = "process" | "file" | "network";

export function categoryOf(type: string): Category {
  if (type.startsWith("process")) return "process";
  if (type.startsWith("file")) return "file";
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
  net_listen: "Listening port",
};

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
