# Architecture

Ironsight is **Security Intelligence and Privileged Access for Linux and
cloud workloads**: the same platform knows the asset, the user, the process
tree, the exposure, the current incident and the administrative session.
This file is the target architecture (Security Intelligence + PAM, v2.0) and
the contracts every agent and service follows. Parts marked *later* are not
built yet; the boundaries are.

Observe → Understand → Correlate → Explain → Control access → Investigate →
Respond → Prevent.

```
            Unified console (React + TypeScript)
   incidents · attack graph · inventory · privileged access · audit
                              │ HTTPS, users + roles + MFA
                              ▼
 ┌──────────────────────── xdr-server (Go) ─────────────────────────┐
 │ Control plane: identity & access (iam), fleet, policies, audit    │
 │ Security Intelligence: pipeline, detection, storyline, risk       │
 │ PAM (internal/server/pam): access policies, approvals, sessions   │
 └──────┬──────────────────┬───────────────────────┬────────────────┘
        ▼                  ▼                       ▼
   PostgreSQL          ClickHouse          Object storage (later)
 tenants, users,     telemetry, session    recordings, evidence
 roles, assets,      events, hunting       (Postgres until then)
 policies, approvals
        ▲
        │ gRPC + protobuf + mTLS (persistent Live stream, outbound from agent)
 Rust security agent: Linux now (eBPF CO-RE, fanotify, netlink, procfs),
 Windows later (ETW, WFP, minifilter). SQLite offline queue and state.
```

What stays: Go for every backend service, PostgreSQL, ClickHouse, gRPC/mTLS,
eBPF CO-RE and the React console. What changes: the endpoint agent moves to
Rust with a platform-independent core and per-OS adapters. Since 0.10.0 the
Rust agent is the only agent; the Go agent was removed before parity (see
"Migration from the Go agent").

NATS JetStream is added between ingest and detection when scale needs it.

## Modules

| Module | Responsibility | Where it lives now |
|---|---|---|
| Visibility | Endpoint, workload, identity, network, container and inventory telemetry. | `agent-rs/`, `proto/xdr/v1`, `internal/server/pipeline` (normalize, store) |
| Detection | Rules, behaviour analytics, IOC/YARA, correlation, detection as code. | `internal/server/detect`, `xdr-detect` container |
| Security Intelligence | Process graph, asset graph, attack story, risk, explainability, exposure, blast radius. | `internal/server/storyline`, `pipeline/enrich`, `pam.Risk` (baseline) |
| PAM | Identity, RBAC, JIT, approvals, SSH/RDP/browser access, sessions, credentials, audit. | `internal/server/iam`, `internal/server/pam`, `store/iam.go`, `api/iam.go`, `api/pam.go`, `live` (shell transport) |
| Investigation | Hunting, timeline, graph exploration, evidence packages, attack replay. | console Threat hunting, Workbench, Storyline, session timeline |
| Response | Controlled administrative actions and automated remediation. | commands (`detect.Service.QueueCommand`), Live push |
| Protection | Malware, application control, isolation, firewall, IPS, enforcement. | endpoint policies (`internal/policy`), agent prevention modules |

PAM is a separate module with its own package boundary: it reads identity,
asset and incident context but owns its own decisions, and nothing in
Detection or Protection can open a session. Protection evolves on its own
too.

## Canonical SecurityEvent (schema_version 1)

`xdr.v1.Event` in `proto/xdr/v1/agent.proto` is the one event model for all
platforms. Envelope fields:

| Field | Set by | Meaning |
|---|---|---|
| `id` | agent | Unique event ID. Re-sent events keep it, so the server can drop duplicates. |
| `timestamp_unix_nano` | agent | When it happened. |
| `type` | agent | `EventType`. |
| `schema_version` | agent | 1 for this envelope; 0 means a pre-0.8 agent. |
| `agent_id` | agent | Informational only. |
| `tenant_id`, `endpoint_id` | server | Taken from the enrollment record of the authenticated certificate. Agent values are ignored. |
| `priority` | agent | `LOW`, `NORMAL`, `HIGH`, `CRITICAL`; drives the local queue. |
| `process_context` | agent | The process that caused the event, with its parent. |
| `metadata` | agent | Free-form key/value pairs. |
| `payload` | agent | Type-specific detail (process, file, network, YARA, tamper, policy). |

New fields are only ever added, never renumbered, so old agents keep working
against a newer server.

### process_guid

PIDs are reused, so every process is identified by `process_guid`:

```
start_ticks  = field 22 of /proc/<pid>/stat (clock ticks since boot)
boot_id      = /proc/sys/kernel/random/boot_id
digest       = SHA-256("<boot_id>/<pid>/<start_ticks>")
process_guid = first 16 bytes of digest as hex, formatted 8-4-4-4-12
```

The GUID survives `execve` (the start time does not change) and differs for a
reused PID or after a reboot. If a process exits before the agent can read its
start time, the exec event's timestamp in nanoseconds stands in for
`start_ticks`. The Rust agent must use exactly this derivation so both agents
produce the same IDs. `parent_process_guid` links a process to its parent and
is the key of the process tree.

### Priority

| Priority | Event types |
|---|---|
| CRITICAL | exec_blocked, yara_match, agent_tamper |
| HIGH | fim_change, web_reputation, intrusion, device_control, app_control |
| NORMAL | process_exec, process_exit, net_connect, net_accept |
| LOW | file_* telemetry, net_listen |

## Agent local queue contract

The Rust agent keeps a SQLite queue (`state_dir/queue.db`, WAL mode) between
the event bus and the uploader:

- Events are persisted before they count as accepted. Upload is at least once;
  the server deduplicates by `id` (ClickHouse `ReplacingMergeTree`).
- The uploader drains by priority, highest first and oldest first within a
  priority, in batches of up to 500 events.
- Retry uses exponential backoff from 1 s to 60 s with jitter. A batch is only
  deleted after `SendEvents` succeeds.
- The queue has a byte budget (default 256 MiB). When full, the oldest `LOW`
  events are evicted first, then `NORMAL`, then `HIGH`. `CRITICAL` events are
  never evicted for lower priorities; only when the queue holds nothing else
  are the oldest `CRITICAL` events dropped. Every eviction is counted in
  `AgentStats.events_dropped`.
- Local detection and prevention read from the event bus, not the queue, so
  they keep working while the console is unreachable.
- The last policy, detection content and command state are cached in the same
  database, so a restart without the console enforces the last known policy.

## Rust agent (agent-rs/)

| Crate | Role |
|---|---|
| `xdr-proto` | Generated protobuf and gRPC client for `proto/xdr/v1` (committed; `cargo build -p xdr-proto --features regen` updates it). |
| `xdr-core` | Platform-independent core: config (/etc/xdr-agent/agent.yaml), identity and enrollment, event bus and normalizer, SQLite queue and policy cache, uploader, heartbeat, mTLS transport. |
| `xdr-linux` | Linux adapters behind the `Platform` trait: netlink process events, inotify files, /proc/net connections, procfs process identity, response actions. |
| `xdr-agent` | The `xdr-agent` binary. |

Flow: collectors (blocking threads) → `EventSink` → normalizer (envelope,
process context, priority) → local subscribers and the SQLite queue →
uploader. Response actions (kill, quarantine, restore, isolate, unisolate,
uninstall) live in `xdr-linux/src/response.rs`. The Live stream opens with
`LiveHello{commands: true}`, so commands arrive at once; commands from Live
and heartbeats are deduplicated by ID. Commands not ported yet fail at once
with "not supported by xdr-agent <version> yet". Since 0.10.3 the Live
stream also carries remote shells (`xdr-linux/src/shell.rs`: `su -l` on a
new pty, at most 8, hung up when the stream drops, `disable_remote_shell`
in agent.yaml refuses them) and the live view (`xdr-linux/src/activity.rs`).
Every process in a console shell has `XDR_CONSOLE_SESSION=<session id>`,
kept through `su -l` with `-w`.

Build: `make agent` (Docker, static musl binary in `bin/xdr-agent`) or
`cd agent-rs && cargo build --release`. The console image builds the amd64
agent with `XDR_VERSION` set to the release version and serves it to
installers and updates. arm64 is not built yet.

### Migration from the Go agent

The Rust agent uses the Go agent's binary path (`/usr/local/bin/xdr-agent`),
unit, config, state directory (`/var/lib/xdr-agent`), identity files,
isolation state and quarantine records. A Go endpoint moves over with a
console **Update**: the Go agent downloads the new binary, checks that
`xdr-agent -version` prints the release version, swaps it in and restarts;
the endpoint keeps its agent ID. On every start the Rust agent clears what
the Go agent enforced and it does not manage yet: tamper immutable flags and
the RefuseManualStop drop-in, the `xdr_firewall` nftables table, and the JIT
sudo and session-recording sudoers files. `xdr-agent maintenance` only does
that clean-up, so the install and uninstall scripts keep working.

The Go agent's eBPF C program and compiled objects are kept in
`agent-rs/bpf/` for the eBPF port.

Porting order to parity: response actions and Live commands (done in
0.10.0), self-update (done in 0.10.1, `xdr-core/src/update.rs`: chunked
download over mTLS, SHA-256 and `-version` check, atomic swap, exit so
systemd restarts it, rollback to the previous binary when the new one does
not reach the console within 3 minutes or 3 starts), eBPF CO-RE collectors
(reusing the committed BPF objects), YARA scanning and detection content,
prevention modules (fanotify exec/script blocking, application control, FIM,
firewall, IPS, web reputation, device control including read-only USB),
tamper protection and the self-protection password, PAM, live shell and
activity (done in 0.10.3), bash command telemetry (uprobes on readline and parse_and_execute,
emitting ShellCommandEvent).

## Detection pipeline (0.9)

Every `SendEvents` batch goes through `internal/server/pipeline`:

1. **Normalize**: wire `Event` to the stored row. Tenant, agent and hostname
   come from the authenticated certificate.
2. **Enrich**: an in-memory process cache (two generations of 200k processes)
   keyed by agent and `process_guid` fills the parent of a process and the
   actor of file and network events when the agent did not send them, and
   sets `storyline_guid`.
3. **Store**: insert into ClickHouse. Only a failure here fails the batch.
4. **Detect**: Sigma, YARA-result and IOC rules raise or count alerts and
   queue automatic responses (`detect.Service`).
5. **Correlate**: when three different detections are open in one storyline,
   one critical `correlation-multi-stage` alert is raised for it.

Detect and correlate run in xdr-server by default. With `XDR_DETECT_URL`
and `XDR_DETECT_TOKEN` set, xdr-server posts each stored batch to the
`xdr-detect` service (same image, `docker compose --profile detect`) and
keeps ingesting if it is slow or down; batches it cannot deliver after five
tries skip detection and are logged. xdr-server keeps serving detection
content to agents and refreshing IOC feeds, and tells xdr-detect to reload
when rules or IOCs change. NATS JetStream replaces the HTTP hop when ingest
needs to scale.

### Storyline

A storyline is one process tree: everything started by one login, service
or scheduled job. Its ID is the `process_guid` of the topmost ancestor below
a session root (systemd, init, sshd, cron, atd, login, container runtimes,
the agents). So each SSH session or cron job is its own storyline instead of
one tree under sshd. The console's Storyline view (`/storyline/<agent>/<guid>`,
API `GET /api/v1/storyline?agent_id=&guid=`) walks `parent_process_guid` up
to that root and back down, at most 300 processes and 1000 activity events,
and does not depend on `storyline_guid`, so it works for events stored before
0.9 too. A process that called execve keeps its GUID; the view shows the
current image and the earlier ones.

## Real-time commands

Response commands are still stored in Postgres first. An agent that opens
the live stream sends `LiveHello{commands: true}`; from then on xdr-server
pushes its commands as `LiveDown.command` the moment they are queued, and
every 2 s picks up commands queued by another process (xdr-detect). A
command that cannot be written to the stream goes back to pending. Agents
without the hello (old Go agents) get commands
with their heartbeat as before. Results always come back through
`ReportCommandResult`, and the agent ignores a command ID it already ran.

## Identity and access model (P0)

Entities are independent of telemetry and referenced by stable IDs.

| Entity | Table | Key fields |
|---|---|---|
| Tenant | `tenants` | id, name |
| User | `users` | id, tenant_id, username, role_id, password (PBKDF2-SHA256), mfa_secret/mfa_enabled, disabled, builtin |
| Role | `roles` | tenant_id + id, permissions[], builtin |
| Asset group | `asset_groups`, `asset_group_members` | name, criticality, environment, all_assets, agent ids |
| Access policy | `access_policies` | subject roles/users, asset groups, access types, accounts, approval count, MFA, ticket, max minutes, UTC hours, incident mode, priority, effect |
| Access request | `pam_requests` | kind (`shell`, `jit_sudo`), requester, account, reason, ticket, policy, approvals_required, incident, emergency, status, expiry |
| Approval | `approvals` | request, approver, decision, note, emergency (one per approver) |
| Privileged session | `access_sessions` | id, tenant, user, asset, source IP and user agent, protocol, account, auth method, request, policy, ticket, recording, start/end, risk score and reasons |
| Recording | `pam_sessions` | session output (Postgres for now, object storage later) |
| Audit entry | `audit_log` | actor, action, target, outcome, remote, detail, prev_hash, hash |
| Team, credential, service account, ticket | *later (P2)* | |

**Console sign-in.** Users sign in with username and password, plus a TOTP
code when they turned MFA on. `XDR_ADMIN_USER` / `XDR_ADMIN_PASSWORD` is the
built-in break-glass administrator: created on first start, its password and
admin role reset on every start. TOTP (RFC 6238) is the MFA integration
point; WebAuthn or an IdP plugs in at the same place.

**Permissions.** Built-in roles: Administrator (`*`), SOC analyst, Server
operator, Auditor; custom roles pick from the permission list in
`internal/server/iam`. Every API route needs one permission
(`iam.RoutePermission`): unlisted GET routes need `view`, every other
unlisted route is admin-only, so a new route is safe by default.

**Audit.** Every change, sign-in, denied request, shell, maintenance-token
reveal and recording view is appended to `audit_log`. Each entry stores the
hash of the one before (`sha256(prev_hash | at | actor | … | detail)`), and
`GET /api/v1/audit/verify` walks the chain to prove nothing was edited or
removed.

**Event ↔ identity.** Telemetry rows keep their own fields; they point at
identity through stable IDs: an `access_sessions.id` is the console shell
session ID the agent receives in `ShellOpen.session_id`; agents that pass
it to the processes they start tag their events with it (`console_session`,
added by the Linux telemetry work). Until every agent sends it, the session timeline matches the shells the agent started
for that session's window.

## Privileged access (P1)

A privileged session is never a bare "remote shell button". Each one has a
tenant, an authenticated user, a target asset, a policy decision, an expiry,
an audit trail and a recording.

```
Admin (console, password + optional MFA)
  │  POST /api/v1/pam/access {agent, kind, account, reason, ticket, minutes, mfa_code}
  ▼
Access-policy engine (pam.Decide)
  first enabled policy by priority matching role/user, asset group,
  access type, account and UTC hours; deny wins if it matches first;
  an open high/critical alert can add approval or block (incident mode)
  │ allowed, needs approval → pending  │ allowed, no approval → approved
  ▼                                    ▼
Approvals (N distinct approvers, never the requester; admins can
self-approve as emergency access with a note, which raises risk)
  ▼
Grant until expiry: shell usable (GET /agents/{id}/shell?request=)
or JIT sudo sent to the agent (grant_elevation)
  ▼
Session broker (live.Hub over the agent's outbound Live stream)
  records output, closes the shell at expiry or revoke
  ▼
access_sessions row: scored at the end (pam.Risk), linked to the
recording, the alerts raised during it and the processes it started
```

Sudo asked for on the host (`xdr-agent elevate`) goes through the same
engine with the pseudo-role `host`; its recordings become `access_sessions`
rows with protocol `sudo`.

Default policies on first start: administrators get shells and sudo on every
server without approval (recorded); analysts and operators need one approval,
up to 2 hours, and are blocked while the server has an open high or critical
alert; host sudo requests need one approval, up to 8 hours.

The session data path (agent ↔ hub ↔ browser) is separate from the control
plane decisions, no credentials are stored or handed to the browser, and
servers need no inbound management port.

## Data model rules

- **tenant_id everywhere.** Postgres: agents, enrollment tokens, deploy jobs,
  policies, rules, IOC feeds, IOCs, alerts, commands, PAM requests, accounts
  and sessions, and agent certificates. ClickHouse: every event. Everything
  that exists today belongs to tenant `default`. An agent joins the tenant of
  the enrollment token it used.
- **Version everything.** Agent version (heartbeat), event `schema_version`,
  policy `version` (bumped on each change, sent to the agent in
  `PreventionPolicy.version`), detection content version.
- **Identity is separate from the certificate.** `agent_certificates` records
  every issued certificate. The certificate authenticates the host; the
  `agents` row decides tenant and authorization. A single certificate can be
  revoked without revoking the endpoint.
- **ClickHouse is designed for queries.** Partitioned by day, ordered by
  `(tenant_id, agent_id, type, ts, event_id)`, bloom filters on hashes,
  remote addresses and process GUIDs.
- **Large artifacts go to object storage later.** PAM recordings stay in
  Postgres for now and move to S3/MinIO with metadata in ClickHouse.
- **Identity and access tables are tenant-scoped.** Users, roles, asset
  groups, access policies, approvals, privileged sessions and the audit log
  carry tenant_id; API handlers for them filter by the signed-in user's
  tenant.

## Roadmap

Platform (Phase 1 and 2, done or in progress):

1. Canonical SecurityEvent v1, process_guid, priority, tenant_id and
   versioning (0.8.0).
2. Rust agent workspace: `xdr-core` and `xdr-linux`.
3. Detection service boundary: normalize, enrich, detect, correlate (0.9.0).
4. Process tree model and storyline view keyed by `process_guid` (0.9.0).
5. Real-time command stream over the Live stream (0.9.0).
6. Rust feature parity; the Rust agent is the only agent from 0.10.0.

Privileged access:

- **P0 platform foundation** (done): tenant-aware identity, users, roles,
  permissions, asset groups, session entity, audit model, MFA integration
  point, approval model, access-policy engine, event ↔ identity references.
- **P1 core PAM** (done, Linux): browser terminal through the agent, JIT
  sudo, approval workflow, session metadata, session recording, command
  audit via the session timeline, admin activity in the audit log. Direct SSH
  through a gateway is next.
- **P2 enterprise PAM** (later): RDP gateway, credential vault and rotation,
  SSH keys and service accounts, emergency access policies, ticket
  integration, advanced conditions (device trust, source network), session
  search and replay.
- **P3 deep integration** (later): risk-aware access, incident-driven
  restrictions beyond the incident mode, suspicious-session detection rules,
  automatic response, SOAR.

Not yet: NATS JetStream, Kubernetes, Windows.
