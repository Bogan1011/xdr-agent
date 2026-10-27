# Architecture

This is the target architecture from the Ironsight review (0.7 to 1.0) and
the contracts every agent and service follows. Boxes marked *later* are not
built yet; the boundaries are.

```
React console ──HTTPS──▶ xdr-server (Go): API, control plane, fleet, ingest
                                │
              ┌─────────────────┼──────────────────┐
              ▼                 ▼                  ▼
         PostgreSQL     detection service     ClickHouse
      (config, identity,  (normalize, enrich,  (telemetry,
       policies, jobs)     detect, correlate)   hunting)
                                ▲
             NATS JetStream (later, when ingest needs to scale)
                                ▲
                    gRPC + protobuf + mTLS
              ┌─────────────────┴──────────────────┐
        Linux agent (Rust)                  Windows agent (Rust, later)
   eBPF CO-RE, fanotify, netlink, procfs      ETW, WFP, minifilter
```

What stays: Go for every backend service, PostgreSQL, ClickHouse, gRPC/mTLS,
eBPF CO-RE and the React console. What changes: the endpoint agent moves to
Rust with a platform-independent core and per-OS adapters. Since 0.10.0 the
Rust agent is the only agent; the Go agent was removed before parity (see
"Migration from the Go agent").

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
with "not supported by xdr-agent <version> yet", and a remote shell request
gets a `ShellExit` error.

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
0.10.0), eBPF CO-RE collectors (reusing the committed BPF objects), YARA
scanning and detection content, prevention
modules (fanotify exec/script blocking, application control, FIM, firewall,
IPS, web reputation, device control including read-only USB), tamper
protection and the self-protection password, PAM, live shell and activity,
self-update, bash command telemetry (uprobes on readline and
parse_and_execute, emitting ShellCommandEvent).

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

## Roadmap (Phase 1 and 2)

1. Canonical SecurityEvent v1, process_guid, priority, tenant_id and
   versioning (0.8.0).
2. Rust agent workspace: `xdr-core` (config, identity, event bus, SQLite queue,
   policy cache, gRPC/mTLS transport) and `xdr-linux` (collectors and
   response). Ships as an opt-in second binary.
3. Detection service boundary: normalize, enrich, detect, correlate, runnable
   inside xdr-server or as its own container (0.9.0).
4. Process tree model and storyline view keyed by `process_guid` (0.9.0).
5. Real-time command stream over the existing bidirectional Live stream (0.9.0).
6. Rust feature migration to parity, then the Rust agent becomes the default.

Not yet: NATS JetStream, Kubernetes, Windows.
