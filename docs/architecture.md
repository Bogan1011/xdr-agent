# Architecture

This is the target architecture from the Ironsight review (0.7 to 1.0) and
the contracts every agent and service follows. Boxes marked *later* are not
built yet; the boundaries are.

```
React console ──HTTPS──▶ xdr-server (Go): API, control plane, fleet
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
Rust with a platform-independent core and per-OS adapters; the Go agent
stays the shipped agent until the Rust agent reaches feature parity.

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
| `xdr-core` | Platform-independent core: config (reads the Go agent's YAML), identity and enrollment, event bus and normalizer, SQLite queue and policy cache, uploader, heartbeat, mTLS transport. |
| `xdr-linux` | Linux adapters behind the `Platform` trait: netlink process events, inotify files, /proc/net connections, procfs process identity. |
| `xdr-agent` | The `xdr-agent-rs` binary. |

Flow: collectors (blocking threads) → `EventSink` → normalizer (envelope,
process context, priority) → local subscribers and the SQLite queue →
uploader. Until parity it runs beside the Go agent with its own state
directory (`/var/lib/xdr-agent-rs`) and enrollment, so it shows up as a second
endpoint, with version `<x.y.z>-rs`. Response commands it does not support yet
are answered with a failure, not left pending.

Build: `make agent-rs` (Docker, static musl binary in `bin/xdr-agent-rs`) or
`cd agent-rs && cargo build --release`.

Porting order to parity: eBPF CO-RE collectors (reusing the committed BPF
objects), YARA scanning and detection content, response actions, prevention
modules (fanotify exec/script blocking, application control, FIM, firewall,
IPS, web reputation, device control including read-only USB), tamper
protection and the self-protection password, PAM, live shell and activity,
self-update.

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
   inside xdr-server or as its own container.
4. Process tree model and storyline view keyed by `process_guid`.
5. Real-time command stream over the existing bidirectional Live stream.
6. Rust feature migration to parity, then the Rust agent becomes the default.

Not yet: NATS JetStream, Kubernetes, Windows.
