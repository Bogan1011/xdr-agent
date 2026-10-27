# XDR Agent

A self-hosted XDR platform: a Linux endpoint agent, a backend that ingests
its telemetry, and a web console in the style of Trend Micro Vision One.

This is **step 1 (foundation)** of the roadmap below. It runs everything on
one Ubuntu VM: the console and databases in Docker, the agent as a systemd
service on the host.

## What works today

| Area | Status |
|---|---|
| Process telemetry | Exec and exit of every process: pid, parent, user, command line, cwd, SHA-256 of the binary |
| File telemetry | Create, modify, delete, rename and permission changes under `/etc`, binary dirs, `/tmp`, `/dev/shm`, home dirs, cron and systemd dirs, with SHA-256 of changed files |
| Network telemetry | New outbound TCP connections and listening ports, attributed to the owning process |
| Agent security | One-time enrollment tokens, a private CA, mutual TLS for all telemetry, per-agent revocation |
| Console | Overview, endpoint inventory and health, per-endpoint activity, event search, agent deployment |
| Install / uninstall | One-line installer with CA pinning and checksum verification; one-line uninstaller; remote install over SSH |
| Detection | Sigma-style behaviour rules (20 built-in for Linux, custom rules in the console), YARA scanning on the agent, IOC lists and feeds (SHA-256, IP/CIDR, domain) |
| Alerts | Deduplicated alerts with severity, MITRE ATT&CK tags, triage status and the triggering event |
| Response | Kill process, quarantine and restore file, isolate and un-isolate host, on-demand YARA scan; optional automatic response per rule |
| Fleet | Self-update with rollback, tamper protection with a maintenance token, SSH host key pinning |
| Privileged access | Just-in-time sudo with console approval, recorded sudo sessions, privileged account inventory with alerts |

## Detection and response

* **Sigma rules** run on the console against every event. They use Sigma's
  layout (`logsource`, named selections, `field|modifier: value`, a
  `condition`), with the fields and categories listed in the rule editor.
  Add `response: [kill_process]` (or `quarantine_file`, `isolate_host`) to
  act automatically when a rule fires. The built-in rules live in
  `internal/server/detect/rules/`.
* **YARA rules** are sent to agents within one heartbeat of being saved. The
  agent scans files when they are written and the binary of every new
  process, up to 32 MB (`scan_max_bytes` in `agent.yaml`). The engine is a
  pure-Go subset of YARA so the agent stays a static binary: modules and
  `for` loops are not supported.
* **IOCs** are matched on ingest: hashes against executed and written files,
  IPs against outbound connections, domains against command lines (there is
  no DNS telemetry yet). Feeds are plain-text or CSV URLs refreshed every 6
  hours.
* **Response actions** are queued in the console and delivered on the
  agent's next heartbeat (every 15 seconds); results show on the endpoint
  and alert pages. Quarantined files are moved to
  `/var/lib/xdr-agent/quarantine/` with no permissions. Isolation uses an
  nftables table (`inet xdr_isolation`, needs the `nft` command) that drops
  everything except loopback, DHCP and the console, plus any addresses given
  when isolating; it survives agent restarts and reboots.

## Architecture

```
 Ubuntu VM
 ┌──────────────────────────────────────────────────────────────┐
 │ xdr-agent (systemd, root)                                    │
 │   process ── netlink proc connector                          │
 │   file ───── eBPF (or inotify)             gRPC + mTLS :8444 │
 │   network ── eBPF connect/accept, /proc/net ─────────────┐   │
 │                                                          ▼   │
 │ docker compose                                               │
 │   xdr-server ── enrollment :8443, ingest :8444, console :8080│
 │   postgres ──── agents, enrollment tokens                    │
 │   clickhouse ── events (30-day TTL)                          │
 └──────────────────────────────────────────────────────────────┘
```

* **Agent** (`cmd/xdr-agent`, Go): collectors push events into a bounded queue;
  the sender ships acknowledged batches with retry and backoff. If the
  server is unreachable the agent keeps running and counts dropped events.
* **Server** (`cmd/xdr-server`, Go): gRPC services for enrollment and ingest,
  REST API and the built dashboard over HTTP.
* **Console** (`web/`, React + TypeScript + Vite).
* **Protocol** (`proto/xdr/v1/agent.proto`): the agent identity is the
  common name of its client certificate, issued by the server's CA at
  enrollment. It is never taken from the request body.

## Run it on your VM

Requirements: Ubuntu 22.04 or newer, Docker with the compose plugin, and
ports 8080, 8443 and 8444 reachable from your other VMs.

```bash
git clone https://github.com/Bogan1011/xdr-agent.git
cd xdr-agent/deploy
cp .env.example .env
nano .env            # set XDR_PUBLIC_HOST to this VM's IP and change all passwords
docker compose up -d --build
```

Open `http://<vm-ip>:8080` and sign in as `admin` with `XDR_ADMIN_PASSWORD`.

### Install the agent

1. In the console, go to **Deploy agents**, create a token, and copy the
   install command.
2. Run it as root on the host (the same VM works):

   ```bash
   curl -fsSL http://<vm-ip>:8080/install.sh | sudo bash -s -- --token xdr_... --ca-sha256 ...
   ```

3. The host shows up under **Endpoints** within a few seconds.
   Agent logs: `journalctl -u xdr-agent -f`.

### Uninstall the agent

Use **Uninstall** on the endpoint's page. To remove the agent on the host
itself, pass the maintenance token from the endpoint's page (needed while
tamper protection is on):

```bash
curl -fsSL http://<vm-ip>:8080/uninstall.sh | sudo bash -s -- --token <maintenance token>
```

Then revoke or delete the endpoint in the console.

## Fleet management

* **Self-update.** The console offers the agent version it was built with
  (`XDR_VERSION` in `deploy/.env`). Endpoints that run another version show
  "update to …"; update one from its page or all online ones from
  **Endpoints**. The agent downloads the binary over its mTLS connection,
  checks the SHA-256 the console sent and that the binary runs, swaps it in
  and restarts. If the new version cannot reach the console within three
  minutes or fails to start three times, the agent puts the old binary back.
* **Tamper protection** (on by default, per endpoint). The agent makes its
  binary, config, CA and unit file immutable, adds `RefuseManualStop=yes` to
  its unit, ignores SIGTERM unless the host is shutting down, and reports
  every attempt (ignored signals, a restart after SIGKILL, cleared flags) as
  an `agent_tamper` event that raises an alert. Commands such as
  `systemctl stop xdr-agent` or `chattr -i` on its files also alert. Root can
  still defeat it; the point is that it cannot happen quietly. To work on the
  agent locally, run `sudo xdr-agent maintenance --token <token>`, which
  suspends protection for an hour.
* **Roll-out.** Remote install over SSH (Deploy page) takes many hosts at
  once. The first SSH host key a host presents is pinned; a changed key
  fails the install until you forget it on the Deploy page.

## Privileged access (PAM)

* **Just-in-time sudo.** A user on a host runs
  `xdr-agent elevate -reason "restart nginx, OPS-42" -duration 30m` (no root
  needed). The agent identifies the user from the local socket, the request
  shows up under **Privileged access** in the console, and an admin approves
  (optionally shortening it) or denies. On approval the agent installs a
  validated drop-in, `/etc/sudoers.d/xdr-jit-<uid>`, with a `NOTAFTER` limit
  where sudo supports it. At expiry or on **Revoke** the agent removes it and
  ends the user's running sudo sessions. Admins can also grant sudo to a
  user directly from the same page. Requests nobody decides expire after
  24 hours; grants last 5 minutes to 8 hours.
* **Session recording.** Granted sudo sessions are recorded by sudo's own
  I/O logging (`log_output`) under `/var/log/xdr-agent/sudo-io`. The agent
  uploads each session's terminal output (up to 2 MiB) when it ends, and the
  console shows it as text next to the grant that allowed it. Per endpoint,
  **Record all** extends recording to every sudo session on the host.
* **Privileged accounts.** Each agent reports the accounts that can act as
  root: uid 0, sudoers rules (users, `%groups`, `User_Alias`, drop-ins) and
  root-equivalent groups (`docker`, `lxd`, `disk`), with password state,
  NOPASSWD, SSH key count and last login. An account that gains a new path
  to root raises a **New privileged account** alert.

## Policies

Protection is set with **policies** (Endpoints → Policies), Deep Security
style. Each endpoint follows one policy; endpoints without one follow the
**Default** policy. A policy has eight modules, each switched on or off on
its own: pick a module in the policy's left-hand list, change it, then
**Save policy**. Assign endpoints from the policy's Overview tab or from the
policy menu on an endpoint's page. Endpoints apply changes at their next
check-in (within 15 seconds) and keep the last policy across reboots.

* **Anti-malware.** Real-time YARA scanning of new and changed files and
  every program that starts; blocking of files whose SHA-256 is a hash IOC
  (manual or feed, up to 500,000) with fanotify permission events
  (Linux 5.0+), raising **Execution blocked**; optional auto-quarantine of
  YARA matches (restore from the endpoint's Response panel). Scripts run
  through an interpreter (`bash evil.sh`) are not execs of the script and
  are not blocked; `./evil.sh` is.
* **Web reputation.** Outbound connections to IP IOCs and to the addresses
  of domain IOCs and the policy's own blocked domains (subdomains included)
  are rejected with the nftables table `inet xdr_webrep` (output and
  forward, so containers too), or only reported. The agent resolves domains
  every 10 minutes (up to 2,000, the policy's own first). The console is
  never blocked. Alert: **Connection to a known-bad address**.
* **File integrity.** The agent records a baseline (SHA-256, mode, owner)
  of the monitored paths, then reports files added, removed or changed:
  within seconds when the file collectors see the change, and on a full
  rescan every interval. Each change is reported once and stays visible
  until someone clicks **Accept changes as FIM baseline**. Critical system
  files and system binaries alert high, everything else medium.
* **Firewall.** Inbound and outbound allow/deny rules by protocol, port and
  remote CIDR, applied atomically as `inet xdr_firewall`, optionally denying
  unsolicited inbound traffic by default. Loopback, established
  connections, DHCP and the console are always allowed. If someone deletes
  the table the agent restores it and raises a tamper alert.
* **Intrusion prevention.** SSH brute-force protection: the agent follows
  sshd's log (journald, or `/var/log/auth.log` / `/var/log/secure`) and
  when one address fails N logins within the window it bans it for M
  minutes (`inet xdr_ips`, nftables set timeouts) or only reports it.
  Addresses on the never-ban list, loopback and the console are exempt.
  Alert: **SSH brute force**.
* **Device control.** USB mass storage can be allowed (each device is
  reported) or blocked: the agent deauthorizes the device in sysfs as soon
  as the kernel announces it, before a disk appears. Devices listed by
  `vendor:product` ID (see `lsusb`) are always allowed. Other USB devices
  are never touched. Alert: **USB storage device blocked**.
* **Activity monitoring.** Which telemetry is sent: process, file, network.
  Turning one off saves bandwidth and storage but stops the behaviour rules
  that need it. Alerts and prevention events are always sent.
* **Application control.** Programs listed by path (prefix or glob, e.g.
  `/tmp/*`) or SHA-256 are blocked with fanotify, or only reported. Alert:
  **Application control rule matched**.

See [docs/comparison.md](docs/comparison.md) for how this product compares
with Trend Micro Vision One and CrowdStrike Falcon, and the gaps that set
the roadmap.

## Development

```bash
make test     # go vet + unit tests
make agent    # bin/xdr-agent
make server   # bin/xdr-server
make web      # web/dist
make proto    # regenerate gen/ (needs protoc and the Go plugins)
```

Run the server locally against Postgres and ClickHouse with the
`XDR_*` variables listed in `deploy/docker-compose.yml`, and the dashboard
with `cd web && npm run dev` (it proxies `/api` to `:8080`).

## Known limits

* The console is served over plain HTTP. The installer pins the CA by the
  fingerprint shown in the console, so agent traffic is still protected, but
  put the console behind HTTPS before using it outside a lab.
* Console login is a single admin account; sessions are in memory and end
  when the server restarts.
* File and network events name the process behind them only when the
  eBPF collectors load (kernel 5.8+ with BTF, kprobes, and
  CONFIG_SECURITY_PATH; stock Ubuntu 20.04 HWE and later). Otherwise the
  agent logs why and falls back to inotify, which cannot tell who changed a
  file, and /proc/net polling, which can miss very short connections. Set
  `ebpf: off` in the agent config to force the fallback.
* eBPF file events report a write when a file is opened for writing, and
  hash it a second later. Paths inside containers are relative to the
  container's root.
* Session recording relies on sudo. A user who becomes root can delete
  local recordings before upload or start shells that sudo does not log
  (e.g. `su` with a known root password); their commands still show up in
  process telemetry. Recordings are terminal output, not keystrokes.
* Isolating the host that runs the console does not cut it off: the
  console's own address must stay reachable, and on that host it is the
  host itself. Test isolation on a second machine.

## Roadmap

1. **Foundation** (done): telemetry, console, enrollment, installer.
2. **Detection and response** (done): Sigma-style rules, YARA
   scanning, IOC feeds, alerts, and response actions. eBPF collectors for
   process-attributed file and network events.
3. **Fleet management** (done): remote install and uninstall from
   the console over SSH, agent self-update with rollback, tamper protection,
   SSH host key pinning.
4. **PAM** (done): just-in-time sudo elevation with approval,
   session recording, privileged account inventory, and the
   [comparison](docs/comparison.md) with Vision One and CrowdStrike Falcon.
5. **Prevention** (done): exec blocking of hash IOCs, file integrity
   monitoring with baselines, host firewall policy.
6. **Policies** (this release, 0.6.0): named policies assigned to endpoints
   with eight modules: anti-malware, web reputation, file integrity,
   firewall, intrusion prevention, device control, activity monitoring and
   application control.
7. **Lockdown** (0.7.0): application control allow-list mode and blocking
   of scripts run by shells and interpreters from temp folders.
8. **Architecture foundation** (0.8.0): canonical SecurityEvent v1 with a
   stable `process_guid` and parent context on every event, event priority,
   tenant_id and policy versions in the data model. See
   [docs/architecture.md](docs/architecture.md) for the target architecture
   and the Rust agent plan.
9. **Detection architecture** (0.9.0): the detection pipeline (normalize,
   enrich, detect, correlate) with an optional separate `xdr-detect`
   service, a process tree keyed by `process_guid` with a Storyline view in
   the console, correlation of several detections in one storyline into a
   critical alert, and response commands pushed to agents over the live
   stream instead of waiting for the heartbeat.
10. Rust agent feature parity, the remaining Linux gaps, then the Windows
    agent.
