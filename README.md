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
| Install / uninstall | One-line installer with CA pinning and checksum verification; one-line uninstaller |

## Architecture

```
 Ubuntu VM
 ┌──────────────────────────────────────────────────────────────┐
 │ xdr-agent (systemd, root)                                    │
 │   process ── netlink proc connector                          │
 │   file ───── inotify                       gRPC + mTLS :8444 │
 │   network ── /proc/net polling  ─────────────────────────┐   │
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

```bash
curl -fsSL http://<vm-ip>:8080/uninstall.sh | sudo bash
```

Then revoke or delete the endpoint in the console.

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

## Known limits of step 1

* The console is served over plain HTTP. The installer pins the CA by the
  fingerprint shown in the console, so agent traffic is still protected, but
  put the console behind HTTPS before using it outside a lab.
* Console login is a single admin account; sessions are in memory and end
  when the server restarts.
* inotify cannot tell which process changed a file, and network polling
  every 5 seconds can miss very short connections. Both are fixed by the
  eBPF collectors planned below.

## Roadmap

1. **Foundation** (this release): telemetry, console, enrollment, installer.
2. **Detection and response**: Sigma-style rules, YARA scanning, IOC feeds,
   alerts, and response actions (kill process, quarantine file, isolate host).
   eBPF collectors for process-attributed file and network events.
3. **Fleet management**: remote install and uninstall from the console over
   SSH, agent self-update, tamper protection; roll out to all VMs.
4. **PAM**: just-in-time sudo elevation with approval, session recording,
   privileged account inventory. Then a comparison with Vision One and
   CrowdStrike Falcon, and the Windows agent.
