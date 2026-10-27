# Linux telemetry

What the Rust agent collects, mapped to the Ironsight Linux telemetry
specification (Trend Vision One / CrowdStrike Falcon comparison). Events are
`xdr.v1.Event` messages (proto/xdr/v1/agent.proto); the server stores one row
per event in ClickHouse `events` and adds a one-line English `summary` that the
console shows and a local language model can explain further.

Fields are only ever appended to the proto and the table, never renumbered.

## Coverage

| # | Capability (spec priority) | Event types | Source | Status |
|---|---|---|---|---|
| 1 | Process start/exit, stable process GUID | `process_exec`, `process_exit` | netlink proc connector, /proc | done |
| 2 | Parent/child tree | `parent_process_guid`, storyline | resolver | done |
| 3 | Command line, executable, hashes | SHA-256, SHA-1, MD5 in one read | /proc, file | done (0.10) |
| 3b | User/group, euid, loginuid, tty, session, capabilities, namespaces, exe owner/mode, run time | process payload + context | /proc | done (0.10) |
| 4 | Network connect/accept/listen + process | `net_connect`, `net_accept`, `net_listen`; TCP+UDP, direction, netns | /proc/net + socket inodes | done (0.10); eBPF for short-lived connections comes with the eBPF port |
| 5 | File create/write/delete/rename/attrib | `file_*`; inode, device, owner, gid, mount, fs type, hashes | inotify (configured paths) | done (0.10); writer process via eBPF port |
| 6 | DNS query/response + process | `dns_query` | packet socket on port 53 | PR 2 |
| 7 | SSH/login/sudo/su/account changes | `auth_login`, `auth_logout`, `auth_failed`, `sudo`, `su`, `account_change` | journald / auth.log | PR 2 |
| 8 | Persistence | `persistence` (cron, systemd, ssh keys, sudoers, profiles, ld.so.preload, udev, modules-load, sysctl.d, rc.local, at) | inotify on fixed locations, line diff | PR 2 |
| 9 | Memory / process access | `process_access`, `memory_protect`, `process_injection` | /proc (TracerPid, maps, environ, memfd) | PR 3 |
| 10 | Container / Kubernetes context | `container` on every event, `container_start/stop` | cgroup + runtime metadata | PR 3 |
| 11 | Kernel signals | `kernel_module`, `kernel_change` (sysctl, mounts, taint) | /proc | PR 3 |
| 12 | Inventory | `inventory` (system, packages, interfaces, mounts), on change only | /proc, dpkg/rpm | PR 3 |
| - | Sensitive file open (credential access) | `file_open` | fanotify | PR 3 |

## Envelope

Every event carries `id`, `timestamp_unix_nano`, `type`, `schema_version`,
`agent_id`, `tenant_id`/`endpoint_id` (set by the server), `priority`,
`collector`, `process_context` (the actor, with `process_guid` and its parent)
and, inside a container, `container`. Host facts (hostname, OS, kernel,
architecture, agent version) are sent with heartbeats and joined by agent ID
instead of being repeated on every event, as the spec recommends.

## Priority

| Priority | Event types |
|---|---|
| critical | exec_blocked, yara_match, agent_tamper, process_injection, process_access, kernel_module |
| high | process_exec, persistence, memory_protect, kernel_change, auth_failed, sudo, su, account_change, file_open, policy module events |
| normal | process_exit, network, DNS, logins |
| low | file create/modify/delete/rename/attrib, net_listen, inventory |

The local SQLite queue drops the lowest priority first under pressure.

## ClickHouse columns added in 0.10

`gid, group_name, euid, login_uid, tty, session_id, capabilities, md5, sha1,
duration_ms, pid_ns, mnt_ns, net_ns, container_id, container_name,
container_image, pod_name, pod_namespace, inode, device, owner, filesystem,
mount_point, direction, dns_query, dns_type, dns_rcode, dns_answers, category,
action, outcome, target_user, target_pid, target_process_guid, old_value,
new_value, collector, summary`.

How payloads map onto shared columns:

| Payload | category | action | outcome | other |
|---|---|---|---|---|
| auth | method (password, publickey) | login/failed/sudo/su/user_created... | success/failure | service in path, sudo command in args, source in remote_addr, failure reason in old_value |
| persistence | persistence_type | created/modified/deleted | | removed lines in old_value, added lines in new_value |
| memory | injection or rwx | operation | | target in target_pid/target_process_guid/target_user, target exe in path |
| kernel | | action | | name in path, old/new value |
| inventory | kind | snapshot/changed | | added items in new_value, removed in old_value, system facts in metadata |
| dns | | | success/failure (rcode) | server in remote_addr |
