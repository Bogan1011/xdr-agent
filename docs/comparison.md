# How we compare: Trend Micro Vision One and CrowdStrike Falcon

Status as of release 0.8.1 (Linux agent, single-tenant console). The
competitor columns describe what their commercial platforms offer in
general; exact features depend on the licence tier, and both vendors change
their line-ups often, so check current datasheets before quoting this
externally.

Legend: ✅ have it · 🟡 partial · ❌ not yet

## Feature matrix

| Capability | XDR Agent (ours) | Trend Vision One | CrowdStrike Falcon |
|---|---|---|---|
| **Platforms** | | | |
| Linux servers | ✅ eBPF + fallbacks | ✅ | ✅ |
| Windows servers and endpoints | ❌ next step | ✅ | ✅ |
| macOS | ❌ | ✅ | ✅ |
| Containers / Kubernetes | 🟡 host-level events only | ✅ Container Security | ✅ Falcon Cloud Security |
| Cloud workloads, agentless posture | ❌ | ✅ | ✅ |
| **Prevention** | | | |
| Policies with per-module settings, assigned to endpoints | ✅ eight modules, Deep Security style | ✅ | ✅ prevention policies |
| Signature anti-malware | 🟡 real-time YARA + SHA-256 IOCs, exec blocking, auto-quarantine | ✅ | ✅ (ML, no signatures) |
| Web reputation | 🟡 IP/domain IOC block list (nftables), no URL categories | ✅ | 🟡 |
| Machine-learning file prevention | ❌ | ✅ | ✅ |
| Exploit / memory protection | ❌ | ✅ | ✅ |
| Host firewall, IPS / virtual patching | 🟡 host firewall (nftables), SSH brute-force IPS, no virtual patching | ✅ (Deep Security heritage) | 🟡 firewall management |
| File integrity monitoring | ✅ baselines, drift alerts, accept-as-baseline | ✅ | ✅ (FileVantage) |
| Application control | ✅ block lists, allow-list lockdown, scripts from temp folders stopped | ✅ | 🟡 |
| Device control (USB) | ✅ USB storage allow, read-only or block, with exceptions | ✅ | ✅ |
| **Detection and investigation** | | | |
| Process, file, network telemetry | ✅ | ✅ | ✅ |
| Shell command telemetry (bash builtins, typed commands) | ✅ eBPF uprobes on bash (interactive lines, bash -c / eval strings) | ✅ | ✅ |
| Behaviour rules, MITRE tags | ✅ Sigma-style, 20+ built-in | ✅ | ✅ |
| Custom rules | ✅ in the console | ✅ | ✅ |
| Threat intel feeds / IOCs | ✅ hash, IP/CIDR, domain feeds | ✅ | ✅ |
| Cross-layer correlation (email, network, cloud, identity) | ❌ endpoint only | ✅ the "X" in XDR | ✅ via Falcon modules + Next-Gen SIEM |
| Attack storyline / process tree view | ❌ flat event list | ✅ | ✅ |
| Threat hunting query language | 🟡 filters, no query language | ✅ | ✅ (Event Search / LogScale) |
| Managed threat hunting (MDR) | ❌ | ✅ | ✅ (OverWatch / Complete) |
| **Response** | | | |
| Kill process, quarantine file | ✅ | ✅ | ✅ |
| Network isolation | ✅ | ✅ | ✅ |
| Remote shell / live response | ✅ browser shell over the agent's mTLS link, recorded, watchable live | ✅ | ✅ (Real Time Response) |
| Automated playbooks / SOAR | 🟡 per-rule auto-response | ✅ | ✅ (Fusion SOAR) |
| **Fleet** | | | |
| Remote install / uninstall | ✅ SSH + one-liner | ✅ | ✅ |
| Self-update with rollback | ✅ | ✅ | ✅ (sensor update policies) |
| Tamper protection | ✅ maintenance token | ✅ | ✅ uninstall token |
| **Privileged access (PAM)** | | | |
| Just-in-time sudo with approval | ✅ | ❌ (no native PAM) | ❌ (no native PAM) |
| Privileged session recording | ✅ sudo sessions + console remote shells | ❌ | ❌ |
| Live view of logged-in users | ✅ who is on which terminal, what they run now | 🟡 via search | 🟡 via RTR `ps` / `users` |
| Privileged account inventory | ✅ Linux local accounts | 🟡 identity posture (AD / Entra) | 🟡 Falcon Identity (AD / Entra) |
| Identity threat detection | 🟡 new-privileged-account alert | ✅ | ✅ |
| Password vaulting, credential rotation | ❌ | ❌ | ❌ |
| **Platform** | | | |
| Multi-tenant, RBAC, SSO | ❌ single admin | ✅ | ✅ |
| Risk scoring / attack surface management | ❌ | ✅ (Cyber Risk Exposure Management) | ✅ (Exposure Management) |
| Vulnerability assessment | ❌ | ✅ | ✅ (Spotlight) |
| SIEM export / API | 🟡 REST API, no export | ✅ | ✅ |
| Self-hosted / on-premises | ✅ Docker Compose | 🟡 SaaS-first | ❌ SaaS only |

## Where we are different

* **PAM is built in.** Neither Vision One nor Falcon manages local
  privileged access on servers; customers buy CyberArk, BeyondTrust or
  Delinea for just-in-time elevation and session recording. Ours shares the
  agent, the console and the alerting, so a grant, the session it allowed,
  and the process telemetry from that session sit side by side.
* **Self-hosted and transparent.** One Docker Compose stack, readable rules,
  no data leaving the network. Both competitors are SaaS consoles.
* **Lightweight Linux sensor** using eBPF with graceful fallback, similar in
  approach to Falcon's Linux sensor in user mode.

## Gaps, in roadmap order

1. **Windows agent** (servers first): ETW-based process, file, network and
   registry telemetry, the same response actions, tamper protection, and
   PAM equivalents (just-in-time local admin group membership, RDP / admin
   session recording).
2. **Investigation UX**: process tree and attack storyline per alert, a
   query language over ClickHouse, and saved hunts.
3. **Console hardening**: HTTPS by default, multiple users with roles,
   SSO (OIDC), audit log of admin actions, approval by a second person for
   PAM grants. (The admin-set agent password shipped in 0.8.1.)
4. **Prevention depth**: policies with eight modules shipped in 0.6.0;
   0.7.0 adds application control lockdown (allow-list) and stops
   interpreters running scripts from temp folders. Next: machine-learning
   blocking, IPS rules beyond SSH brute force / virtual patching, URL
   categories for web reputation. Script blocking does not cover code piped
   to a shell (`curl | bash`). 0.8.1 adds read-only USB storage and a
   Self-protection module: tamper protection for every endpoint in a policy,
   unlocked locally with an admin-set password (Deep Security style).
5. **Vulnerability and posture**: package inventory matched against CVE
   feeds, CIS-style configuration checks, a per-host risk score.
6. **Live response**: the remote shell and live view shipped in 0.5.0.
   Next: file upload/download in the shell, and per-admin roles for who may
   open a shell on which hosts.
7. **PAM depth**: password vaulting and rotation for local root, SSH
   certificate issuance instead of standing `authorized_keys`, command
   allow-lists per grant, Slack / email approval.
8. **Integrations**: syslog / webhook / SIEM export, ticketing links on
   requests, and later email, network and cloud sources for real
   cross-layer XDR correlation.
