# Active Directory + Wazuh Hybrid SOC Homelab

**A hybrid security-monitoring lab: an Azure-hosted Windows Server domain controller, a VirtualBox Windows 10 endpoint joined to it over the public internet, Sysmon endpoint telemetry, a remote Wazuh SIEM, an agentless SCP-and-cron log pipeline from a shared host, and VirusTotal hash lookups.**

> [!NOTE]
> **Status: completed and archived.** I built the lab in early 2024 and documented it in 2025. The files in `configs/` and `scripts/` were reconstructed from memory and checked against the official documentation, not recovered from the original lab — see [Status and limitations](#status-and-limitations). How it was built: [AI disclosure](#ai-disclosure).

## What it does

I wanted to understand how security monitoring works across distributed
infrastructure, not just on one machine. So I set up an Azure-hosted Windows
Server as the domain controller, joined a local VirtualBox Windows 10 VM to it
over the public internet, and pointed everything at a remote Wazuh server.
Then I hit a separate problem: a shared Hostinger server whose web-app logs I
wanted to monitor, with no root access and therefore no Wazuh agent. I worked
around it with SCP and cron.

It ended up covering more ground than I planned — hybrid domain join, SIEM
integration, endpoint telemetry with Sysmon, agentless log shipping, and
VirusTotal-based malware detection. Not bad for something that started as
"let me try AD". It is a personal learning lab, not a production deployment.

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                    IDENTITY LAYER (Azure)                    │
│   Windows Server DC  ←  dc.example.org                       │
│   AD DS + DNS + Kerberos + Group Policy                      │
└────────────────────────┬────────────────────────────────────┘
                         │ Domain Join (over public internet)
┌────────────────────────▼────────────────────────────────────┐
│                  ENDPOINT LAYER (Local)                      │
│   Windows 10 VM (VirtualBox)                                 │
│   Sysmon → process, network, registry, file telemetry        │
└────────────────────────┬────────────────────────────────────┘
                         │ Wazuh Agent (port 1514)
┌────────────────────────▼────────────────────────────────────┐
│                   SIEM LAYER (Remote)                        │
│   Wazuh Server  ←  wazuh.example.org                         │
│   Ingest → Decode → Match Rules → Alert                      │
└────────────────────────┬────────────────────────────────────┘
                         │ SSH + Cron (every 12h)
┌────────────────────────▼────────────────────────────────────┐
│              AGENTLESS EXTENSION (Shared Hosting)            │
│   Hostinger server — no root access                          │
│   Custom log push → /home/deployment/shared-logs/            │
└─────────────────────────────────────────────────────────────┘
```

Both the DC and the Wazuh server used Dynu dynamic DNS, so neither needed a
static IP — everything talks by hostname across networks. The hostnames in
this repository are placeholders.

| Component | Technology | What it does |
|---|---|---|
| Domain Controller | Windows Server on Azure | Identity authority — Kerberos, AD DS, DNS |
| Endpoint | Windows 10 (VirtualBox) | Domain-joined machine, simulates user activity |
| SIEM | Wazuh (manager + indexer) | Ingests logs, runs rules, generates alerts |
| Telemetry | Sysmon | Deep endpoint logging — process, network, registry |
| DNS | Dynu dynamic DNS | Hostname resolution across cloud and local |
| Log forwarder | Bash + cron + SCP | Agentless pipeline from shared hosting |
| Threat intel | VirusTotal API | File-hash lookups, malware detection |

Data flow:

```text
User or simulated attack activity
          ↓
Windows Event Logs + Sysmon events fire
          ↓
Wazuh Agent ships logs → port 1514 → Wazuh manager
  (or SCP push every 12h from Hostinger)
          ↓
Wazuh Manager decodes, normalizes, matches rules
          ↓
Alert generated with severity level 1–15
          ↓
Dashboard — investigate, correlate, map to MITRE
```

## Key parts of the build

### 1. Hybrid domain join (Azure DC ↔ local VM)

Joining a local VM to an Azure-hosted domain does not work out of the box.
The VM's DNS had to point directly at the Azure DC's IP, not the default
gateway, and the Azure network security group needed these ports open before
anything would function:

```text
TCP/UDP 53   — DNS
TCP/UDP 88   — Kerberos
TCP 389      — LDAP
TCP 445      — SMB (Group Policy)
TCP 1514     — Wazuh agent traffic
TCP 1515     — Wazuh agent registration
```

After that, the domain join worked. Validated with:

```powershell
nslookup dc.example.org
Test-ComputerSecureChannel -Verbose
```

### 2. Sysmon + Wazuh

Default Sysmon without a proper config generates too much noise to be
useful, so I used the SwiftOnSecurity config as a base. The step most people
miss: Wazuh does not read the Sysmon channel automatically. You have to add
it explicitly:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Without that block, Sysmon runs fine but Wazuh sees nothing from it. Event
IDs monitored:

| Event ID | What it captures |
|---|---|
| 1 | Process creation — full command line, parent process |
| 3 | Network connections — src/dst IP and port |
| 7 | Image/DLL load |
| 11 | File creation |
| 13 | Registry value set |
| 22 | DNS queries |

### 3. Agentless log pipeline

The Hostinger server had no root access, so I could not install the Wazuh
agent. I needed those web-app logs in the SIEM anyway, so a cron job pushes
them over SCP every 12 hours:

```bash
0 */12 * * * scp /home/deployment/logs/app.log deployment@wazuh.example.org:/home/deployment/shared-logs/app.log
```

Wazuh watches that directory like any other log source:

```xml
<localfile>
  <location>/home/deployment/shared-logs/app.log</location>
  <log_format>syslog</log_format>
</localfile>
```

The same approach works for anything that cannot run an agent — IoT devices,
legacy systems, restricted environments. The full script, with error
handling, is `scripts/log-forwarder.sh`.

### 4. VirusTotal integration

Every 12 hours a script scans the monitored directories recursively, hashes
each file with SHA-256 and checks the hash against the VirusTotal API. The
results are logged and picked up by Wazuh:

```text
Scan directories recursively
        ↓
SHA256 hash per file
        ↓
VirusTotal API lookup (hash check, not upload)
        ↓
Verdict logged → Wazuh ingests → rule fires if malicious
```

It is a hash lookup only; no file is uploaded to VirusTotal. A 15-second
sleep between requests keeps it within the free tier's rate limit. Full
script: `scripts/virustotal-scanner.sh`.

## Detection coverage

Active Directory events:

| Category | Event IDs | What it catches |
|---|---|---|
| Authentication | 4624, 4625, 4648 | Brute force, pass-the-hash, lateral movement |
| Privilege changes | 4728, 4732, 4756 | Group membership changes |
| Account management | 4720, 4722, 4725 | User creation, enable/disable |
| Kerberos | 4768, 4769, 4771 | TGT requests, service tickets, pre-auth failures |
| Policy changes | 4739, 4713 | Domain policy modifications |

MITRE ATT&CK mapping:

| Technique | ID | How it is detected |
|---|---|---|
| Brute Force | T1110 | Multiple 4625s → Wazuh rule 60204 → custom rule 100001 |
| Valid Accounts | T1078 | 4624 from unexpected source |
| Pass the Hash | T1550.002 | Logon type 3 + NTLM |
| Kerberoasting | T1558.003 | 4769 with RC4 encryption type (0x17) |
| PowerShell | T1059.001 | Sysmon EID 1 + encoded command in args |
| Scheduled Task | T1053.005 | Sysmon EID 1 — schtasks.exe |
| Lateral Movement | T1021 | Remote logons from unexpected workstations |
| Malware | T1204 | VirusTotal hash match → rule 100011 |

The 11 custom rules (IDs 100001–100011) are in
`configs/wazuh-custom-rules.xml`.

## What went wrong

**Domain join failing — "DNS name does not exist".** The VM was resolving
against the default gateway, not the DC. Fixed by setting the DNS adapter to
the Azure DC's IP manually before attempting the join.

**Sysmon installed, nothing in Wazuh.** Wazuh does not monitor the Sysmon
event channel by default; the `<localfile>` block has to be added
explicitly. This one took longer to figure out than it should have.

**Agents connected, zero alerts.** The pipeline was working — logs were
flowing — but no rules fired because I had not generated any test activity.
I spent time thinking something was broken when it was working correctly.
Lesson: test with deliberate activity; silence does not mean failure.

**Kerberos failing intermittently.** Clock drift between the Azure DC and the
local VM. Kerberos refuses to authenticate when clocks differ by more than
five minutes, and it fails silently. Fixed with `w32tm /resync`.

**VirusTotal returning inconsistent results.** The free tier's rate limit was
being hit mid-scan. Adding `sleep 15` between requests stabilized it.

## What I took away

The hardest part was not setting up individual tools. It was getting
components on different networks — a cloud VM, a local VM, shared hosting —
to talk to each other, and then working out why things were quiet when they
should have been alerting.

The lesson that stuck: logs flowing into a SIEM does not mean detection is
working. A perfectly healthy pipeline can produce zero alerts because the
rules do not match. I only understood the difference between *pipeline
health* and *detection coverage* by running this and being confused by it.

## Status and limitations

| Area | Status | Notes |
|---|---|---|
| The lab environment | Archived | Built early 2024; not maintained |
| `configs/`, `scripts/` | Reconstructed | Rebuilt from memory, then checked against the Wazuh docs, the Wazuh GitHub ruleset and the Sysmon schema reference |

- **Reconstructed, not recovered.** I did not keep notes while building; I
  was busy getting it to work. The documentation and the config files are
  accurate to what I built, but they were rebuilt afterwards, not copied from
  the running lab.
- **Placeholders to adjust.** Hostnames (`dc.example.org`,
  `wazuh.example.org`), paths and the VirusTotal API key must be replaced
  for your environment.
- **Not a production deployment.** One endpoint, one domain controller, one
  Wazuh server.

## Repository layout

```text
active-directory-wazuh-homelab/
├── configs/
│   ├── sysmon-config.xml          # Sysmon config — SwiftOnSecurity baseline, trimmed
│   ├── wazuh-agent-ossec.conf     # Agent config — log channels + syscheck
│   └── wazuh-custom-rules.xml     # 11 custom rules — AD, Sysmon, VirusTotal
├── scripts/
│   ├── log-forwarder.sh           # SCP-based log push from shared hosting
│   └── virustotal-scanner.sh      # Hash scan + VT API lookup
└── README.md
```

Start with `configs/wazuh-agent-ossec.conf` to see what gets collected, then
`configs/wazuh-custom-rules.xml` for the detection logic.

## Requirements to reproduce

| Requirement | Why |
|---|---|
| A cloud Windows Server VM (Azure free tier works) | Domain controller |
| VirtualBox on a local machine | Windows 10 endpoint |
| A Linux VPS | Wazuh manager |
| A dynamic-DNS provider (Dynu is free) | Hostnames instead of static IPs |
| A VirusTotal API key (free tier) | Hash lookups |

## AI disclosure

I designed, built, configured and documented this lab without AI
assistance. In September 2026 this README was restructured with an AI
assistant to match my documentation standard; the technical content is
unchanged, except that my lab's real hostnames were replaced with
placeholders in the README, `configs/wazuh-agent-ossec.conf` and
`scripts/log-forwarder.sh`.

## Built with

Wazuh · Active Directory · Azure · Windows Server · Sysmon · VirtualBox · Dynu DNS · VirusTotal API · Bash · cron · SSH/SCP

*Personal project, not affiliated with any vendor.*
