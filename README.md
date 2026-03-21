# Active Directory + Wazuh Hybrid SOC Homelab

> Azure-hosted Active Directory, Wazuh SIEM, Sysmon endpoint telemetry, and a custom agentless log pipeline — all running together as one environment.

![Status](https://img.shields.io/badge/Status-Completed%20%2F%20Archived-lightgrey)
![Platform](https://img.shields.io/badge/Platform-Azure%20%7C%20VirtualBox%20%7C%20Linux-blue)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh-orange)
![Domain](https://img.shields.io/badge/Identity-Active%20Directory-0078D4?logo=microsoft)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## What This Is

Most homelab guides are single-machine setups - one VM, one tool, done. This one is different.

I wanted to understand how security monitoring actually works across distributed infrastructure, not just on a local box. So I set up an Azure-hosted Windows Server as the Domain Controller, joined a local VirtualBox Windows 10 VM to it over the public internet, and pointed everything at a remote Wazuh server. Then I hit a separate problem — I had a shared Hostinger server with web app logs I wanted to monitor but had no root access, so no Wazuh agent. I worked around it using SCP and cron.

It ended up covering more ground than I planned — hybrid domain join, SIEM integration, endpoint telemetry with Sysmon, agentless log shipping, and VirusTotal-based malware detection. Not bad for something that started as just "let me try AD."

---

## Honest Notes

**On documentation:** Built this in early 2024, documented it in 2025. I wasn't keeping notes while building — I was too busy getting it to actually work. Everything here is reconstructed from memory and what I remembered going wrong.

**On the config files:** The files in `configs/` and `scripts/` were rebuilt from memory, not recovered from the original lab. I verified each one against the official Wazuh docs, the Wazuh GitHub ruleset, and the Sysmon schema reference before putting them here. They're accurate to what I built — just reconstructed, not recovered. If you're using them, adjust the hostnames, paths, and API keys for your environment.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    IDENTITY LAYER (Azure)                    │
│   Windows Server DC  ←  mylab-local.mywire.org              │
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
│   Wazuh Server  ←  wazuh.mywire.org                         │
│   Ingest → Decode → Match Rules → Alert                      │
└────────────────────────┬────────────────────────────────────┘
                         │ SSH + Cron (every 12h)
┌────────────────────────▼────────────────────────────────────┐
│              AGENTLESS EXTENSION (Shared Hosting)            │
│   Hostinger server — no root access                          │
│   Custom log push → /home/deployment/shared-logs/            │
└─────────────────────────────────────────────────────────────┘
```

Both the DC and the Wazuh server use Dynu dynamic DNS (`mywire.org`) so I didn't need static IPs — everything talks by hostname across networks.

---

## Components

| Component | Technology | What It Does |
|---|---|---|
| Domain Controller | Windows Server on Azure | Identity authority — Kerberos, AD DS, DNS |
| Endpoint | Windows 10 (VirtualBox) | Domain-joined machine, simulates user activity |
| SIEM | Wazuh (manager + indexer) | Ingests logs, runs rules, generates alerts |
| Telemetry | Sysmon | Deep endpoint logging — process, network, registry |
| DNS | Dynu Dynamic DNS | Hostname resolution across cloud and local |
| Log Forwarder | Bash + Cron + SCP | Agentless pipeline from shared hosting |
| Threat Intel | VirusTotal API | File hash scanning, malware detection |

---

## Data Flow

```
User or simulated attack activity
          ↓
Windows Event Logs + Sysmon events fire
          ↓
Wazuh Agent ships logs → port 1514 → wazuh.mywire.org
  (or SCP push every 12h from Hostinger)
          ↓
Wazuh Manager decodes, normalizes, matches rules
          ↓
Alert generated with severity level 1–15
          ↓
Dashboard — investigate, correlate, map to MITRE
```

---

## Key Parts of the Build

### 1. Hybrid Domain Join (Azure DC ↔ Local VM)

Joining a local VM to an Azure-hosted domain doesn't just work out of the box. The VM's DNS had to point directly at the Azure DC's IP — not the default gateway. Then the Azure NSG needed these ports open before anything would function:

```
TCP/UDP 53   — DNS
TCP/UDP 88   — Kerberos
TCP 389      — LDAP
TCP 445      — SMB (Group Policy)
TCP 1514     — Wazuh agent traffic
TCP 1515     — Wazuh agent registration
```

After that, domain join worked. Validated with:

```powershell
nslookup mylab-local.mywire.org
Test-ComputerSecureChannel -Verbose
```

---

### 2. Sysmon + Wazuh

Default Sysmon without a proper config generates too much noise to be useful. I used the SwiftOnSecurity config as a base. The key thing most people miss — Wazuh doesn't automatically read the Sysmon channel. You have to explicitly add it:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Without that line, Sysmon runs fine but Wazuh sees nothing from it.

Event IDs being monitored:

| Event ID | What It Captures |
|---|---|
| 1 | Process creation — full command line, parent process |
| 3 | Network connections — src/dst IP and port |
| 7 | Image/DLL load |
| 11 | File creation |
| 13 | Registry value set |
| 22 | DNS queries |

---

### 3. Agentless Log Pipeline

The Hostinger server had no root access so I couldn't install the Wazuh agent. I needed those web app logs in the SIEM anyway, so I wrote a cron job that pushes them via SCP every 12 hours:

```bash
0 */12 * * * scp /home/deployment/logs/app.log deployment@wazuh.mywire.org:/home/deployment/shared-logs/app.log
```

Wazuh just watches that directory like any other log source:

```xml
<localfile>
  <location>/home/deployment/shared-logs/app.log</location>
  <log_format>syslog</log_format>
</localfile>
```

Same approach works for anything you can't install an agent on — IoT devices, legacy systems, restricted environments. The full script with error handling is in `scripts/log-forwarder.sh`.

---

### 4. VirusTotal Integration

Every 12 hours, a script recursively scans monitored directories, pulls SHA256 hashes, and checks them against the VirusTotal API. Results get logged and picked up by Wazuh:

```
Scan directories recursively
        ↓
SHA256 hash per file
        ↓
VirusTotal API lookup (hash check, not upload)
        ↓
Verdict logged → Wazuh ingests → rule fires if malicious
```

This is hash-based lookup only — no files are uploaded to VT. Rate limiting (15s sleep between requests) keeps it within the free tier. Full script in `scripts/virustotal-scanner.sh`.

---

## AD Monitoring Coverage

| Category | Event IDs | What It Catches |
|---|---|---|
| Authentication | 4624, 4625, 4648 | Brute force, pass-the-hash, lateral movement |
| Privilege changes | 4728, 4732, 4756 | Group membership changes |
| Account management | 4720, 4722, 4725 | User creation, enable/disable |
| Kerberos | 4768, 4769, 4771 | TGT requests, service tickets, pre-auth failures |
| Policy changes | 4739, 4713 | Domain policy modifications |

---

## MITRE ATT&CK Coverage

| Technique | ID | How It's Detected |
|---|---|---|
| Brute Force | T1110 | Multiple 4625s → Wazuh rule 60204 → custom rule 100001 |
| Valid Accounts | T1078 | 4624 from unexpected source |
| Pass the Hash | T1550.002 | Logon type 3 + NTLM |
| Kerberoasting | T1558.003 | 4769 with RC4 encryption type (0x17) |
| PowerShell | T1059.001 | Sysmon EID 1 + encoded command in args |
| Scheduled Task | T1053.005 | Sysmon EID 1 — schtasks.exe |
| Lateral Movement | T1021 | Remote logons from unexpected workstations |
| Malware | T1204 | VirusTotal hash match → rule 100011 |

---

## Troubleshooting — What Actually Went Wrong

**Domain join failing — "DNS name does not exist"**
The VM was resolving against the default gateway, not the DC. Fixed by manually setting the DNS adapter to the Azure DC's IP before attempting the join.

**Sysmon installed but nothing showing in Wazuh**
Wazuh doesn't monitor the Sysmon event channel by default. Had to add the `<localfile>` block explicitly. This one took longer to figure out than it should have.

**Agents connected, zero alerts**
The pipeline was working fine — logs were flowing. But no rules were firing because I hadn't generated any test activity. Spent time thinking something was broken when it was actually working correctly. Lesson: always test with deliberate activity, don't assume silence means failure.

**Kerberos failing intermittently**
Time drift between the Azure DC and local VM. Kerberos won't authenticate if clocks are off by more than 5 minutes — and it fails silently. Fixed with `w32tm /resync`.

**VirusTotal returning inconsistent results**
Free tier API rate limits. Was hitting the limit mid-scan. Added `sleep 15` between requests and it stabilized.

---

## What I Actually Took Away From This

The hardest part wasn't setting up individual tools. It was getting components across different networks — cloud VM, local VM, shared hosting — to talk to each other, and then figuring out why things were quiet when they should have been alerting.

The thing that stuck with me most: logs flowing into a SIEM doesn't mean detection is working. You can have a perfectly healthy pipeline and zero alerts because the rules don't match. Understanding the difference between "pipeline health" and "detection coverage" is something I only got from actually running this and being confused by it.

---

## Repository Structure

```
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

Start with `configs/wazuh-agent-ossec.conf` to see what gets collected, then `configs/wazuh-custom-rules.xml` for the detection logic.

---

## Requirements to Reproduce

- Azure free tier or any cloud Windows Server VM
- VirtualBox on a local machine
- Any Linux VPS for Wazuh
- Dynu account for dynamic DNS (free)

Adjust `wazuh.mywire.org`, `mylab-local.mywire.org`, and the VirusTotal API key in the configs before deploying.

---

## Tech Stack

`Wazuh` · `Active Directory` · `Azure` · `Windows Server` · `Sysmon` · `VirtualBox` · `Dynu DNS` · `VirusTotal API` · `Bash` · `Cron` · `SSH/SCP`

---

## Author

**Kunal Patil** — BSc Computer Science (Hons) · Cybersecurity  
[LinkedIn](https://linkedin.com/in/kunal-patil-0b4713276) · [GitHub](https://github.com/Aakhri-Pastaa)

---

*Personal project, not affiliated with any vendor.*
