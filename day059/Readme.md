# Day 059 - Threat Hunting: Proactive Detection

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Advanced

---

## 🧠 The Concept

Alerts catch known patterns.

But what about attacks that don't trigger any alert?

**Threat hunting** is proactive searching through logs, network data, and system artifacts to find attacks **before they trigger alerts**.

It's detective work. No IDS rule to guide you. Just suspicious patterns and intuition.

---

## 🔍 Hunting vs Detection

```
DETECTION (Reactive)
├─ Attack happens
├─ Alert fires
├─ Team investigates
└─ Takes action
Response time: Hours to days
Coverage: Limited to what rules detect

THREAT HUNTING (Proactive)
├─ Threat intel says "APT-X is targeting finance sector"
├─ You search for their TTPs in your logs
├─ You find 3 compromised hosts (no alert ever fired)
├─ You remediate before attack escalates
Response time: Attack caught early
Coverage: Unlimited (depends on your creativity)
```

Most enterprises only detect attacks after customers report them or regulators notify them.

Threat hunters find attacks first.

---

## 🎯 Types of Threat Hunts

### 1. Intelligence-Driven Hunts

```
Threat intel says:
  APT-X uses Mimikatz to dump credentials
  They target admin accounts
  They modify PowerShell execution policy

What you hunt for:
  Processes: mimikatz.exe, powerkatz.dll
  Registry: Set-ExecutionPolicy entries
  Event logs: PowerShell ScriptBlockText = "Mimikatz"
  Access patterns: Admin account logins at 3am
```

**Start with:** Threat intel → TTPs → Hunt hypothesis → Search logs

---

### 2. Behavioral Hunts

```
You notice:
  A domain controller accessed by 50 different IPs
  An admin account used from China (never before)
  Massive data transfer from accounting server (5GB in 1 hour)
  Service account running PowerShell (unusual)

What you hunt for:
  Traffic to/from this DC (lateral movement)
  All logins from this user (compromise scope)
  File modifications during data transfer (what was stolen)
  Service account privilege escalation (how they escalated)
```

**Start with:** Anomaly → Expand scope → Find root cause

---

### 3. Vulnerability-Based Hunts

```
CVE-2021-44228 (Log4Shell) disclosed

What you hunt for:
  Java processes making unusual network connections
  Outbound connections to attacker-controlled domains
  Reverse shell indicators (bash, PowerShell outbound)
  LDAP queries for credential lookups
  File modifications in /tmp and /var/tmp
```

**Start with:** CVE → Attack vector → Hunt for exploitation

---

## 📊 Hunt Methodologies

### The HUNT Framework

```
HYPOTHESIS
  "APT-X is living in our network using pass-the-hash attacks"

EVIDENCE SOURCES
  ├─ Windows Event Log (4688 - process creation with hashes)
  ├─ Sysmon logs (10 - process access to lsass.exe)
  ├─ NetFlow (unusual lateral movement patterns)
  ├─ EDR (endpoint detection, process execution)
  └─ Memory forensics (injected code, privilege escalation)

HUNTING QUERIES
  Splunk: index=main EventID=4688 ParentProcessName=*lsass* | stats count by Account
  Elastic: event.id:10 AND process.name:lsass.exe | top 20 by actor.process.name
  Raw logs: grep -r "lsass" /var/log/security.log | cut -d',' -f3 | sort | uniq -c

VALIDATION
  ├─ Are these expected processes?
  ├─ Are they running from expected user accounts?
  ├─ Is this normal time-of-day?
  ├─ Are there corresponding network indicators?
  └─ Does it match known TTPs?

ACTION
  ├─ If true positive: alert IR team
  ├─ If false positive: update baseline
  ├─ If suspicious: deep dive forensics
  └─ Document for future hunts
```

---

## 🔎 Hunting Hypotheses by TTP

### Persistence

```
HYPOTHESIS: Attacker created scheduled task for persistence

INDICATORS:
  Registry: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
  Event: 4698 (Scheduled task created)
  Process: schtasks.exe /create
  
HUNT QUERY (Splunk):
  index=main EventID=4698
  | search NOT user=SYSTEM NOT user=NT AUTHORITY\SYSTEM
  | search NOT TaskName="*Windows*"
  | table EventTime, ComputerName, Account, TaskName
```

---

### Lateral Movement

```
HYPOTHESIS: Attacker using pass-the-hash for lateral movement

INDICATORS:
  Logon without plaintext password
  Process access to lsass.exe
  NTLM hash usage
  SMB to admin$ share
  
HUNT QUERY (Splunk):
  index=main EventID=4688
  | search ParentProcessName="*smb*" OR ParentProcessName="*lateral*"
  | search TargetObject="lsass*"
  | stats count by SourceIP, DestinationIP, Account
```

---

### Exfiltration

```
HYPOTHESIS: Attacker exfiltrating data via DNS or HTTPS

INDICATORS:
  Unusual DNS query volume
  Long DNS query names (data encoded in subdomain)
  Outbound HTTPS to unknown domains
  Data transfer volume anomalies
  
HUNT QUERY (Splunk):
  index=main sourcetype=dns
  | stats count by query_name
  | where count > 100
  | stats avg(string_length) by query_name
  | where avg > 50
```

---

## 🛠️ Hunting Tools & Data Sources

### Log Sources

```
Windows Security Event Log
├─ 4625 - Failed logon
├─ 4688 - Process creation
├─ 4698 - Scheduled task created
├─ 4720 - User account created
└─ 4738 - User account modified

Sysmon (System Monitoring)
├─ Event 1 - Process creation
├─ Event 3 - Network connection
├─ Event 10 - Process access
├─ Event 21 - WmiEvent
└─ Event 22 - DNSQuery

DNS Logs
├─ Query names
├─ Query types (A, TXT, MX)
├─ Response codes
└─ Query frequency

Proxy/Firewall
├─ URL categories
├─ User/IP mapping
├─ Outbound destinations
└─ Protocol anomalies

EDR (Endpoint Detection & Response)
├─ File creation/modification
├─ Process injection
├─ Registry changes
├─ Network connections
└─ Behavior scores
```

### Query Tools

```
SIEM Platforms
├─ Splunk - SPL queries
├─ Elastic - KQL queries
├─ Sumo Logic - Sumo queries
└─ ArcSight - ArcSight queries

Command Line
├─ grep + awk + sed (Unix)
├─ PowerShell (Windows)
├─ Python (flexible parsing)
└─ jq (JSON processing)

Query Languages
├─ SQL (structured logs)
├─ YARA (pattern matching)
├─ KQL (Kibana Query Language)
└─ SPL (Splunk Processing Language)
```

---

## 📋 Threat Hunting Checklist

```
PLANNING
☐ Define hypothesis (what are we looking for?)
☐ Identify data sources (where does this evidence live?)
☐ Draft hunting queries (how will we search?)
☐ Set time scope (last 30 days? 90 days?)

SEARCH
☐ Run initial queries
☐ Identify candidates (suspicious activities)
☐ Pivot on suspicious assets (expand investigation)
☐ Cross-reference multiple data sources

INVESTIGATION
☐ Validate findings (is this actually malicious?)
☐ Check for false positives (is this normal?)
☐ Determine scope (how many hosts affected?)
☐ Timeline reconstruction (when did it start?)

RESPONSE
☐ If true positive: escalate to incident response
☐ Preserve evidence (forensic capture)
☐ Document findings (for future hunts)
☐ Update detection rules (catch this pattern)

IMPROVEMENT
☐ Add to threat intelligence (IOCs, TTPs)
☐ Create new SIEM dashboards
☐ Schedule recurring hunts (quarterly)
☐ Share findings with security team
```

---

## 🎓 Sample Hunt Walkthrough

### Hunt: Living off the Land (LOLBins)

**Hypothesis:** Attacker using legitimate Windows tools (PowerShell, WMI, BITS) to avoid malware detection

**Indicators:**
```
PowerShell:
  ├─ -EncodedCommand flag
  ├─ IEX (Invoke-Expression) used
  ├─ Unusual parent process (Office, explorer.exe)
  └─ History: C:\Windows\System32\config\SAM accessed

WMI:
  ├─ Process creation via wmic.exe
  ├─ StdRegProv (registry access)
  ├─ Remote WMI execution
  └─ Unusual user account running WMI

BITS (Background Intelligent Transfer Service):
  ├─ bitsadmin creating jobs
  ├─ Downloading to unusual locations (/tmp, /var/tmp)
  ├─ Resume after reboot
  └─ Large transfer volume
```

**Hunt Query:**
```
index=main (EventID=4688)
  (Image="*powershell.exe" AND CommandLine="*-EncodedCommand*")
  OR (Image="*wmic.exe" AND CommandLine="*process*")
  OR (Image="*bitsadmin.exe")
| search NOT User=SYSTEM
| stats count by Image, CommandLine, User, ComputerName
| where count > 5
```

**Investigation:**
1. Identify the hosts/users
2. Capture their process trees (what spawned PowerShell?)
3. Check for credential access (lsass.exe access?)
4. Check network connections (C2 communication?)
5. Validate if this is admin activity or compromise

---

## 🔑 Key Takeaways

- **Threat hunting is detective work** - use threat intel to guide hypotheses
- **Intelligence + creativity = detection** - combine what you know with what you suspect
- **Start with high-confidence indicators** - known C2 IPs, known malware families
- **Expand scope systematically** - one finding leads to others
- **Document everything** - for response, for future hunts, for intelligence sharing
- **Convert hunts to rules** - turn manual hunts into automated detections

---

## 📚 Resources

- [NIST Threat Hunting](https://www.nist.gov/publications)
- [Splunk Hunting Resources](https://www.splunk.com/en_us/resources.html)
- [MITRE ATT&CK for Threat Hunting](https://attack.mitre.org/)
- [Threat Hunting Projects](https://github.com/delirvfx/threat_hunting)

---

## [⬅️ Day 058](../day058/) | [➡️ Day 060](../day060/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*