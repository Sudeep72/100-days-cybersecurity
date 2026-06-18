# Day 046 - Blue Team vs Red Team: How Detection Engineering Works

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

For 25 days we thought like attackers.

Now we flip the perspective.

Detection engineering is the discipline of building systems that find attackers - reliably, at scale, with low noise. It's what separates a security team that reacts to breaches from one that catches them mid-attack.

This is also where my research lives. LogREx - the log anomaly detection system from my undergraduate thesis - is fundamentally a detection engineering project. Phase 3 builds toward that.

---

## 🔴 Red Team vs 🔵 Blue Team

```
Red Team                        Blue Team
────────────────────────────────────────────────────────
Simulates attackers             Defends against attackers
Finds vulnerabilities           Detects exploitation attempts
Thinks offensively              Thinks defensively
Goal: get in undetected         Goal: detect and respond
Measures: time to compromise    Measures: time to detect
Output: pen test report         Output: detection rules + alerts
```

They're not opposites - they're partners. Red team findings directly drive blue team rules. The best detection engineers have offensive security knowledge.

---

## 🔍 What Detection Engineering Actually Is

Detection engineering is the process of:

```
1. Understanding attacker behaviour (TTPs - Tactics, Techniques, Procedures)
2. Identifying what data sources capture evidence of that behaviour
3. Writing rules that match malicious patterns without false positives
4. Testing those rules against real attack data
5. Iterating as attackers evolve
```

It's software engineering applied to security detection. The output is rules, queries, and systems - not reports.

---

## 📊 The Detection Hierarchy

```
                    ┌─────────────────────┐
                    │  Threat Intelligence │  ← What attackers are doing globally
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   MITRE ATT&CK       │  ← Structured taxonomy of techniques
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Detection Rules    │  ← Sigma, YARA, KQL, SPL
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   SIEM / Data Lake   │  ← Splunk, Elastic, Sentinel
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Log Sources        │  ← Endpoints, network, cloud, apps
                    └─────────────────────┘
```

---

## 🗂️ Data Sources - What to Log

The more visibility you have, the more you can detect. But more logs = more cost and noise.

```
Endpoint logs:
├── Windows Event Logs        → process creation, logon, PowerShell, registry
├── Sysmon                    → enhanced Windows telemetry (process, network, file)
├── Linux auditd              → syscalls, file access, user commands
└── EDR (CrowdStrike, SentinelOne) → rich endpoint telemetry

Network logs:
├── Firewall logs             → allowed/denied connections
├── DNS logs                  → queries and responses
├── HTTP proxy logs           → web traffic with URLs
├── NetFlow/IPFIX             → connection metadata (no payload)
└── Full packet capture       → everything (expensive, targeted use only)

Authentication logs:
├── Windows Security Event Log → 4624 (logon), 4625 (failed), 4648 (explicit)
├── Active Directory           → Kerberos, LDAP queries
├── VPN logs                   → remote access
└── Cloud identity             → AWS CloudTrail, Azure AD, Okta

Application logs:
├── Web server                 → Apache/nginx access logs
├── Application                → custom app events
├── Database                   → queries, errors, schema changes
└── Cloud services             → S3 access, Lambda invocations
```

---

## 🎯 Detection Models

### Signature-Based Detection
Match exact known-bad patterns.

```
Rule: if process_name = "mimikatz.exe" → alert
```

Pros: zero false positives on exact matches, fast
Cons: trivially bypassed (rename the file, modify the hash)

---

### Anomaly-Based Detection
Establish a baseline, alert on deviations.

```
Rule: if login_count_per_hour > (mean + 3*stdev) → alert
```

Pros: catches unknown attacks, doesn't rely on signatures
Cons: high false positive rate during setup, requires tuning

This is what my LogREx research does with log data.

---

### Behavioral Detection (TTP-Based)
Match the behaviour, not the tool.

```
Rule: if process spawns cmd.exe AND parent_process is office application → alert
```

Pros: catches attack techniques regardless of specific tool used
Cons: complex to write, requires rich telemetry

This is the gold standard. Attackers can change tools but can't change the fundamental behaviour of what they're trying to achieve.

---

## 🔗 The MITRE ATT&CK Connection

ATT&CK maps every known attacker technique to observable behaviours.

Detection engineers use it to:
1. Identify which techniques they can currently detect
2. Find gaps in their detection coverage
3. Prioritise which rules to write next

```
Example: Technique T1059.001 - PowerShell

Observable evidence:
→ Process creation: powershell.exe with encoded command (-enc flag)
→ Network: outbound connection from powershell.exe
→ Registry: PowerShell execution policy changes

Detection rule:
EventID 4688 (process creation)
AND process_name = "powershell.exe"
AND command_line contains "-enc" OR "-EncodedCommand"
```

We go deep on ATT&CK at Day 51.

---

## 📐 The Detection Engineering Lifecycle

```
1. Intelligence → What technique are we detecting?
                  (ATT&CK, threat reports, red team findings)
       ↓
2. Data → What log sources capture this technique?
          (endpoint, network, auth, app logs)
       ↓
3. Rule → Write the detection logic
          (Sigma for portability, SPL for Splunk, KQL for Sentinel)
       ↓
4. Test → Validate against attack data
          (test with real attack tools in lab, red team testing)
       ↓
5. Tune → Reduce false positives
          (add exclusions, threshold tuning, context enrichment)
       ↓
6. Deploy → Push to SIEM
       ↓
7. Monitor → Alert fires → SOC investigates → feedback loop
       ↓
8. Iterate → ATT&CK evolves, attackers evolve, rules evolve
```

---

## 📊 Key Metrics

Detection engineers measure success with:

```
MTTD  → Mean Time to Detect
        How long from attack start to alert firing?
        Target: minutes, not days

MTTR  → Mean Time to Respond
        How long from alert to containment?
        Target: <1 hour for critical

FPR   → False Positive Rate
        What % of alerts are benign?
        Target: <5% for production rules

Coverage → What % of ATT&CK techniques do we detect?
           Track this with ATT&CK Navigator
```

The industry average MTTD is still 207 days (Day 17).
Good detection engineering brings this to hours.

---

## 🔑 Key Takeaways

- Detection engineering is software engineering applied to finding attackers
- Behavioural detection beats signature detection - techniques don't change, tools do
- Every detection rule needs a data source - log what matters before writing rules
- ATT&CK is the framework that structures detection coverage across techniques
- Red team knowledge makes better blue team rules - understand the attack to detect it
- The metrics that matter: MTTD, MTTR, false positive rate, ATT&CK coverage

---

## 📚 Resources
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sigma - generic detection rules](https://github.com/SigmaHQ/sigma)
- [Detection Engineering Weekly](https://detectionengineering.net/)
- [The DFIR Report - real attack telemetry](https://thedfirreport.com/)

---

## [⬅️ Day 045](../day045/) | [➡️ Day 047](../day047/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*