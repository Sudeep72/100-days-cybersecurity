# Day 061 - SOC Analyst Workflow: A Day in the Life

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Everything we've built so far - detection rules, threat hunting, forensics, incident response - comes together in the SOC (Security Operations Center).

A SOC analyst is the first human to see an alert. They decide: is this real? Is it urgent? Does it need escalation?

Understanding the SOC workflow helps you write better detection rules, understand what analysts need, and eventually work in a SOC yourself.

---

## 🏢 What Is a SOC?

```
A Security Operations Center (SOC) is:

├─ 24/7 monitoring operation (someone is always watching)
├─ Network of analysts at different skill levels
├─ Centralized alert management (SIEM dashboard)
├─ Escalation pathways (Tier 1 → Tier 2 → Incident Response)
├─ Ticketing system (track every alert and investigation)
├─ Oncall rotation (who responds at 3am)
└─ Metrics and KPIs (measure effectiveness)

Staffing:
├─ Tier 1: Alert triage, basic investigation
├─ Tier 2: Deep technical analysis, threat hunting
├─ Tier 3: Incident Response (IR team)
├─ Manager: Shift oversight, escalations
└─ Analyst Specialists: Malware, cloud, threat intel
```

---

## 📅 Typical SOC Day (Tier 1 Analyst)

### 6:00 AM - Shift Starts

```
Morning Standup (5 min)
├─ Previous shift summary (what happened overnight)
├─ Known incidents from yesterday (still ongoing?)
├─ Tool outages or maintenance windows
├─ Staffing changes (who's oncall)
└─ Day's priorities

Setup (10 min)
├─ Check email for overnight escalations
├─ Review alert queue
├─ Dashboard check (any spiking metrics)
└─ Coffee (essential)
```

### 6:30 AM - Alert Triage Begins

```
Alert Assessment Process:

1. Look at the alert
   ├─ What triggered it?
   ├─ What host/user is involved?
   ├─ When did it fire?
   └─ What's the severity?

2. Initial validation
   ├─ Is this a known false positive?
   ├─ Is this part of scheduled maintenance?
   ├─ Can I quickly rule it out?
   └─ Do I need more data?

3. Evidence gathering
   ├─ Pull logs from SIEM
   ├─ Check asset management (is this host expected?)
   ├─ Review user context (this user = normal?)
   ├─ Check for related alerts (part of larger attack?)
   └─ Timeline reconstruction

4. Decision
   ├─ True Positive → Escalate to Tier 2
   ├─ False Positive → Close, update rule
   ├─ Suspicious but not clear → Tag for Tier 2 review
   └─ Informational → Log and close
```

### Sample Alert Triage (9:15 AM)

```
Alert: "SQL Injection Attempt Detected"
Severity: HIGH
Timestamp: 2024-01-15 09:12:00 UTC
Source: 192.168.1.45 (John's Laptop)
Target: 192.168.100.50 (Internal Database)
Payload: GET /admin.php?id=1 UNION SELECT

TRIAGE STEPS:

1. Is this real SQL injection?
   └─ Check raw HTTP logs → payload is: id=1 UNION SELECT username,password FROM users
   └─ Decision: This looks like real SQL injection attempt

2. Who is the source?
   └─ Asset check: 192.168.1.45 = John Doe (Finance Department)
   └─ Context: John is not a developer, shouldn't be attacking databases

3. Is this intentional?
   └─ Check John's activity history: no history of SQL injection attempts
   └─ Check if John is testing something: not in test plan
   └─ Decision: Likely not intentional, possibly compromised system

4. Escalation decision
   └─ TRUE POSITIVE
   └─ Escalate to Tier 2 for further investigation
   └─ Create ticket: "Possible SQL Injection from Finance Host"

RESULT: Alert escalated at 09:18:00
```

### 10:00 AM - Investigation Deep Dive (Mixed)

```
Investigating 6 Alerts from Triage:

Alert 1: "PowerShell Obfuscated Command"
├─ Quick check → This is admin maintenance script (scheduled)
├─ Decision: False Positive (update rule whitelist)
├─ Time: 5 minutes

Alert 2: "Multiple Failed RDP Attempts"
├─ Source: External IP (China region)
├─ Target: 10 accounts
├─ Time window: 5 minutes with 150+ failures
├─ Decision: Brute force attack (block IP, watch for compromise)
├─ Escalate: Yes, potential breach
├─ Time: 15 minutes

Alert 3: "Unusual Outbound DNS Query"
├─ Query: xjkqmvnpqwertycvbnm.com (random-looking)
├─ Source: 192.168.1.88 (marketing workstation)
├─ Frequency: 50+ queries in 5 minutes (DGA pattern)
├─ Decision: Likely malware C2 (high confidence)
├─ Escalate: Yes, immediate
├─ Time: 20 minutes

Alerts 4-6: Benign (false positives, informational, known good)
├─ Time: 10 minutes total
```

### 11:00 AM - Documentation & Handoff

```
Ticket Updates (per escalated alert):

Ticket #5847: SQL Injection from Finance Host
├─ Status: Escalated to Tier 2
├─ Summary: Analyst identified potential SQL injection attempt
├─ Evidence:
│  ├─ Alert triggered at 09:12:00 UTC
│  ├─ Payload: UNION SELECT query (standard SQLi pattern)
│  ├─ Source host: John Doe's laptop (Finance Dept)
│  └─ No prior history of such behavior
├─ Recommendation: Isolate host, check for malware
└─ Assigned to: Senior Analyst (Tier 2)

Ticket #5848: RDP Brute Force from China
├─ Status: Escalated to Incident Response
├─ Severity: CRITICAL
├─ Evidence:
│  ├─ 150+ failed RDP attempts in 5 minutes
│  ├─ Source: 202.28.x.x (China)
│  ├─ Targets: 10 different admin accounts
│  └─ Timeline: 10:45-10:50 UTC
├─ Action: Firewall rule deployed (block China IPs on RDP port)
├─ Recommendation: Check for successful RDP logins in last 24h
└─ Assigned to: Incident Response On-Call

Ticket #5849: DGA DNS Queries (Malware C2)
├─ Status: Escalated to Incident Response
├─ Severity: CRITICAL
├─ Evidence:
│  ├─ Host: 192.168.1.88 (Marketing workstation)
│  ├─ Queries: 50+ to random-looking domains (.com/.net/.info)
│  ├─ Pattern matches: DGA malware (high confidence)
│  └─ Confidence: 95%
├─ Action: Isolate host from network
├─ Recommendation: Memory capture, disk forensics, malware analysis
└─ Assigned to: Incident Response On-Call
```

### 12:00 PM - Mid-Shift Status

```
Metrics by 12:00 PM:
├─ Alerts processed: 34
├─ True positives: 3
├─ False positives: 27
├─ Suspicious (pending review): 4
├─ Mean time to triage: 8 minutes
└─ Escalations: 2 (critical)

Alert queue size: 12 (manageable)
Tickets waiting for Tier 2: 6
Critical incidents: 2 (oncall team engaged)
```

### 1:00 PM - 3:00 PM: Routine Work

```
Afternoon Tasks:

Threat Intel Updates (30 min)
├─ New malware hashes from threat feed
├─ New C2 domains to blocklist
├─ Update YARA rules for detection

Dashboard Review (30 min)
├─ Monitor escalated incidents (check status)
├─ Review trending alerts (pattern analysis)
├─ Check metrics (are we meeting SLA?)

Alert Processing (90 min)
├─ Continue triage of new alerts
├─ Document findings
├─ Close/escalate as appropriate

Lunch (45 min)
```

### 4:00 PM - 6:00 PM: Deep Work

```
Pending Investigations:

Ticket #5847 Update (SQL Injection) - Tier 2 Response
├─ Tier 2 analyst confirms: Host is compromised
├─ Malware family identified: Emotet banking trojan
├─ Scope: SQL injection tool found in C:\Users\John\AppData
├─ Lateral movement: Attempts to dump database credentials
├─ Status: Host isolated, forensics in progress
├─ Next: Memory dump analysis, timeline reconstruction

Ticket #5848 Update (RDP Brute Force) - IR Response
├─ Found: 1 successful RDP login from attacker IP
├─ Timestamp: 2024-01-14 23:47:00 (during night shift)
├─ Account: Administrator (compromised)
├─ Risk: Admin access to entire network
├─ Status: Password reset, all RDP sessions terminated
├─ Next: Hunt for lateral movement from this account

Ticket #5849 Update (DGA Malware) - IR Response
├─ Host isolated successfully
├─ Malware identified: LockBit ransomware (dropper)
├─ Status: Ransomware did NOT execute (caught in time)
├─ Memory dump captured for analysis
├─ Next: Full forensics, scope determination
├─ Estimated time to clean: 24-48 hours
```

### 6:00 PM - Shift End

```
End of Shift Handoff:

Tickets Summary for Night Shift:
├─ 34 alerts processed
├─ 3 true positives escalated
├─ 2 critical incidents (active, IR engaged)
├─ 1 high-priority threat hunt (DGA/ransomware)
└─ 1 medium-priority forensics (SQL injection/trojan)

Night Shift Priorities:
├─ Monitor Ticket #5849 (ransomware escalation)
├─ Check for lateral movement from compromised admin account
├─ Monitor alert queue (should be quiet at night)
├─ Oncall IR team is engaged (they handle escalations)
└─ Wake up day shift if CRITICAL alert fires

Outstanding items:
├─ 3 tickets awaiting Tier 2 analysis
├─ 2 incidents in active response
└─ All assets patched? Check overnight
```

---

## 🛠️ SOC Tools

### Monitoring & Alerting

```
SIEM Platform (Splunk, Elastic, ArcSight)
├─ Ingest logs from all sources
├─ Run detection rules
├─ Display alerts on dashboard
├─ Full-text search across all events
└─ Alert context (related events, timeline)

Ticketing System (Jira, ServiceNow, Demisto)
├─ Track every alert and investigation
├─ Assign work to analysts
├─ Add evidence and notes
├─ SLA tracking (how fast did we respond?)
└─ Post-incident reporting
```

### Investigation Tools

```
Playbooks (canned response procedures)
├─ SQL Injection playbook: what to check
├─ Malware playbook: investigation steps
├─ Ransomware playbook: immediate actions
└─ Lateral movement playbook: scope hunt

Dashboards (real-time visualization)
├─ Alert trending (spike detection)
├─ Mean time to respond (MTTR)
├─ False positive ratio
├─ Detection coverage by TTP
└─ Oncall availability
```

---

## 📊 SOC Metrics

```
Mean Time To Respond (MTTR)
├─ Time from alert to first investigation action
├─ Target: < 15 minutes for critical
├─ Target: < 1 hour for high
└─ Target: < 4 hours for medium

Mean Time To Detect (MTTD)
├─ Time from attack start to detection
├─ Industry average: 207 days (too long!)
├─ Target: < 24 hours for advanced teams
└─ Depends on rule coverage

False Positive Ratio
├─ % of alerts that are not real incidents
├─ High ratio = analyst fatigue, slower response
├─ Target: < 10% false positives
├─ Too strict rules miss attacks
├─ Too loose rules = alert fatigue

Alert Volume
├─ Total alerts per day
├─ Manageable range: 50-200 per analyst per day
├─ > 500/day = analyst can't keep up
├─ < 50/day = rules may be too strict

Escalation Rate
├─ % of alerts escalated to higher tier
├─ Target: 5-15% escalation rate
├─ Too high = rules generating noise
├─ Too low = analysts not catching real incidents
```

---

## 🔑 Key Takeaways

- **Tier 1 analysts are the filter** - they decide what reaches IR
- **Triage speed is critical** - alert fatigue kills detection
- **Context is everything** - know the asset, know the user, know what's normal
- **Escalation is not failure** - it's showing good judgment
- **Documentation matters** - every step goes in the ticket
- **False positives kill alerts** - tune rules, don't just ignore

---

## 📚 Resources

- [NIST SOC Best Practices](https://www.nist.gov/publications)
- [SOC Metrics Framework](https://www.gartner.com/document/3977564)

---

## [⬅️ Day 060](../day060/) | [➡️ Day 062](../day062/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*