# Day 049 - SIEM Architecture: How It All Fits Together

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Splunk is a SIEM. But what is a SIEM really - and how does it actually work at enterprise scale?

SIEM stands for Security Information and Event Management. It's the central nervous system of a modern SOC - collecting, normalising, correlating, and alerting on security events from across the entire environment.

Understanding SIEM architecture helps you design better detection, understand why alerts fire, and explain to employers how you think about security at scale.

---

## 🏗️ SIEM Architecture

```
Data Sources
├── Endpoints          (Windows logs, Sysmon, EDR)
├── Network devices    (Firewalls, IDS/IPS, switches)
├── Applications       (Web servers, databases, apps)
├── Cloud              (AWS CloudTrail, Azure AD, GCP)
└── Identity           (Active Directory, Okta, SSO)
         ↓
Log Collection Layer
├── Agents             (Splunk UF, Elastic Agent, Syslog)
├── Syslog             (UDP/TCP 514)
├── API pulls          (Cloud logs, SaaS platforms)
└── Streaming          (Kafka, Kinesis)
         ↓
Normalisation / Parsing
├── Field extraction   (parse raw text into structured fields)
├── Common schema      (map different log formats to same field names)
└── Enrichment         (add GeoIP, threat intel, asset context)
         ↓
Correlation Engine
├── Rule-based         (if X AND Y within Z minutes → alert)
├── Statistical        (anomaly vs baseline)
├── ML-based           (clustering, sequence models)
└── Threat intel       (match IOCs against ingested data)
         ↓
Alert Management
├── Triage             (filter noise, prioritise)
├── Case management    (ticket creation, assignment)
├── Playbooks          (automated response steps)
└── Escalation         (severity-based routing)
         ↓
SOC Analyst
├── Investigation      (query logs, pivot on indicators)
├── Containment        (block IP, isolate host)
└── Reporting          (document findings, metrics)
```

---

## 📥 Log Collection Methods

### Agent-Based Collection

Software agent installed on each host - ships logs to SIEM.

```
Advantages:
→ Reliable delivery (buffers locally if network drops)
→ Local filtering (reduce noise before shipping)
→ Encrypted transport
→ Can collect logs the OS doesn't send via syslog

Examples:
→ Splunk Universal Forwarder (UF)
→ Elastic Agent / Beats
→ Cribl Edge
→ NXLog
```

### Syslog

Industry-standard protocol. Devices send logs to a central syslog server.

```
UDP 514  → fast, no delivery guarantee (fire-and-forget)
TCP 514  → reliable delivery
TCP 6514 → TLS encrypted syslog

Devices that use syslog: firewalls, switches, routers, printers, IoT
Linux systems: rsyslog, syslog-ng
```

### API Polling

SIEM queries cloud/SaaS APIs on a schedule to pull logs.

```
AWS CloudTrail → S3 bucket → SIEM pulls from S3
Microsoft 365  → Microsoft Graph API → SIEM polls
Okta           → Okta API → SIEM polls system log
GitHub         → Audit log API
Slack          → Audit logs API
```

### Streaming

High-volume logs sent via message queue.

```
Kafka → handles millions of events/second
Kinesis → AWS-native streaming
→ SIEM consumes from the queue
→ Better than direct ingestion for very high volumes
```

---

## 🔄 Normalisation - Why It Matters

Different devices log the same event differently:

```
Linux auth.log:
"Failed password for root from 10.0.0.5 port 22 ssh2"

Windows Event 4625:
Account: root
Source: 10.0.0.5
Protocol: SSH

Cisco ASA firewall:
%ASA-6-302015: Built inbound TCP connection for faddr 10.0.0.5/22

After normalisation → all become:
{
  "event_type": "authentication_failure",
  "user": "root",
  "src_ip": "10.0.0.5",
  "dest_port": 22,
  "protocol": "SSH",
  "timestamp": "2024-01-15T10:23:45Z"
}
```

Now one detection rule catches brute force across all three sources.

**Common schemas:**
- OCSF (Open Cybersecurity Schema Framework) - vendor-neutral
- Elastic Common Schema (ECS) - used by Elastic stack
- Splunk CIM (Common Information Model) - used by Splunk

---

## 🔗 Correlation - Finding Attacks Across Events

Single events rarely tell the full story. Correlation links related events into an attack sequence.

**Example - Detecting Lateral Movement:**

```
Event 1: 4625 (failed login) from 10.0.0.5 to 192.168.1.10
Event 2: 4625 (failed login) from 10.0.0.5 to 192.168.1.11
Event 3: 4625 (failed login) from 10.0.0.5 to 192.168.1.12
Event 4: 4624 (successful login) from 10.0.0.5 to 192.168.1.13
Event 5: 4688 (process created) - cmd.exe → powershell.exe (on 192.168.1.13)

Individually: unremarkable
Correlated: password spray → compromise → execution chain
```

**Correlation rule in pseudo-SPL:**
```spl
index=windows EventCode IN (4624, 4625)
| bucket _time span=5m
| stats dc(dest) as targets_hit
        count(eval(EventCode=4625)) as failures
        count(eval(EventCode=4624)) as successes by _time, src_ip
| where targets_hit > 5 AND successes > 0
| eval alert="Lateral Movement - Password Spray Success"
```

---

## 📊 SIEM Tiers - What's Actually Available

| Tier | Examples | Cost | Scale |
|------|---------|------|-------|
| Enterprise | Splunk, IBM QRadar, Microsoft Sentinel | $$$$ | Unlimited |
| Mid-market | LogRhythm, Exabeam, Securonix | $$$ | Large |
| Open Source | Elastic Stack (ELK), Wazuh, Graylog | Free-$ | Medium |
| Cloud-native | Microsoft Sentinel, Chronicle, Panther | Pay-per-GB | Any |

**For home lab / learning:**
- **Wazuh** - full SIEM + EDR, completely free
- **Elastic Stack** - Elasticsearch + Kibana + Logstash, free tier
- **Graylog** - open source, easier setup than ELK

---

## 🎯 SIEM Maturity Model

```
Level 1 - Collection
  All critical log sources ingested
  Basic storage and search working

Level 2 - Detection
  Core detection rules running
  Alerts firing for known-bad patterns

Level 3 - Correlation
  Multi-event rules catching attack chains
  Threat intel integration
  Asset and identity context enrichment

Level 4 - Response
  Automated playbooks for common alerts
  SOAR integration (automated containment)
  SLA tracking for MTTD/MTTR

Level 5 - Intelligence
  ML-based anomaly detection
  Custom threat hunting queries
  Continuous rule tuning and improvement
```

Most organisations operate at Level 1-2. Level 3+ is where sophisticated detection happens.

---

## 🔑 Key Takeaways

- SIEM is the central nervous system of a SOC - collect, normalise, correlate, alert
- Normalisation is what makes cross-source detection possible - same schema, different sources
- Correlation is where the real value is - single events mislead, sequences reveal
- Most organisations are at maturity Level 1-2 - getting to Level 3 is a significant step
- Open source SIEMs (Wazuh, ELK) are viable for learning and small environments
- The SIEM is only as good as the log sources feeding it - garbage in, garbage out

---

## 📚 Resources
- [Wazuh - free open source SIEM](https://wazuh.com/)
- [Elastic Stack - free tier](https://www.elastic.co/elastic-stack)
- [Microsoft Sentinel - free trial](https://azure.microsoft.com/en-us/products/microsoft-sentinel/)
- [OCSF - Open Cybersecurity Schema Framework](https://schema.ocsf.io/)

---

## [⬅️ Day 048](../day048/) | [➡️ Day 050](../day050/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*