# Day 064 - Security Metrics: What to Measure & Why

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

You can't improve what you don't measure.

Security metrics are how you track whether your defenses are actually working.

Without metrics, you're flying blind - you don't know if your investment in tools/people/processes is paying off.

**Security metrics answer:**
- How fast are we detecting attacks?
- How many attacks are we missing?
- Is alert fatigue increasing or decreasing?
- Are we improving year-over-year?
- Where should we invest next?

---

## 📊 Three Types of Metrics

### 1. Detection Metrics (Speed & Coverage)

```
MTTD - Mean Time To Detect
├─ Question: How long from attack start to detection?
├─ Industry average: 207 days (too slow)
├─ Target: < 24 hours
├─ How to measure:
│  ├─ Look at incident timeline: when did attacker start?
│  ├─ Compare to alert timestamp: when were we alerted?
│  └─ Difference = MTTD
│
└─ Why it matters:
   ├─ Every day of undetected compromise = attacker moving laterally
   ├─ 30 days = attacker has domain admin
   ├─ 60 days = attacker has deleted backups
   └─ Early detection = limited damage

Detection Coverage
├─ Question: What % of attacks are we catching?
├─ Metric: True Positive Rate
│  ├─ (Real incidents detected) / (all real incidents)
│  └─ Target: > 90%
│
├─ How to measure:
│  ├─ Run red team exercises (simulated attacks)
│  ├─ See what % were detected
│  └─ Missing ones = coverage gaps
│
└─ Why it matters:
   ├─ 10 attacks per month
   ├─ If detecting 80%, missing 2
   ├─ Those 2 could be the ransomware
   └─ Coverage gaps are where breaches happen
```

### 2. Response Metrics (Speed & Efficiency)

```
MTTR - Mean Time To Respond
├─ Question: How long from detection to first response action?
├─ Industry benchmark: 15-30 minutes for critical
├─ How to measure:
│  ├─ Alert timestamp
│  ├─ First investigation action timestamp
│  └─ Difference = MTTR
│
└─ Why it matters:
   ├─ 30 seconds faster = attacker has less time to escalate
   ├─ 5 minute response = can block before lateral movement
   ├─ 1 hour response = attacker already on 5 other systems
   └─ Response speed = containment success

MTTRE - Mean Time To Root Cause
├─ Question: How long to understand what happened?
├─ Target: < 24 hours for critical incidents
├─ How to measure:
│  ├─ Alert timestamp
│  ├─ Root cause analysis complete timestamp
│  └─ Difference = MTTRE
│
└─ Why it matters:
   ├─ Understand attack = prevent recurrence
   ├─ Identify patient zero = scope the breach
   ├─ Find all entry points = prevent reinfection
   └─ Root cause awareness = improvement decisions

False Positive Rate
├─ Question: What % of alerts are not real incidents?
├─ Target: 5-15% false positive rate
├─ How to measure:
│  ├─ Close alerts manually: are they real?
│  ├─ Calculate (closed as false positive) / (total alerts)
│  └─ % = false positive rate
│
├─ Too high (> 30%):
│  ├─ Alert fatigue (analysts stop trusting alerts)
│  ├─ Slower response time
│  └─ Real incidents missed
│
└─ Too low (< 5%):
   ├─ Rules might be too strict
   ├─ Missing real attacks (coverage gap)
   └─ Need to add more detection rules
```

### 3. Business Metrics (Cost & Impact)

```
Cost Per Incident
├─ Question: How much does each security incident cost?
├─ Includes:
│  ├─ IR team labor (hours × rate)
│  ├─ Forensic analysis
│  ├─ Downtime (lost revenue)
│  ├─ Regulatory fines (GDPR, HIPAA, state laws)
│  ├─ Notification costs (call customers)
│  ├─ Reputation damage (lost business)
│  └─ Remediation (patching, rebuilding systems)
│
├─ Industry average: $4.5M per incident (includes breach notification)
├─ Ransomware average: $18.4M per incident
│
└─ Why it matters:
   ├─ Justifies SOC investment ("$2M/year SOC saves $18M/incident")
   ├─ Shows ROI of detection tools
   ├─ Proves faster response = less cost
   └─ Drives funding for security improvements

Incidents Prevented (Red Team Testing)
├─ Question: How many attacks would have succeeded before detection?
├─ How to measure:
│  ├─ Run red team exercise (simulated breach)
│  ├─ See where our detection would have caught it
│  ├─ Calculate "cost of breach if undetected" vs. "what we caught"
│  └─ Prevented cost = defense value
│
└─ Why it matters:
   ├─ Shows detection value in business terms
   ├─ "Our SIEM prevented a $10M breach last month"
   └─ Justifies continued investment

Risk Score / Security Posture
├─ Question: Are we getting better or worse?
├─ Metrics:
│  ├─ CVSS score of unpatched vulnerabilities
│  ├─ % of systems with EDR
│  ├─ % of users with MFA
│  ├─ % of critical systems with network segmentation
│  ├─ % of cloud resources with least privilege
│  └─ Combined = security posture score
│
└─ Why it matters:
   ├─ Track year-over-year improvement
   ├─ Measure control effectiveness
   ├─ Show board-level progress
   └─ Guide investment decisions
```

---

## 📈 Dashboard Examples

### SOC Tier 1 Analyst Dashboard

```
Today's Metrics:
├─ Alerts processed: 87
├─ Closed as FP: 74 (85%)
├─ Escalated: 13 (15%)
├─ Mean triage time: 6.2 minutes
├─ Critical alerts this shift: 0
└─ SLA violations: 0

This Week:
├─ Average daily alerts: 92
├─ Average escalation rate: 12%
├─ MTTR (median): 8.3 minutes
├─ Analyst utilization: 78%
└─ False positive trend: ↓ (improving)

This Month:
├─ Total alerts: 2,847
├─ True positives: 267
├─ Detection coverage: 89%
├─ Incident response handoffs: 267
└─ Training hours per analyst: 4
```

### Security Leadership Dashboard

```
This Quarter:
├─ Incidents detected: 23
├─ Incidents prevented (red team): 8
├─ MTTD (average): 18 hours
├─ MTTR (average): 23 minutes
├─ Cost saved (prevented incidents): $14.2M
├─ Security tools ROI: 7.1x (investment vs. breach cost)

This Year:
├─ Security posture score: 72/100 (up from 61 last year)
├─ EDR coverage: 98% of endpoints
├─ MFA adoption: 94% of users
├─ Vulnerability patch time: 14 days (target: 30)
├─ Budget spent: $4.2M
└─ Expected breach cost if undetected: $12.5M

Risk Trends:
├─ Critical vulnerabilities: 3 (down from 12 last quarter)
├─ High-risk cloud misconfigs: 47 (down from 89)
├─ Phishing click rate: 3.2% (down from 5.1%)
└─ Overall risk posture: ↓ IMPROVING
```

---

## 🎯 Metrics by Audience

### For IT Security (Practitioners)

```
What they care about:
├─ MTTD (are we catching attacks fast?)
├─ False positive rate (am I wasting time?)
├─ Alert queue size (am I drowning?)
├─ Tool uptime (is my SIEM running?)
└─ Detection coverage gaps (what are we missing?)

Key metrics:
├─ Alert volume per analyst
├─ Escalation rate
├─ Tool performance (latency, false positives)
├─ Coverage by TTP (which attacks do we detect?)
└─ Oncall page frequency (am I getting paged too much?)
```

### For Security Leadership (CISOs)

```
What they care about:
├─ Risk reduction (are we safer?)
├─ Cost of incidents (what's the financial impact?)
├─ Regulatory compliance (can we pass audits?)
├─ Team efficiency (are people productive?)
└─ Board reporting (what do I tell executives?)

Key metrics:
├─ MTTD, MTTR, MTTRE (speed metrics)
├─ Cost per incident vs. prevention cost
├─ Security posture score (year-over-year)
├─ Incident trends (more or fewer?)
└─ Tool ROI (are expensive tools worth it?)
```

### For Board / Executives

```
What they care about:
├─ Risk to business (can we lose money?)
├─ Regulatory risk (will we get fined?)
├─ Reputation risk (will customers leave?)
├─ Budget ROI (is security worth the spend?)
└─ Board liability (are we covered?)

Key metrics:
├─ Incidents prevented (value delivered)
├─ Cost avoided (cost of undetected breach)
├─ Year-over-year risk reduction
├─ Budget vs. industry benchmarks
└─ Insurance premium impact
```

---

## 🔧 How to Implement Metrics

### Step 1: Define What Matters

```
Questions to ask:
├─ What are our biggest risks? (ransomware, data breach, DDoS?)
├─ What would a breach cost? (regulatory + reputation + downtime)
├─ How would we know we're improving?
└─ What would success look like?

Example:
├─ Risk: Ransomware (costs $18M if undetected)
├─ Success: Detect before encryption (within 30 minutes of access)
├─ Metrics: MTTD for file access anomalies, shadow copy deletion alerts
└─ Target: 99% of ransomware-stage attacks detected in < 30 min
```

### Step 2: Collect Data

```
Sources:
├─ SIEM logs (alert timestamps, investigation times)
├─ Ticketing system (incident creation time, closure time)
├─ EDR (malware detection time, response time)
├─ Firewall (connection attempts, blocked connections)
├─ User feedback (analyst time spent, frustration points)
└─ Red team exercises (attack detection points)

Automation:
├─ Splunk queries (calculate MTTD from log timestamps)
├─ API integrations (pull data from SIEM, ticketing, EDR)
├─ Daily/weekly metric collection (consistent data)
└─ Dashboard auto-update (fresh metrics always available)
```

### Step 3: Report & Iterate

```
Frequency:
├─ Daily: Analyst-level (alert volume, FP rate, queue size)
├─ Weekly: Team-level (MTTR, escalations, coverage gaps)
├─ Monthly: Leadership-level (cost, posture, trends)
├─ Quarterly: Board-level (risk reduction, ROI, strategy)

Use metrics to:
├─ Identify bottlenecks (why is MTTR slow?)
├─ Prioritize improvements (which detection rules add value?)
├─ Justify investments (cost-benefit of new tools)
├─ Celebrate wins (we improved MTTD by 40%!)
└─ Drive accountability (teams own their metrics)
```

---

## 🔑 Key Takeaways

- **Measure MTTD first** - fastest path to value
- **False positive rate drives everything** - too high = alert fatigue, too low = missing attacks
- **MTTR is speed to contain** - faster containment = less damage
- **Business metrics justify budget** - security leaders need to speak CFO language
- **Trend matters more than absolute** - are we improving or degrading?
- **Metrics drive behavior** - what you measure is what gets done

---

## 📚 Resources

- [NIST Cybersecurity Metrics](https://www.nist.gov/publications)
- [Forrester Security Metrics Guide](https://www.forrester.com/)
- [Gartner Security Metrics](https://www.gartner.com/)

---

## [⬅️ Day 063](../day063/) | [➡️ Day 065](../day065/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*