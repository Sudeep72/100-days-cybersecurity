# Day 055 - Incident Response: The 6-Phase Process

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Detection is the beginning, not the end.

The moment you identify a security incident, the clock starts. Every second costs - data stolen, systems compromised, attackers entrenching themselves deeper.

Incident Response (IR) is the structured process for containing, investigating, and recovering from security breaches.

A well-run IR process turns chaos into control.

---

## 🔄 The 6 Phases

```
1. PREPARATION       → Tools, people, processes ready before incident
2. DETECTION         → Alert fires, anomaly spotted
3. ANALYSIS          → Understand the attack, scope, impact
4. CONTAINMENT       → Stop the attack, isolate affected systems
5. ERADICATION       → Remove attacker access, patch vulnerabilities
6. RECOVERY          → Restore systems, lessons learned
```

---

## 1️⃣ Preparation

**Before** an incident occurs:

```
IR Team Structure
├─ Incident Commander (IC)
├─ Detection Lead
├─ Analysis Lead
├─ Response Lead
├─ Communications Lead
└─ Forensics Lead

Essential Tools
├─ Incident ticketing (Jira, ServiceNow)
├─ Secure comms (Slack, encrypted chat)
├─ Forensic tools (Volatility, EnCase)
├─ SIEM with fast search
├─ Network isolation capability
└─ Golden image backups

Playbooks
├─ Alert triage decision tree
├─ Severity definitions
├─ Communication templates
├─ Escalation procedures
├─ Backup/recovery procedures
└─ Regulatory notification requirements
```

---

## 2️⃣ Detection (Minute 0-15)

An alert fires. Someone reports suspicious activity.

**Initial Triage:**
```
Is this real?
  → Look for supporting evidence
  → Check for false positives

What's the severity?
  → Data breach? Ransomware? Insider threat?
  
What's the scope?
  → Single host? Entire network?
  → How many users/systems?
```

**First Hour Actions:**
- Open incident ticket
- Isolate the alert in SIEM
- Interview reporter / affected user
- Pull related logs
- Preserve evidence (don't restart systems)
- Activate incident commander

---

## 3️⃣ Analysis (Hour 1-24)

Deep dive into what happened.

```
Timeline Construction
  ├─ First compromise (often weeks before detection)
  ├─ Lateral movement through network
  ├─ Data accessed or stolen
  ├─ Detection point
  └─ Current attacker status

Scope Determination
  ├─ Which systems compromised?
  ├─ Which accounts accessed?
  ├─ What data was exposed?
  ├─ Is attacker still active?
  └─ Secondary backdoors?

Evidence Collection
  ├─ Memory dumps (before shutdown)
  ├─ Forensic disk images
  ├─ Network traffic (pcaps, flows)
  ├─ All relevant logs
  └─ Chain of custody documentation
```

---

## 4️⃣ Containment (Hour 2-12)

Stop the attack. Prevent escalation.

```
Immediate Actions
├─ Isolate affected systems (preserve evidence first)
├─ Disable compromised accounts
├─ Block known C2 IPs (firewall rules)
├─ Revoke API keys and tokens
└─ Check for persistence mechanisms

Short-term Containment
├─ Emergency vulnerability patch
├─ Force password resets
├─ Restrict outbound connections
├─ Monitor for lateral movement
└─ Implement network segmentation

Validation
├─ No new compromises detected
├─ Attacker C2 connections blocked
├─ All known backdoors removed
└─ Increased monitoring confirmed
```

---

## 5️⃣ Eradication (Day 1-7)

Remove the attacker completely.

```
Remove Attacker Access
├─ Delete malware and payloads
├─ Close all backdoors
├─ Remove persistence mechanisms
├─ Verify with multiple scanners
└─ Kernel-level inspection

Rebuild Systems
├─ Restore from clean backups (pre-compromise)
├─ Fresh OS installation
├─ Apply all security patches
├─ Restore data from verified clean sources
└─ Validate functionality

Verification
├─ Multiple malware scanners clean
├─ Full vulnerability scan
├─ EDR/AV reports clean
├─ No IOCs in logs
└─ Network segmentation validated
```

---

## 6️⃣ Recovery & Learning (Week 1+)

Restore to normal. Learn. Improve.

```
System Recovery
├─ Gradually bring systems online
├─ Restore applications and data
├─ Continuous monitoring
└─ Watch for recompromise indicators

User Notification
├─ Breach notification (required by law)
├─ Affected user communications
├─ Credit monitoring (if PII exposed)
└─ Status updates

Regulatory Response
├─ Notify regulators (GDPR, HIPAA, state laws)
├─ Work with legal counsel
├─ Report to law enforcement (FBI/Secret Service)
├─ Preserve evidence
└─ Document for potential litigation

Post-Incident Review (2 weeks later)
├─ Timeline validation
├─ Root cause analysis
├─ Detection gap analysis
├─ Control recommendations
├─ Playbook updates
└─ Team debriefing

Lessons Learned
├─ New SIEM detection rules
├─ Patch vulnerabilities org-wide
├─ Security training updates
├─ IR playbook improvements
└─ Threat intelligence sharing
```

---

## 📊 Incident Severity Levels

```
CRITICAL (P1)           HIGH (P2)               MEDIUM (P3)
─────────────           ────────               ───────────
Ransomware              Confirmed breach       Suspicious activity
Nation-state APT        Malware on critical    Brute force attempts
Mass data exfil         Privilege escalation   Policy violation
Production down         Limited scope          Single host
Customer data exposed   Potential exposure     Non-critical system
```

---

## 🛠️ IR Team Roles

| Role | Responsibility |
|------|----------------|
| **IC (Incident Commander)** | Overall coordination, decisions, status updates |
| **Detection Lead** | Alert triage, validate incident, initial scope |
| **Analysis Lead** | Timeline, root cause, IOC extraction |
| **Response Lead** | Containment, isolation, remediation execution |
| **Communications** | Management, customers, law enforcement, press |
| **Forensics** | Evidence collection, preservation, investigation |

---

## 📈 Key Metrics

```
MTTD (Mean Time To Detect)
  → Target: < 1 hour for critical systems

MTTR (Mean Time To Respond)
  → Time to containment after detection
  → Target: < 2 hours

MTTRE (Mean Time To Root Cause)
  → Understand what happened
  → Target: < 24 hours

Cost Per Incident
  → Justifies prevention investment
```

---

## 🔑 Key Takeaways

- **Preparation is everything** - IR starts before the incident
- **Speed matters** - containment time directly impacts damage
- **Evidence preservation is critical** - capture logs before containment
- **Communicate constantly** - management and legal stay informed
- **Document everything** - for legal, learning, and future incidents
- **Post-incident review drives improvement** - turn incidents into controls

---

## 📚 Resources

- [NIST IR Framework](https://www.nist.gov/cyberframework)
- [Volatility Memory Analysis](https://www.volatilityfoundation.org/)
- [SANS IR Handling](https://www.sans.org/)

---

## [⬅️ Day 054](../day054/) | [➡️ Day 056](../day056/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*