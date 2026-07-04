# Day 062 - Building an Automated Alert Triage Tool

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate-Advanced

---

## 🧠 The Concept

A SOC analyst can't process 500 alerts per day manually.

So we automate the easy decisions.

**Alert triage automation** uses rules and context to:
- Filter obvious false positives
- Auto-escalate high-confidence threats
- Enrich alerts with context (host info, user info, threat intel)
- Suggest response actions
- Reduce analyst toil by 60-80%

---

## 🎯 Triage Decision Tree

```
Alert Fires
    ↓
1. Is it a KNOWN FALSE POSITIVE?
    ├─ Yes → Close with reason
    └─ No → Continue
    ↓
2. Is it during SCHEDULED MAINTENANCE?
    ├─ Yes → Close with reason
    └─ No → Continue
    ↓
3. Is source/destination WHITELISTED?
    ├─ Yes → Close
    └─ No → Continue
    ↓
4. SEVERITY ASSESSMENT
    ├─ Critical (needs immediate IR) → ESCALATE
    ├─ High (needs human review) → ESCALATE
    ├─ Medium (gather context, auto-triage) → INVESTIGATE
    └─ Low (likely false positive) → CLOSE
    ↓
5. Context enrichment
    ├─ Host reputation
    ├─ User activity history
    ├─ Threat intelligence match
    └─ Related alerts in last 24h
    ↓
6. Final decision
    ├─ High confidence escalation → Create ticket
    ├─ Suspicious but unclear → Add to hunt queue
    └─ False positive → Close
```

---

## 💻 The Code - Automated Alert Triage

```python
"""
Day 062 - Automated Alert Triage Tool
100 Days of Cybersecurity by Sudeep Ravichandran

Automatically triages security alerts:
  - Filters false positives
  - Enriches with context
  - Scores risk
  - Routes to appropriate response

Input: Alert from SIEM (JSON)
Output: Triage decision + escalation ticket
"""

import json
import requests
from datetime import datetime
from typing import Dict, List, Tuple

class AlertTriager:
    def __init__(self, config: Dict):
        self.config = config
        self.whitelist = config.get("whitelist_ips", [])
        self.known_fp = config.get("known_false_positives", [])
        self.scheduled_maintenance = config.get("maintenance_windows", [])
        self.threat_intel = {}  # Loaded from feeds
        self.host_db = {}  # Asset database
        self.user_db = {}  # User activity database

    def triage_alert(self, alert: Dict) -> Dict:
        """
        Main triage function.
        
        Input: Alert dict with fields:
          - rule_name
          - severity
          - source_ip
          - dest_ip
          - user_id
          - timestamp
          - payload
        """
        
        # Step 1: Check for known false positives
        if self._is_known_false_positive(alert):
            return {
                "decision": "CLOSE",
                "reason": "Known false positive",
                "confidence": 0.99,
                "escalate": False
            }
        
        # Step 2: Check if during scheduled maintenance
        if self._is_scheduled_maintenance(alert):
            return {
                "decision": "CLOSE",
                "reason": "During scheduled maintenance",
                "confidence": 0.95,
                "escalate": False
            }
        
        # Step 3: Check whitelist
        if self._is_whitelisted(alert):
            return {
                "decision": "CLOSE",
                "reason": "Source/dest is whitelisted",
                "confidence": 0.90,
                "escalate": False
            }
        
        # Step 4: Assess severity
        severity_score = self._calculate_severity(alert)
        
        # Step 5: Enrich with context
        context = self._enrich_alert(alert)
        alert.update(context)
        
        # Step 6: Calculate risk score
        risk_score = self._calculate_risk_score(alert, severity_score)
        
        # Step 7: Make decision
        decision = self._make_decision(alert, risk_score, severity_score)
        
        return decision

    def _is_known_false_positive(self, alert: Dict) -> bool:
        """Check if alert matches known false positive pattern."""
        rule_name = alert.get("rule_name", "").lower()
        
        for fp in self.known_fp:
            if fp["rule"] in rule_name and fp["match_condition"](alert):
                return True
        
        return False

    def _is_scheduled_maintenance(self, alert: Dict) -> bool:
        """Check if alert occurred during maintenance window."""
        alert_time = datetime.fromisoformat(alert.get("timestamp"))
        
        for window in self.scheduled_maintenance:
            start = datetime.fromisoformat(window["start"])
            end = datetime.fromisoformat(window["end"])
            
            if start <= alert_time <= end:
                return True
        
        return False

    def _is_whitelisted(self, alert: Dict) -> bool:
        """Check if source/dest is whitelisted."""
        src_ip = alert.get("source_ip")
        dst_ip = alert.get("dest_ip")
        
        return src_ip in self.whitelist or dst_ip in self.whitelist

    def _calculate_severity(self, alert: Dict) -> float:
        """
        Calculate severity score (0-1) based on rule and indicators.
        """
        severity_map = {
            "CRITICAL": 0.95,
            "HIGH": 0.75,
            "MEDIUM": 0.50,
            "LOW": 0.25
        }
        
        base_severity = severity_map.get(alert.get("severity", "MEDIUM"), 0.50)
        
        # Boost if multiple alerts from same source in short time
        alert_count = self._count_recent_alerts(
            alert.get("source_ip"),
            hours=1
        )
        
        if alert_count > 5:
            base_severity = min(1.0, base_severity + 0.2)
        
        return base_severity

    def _enrich_alert(self, alert: Dict) -> Dict:
        """Add context to alert."""
        enrichment = {}
        
        # Host reputation
        host = self.host_db.get(alert.get("source_ip"), {})
        enrichment["host_os"] = host.get("os")
        enrichment["host_owner"] = host.get("owner")
        enrichment["host_risk_score"] = host.get("risk_score", 0)
        
        # User history
        user = self.user_db.get(alert.get("user_id"), {})
        enrichment["user_department"] = user.get("department")
        enrichment["user_role"] = user.get("role")
        enrichment["user_login_hours"] = user.get("normal_hours")
        enrichment["is_off_hours"] = self._is_off_hours(
            alert.get("timestamp"),
            user.get("normal_hours", [9, 17])
        )
        
        # Threat intelligence
        threat_match = self._check_threat_intel(alert)
        enrichment["threat_intel_match"] = threat_match
        
        return enrichment

    def _calculate_risk_score(self, alert: Dict, severity: float) -> float:
        """
        Calculate overall risk (0-1) based on:
        - Severity
        - Context (host reputation, user role)
        - Threat intel matches
        """
        
        risk = severity  # Base on severity
        
        # Host risk factor
        risk += alert.get("host_risk_score", 0) * 0.1
        risk = min(1.0, risk)
        
        # User factor (off-hours access = higher risk)
        if alert.get("is_off_hours"):
            risk += 0.15
            risk = min(1.0, risk)
        
        # Threat intel match (if exists, high risk)
        if alert.get("threat_intel_match"):
            risk += 0.20
            risk = min(1.0, risk)
        
        # Lateral movement indicator (multiple targets)
        if self._detect_lateral_movement(alert):
            risk += 0.25
            risk = min(1.0, risk)
        
        return risk

    def _make_decision(self, alert: Dict, risk_score: float, severity: float) -> Dict:
        """
        Make triage decision based on risk and severity.
        """
        
        # CRITICAL: High severity + High risk
        if severity > 0.8 or risk_score > 0.85:
            return {
                "decision": "ESCALATE",
                "severity": "CRITICAL",
                "risk_score": risk_score,
                "escalate": True,
                "priority": 1,
                "suggested_action": "Immediate IR team engagement",
                "confidence": 0.95,
                "ticket_template": "critical_incident"
            }
        
        # HIGH: Moderate-high risk, needs review
        if severity > 0.6 or risk_score > 0.65:
            return {
                "decision": "ESCALATE",
                "severity": "HIGH",
                "risk_score": risk_score,
                "escalate": True,
                "priority": 2,
                "suggested_action": "Tier 2 analyst review + context gathering",
                "confidence": 0.85,
                "ticket_template": "escalation"
            }
        
        # MEDIUM: Investigate but not immediately escalate
        if severity > 0.4 or risk_score > 0.45:
            return {
                "decision": "INVESTIGATE",
                "severity": "MEDIUM",
                "risk_score": risk_score,
                "escalate": False,
                "priority": 3,
                "suggested_action": "Gather additional context, check related alerts",
                "confidence": 0.70,
                "ticket_template": "investigation"
            }
        
        # LOW: Likely false positive
        return {
            "decision": "CLOSE",
            "severity": "LOW",
            "risk_score": risk_score,
            "escalate": False,
            "priority": 4,
            "reason": "Low risk score, likely false positive",
            "confidence": 0.80,
        }

    def _count_recent_alerts(self, ip: str, hours: int = 1) -> int:
        """Count similar alerts from same IP in last N hours."""
        # In real implementation, query SIEM
        pass

    def _is_off_hours(self, timestamp: str, normal_hours: List[int]) -> bool:
        """Check if timestamp is outside normal working hours."""
        dt = datetime.fromisoformat(timestamp)
        return dt.hour < normal_hours[0] or dt.hour > normal_hours[1]

    def _check_threat_intel(self, alert: Dict) -> bool:
        """Check if alert matches known threat indicators."""
        # Query threat intel feeds (VirusTotal, AlienVault OTX, etc.)
        src_ip = alert.get("source_ip")
        # Check if IP is known C2 or malicious
        return src_ip in self.threat_intel.get("malicious_ips", [])

    def _detect_lateral_movement(self, alert: Dict) -> bool:
        """Detect if alert is part of lateral movement pattern."""
        # Check if same source accessing multiple unusual destinations
        pass


def process_alerts_from_siem(alerts: List[Dict]) -> Dict:
    """
    Process batch of alerts from SIEM.
    
    Returns: Summary of triaged alerts + escalation queue
    """
    config = {
        "whitelist_ips": ["10.0.0.1", "192.168.1.1"],
        "known_false_positives": [
            {
                "rule": "PowerShell Execution",
                "match_condition": lambda a: "admin" in a.get("user_id", "").lower()
            }
        ],
        "maintenance_windows": [
            {
                "start": "2024-01-15T22:00:00Z",
                "end": "2024-01-16T02:00:00Z"
            }
        ]
    }
    
    triager = AlertTriager(config)
    
    results = {
        "total_alerts": len(alerts),
        "closed": [],
        "escalated": [],
        "under_investigation": [],
        "summary": {}
    }
    
    for alert in alerts:
        decision = triager.triage_alert(alert)
        
        if decision["decision"] == "CLOSE":
            results["closed"].append({
                "alert": alert,
                "reason": decision.get("reason"),
                "confidence": decision.get("confidence")
            })
        elif decision["decision"] == "ESCALATE":
            results["escalated"].append({
                "alert": alert,
                "priority": decision.get("priority"),
                "action": decision.get("suggested_action"),
                "confidence": decision.get("confidence")
            })
        elif decision["decision"] == "INVESTIGATE":
            results["under_investigation"].append({
                "alert": alert,
                "action": decision.get("suggested_action"),
                "confidence": decision.get("confidence")
            })
    
    # Summary metrics
    results["summary"] = {
        "close_rate": len(results["closed"]) / len(alerts),
        "escalation_rate": len(results["escalated"]) / len(alerts),
        "investigation_rate": len(results["under_investigation"]) / len(alerts),
        "analyst_time_saved_hours": (len(results["closed"]) * 0.1) / 60  # Assume 6min per alert
    }
    
    return results
```

---

## 📊 Benefits

```
Before Automation
├─ 500 alerts/day
├─ Analyst processes each: 5-10 min
├─ Time needed: 40+ hours/day (impossible)
├─ Result: 80% of alerts missed

After Automation
├─ 500 alerts/day
├─ Tool filters 400 (false positives + known good)
├─ 100 alerts for analyst review: 5-10 min each
├─ Time needed: 8 hours (manageable)
├─ Result: 95% of real alerts caught
├─ False positive reduction: 400 filtered alerts/day
└─ Analyst time saved: 30+ hours/day
```

---

## 🔧 Implementation Considerations

```
Data Sources Required
├─ Asset database (what hosts are what)
├─ User activity database (normal behavior patterns)
├─ Threat intelligence feeds (malicious IPs, domains)
├─ Historical alert data (training for ML)
└─ Maintenance calendars (scheduled downtime)

Integration Points
├─ SIEM (fetch alerts, query logs)
├─ Ticketing system (create escalation tickets)
├─ Threat intelligence feeds (update malicious indicators)
├─ ChatOps (notify analysts of escalations)
└─ Analytics (measure performance)

Tuning Required
├─ False positive rates (adjust thresholds)
├─ Escalation sensitivity (catch real incidents, not noise)
├─ Whitelist accuracy (don't suppress real threats)
├─ Context data freshness (keep databases updated)
└─ Performance (process alerts in real-time)
```

---

## 🔑 Key Takeaways

- **Automation handles volume** - free analysts for deep investigation
- **Context is king** - enrichment separates signal from noise
- **Risk scoring > severity scoring** - risk combines severity + context
- **Whitelists prevent suppression of real threats** - maintain carefully
- **Iterative tuning essential** - start conservative, adjust based on results

---

## [⬅️ Day 061](../day061/) | [➡️ Day 063](../day063/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*