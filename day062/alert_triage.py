"""
Day 062 - Automated Alert Triage Tool
100 Days of Cybersecurity by Sudeep Ravichandran

Automatically triages security alerts using risk scoring,
context enrichment, and decision logic.

Usage:
  python3 alert_triage.py --input alerts.json --output decisions.json
  python3 alert_triage.py --stream  # Real-time from SIEM
"""

import json
import argparse
from datetime import datetime
from typing import Dict, List, Tuple
from collections import defaultdict

class AlertTriager:
    def __init__(self, config: Dict):
        """Initialize triager with config (whitelist, known FPs, etc.)"""
        self.config = config
        self.whitelist_ips = set(config.get("whitelist_ips", []))
        self.whitelist_users = set(config.get("whitelist_users", []))
        self.known_false_positives = config.get("known_false_positives", [])
        self.maintenance_windows = config.get("maintenance_windows", [])
        self.malicious_ips = set(config.get("threat_intel", {}).get("malicious_ips", []))
        self.c2_domains = set(config.get("threat_intel", {}).get("c2_domains", []))

    def triage(self, alert: Dict) -> Dict:
        """Main triage function."""
        
        # Step 1: Known false positive?
        if self._is_known_false_positive(alert):
            return self._decision("CLOSE", "Known false positive", 0.95)
        
        # Step 2: Scheduled maintenance?
        if self._is_maintenance_window(alert):
            return self._decision("CLOSE", "During scheduled maintenance", 0.90)
        
        # Step 3: Whitelisted?
        if self._is_whitelisted(alert):
            return self._decision("CLOSE", "Source/dest whitelisted", 0.85)
        
        # Step 4: Calculate severity
        severity = self._calculate_severity(alert)
        
        # Step 5: Enrich with context
        enrichment = self._enrich_alert(alert)
        alert.update(enrichment)
        
        # Step 6: Calculate risk
        risk = self._calculate_risk_score(alert, severity)
        
        # Step 7: Make decision
        if severity > 0.8 or risk > 0.85:
            return self._decision(
                "ESCALATE",
                "CRITICAL",
                confidence=0.95,
                priority=1,
                risk_score=risk
            )
        
        if severity > 0.6 or risk > 0.65:
            return self._decision(
                "ESCALATE",
                "HIGH",
                confidence=0.85,
                priority=2,
                risk_score=risk
            )
        
        if severity > 0.4 or risk > 0.45:
            return self._decision(
                "INVESTIGATE",
                "MEDIUM",
                confidence=0.70,
                priority=3,
                risk_score=risk
            )
        
        return self._decision("CLOSE", "Low risk", 0.80, risk_score=risk)

    def _is_known_false_positive(self, alert: Dict) -> bool:
        """Check against known false positive patterns."""
        rule_name = alert.get("rule_name", "").lower()
        
        for fp in self.known_false_positives:
            if fp["rule"].lower() in rule_name:
                return True
        
        return False

    def _is_maintenance_window(self, alert: Dict) -> bool:
        """Check if alert occurred during maintenance."""
        try:
            alert_time = datetime.fromisoformat(alert.get("timestamp", "").replace("Z", "+00:00"))
            
            for window in self.maintenance_windows:
                start = datetime.fromisoformat(window["start"].replace("Z", "+00:00"))
                end = datetime.fromisoformat(window["end"].replace("Z", "+00:00"))
                
                if start <= alert_time <= end:
                    return True
        except:
            pass
        
        return False

    def _is_whitelisted(self, alert: Dict) -> bool:
        """Check if source/dest/user is whitelisted."""
        src_ip = alert.get("source_ip")
        dst_ip = alert.get("dest_ip")
        user = alert.get("user_id", "").lower()
        
        return (
            src_ip in self.whitelist_ips or
            dst_ip in self.whitelist_ips or
            user in self.whitelist_users
        )

    def _calculate_severity(self, alert: Dict) -> float:
        """Calculate base severity (0-1)."""
        severity_map = {
            "CRITICAL": 0.95,
            "HIGH": 0.75,
            "MEDIUM": 0.50,
            "LOW": 0.25
        }
        
        base = severity_map.get(alert.get("severity", "MEDIUM"), 0.50)
        
        # Boost for certain rule types
        rule = alert.get("rule_name", "").lower()
        if any(x in rule for x in ["ransomware", "malware", "c2", "backdoor"]):
            base = min(1.0, base + 0.25)
        
        return base

    def _enrich_alert(self, alert: Dict) -> Dict:
        """Add contextual information."""
        enrichment = {}
        
        # Threat intel
        src_ip = alert.get("source_ip")
        enrichment["is_malicious_ip"] = src_ip in self.malicious_ips
        
        dst_fqdn = alert.get("dest_fqdn", "").lower()
        enrichment["is_c2_domain"] = dst_fqdn in self.c2_domains
        
        # Time context
        try:
            ts = datetime.fromisoformat(alert.get("timestamp", "").replace("Z", "+00:00"))
            hour = ts.hour
            enrichment["is_off_hours"] = hour < 6 or hour > 22
        except:
            enrichment["is_off_hours"] = False
        
        return enrichment

    def _calculate_risk_score(self, alert: Dict, severity: float) -> float:
        """Calculate overall risk (0-1)."""
        risk = severity
        
        # Threat intel hits
        if alert.get("is_malicious_ip"):
            risk += 0.25
        if alert.get("is_c2_domain"):
            risk += 0.25
        
        # Time anomaly
        if alert.get("is_off_hours"):
            risk += 0.15
        
        # Multiple indicators
        indicator_count = sum([
            alert.get("is_malicious_ip", False),
            alert.get("is_c2_domain", False),
            alert.get("is_off_hours", False),
        ])
        if indicator_count > 1:
            risk += 0.15
        
        return min(1.0, risk)

    def _decision(self, action: str, reason: str, confidence: float = 0.80, 
                  priority: int = 4, risk_score: float = 0) -> Dict:
        """Format triage decision."""
        return {
            "decision": action,
            "reason": reason,
            "confidence": confidence,
            "priority": priority,
            "risk_score": risk_score,
            "timestamp": datetime.utcnow().isoformat()
        }


def load_default_config() -> Dict:
    """Default configuration."""
    return {
        "whitelist_ips": [
            "10.0.0.1",      # Internal DNS
            "192.168.1.1",   # Corporate gateway
            "8.8.8.8",       # Google DNS (often whitelisted)
        ],
        "whitelist_users": [
            "admin",
            "system",
            "svc_backup",
            "svc_antivirus",
        ],
        "known_false_positives": [
            {"rule": "PowerShell Execution", "reason": "Admin activity"},
            {"rule": "Process Creation - cmd.exe", "reason": "Normal activity"},
        ],
        "maintenance_windows": [
            {
                "start": "2024-01-15T22:00:00Z",
                "end": "2024-01-16T02:00:00Z",
                "reason": "Nightly patching"
            }
        ],
        "threat_intel": {
            "malicious_ips": [
                "203.0.113.50",
                "198.51.100.25",
            ],
            "c2_domains": [
                "attacker-c2.evil.com",
                "malware-command.net",
            ]
        }
    }


def process_alerts(alerts: List[Dict], config: Dict) -> Dict:
    """Process batch of alerts."""
    triager = AlertTriager(config)
    
    results = {
        "total": len(alerts),
        "closed": [],
        "escalated": [],
        "investigating": [],
        "stats": {}
    }
    
    for alert in alerts:
        decision = triager.triage(alert)
        
        decision["rule"] = alert.get("rule_name")
        decision["source_ip"] = alert.get("source_ip")
        decision["timestamp_alert"] = alert.get("timestamp")
        
        if decision["decision"] == "CLOSE":
            results["closed"].append(decision)
        elif decision["decision"] == "ESCALATE":
            results["escalated"].append(decision)
        else:
            results["investigating"].append(decision)
    
    # Statistics
    results["stats"] = {
        "close_rate": len(results["closed"]) / max(1, len(alerts)),
        "escalation_rate": len(results["escalated"]) / max(1, len(alerts)),
        "investigation_rate": len(results["investigating"]) / max(1, len(alerts)),
        "analyst_time_saved_min": len(results["closed"]) * 5,
    }
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Alert Triage Tool - Day 062")
    parser.add_argument("--input", help="Input alerts JSON file")
    parser.add_argument("--output", help="Output decisions JSON file")
    parser.add_argument("--config", help="Custom config JSON file")
    args = parser.parse_args()

    # Load configuration
    if args.config:
        with open(args.config) as f:
            config = json.load(f)
    else:
        config = load_default_config()

    # Load alerts
    if args.input:
        with open(args.input) as f:
            alerts = json.load(f)
    else:
        # Example alerts
        alerts = [
            {
                "rule_name": "PowerShell Encoded Command",
                "severity": "HIGH",
                "source_ip": "192.168.1.50",
                "dest_ip": "10.0.0.5",
                "user_id": "john.doe",
                "timestamp": "2024-01-15T09:30:00Z"
            },
            {
                "rule_name": "SQL Injection Attempt",
                "severity": "MEDIUM",
                "source_ip": "203.0.113.50",
                "dest_ip": "192.168.100.10",
                "user_id": "unknown",
                "timestamp": "2024-01-15T14:15:00Z",
                "dest_fqdn": "attacker-c2.evil.com"
            }
        ]

    # Triage alerts
    results = process_alerts(alerts, config)

    # Output
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results written to {args.output}")
    else:
        print(json.dumps(results, indent=2))

    # Print summary
    print(f"\n{'='*60}")
    print(f"  TRIAGE SUMMARY")
    print(f"{'='*60}")
    print(f"  Total alerts: {results['total']}")
    print(f"  Closed: {len(results['closed'])} ({results['stats']['close_rate']:.1%})")
    print(f"  Escalated: {len(results['escalated'])} ({results['stats']['escalation_rate']:.1%})")
    print(f"  Investigating: {len(results['investigating'])} ({results['stats']['investigation_rate']:.1%})")
    print(f"  Analyst time saved: {results['stats']['analyst_time_saved_min']:.0f} min")


if __name__ == "__main__":
    main()