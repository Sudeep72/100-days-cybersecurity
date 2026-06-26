# Day 054 - UEBA: User and Entity Behavior Analytics

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Network traffic is what attackers do.

UEBA is *who* the attackers are (or who they've compromised).

It's the detection layer focused on user and entity (machine) behaviour - learning what normal looks like for each user, then flagging deviations.

A user logging in from 3 different countries in one day. A service account suddenly running PowerShell. A file server accessing sensitive databases. These are behavioural anomalies.

---

## 🎯 Entities in UEBA

```
Users               →  Human accounts (employees, contractors)
Service Accounts    →  App service accounts, scheduled jobs
Machines/Hosts      →  Servers, workstations, IoT, printers
Applications        →  What software is running, APIs being called
Data / Repositories →  Sensitive files and folders
```

Each entity has a baseline behaviour. Deviations are risky.

---

## 📊 Behavioural Baselines

**User baseline includes:**
```
Login times          → when they normally log in (9am vs 2am)
Locations           → which geographies/networks (office vs home)
Login frequency     → hourly patterns, work-day patterns
Applications used   → which tools they access (Salesforce, Slack, etc.)
Data accessed       → typical files, folders, databases they touch
Peer group          → similar users for group comparison
Permissions         → what they're authorized for
Failed attempts     → normal auth failure rate (malware uses wrong passwords)
```

**Machine baseline includes:**
```
Outbound connections → IPs, ports, protocols, volume
Process execution    → typical programs that run (Chrome, Excel, etc.)
Service behavior     → expected uptime, restart patterns
User logins          → which accounts typically access it (humans vs service)
Network shares       → which systems it accesses
CPU/memory patterns  → usage over time
```

---

## 🚩 UEBA Signals

```
Impossible Travel       → User in NYC at 2pm, then Singapore at 3pm (impossible speed)
Privilege Escalation    → User suddenly accessing admin functions they never used
Time Anomaly           → Login at 3am when they always work 9-5
Failed Auth Spike      → 100 failed login attempts (brute force/credential stuffing)
Geo Anomaly            → Login from country they never accessed before
Peer Anomaly           → Accessing data/tools unlike similar users
Mass Download          → Downloading unusual volume of files/data (exfil)
Lateral Movement       → Machine accessing network resources it normally doesn't
Service Anomaly        → App service account accessing interactive tools (web browsers)
Credential Sharing     → Multiple simultaneous logins from same account
First-Time Activity    → Using an app or accessing data for the first time ever
```

---

## 📈 Detection Methods

### 1. Statistical (Z-score, IQR)
Detect when a metric deviates >2-3σ from the baseline mean.

### 2. Peer Group Analysis
Compare user behaviour to peers. If a finance analyst accesses data like a dev, that's anomalous.

### 3. Time-Series Analysis
Look for trend breaks - if a user's daily file access volume jumps 10x, flag it.

### 4. Rules-Based
Hard rules: logins from impossible locations, after-hours access to sensitive data, etc.

### 5. Machine Learning
Train models (Isolation Forest, Autoencoders) on baseline data to detect unseen patterns.

---

## 🛠️ Data Sources for UEBA

```
Active Directory    → User logins, group membership, password changes
Proxy/Firewall      → Web traffic, DNS queries (user-level context)
Email Logs          → Mail sent/received, file transfers
File Servers        → File access, modifications (who accessed what when)
Applications        → VPN, CRM, HR systems (user login events)
Endpoints           → Endpoint detection (EDR), process execution, logons
Cloud IAM           → AWS/Azure logs, API calls (user + resource)
VPN Logs            → Remote access (user + source IP/location)
```

The key: **correlate across multiple data sources** to get a complete picture.

---

## 💻 The Code - UEBA Anomaly Scorer

```python
"""
Day 054 - UEBA Anomaly Scorer
100 Days of Cybersecurity by Sudeep Ravichandran

Detects user behaviour anomalies based on:
  - Impossible travel
  - Time-of-day anomalies
  - Peer group comparison
  - Access pattern changes
  - Failed auth spikes

Input: User activity log (CSV)
  timestamp,user_id,action,resource,location,ip_address,status
  2024-01-15T09:30:00Z,john.doe,login,VPN,US-Office,10.0.1.5,success
  2024-01-15T10:15:00Z,john.doe,file_access,sales_data.xlsx,US-Office,10.0.1.5,success
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
import argparse

class UEBAAnalyzer:
    def __init__(self, activity_log: str):
        """Load user activity data."""
        self.df = pd.read_csv(activity_log)
        self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
        self.anomalies = []
        self.baselines = {}
        print(f"[+] Loaded {len(self.df)} events from {activity_log}")

    def build_baseline(self, user_id: str, window_days: int = 30):
        """Build baseline profile for a user."""
        user_data = self.df[self.df['user_id'] == user_id]
        if user_data.empty:
            return None
        
        baseline = {
            'total_events': len(user_data),
            'unique_locations': user_data['location'].nunique(),
            'unique_ips': user_data['ip_address'].nunique(),
            'unique_resources': user_data['resource'].nunique(),
            'actions': user_data['action'].value_counts().to_dict(),
            'avg_daily_logins': len(user_data[user_data['action'] == 'login']) / max(1, (user_data['timestamp'].max() - user_data['timestamp'].min()).days),
            'common_locations': user_data['location'].value_counts().head(3).to_dict(),
            'common_hours': user_data['timestamp'].dt.hour.value_counts().head(3).to_dict(),
            'failed_auth_pct': len(user_data[user_data['status'] == 'failed']) / max(1, len(user_data)),
        }
        return baseline

    def impossible_travel_check(self):
        """Detect impossible travel (same user in 2+ locations within unrealistic timespan)."""
        print("\n[*] Checking for impossible travel...")
        
        for user_id in self.df['user_id'].unique():
            user_activity = self.df[self.df['user_id'] == user_id].sort_values('timestamp')
            
            locations = []
            for _, row in user_activity.iterrows():
                locations.append({
                    'location': row['location'],
                    'timestamp': row['timestamp'],
                    'ip': row['ip_address']
                })
            
            # Check consecutive locations for unrealistic time gaps
            for i in range(len(locations) - 1):
                curr = locations[i]
                next_loc = locations[i + 1]
                
                if curr['location'] != next_loc['location']:
                    time_delta = (next_loc['timestamp'] - curr['timestamp']).total_seconds() / 3600
                    
                    # Flagged if <1 hour between different countries/regions (impossible)
                    if time_delta < 1 and 'US' in str(curr['location']) and 'CN' in str(next_loc['location']):
                        self.anomalies.append({
                            'type': 'impossible_travel',
                            'severity': 'high',
                            'user_id': user_id,
                            'from_location': curr['location'],
                            'to_location': next_loc['location'],
                            'time_gap_hours': time_delta,
                            'timestamp': curr['timestamp'],
                        })

    def time_anomaly_check(self):
        """Detect off-hours access."""
        print("\n[*] Checking for time-of-day anomalies...")
        
        for user_id in self.df['user_id'].unique():
            user_activity = self.df[self.df['user_id'] == user_id]
            baseline = self.build_baseline(user_id)
            
            if not baseline:
                continue
            
            # User's normal work hours (from baseline)
            normal_hours = set(baseline['common_hours'].keys())
            
            # Check for logins at unusual hours
            for _, row in user_activity.iterrows():
                hour = row['timestamp'].hour
                if row['action'] == 'login' and hour not in normal_hours and hour not in range(6, 23):
                    self.anomalies.append({
                        'type': 'off_hours_access',
                        'severity': 'medium',
                        'user_id': user_id,
                        'timestamp': row['timestamp'],
                        'hour': hour,
                        'normal_hours': list(normal_hours),
                    })

    def failed_auth_spike_check(self, threshold: int = 5):
        """Detect credential attack attempts (high failed auth rate)."""
        print(f"\n[*] Checking for failed auth spikes (threshold: {threshold}/hour)...")
        
        # Group failed attempts by user and time window
        failed_auths = self.df[(self.df['action'] == 'login') & (self.df['status'] == 'failed')]
        
        for user_id in failed_auths['user_id'].unique():
            user_failed = failed_auths[failed_auths['user_id'] == user_id].sort_values('timestamp')
            
            # Check for spike in 1-hour windows
            if len(user_failed) >= threshold:
                time_span = (user_failed['timestamp'].max() - user_failed['timestamp'].min()).total_seconds() / 3600
                if time_span < 1:  # All within 1 hour
                    self.anomalies.append({
                        'type': 'failed_auth_spike',
                        'severity': 'high',
                        'user_id': user_id,
                        'failed_count': len(user_failed),
                        'time_window_hours': time_span,
                        'timestamp': user_failed['timestamp'].min(),
                    })

    def resource_access_anomaly_check(self):
        """Detect unusual resource access patterns."""
        print("\n[*] Checking for resource access anomalies...")
        
        for user_id in self.df['user_id'].unique():
            user_activity = self.df[self.df['user_id'] == user_id]
            baseline = self.build_baseline(user_id)
            
            if not baseline:
                continue
            
            # Check for access to resources not in baseline
            for _, row in user_activity.iterrows():
                if row['action'] == 'file_access' and row['resource'] not in baseline.get('unique_resources', []):
                    self.anomalies.append({
                        'type': 'new_resource_access',
                        'severity': 'low',
                        'user_id': user_id,
                        'resource': row['resource'],
                        'timestamp': row['timestamp'],
                    })

    def print_anomalies(self):
        """Print all detected anomalies."""
        if not self.anomalies:
            print("\n[+] No anomalies detected.")
            return
        
        print(f"\n{'='*60}")
        print(f"  UEBA ANOMALIES DETECTED: {len(self.anomalies)}")
        print(f"{'='*60}\n")
        
        by_type = defaultdict(list)
        for anom in self.anomalies:
            by_type[anom['type']].append(anom)
        
        for anom_type, items in sorted(by_type.items()):
            print(f"  [{anom_type.upper()}] {len(items)} alerts\n")
            for item in items[:3]:
                print(f"    • User: {item['user_id']}")
                print(f"      Time: {item['timestamp']}")
                if 'from_location' in item:
                    print(f"      Travel: {item['from_location']} → {item['to_location']} ({item['time_gap_hours']:.1f}h)")
                if 'failed_count' in item:
                    print(f"      Failed auths: {item['failed_count']}")
                print()


def main():
    parser = argparse.ArgumentParser(description="UEBA Anomaly Scorer - Day 054")
    parser.add_argument("--analyze", required=True, help="Activity log CSV")
    args = parser.parse_args()

    print("=" * 60)
    print("  UEBA: User & Entity Behaviour Analytics")
    print("  Day 054 | 100 Days of Cybersecurity")
    print("=" * 60)

    ueba = UEBAAnalyzer(args.analyze)
    ueba.impossible_travel_check()
    ueba.time_anomaly_check()
    ueba.failed_auth_spike_check()
    ueba.resource_access_anomaly_check()
    ueba.print_anomalies()


if __name__ == "__main__":
    main()
```


## [⬅️ Day 053](../day053/) | [➡️ Day 055](../day055/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*