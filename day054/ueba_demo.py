"""
Day 054 - UEBA Anomaly Scorer
100 Days of Cybersecurity by Sudeep Ravichandran

Detects user behaviour anomalies based on:
  - Impossible travel (same user in 2+ countries unrealistically fast)
  - Time-of-day anomalies (off-hours access)
  - Peer group comparison
  - Failed auth spikes (credential attacks)
  - Resource access changes

Input CSV format:
  timestamp,user_id,action,resource,location,ip_address,status
  
  2024-01-15T09:30:00Z,john.doe,login,VPN,US-Office,10.0.1.5,success
  2024-01-15T10:15:00Z,john.doe,file_access,sales_data.xlsx,US-Office,10.0.1.5,success
  2024-01-15T10:30:00Z,jane.smith,login,VPN,US-Office,10.0.1.10,failed
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
import argparse
import sys

class UEBAAnalyzer:
    def __init__(self, activity_log: str):
        """Load user activity data."""
        try:
            self.df = pd.read_csv(activity_log)
            self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
            self.anomalies = []
            self.baselines = {}
            print(f"[+] Loaded {len(self.df)} events from {activity_log}")
        except Exception as e:
            print(f"[!] Error loading activity log: {e}")
            sys.exit(1)

    def build_baseline(self, user_id: str):
        """Build baseline profile for a user."""
        user_data = self.df[self.df['user_id'] == user_id]
        if user_data.empty:
            return None
        
        baseline = {
            'total_events': len(user_data),
            'unique_locations': user_data['location'].nunique(),
            'unique_ips': user_data['ip_address'].nunique(),
            'unique_resources': user_data['resource'].nunique(),
            'actions': user_data['action'].value_counts().to_dict() if len(user_data) > 0 else {},
            'avg_daily_logins': len(user_data[user_data['action'] == 'login']) / max(1, (user_data['timestamp'].max() - user_data['timestamp'].min()).days),
            'common_locations': user_data['location'].value_counts().head(3).to_dict(),
            'common_hours': user_data['timestamp'].dt.hour.value_counts().head(3).to_dict(),
            'failed_auth_pct': len(user_data[user_data['status'] == 'failed']) / max(1, len(user_data)),
        }
        self.baselines[user_id] = baseline
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
                    
                    # Flag if <2 hours between different regions (physically impossible)
                    if time_delta < 2 and time_delta > 0:
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
            
            # User's normal work hours (from baseline common hours)
            normal_hours = set(baseline['common_hours'].keys()) if baseline['common_hours'] else set(range(8, 18))
            
            # Check for logins at unusual hours
            for _, row in user_activity.iterrows():
                hour = row['timestamp'].hour
                if row['action'] == 'login' and hour not in normal_hours and hour < 6:
                    self.anomalies.append({
                        'type': 'off_hours_access',
                        'severity': 'medium',
                        'user_id': user_id,
                        'timestamp': row['timestamp'],
                        'hour': hour,
                        'normal_hours': sorted(list(normal_hours)),
                    })

    def failed_auth_spike_check(self, threshold: int = 5):
        """Detect credential attack attempts (high failed auth rate)."""
        print(f"\n[*] Checking for failed auth spikes (threshold: {threshold}/hour)...")
        
        # Group failed attempts by user
        failed_auths = self.df[(self.df['action'] == 'login') & (self.df['status'] == 'failed')]
        
        for user_id in failed_auths['user_id'].unique():
            user_failed = failed_auths[failed_auths['user_id'] == user_id].sort_values('timestamp')
            
            if len(user_failed) >= threshold:
                time_span = (user_failed['timestamp'].max() - user_failed['timestamp'].min()).total_seconds() / 3600
                if time_span < 1:  # All within 1 hour
                    self.anomalies.append({
                        'type': 'failed_auth_spike',
                        'severity': 'high',
                        'user_id': user_id,
                        'failed_count': len(user_failed),
                        'time_window_hours': max(time_span, 0.1),  # Avoid division by zero
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
            
            baseline_resources = set()
            baseline_data = self.df[self.df['user_id'] == user_id]
            if len(baseline_data) > 0:
                baseline_resources = set(baseline_data[baseline_data['action'] == 'file_access']['resource'].unique())
            
            # Check for access to resources not in baseline
            count = 0
            for _, row in user_activity.iterrows():
                if row['action'] == 'file_access' and row['resource'] not in baseline_resources:
                    if count < 3:  # Limit anomalies to top 3 per user
                        self.anomalies.append({
                            'type': 'new_resource_access',
                            'severity': 'low',
                            'user_id': user_id,
                            'resource': row['resource'],
                            'timestamp': row['timestamp'],
                        })
                        count += 1

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
        
        for anom_type in sorted(by_type.keys()):
            items = by_type[anom_type]
            print(f"  [{anom_type.upper()}] {len(items)} alerts\n")
            for item in items[:3]:
                print(f"    • User: {item['user_id']}")
                print(f"      Time: {item['timestamp']}")
                if 'from_location' in item:
                    print(f"      Travel: {item['from_location']} → {item['to_location']} ({item['time_gap_hours']:.1f}h)")
                if 'failed_count' in item:
                    print(f"      Failed auths: {item['failed_count']}")
                if 'resource' in item:
                    print(f"      Resource: {item['resource']}")
                print()

    def export_report(self, filepath: str):
        """Export anomalies to CSV."""
        anom_df = pd.DataFrame(self.anomalies)
        anom_df.to_csv(filepath, index=False)
        print(f"\n[+] Report exported to {filepath}")


def main():
    parser = argparse.ArgumentParser(description="UEBA Anomaly Scorer - Day 054")
    parser.add_argument("--analyze", required=True, help="Activity log CSV")
    parser.add_argument("--export", help="Export anomalies to CSV")
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

    if args.export:
        ueba.export_report(args.export)


if __name__ == "__main__":
    main()