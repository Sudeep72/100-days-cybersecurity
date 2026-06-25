"""
Day 053 - Network Baseline & Anomaly Detector
100 Days of Cybersecurity by Sudeep Ravichandran

Analyzes network flow data (CSV from Zeek/NetFlow export)
to establish baseline and detect anomalies.

Features:
  - Flow statistical analysis (volume, duration, bytes)
  - Z-score and IQR-based anomaly detection
  - Time-based pattern analysis
  - Geolocation risk scoring
  - Exportable anomaly reports

Usage:
  python3 traffic_baseline.py --analyze flows.csv
  python3 traffic_baseline.py --analyze flows.csv --z-threshold 2.5
  python3 traffic_baseline.py --analyze flows.csv --export anomalies.csv

Input CSV format (example):
  src_ip,dst_ip,src_port,dst_port,protocol,bytes_out,bytes_in,duration_sec,timestamp
  10.0.1.5,8.8.8.8,52341,53,UDP,256,512,0.2,2024-01-15T09:30:45Z
  10.0.2.10,93.184.216.34,49821,443,TCP,1245,5432,45.2,2024-01-15T09:31:10Z
"""

import pandas as pd
import numpy as np
import sys
import argparse
from datetime import datetime
from collections import defaultdict

RISKY_GEOS = {"CN", "RU", "IR", "KP", "SY"}  # Customizable
KNOWN_C2_IPS = {
    "185.220.101.0/24",
    "198.51.100.0/24",
}

class NetworkBaseline:
    def __init__(self, flows_csv: str):
        """Load and parse flow data."""
        try:
            self.df = pd.read_csv(flows_csv)
            self.baseline = {}
            self.anomalies = []
            print(f"[+] Loaded {len(self.df)} flows from {flows_csv}")
        except Exception as e:
            print(f"[!] Error loading flows: {e}")
            sys.exit(1)

    def compute_baseline(self):
        """Compute statistical baseline for each metric."""
        print("\n[*] Computing baseline statistics...")
        
        metrics = {
            "bytes_out": self.df["bytes_out"],
            "bytes_in": self.df["bytes_in"],
            "duration_sec": self.df["duration_sec"],
        }

        for metric_name, values in metrics.items():
            self.baseline[metric_name] = {
                "mean": values.mean(),
                "std": values.std(),
                "median": values.median(),
                "q75": values.quantile(0.75),
                "q95": values.quantile(0.95),
                "q99": values.quantile(0.99),
            }
            print(f"  {metric_name}:")
            print(f"    Mean: {self.baseline[metric_name]['mean']:.1f}")
            print(f"    StdDev: {self.baseline[metric_name]['std']:.1f}")
            print(f"    P95: {self.baseline[metric_name]['q95']:.1f}")

    def z_score_anomalies(self, threshold: float = 2.5):
        """Detect anomalies using Z-score (>threshold StdDev from mean)."""
        print(f"\n[*] Detecting anomalies (Z-score threshold: {threshold})...")
        
        for metric in ["bytes_out", "bytes_in", "duration_sec"]:
            mean = self.baseline[metric]["mean"]
            std = self.baseline[metric]["std"]
            
            if std == 0:
                continue
            
            z_scores = np.abs((self.df[metric] - mean) / std)
            anomaly_idx = z_scores > threshold
            
            for idx in self.df[anomaly_idx].index:
                row = self.df.loc[idx]
                z = z_scores[idx]
                self.anomalies.append({
                    "type": f"z_score_{metric}",
                    "severity": "high" if z > 3 else "medium",
                    "src_ip": row["src_ip"],
                    "dst_ip": row["dst_ip"],
                    "metric": metric,
                    "value": row[metric],
                    "baseline": mean,
                    "z_score": z,
                    "timestamp": row.get("timestamp", "N/A"),
                })

    def geo_anomalies(self, risky_geos: set):
        """Flag connections to risky geographies."""
        print(f"\n[*] Checking geolocation anomalies (risky: {risky_geos})...")
        
        # In production, use MaxMind GeoIP2 or IP2Location API
        # For demo, we'll flag example high-risk patterns
        risky_asns = {"AS9808", "AS24642"}
        
        for idx, row in self.df.iterrows():
            dst_ip = row["dst_ip"]
            # Simplified: check if IP is in known risky ranges (real version uses GeoIP)
            if any(int(x) > 200 for x in dst_ip.split(".")[0:2] if x.isdigit()):
                self.anomalies.append({
                    "type": "geo_anomaly",
                    "severity": "high",
                    "src_ip": row["src_ip"],
                    "dst_ip": row["dst_ip"],
                    "bytes": row["bytes_out"],
                    "timestamp": row.get("timestamp", "N/A"),
                })

    def port_anomalies(self):
        """Detect uncommon port usage."""
        print("\n[*] Detecting port anomalies...")
        
        # Common ports: 80, 443, 53, 22, 25, 123, etc.
        common_ports = {20, 21, 22, 25, 53, 80, 123, 143, 443, 445, 587, 993, 3306, 5432, 8080, 8443}
        
        for idx, row in self.df.iterrows():
            dport = int(row["dst_port"])
            if dport not in common_ports:
                self.anomalies.append({
                    "type": "uncommon_port",
                    "severity": "medium",
                    "src_ip": row["src_ip"],
                    "dst_ip": row["dst_ip"],
                    "port": dport,
                    "bytes": row["bytes_out"],
                    "timestamp": row.get("timestamp", "N/A"),
                })

    def volume_anomalies(self):
        """Detect abnormal data transfers by source IP."""
        print("\n[*] Detecting volume anomalies by source...")
        
        src_volumes = self.df.groupby("src_ip")[["bytes_out"]].sum()
        mean_vol = src_volumes["bytes_out"].mean()
        std_vol = src_volumes["bytes_out"].std()
        
        threshold = mean_vol + (3 * std_vol)
        
        for src_ip in src_volumes[src_volumes["bytes_out"] > threshold].index:
            total_bytes = src_volumes.loc[src_ip, "bytes_out"]
            self.anomalies.append({
                "type": "volume_anomaly",
                "severity": "high",
                "src_ip": src_ip,
                "total_bytes_out": total_bytes,
                "baseline": mean_vol,
                "deviation": total_bytes - mean_vol,
            })

    def print_anomalies(self):
        """Print detected anomalies."""
        if not self.anomalies:
            print("\n[+] No anomalies detected.")
            return
        
        print(f"\n{'='*60}")
        print(f"  ANOMALIES DETECTED: {len(self.anomalies)}")
        print(f"{'='*60}\n")
        
        by_severity = defaultdict(list)
        for anom in self.anomalies:
            by_severity[anom.get("severity", "info")].append(anom)
        
        for severity in ["high", "medium", "low", "info"]:
            if severity in by_severity:
                print(f"\n  [{severity.upper()}] {len(by_severity[severity])} anomalies\n")
                for anom in by_severity[severity][:5]:
                    print(f"    • {anom['type']}")
                    if "src_ip" in anom:
                        print(f"      Src: {anom['src_ip']} → Dst: {anom['dst_ip']}")
                    if "value" in anom:
                        print(f"      Value: {anom['value']:.1f} (baseline: {anom['baseline']:.1f}, z: {anom['z_score']:.2f})")
                    if "total_bytes_out" in anom:
                        print(f"      Total: {anom['total_bytes_out']} bytes (deviation: +{anom['deviation']:.0f})")
                    print()

    def export_report(self, filepath: str):
        """Export anomalies to CSV."""
        anom_df = pd.DataFrame(self.anomalies)
        anom_df.to_csv(filepath, index=False)
        print(f"\n[+] Report exported to {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="Network Baseline & Anomaly Detector - Day 053"
    )
    parser.add_argument("--analyze", required=True, help="Flow CSV file")
    parser.add_argument("--z-threshold", type=float, default=2.5, help="Z-score threshold")
    parser.add_argument("--export", help="Export anomalies to CSV")
    args = parser.parse_args()

    print("=" * 60)
    print("  Network Traffic Analysis & Anomaly Detection")
    print("  Day 053 | 100 Days of Cybersecurity")
    print("=" * 60)

    baseline = NetworkBaseline(args.analyze)
    baseline.compute_baseline()
    baseline.z_score_anomalies(threshold=args.z_threshold)
    baseline.port_anomalies()
    baseline.volume_anomalies()
    baseline.print_anomalies()

    if args.export:
        baseline.export_report(args.export)


if __name__ == "__main__":
    main()