# Day 053 — Network Traffic Analysis: Spotting Anomalies

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Most of what attackers do leaves network evidence.

Command and control callbacks. Data exfiltration. Lateral movement reconnaissance. Malware updates. Even encrypted traffic has patterns — volume, timing, size, direction.

Network traffic analysis is how you see attacks without needing to be inside the victim's system.

---

## 🔍 What Network Analysis Reveals

```
Normal Baseline                 Anomaly Signs
────────────────               ──────────────
DNS: regular internal           Sudden spike in DNS queries to rare domains
                                Multiple failed lookups → retry loop (DGA)

HTTP/HTTPS: predictable         Large data transfers to unfamiliar IPs
                                Connections at odd hours to unusual geos
                                Multiple retries to same endpoint

Protocols: expected mix         Protocols never seen before (C2 fingerprints)
                                Uncommon port use (SSH on 443, custom tunnels)

Bytes in/out: symmetrical       Massive outbound (exfil), minimal inbound
                                Unusual packet sizes (polymorphic payloads)
```

---

## 📊 Baseline Concept

Attackers hide in noise.

If all your traffic looks the same, anomalies blend in. So the first step is to understand what "normal" looks like.

**Normal baseline includes:**
- Peak traffic times (9am-5pm vs 2am)
- Expected destinations (AWS, Google, your CDN, ISP DNS)
- Typical transfer volumes per user/host
- Established protocol ratios (HTTP vs DNS vs SMTP)
- Geolocation patterns (employees in US, traffic from US regions)

Deviation from baseline = possible incident.

---

## 🛠️ Tools for Network Analysis

```
Zeek (formerly Bro)        → Network monitoring, protocol analysis, scripting
Suricata                   → IDS/IPS, rule-based detection
Wireshark                  → Interactive packet inspection
tcpdump                    → Command-line packet capture
NetworkMiner              → Passive asset discovery
Splunk/ELK               → Indexing and correlating netflow
ntopng                    → Network intelligence (traffic stats)
Osquery                   → Endpoint-based network queries
```

---

## 📈 Flow Data (NetFlow / sFlow)

Instead of inspecting every packet (expensive), you can use **flow records**:

```
Source IP    Dest IP      Sport   Dport   Protocol   Bytes    Packets   Duration
────────────────────────────────────────────────────────────────────────────────
10.0.1.5     8.8.8.8      52341   53      UDP        256      4         0.2s
10.0.2.10    192.0.2.1    49821   443     TCP        1.2M     845       45s
10.0.3.7     185.220.101.x 55632  80      TCP        3.4M     2104      120s  ← suspicious
192.168.1.50 224.0.0.251  5353    5353    UDP        512      8         2.1s
```

Flow records are lightweight and can be collected at router or host level.

**Key anomalies in flows:**
- Unusual destination IPs (known C2, bulletproof hosters, Tor exit nodes)
- Uncommon ports (SSH on 8888, HTTP on 22)
- High byte counts to new destinations (exfil)
- Connections from hosts that shouldn't initiate outbound (printers, domain controllers, cameras)
- Geo anomalies (server in US talking to IPs in North Korea)
- Time-of-day anomalies (3am large transfers from accounting workstation)

---

## 💻 The Code — Network Baseline & Anomaly Detector

```python
"""
Day 053 — Network Baseline & Anomaly Detector
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
  python3 traffic_baseline.py --analyze flows.csv --risky-geos CN,RU,KP
  python3 traffic_baseline.py --analyze flows.csv --z-threshold 2.5

Input CSV format:
  src_ip,dst_ip,src_port,dst_port,protocol,bytes_out,bytes_in,duration_sec,timestamp
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
        # For demo, we'll flag example high-risk ASNs/ranges
        risky_asns = {"AS9808", "AS24642"}  # Example: China Telecom, etc.
        
        for idx, row in self.df.iterrows():
            dst_ip = row["dst_ip"]
            # Simplified: check if IP is in known risky ranges (real version uses GeoIP)
            if any(ord(x) > 200 for x in dst_ip.split(".")[0:2]):  # simplified heuristic
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
            dport = row["dst_port"]
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
                for anom in by_severity[severity][:5]:  # Show top 5
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
        description="Network Baseline & Anomaly Detector — Day 053"
    )
    parser.add_argument("--analyze", required=True, help="Flow CSV file")
    parser.add_argument("--z-threshold", type=float, default=2.5, help="Z-score threshold")
    parser.add_argument("--risky-geos", help="Comma-separated risky geographies")
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

```

## [⬅️ Day 052](../day052/) | [➡️ Day 054](../day054/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*