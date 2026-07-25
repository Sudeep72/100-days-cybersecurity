# Day 083 - Network Intrusion Detection with ML

> **Challenge:** 100 Days of Cybersecurity | **Phase:** AI × Security | **Difficulty:** Intermediate-Advanced

---

## 🧠 The Concept

Network Intrusion Detection System (NIDS) = Detects malicious traffic on the network.

Traditional NIDS (Snort, Zeek):
- Signature-based (looks for known attacks)
- Misses novel attacks (zero-days)
- High false positive rate

ML-based NIDS:
- Behavioral-based (learns normal traffic)
- Catches novel attacks (any abnormal traffic)
- Low false positive rate

**Combine both: Signature + ML = Complete coverage.**

---

## 📊 Network Intrusion Detection

### Types of Attacks Detected

```
Network Attacks:

1. DoS (Denial of Service)
   ├─ Flood attack (SYN flood, UDP flood)
   ├─ Amplification attack
   └─ Detection: Unusually high packet rate

2. Probe/Reconnaissance
   ├─ Port scanning
   ├─ Network mapping
   └─ Detection: Multiple IPs, multiple ports

3. Exploit/Compromise
   ├─ Buffer overflow
   ├─ Vulnerability exploitation
   └─ Detection: Unusual payload, protocol anomaly

4. Backdoor/Remote Access
   ├─ Reverse shell
   ├─ RDP, SSH from unusual location
   └─ Detection: Unusual port, unusual time, unusual source

5. Data Exfiltration
   ├─ Bulk data transfer
   ├─ C2 communication
   └─ Detection: Unusual volume, unusual destination
```

### Feature Engineering from Network Data

```
Network Flow Features:

Source IP:
├─ IP address
├─ Geolocation
├─ Reputation (blacklisted?)
└─ ASN (Autonomous System Number)

Destination IP:
├─ IP address
├─ Geolocation
├─ Port
├─ Service (HTTP, HTTPS, SSH, etc.)
└─ Reputation

Traffic Characteristics:
├─ Duration (seconds)
├─ Bytes sent (source → destination)
├─ Bytes received (destination → source)
├─ Packets sent
├─ Packets received
└─ Protocol (TCP, UDP, ICMP)

Behavioral Features:
├─ Packet rate (packets/second)
├─ Byte rate (bytes/second)
├─ Average packet size
├─ Payload entropy (randomness)
├─ TLS version (if encrypted)
└─ SSL certificate anomalies

Time-based Features:
├─ Hour of day
├─ Day of week
├─ Time since last connection from source
└─ Connection count in past 1 hour
```

---

## 💻 ML Models for NIDS

### Random Forest vs. Neural Networks

```
Random Forest:
✓ Interpretable (feature importance)
✓ Fast training
✓ Handles missing data
✓ No scaling required
✗ Slower inference

Neural Network:
✓ Faster inference
✓ Better non-linear patterns
✗ Slower training
✗ Requires scaling
✗ Black box (hard to interpret)

For security: Random Forest often better (need to explain decisions).
```

### Implementation: Random Forest NIDS

```python
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix

# Load network data (e.g., CICIDS2017)
df = pd.read_csv('network_traffic.csv')

# Features: Flow properties
feature_columns = [
    'duration',
    'src_bytes',
    'dest_bytes',
    'count',
    'srv_count',
    'error_rate',
    'srv_error_rate',
    'same_srv_rate',
    'diff_srv_rate'
]

X = df[feature_columns]
y = df['label']  # 'Normal' or 'Attack'

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train Random Forest
rf = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1)
rf.fit(X_train, y_train)

# Evaluate
y_pred = rf.predict(X_test)
precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary')

print(f"Precision: {precision:.3f}")
print(f"Recall: {recall:.3f}")
print(f"F1-Score: {f1:.3f}")

# Feature importance
importances = rf.feature_importances_
for feature, importance in sorted(zip(feature_columns, importances), key=lambda x: x[1], reverse=True):
    print(f"{feature}: {importance:.3f}")

# Real-time detection
def detect_intrusion(flow_data):
    """Detect intrusion in new network flow"""
    probability = rf.predict_proba([flow_data])
    is_attack = rf.predict([flow_data])[0]
    confidence = max(probability[0])
    
    return is_attack, confidence
```

---

## 🔍 CICIDS2017 Dataset

Most common dataset for NIDS research:

```
CICIDS2017:
├─ 2.5 million flows
├─ 84 features per flow
├─ 12 attack categories
│  ├─ DoS (Slowloris, Slowhttptest, Hulk, GoldenEye)
│  ├─ DDoS
│  ├─ Port Scan
│  ├─ SSH Bruteforce
│  ├─ FTP Bruteforce
│  ├─ Web Attack (SQL Injection, XSS)
│  ├─ Botnet
│  ├─ Infiltration
│  ├─ Heartbleed
│  └─ Normal
└─ Evaluation: Detection rate, false positive rate

Typical Results:
├─ Signature-based (Snort): 80% detection, 5% false positive
├─ ML-based (Random Forest): 95% detection, 1% false positive
└─ Hybrid (Both): 98% detection, 0.5% false positive
```

---

## 🚨 Deployment in Production

### Real-time Network Analysis

```python
import socket
from scapy.all import sniff, IP, TCP, UDP

class NetworkIntrustionDetector:
    def __init__(self, model):
        self.model = model
        self.flows = {}  # Active flows
    
    def packet_callback(self, packet):
        """Process each packet"""
        if IP not in packet:
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet:
            protocol = 'TCP'
            port = packet[TCP].dport
            flags = packet[TCP].flags
        elif UDP in packet:
            protocol = 'UDP'
            port = packet[UDP].dport
            flags = None
        else:
            return
        
        # Create flow key
        flow_key = (src_ip, dst_ip, port, protocol)
        
        # Update flow statistics
        if flow_key not in self.flows:
            self.flows[flow_key] = {
                'packets': 0,
                'bytes': 0,
                'start_time': time.time()
            }
        
        self.flows[flow_key]['packets'] += 1
        self.flows[flow_key]['bytes'] += len(packet)
        
        # Check flow every 10 packets or every 5 seconds
        if self.flows[flow_key]['packets'] % 10 == 0:
            self.check_flow(flow_key)
    
    def check_flow(self, flow_key):
        """Check if flow is malicious"""
        flow = self.flows[flow_key]
        
        # Extract features
        duration = time.time() - flow['start_time']
        byte_rate = flow['bytes'] / max(duration, 1)
        packet_rate = flow['packets'] / max(duration, 1)
        
        features = [
            duration,
            flow['bytes'],
            flow['packets'],
            byte_rate,
            packet_rate,
            # ... more features
        ]
        
        # Predict
        is_attack = self.model.predict([features])
        
        if is_attack:
            print(f"ALERT: Potential intrusion on {flow_key}")
            # Take action: Alert, block, log, etc.

# Usage
detector = NetworkIntrustionDetector(model=rf_model)
sniff(prn=detector.packet_callback, store=False)
```

---

## 📊 Metrics for NIDS

```
True Positive (TP): Attack correctly identified
False Positive (FP): Normal traffic flagged as attack
True Negative (TN): Normal traffic correctly identified
False Negative (FN): Attack missed

Metrics:

Precision = TP / (TP + FP)
├─ Of detected attacks, how many are real?
├─ High precision = few false alarms
└─ Goal: > 99%

Recall = TP / (TP + FN)
├─ Of real attacks, how many were detected?
├─ High recall = catch all attacks
└─ Goal: > 95%

F1-Score = 2 × (Precision × Recall) / (Precision + Recall)
├─ Balance between precision and recall
└─ Goal: > 0.95

Detection Rate (DR) = TP / (TP + FN)
├─ Same as recall
└─ Goal: > 95%

False Positive Rate (FPR) = FP / (FP + TN)
├─ Percentage of normal traffic incorrectly flagged
└─ Goal: < 1%

Balanced Accuracy = (TPR + TNR) / 2
├─ Average of sensitivity and specificity
└─ Goal: > 0.95
```

---

## 🔑 Key Takeaways

- **Behavioral detection catches novel attacks** - ML finds anomalies, signatures find known attacks
- **Feature engineering is critical** - right features = better detection
- **False positive rate matters** - too many alerts = analyst fatigue
- **Combine signature + ML** - hybrid approach best
- **Real-time constraint** - must process in milliseconds
- **Interpretability important** - need to explain why traffic is flagged
- **Regular retraining** - network behavior changes over time

---

## 📚 Resources

- [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
- [Network Intrusion Detection Survey](https://arxiv.org/abs/2004.10811)
- [Scapy Documentation](https://scapy.readthedocs.io/)

---

## [⬅️ Day 082](../day082/) | [➡️ Day 084](../day084/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*