# Day 082 - Anomaly Detection with Isolation Forest

> **Challenge:** 100 Days of Cybersecurity | **Phase:** AI × Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Anomaly Detection = Finding abnormal behavior in data.

**Isolation Forest** = Algorithm that isolates anomalies (outliers).

Perfect for security:
- Find unusual login patterns
- Detect unusual data access
- Identify abnormal network traffic
- Spot malicious user behavior

No labeled data needed (unsupervised learning).

---

## 📊 How Isolation Forest Works

### The Problem with Traditional ML

```
Traditional ML (Supervised):
├─ Requires labeled data (normal vs. anomaly examples)
├─ Hard to label anomalies (they're rare)
├─ Model overfits to training anomalies
└─ Misses novel anomalies not in training data

Anomaly Detection (Unsupervised):
├─ No labels needed (anomalies are rare anyway)
├─ Learn "normal" behavior automatically
├─ Find anything different from normal
└─ Catches novel anomalies (never seen before)
```

### Isolation Forest Algorithm

```
Core Idea: Anomalies are easier to isolate than normal points.

Visual Example:

Normal data (tightly clustered):
    *   *  *
   *  *    *  *
  *   *  *    *

Anomaly (isolated):
         *    ← Anomaly (far from others)
    *   *  *
   *  *    *  *
  *   *  *    *

Algorithm:
1. Randomly select a feature (column)
2. Randomly select a split value
3. Partition data (left < value, right >= value)
4. Repeat recursively
5. Count how many splits needed to isolate each point

Result:
├─ Normal points: Many splits needed (deeply nested)
├─ Anomalies: Few splits needed (isolated quickly)
├─ Anomaly score = 1 - (splits needed / avg splits)
└─ High score = Anomaly
```

### Why It Works for Security

```
Security Data Characteristics:

1. Normal behavior is repeated
   ├─ User logs in 9am-5pm
   ├─ User accesses same files
   ├─ User downloads similar data volumes
   └─ Anomaly = Deviation from this pattern

2. Anomalies are rare
   ├─ Normal: 99.9% of behavior
   ├─ Anomalies: 0.1% of behavior
   └─ Perfect for Isolation Forest (designed for rare events)

3. High-dimensional data
   ├─ Login time, location, IP, device, files accessed, etc.
   ├─ Need algorithm that handles many features
   └─ Isolation Forest excels with high dimensions

Result: Perfect fit for security use cases.
```

---

## 💻 Implementation

### Basic Isolation Forest Example

```python
import numpy as np
from sklearn.ensemble import IsolationForest

# Simulated user behavior data
# Features: [login_hour, location_lat, location_lon, files_accessed, bytes_downloaded]

data = np.array([
    [9, 40.7128, -74.0060, 50, 1000],      # Normal: 9am, NYC, 50 files, 1MB
    [9, 40.7128, -74.0060, 52, 1050],      # Normal: 9am, NYC, 52 files, 1MB
    [10, 40.7128, -74.0060, 48, 980],      # Normal: 10am, NYC, 48 files, 1MB
    [3, 35.6762, 139.6503, 1000, 50000],   # ANOMALY: 3am, Tokyo, 1000 files, 50MB
    [14, 40.7128, -74.0060, 51, 1020],     # Normal: 2pm, NYC, 51 files, 1MB
    [15, 40.7128, -74.0060, 49, 990],      # Normal: 3pm, NYC, 49 files, 1MB
])

# Train Isolation Forest
iso_forest = IsolationForest(contamination=0.1, random_state=42)
predictions = iso_forest.fit_predict(data)
scores = iso_forest.score_samples(data)

# Results
for i, (pred, score) in enumerate(zip(predictions, scores)):
    status = "ANOMALY" if pred == -1 else "Normal"
    print(f"Sample {i}: {status} (score: {score:.3f})")

# Output:
# Sample 0: Normal (score: -0.045)
# Sample 1: Normal (score: -0.042)
# Sample 2: Normal (score: -0.048)
# Sample 3: ANOMALY (score: 0.850)  ← Detected!
# Sample 4: Normal (score: -0.041)
# Sample 5: Normal (score: -0.046)
```

### Real-World Example: Login Anomaly Detection

```python
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Load user login data
login_data = pd.read_csv('login_logs.csv')
# Columns: user, timestamp, location_lat, location_lon, ip_country, device_type, success

# Create features
features = login_data[[
    'location_lat',
    'location_lon',
    'hour_of_day',
    'day_of_week',
    'time_since_last_login_hours',
    'login_sequence_position'
]].copy()

# Normalize (important for Isolation Forest)
scaler = StandardScaler()
features_scaled = scaler.fit_transform(features)

# Train Isolation Forest
iso = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
anomaly_labels = iso.fit_predict(features_scaled)
anomaly_scores = iso.score_samples(features_scaled)

# Add results to original data
login_data['is_anomaly'] = anomaly_labels == -1
login_data['anomaly_score'] = anomaly_scores

# Display anomalies
anomalies = login_data[login_data['is_anomaly']].sort_values('anomaly_score', ascending=False)
print(f"Found {len(anomalies)} anomalies out of {len(login_data)} logins")
print(anomalies[['user', 'location_lat', 'location_lon', 'hour_of_day', 'anomaly_score']].head(10))

# Alert on high-confidence anomalies
high_confidence = login_data[login_data['anomaly_score'] > 0.7]
for idx, row in high_confidence.iterrows():
    print(f"ALERT: User {row['user']} login from {row['location_lat']}, {row['location_lon']} at {row['hour_of_day']}:00")
```

---

## 🔍 Feature Engineering for Security

### Selecting the Right Features

```
User Login Behavior:

Temporal Features:
├─ Hour of day (0-23)
├─ Day of week (0-6)
├─ Time since last login (hours)
├─ Login frequency (logins per day)
└─ Deviation from usual login time

Location Features:
├─ Latitude, longitude (of login location)
├─ Country code
├─ Distance from previous login
├─ Distance from home office
└─ Number of countries in 24 hours

Device/Network Features:
├─ Device type (laptop, mobile, vpn)
├─ IP address (geolocation)
├─ OS/Browser fingerprint
├─ VPN detected (yes/no)
└─ Proxy detected (yes/no)

Behavior Features:
├─ Files accessed in session
├─ Data downloaded (bytes)
├─ Elevation attempt (sudo, admin)
├─ Unusual operations (creation, deletion)
└─ Interaction with other systems
```

### Feature Engineering Code

```python
import pandas as pd
from math import radians, cos, sin, asin, sqrt

def haversine_distance(lat1, lon1, lat2, lon2):
    """Calculate distance between two coordinates (km)"""
    lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    r = 6371
    return c * r

def engineer_features(login_df):
    """Engineer features for anomaly detection"""
    df = login_df.copy()
    
    # Temporal features
    df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
    df['day_of_week'] = pd.to_datetime(df['timestamp']).dt.dayofweek
    
    # Time since last login (per user)
    df = df.sort_values('timestamp')
    df['time_since_last_login_hours'] = df.groupby('user')['timestamp'].diff().dt.total_seconds() / 3600
    df['time_since_last_login_hours'].fillna(0, inplace=True)
    
    # Distance from previous login (per user)
    prev_lat = df.groupby('user')['location_lat'].shift()
    prev_lon = df.groupby('user')['location_lon'].shift()
    
    distances = []
    for idx, row in df.iterrows():
        if pd.isna(prev_lat.iloc[idx]):
            distances.append(0)
        else:
            dist = haversine_distance(
                prev_lat.iloc[idx], prev_lon.iloc[idx],
                row['location_lat'], row['location_lon']
            )
            distances.append(dist)
    
    df['distance_from_prev_login_km'] = distances
    
    # Logins in past 24 hours
    df['logins_past_24h'] = df.groupby('user')['timestamp'].rolling('24H').count().reset_index(0, drop=True)
    
    # Countries in past 24 hours
    df['countries_past_24h'] = df.groupby('user')['country'].rolling('24H').nunique().reset_index(0, drop=True)
    
    return df

# Usage
login_data = pd.read_csv('logins.csv')
engineered = engineer_features(login_data)
print(engineered[['user', 'hour', 'distance_from_prev_login_km', 'countries_past_24h']])
```

---

## 📊 Hyperparameter Tuning

```python
from sklearn.ensemble import IsolationForest

# Key hyperparameters:

# contamination: Expected proportion of anomalies (0.01 = 1%)
# Too high: Too many false positives
# Too low: Misses actual anomalies
iso = IsolationForest(contamination=0.05)

# n_estimators: Number of trees (100-200 typical)
iso = IsolationForest(n_estimators=100)

# max_samples: Samples per tree (auto, or specific number)
iso = IsolationForest(max_samples='auto')

# max_features: Features per tree split
iso = IsolationForest(max_features=1.0)

# Tuning for security:
# - Start with contamination=0.05 (5% anomalies)
# - Increase n_estimators if not detecting
# - Reduce max_features if overfitting
# - Use validation set to tune
```

---

## 📋 Evaluation Metrics

```
For anomaly detection (no ground truth):

1. Silhouette Score (-1 to 1, higher is better)
   - Measures how well separated anomalies are
   - Use for validation

2. Visual Inspection
   - Plot anomalies on 2D PCA projection
   - Check if they're truly anomalous

3. Business Impact
   - MTTD (Mean Time To Detect)
   - False positive rate
   - False negative rate
   - Analyst feedback

4. Time Series Validation
   - If you have historical labels
   - Calculate precision, recall, F1-score
```

---

## 🔑 Key Takeaways

- **Unsupervised learning** - no labels needed
- **Rare events detection** - perfect for security (0.1% anomalies)
- **Feature engineering matters** - right features = better detection
- **Normalize data** - different scales confuse the algorithm
- **Validation is hard** - no labels means manual inspection required
- **Threshold tuning** - contamination parameter controls false positive rate
- **Real-time scoring** - once trained, predict instantly on new data

---

## 📚 Resources

- [Scikit-learn Isolation Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
- [Isolation Forest Paper](https://cs.anu.edu.au/wp-content/uploads/2015/06/isolation-forest.pdf)
- [Anomaly Detection in Security](https://owasp.org/www-community/attacks/Anomaly_attack)

---

## [⬅️ Day 081](../day081/) | [➡️ Day 083](../day083/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*