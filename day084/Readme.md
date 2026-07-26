# Day 084 - Log Anomaly Detection: DeepLog vs LogREx

> **Challenge:** 100 Days of Cybersecurity | **Phase:** AI × Security | **Difficulty:** Advanced

---

## 🧠 The Concept

Logs are the story of what happened on a system.

**Normal behavior:** Predictable log sequence
**Attack behavior:** Unusual log sequence

**Log Anomaly Detection** = Find unusual sequences in logs.

Two approaches:
1. **DeepLog** (LSTM-based) - Learns sequences using deep learning
2. **LogREx** (my research!) - Extracts rules + detects anomalies

---

## 📖 Why Log Analysis?

### The Problem

```
System generates millions of logs per day:

/var/log/auth.log (authentication)
/var/log/syslog (system)
/var/log/apache2/access.log (web server)
/var/log/application.log (custom app)

Human reading: Impossible (millions of logs)
Simple patterns: Miss novel attacks
Signatures: Only known attacks

Solution: ML to find anomalies automatically.
```

### Log Sequence Example

```
Normal Login Sequence:
1. SSH connection initiated (sshd[1234]: New client)
2. User auth attempt (sshd[1234]: Authentication attempt)
3. Password verified (sshd[1234]: Accepted password)
4. Session opened (sshd[1234]: Session opened)
5. User command executed (bash: command)
6. Session closed (sshd[1234]: Session closed)

Attack Sequence (Brute Force):
1. SSH connection (sshd[1234]: New client)
2. Auth failed (sshd[1234]: Failed password for root)
3. SSH connection (sshd[1235]: New client)  ← Different connection
4. Auth failed (sshd[1235]: Failed password for root)
5. SSH connection (sshd[1236]: New client)  ← Another connection
6. Auth failed (sshd[1236]: Failed password for root)
... (repeated 1000 times in 10 minutes)

Detection: See repeated "Failed password" pattern → ANOMALY
```

---

## 🔍 DeepLog Approach

### How DeepLog Works

```
DeepLog = LSTM (Long Short-Term Memory) neural network

1. Training Phase:
   ├─ Collect normal logs
   ├─ Extract log sequences
   ├─ Train LSTM to predict next log entry
   ├─ Learn: Log sequence A → Log B → Log C (likely)
   └─ Learn: Unusual sequences have low probability

2. Detection Phase:
   ├─ New log arrives: Log X
   ├─ LSTM predicts: What should come next?
   ├─ If actual log matches prediction: Normal
   ├─ If actual log doesn't match: ANOMALY
   └─ Confidence score: How much does it deviate?
```

### DeepLog Example

```
Training (Normal Logs):
├─ Connection → Auth → Success → Session → Close (seen 1000 times)
├─ Connection → Auth → Success → Command → Close (seen 500 times)
└─ Connection → Auth → Success → Transfer → Close (seen 300 times)

LSTM learns:
├─ After "Connection", expect "Auth" (99% probability)
├─ After "Auth", expect "Success" (95% probability)
├─ After "Success", expect "Session" or "Command" or "Transfer"
└─ Unusual sequences get low probability

Detection (Attack Logs):
├─ Connection (normal)
├─ Auth (normal)
├─ Auth (unusual! only happens after Success normally)
├─ Auth (anomaly score: 0.8/1.0 - high deviation)
└─ ALERT: Sequence anomaly detected
```

### DeepLog Code

```python
import numpy as np
from keras.models import Sequential
from keras.layers import LSTM, Dense, Dropout

# Prepare log data
log_sequences = [
    [1, 2, 3, 4, 5],      # Normal sequence
    [1, 2, 3, 6, 7],      # Normal variant
    [1, 2, 3, 4, 5, 8],   # Attack (extra log at end)
    [1, 2, 3, 4, 5],      # Normal
]

# Create training data
X = []
y = []
for seq in log_sequences:
    for i in range(len(seq) - 1):
        X.append(seq[:i+1])
        y.append(seq[i+1])

# Pad sequences
X = np.array([np.pad(seq, (10-len(seq), 0)) for seq in X])
y = np.array(y)

# Build LSTM model
model = Sequential([
    LSTM(64, input_shape=(10, 1), return_sequences=True),
    Dropout(0.2),
    LSTM(64),
    Dropout(0.2),
    Dense(32, activation='relu'),
    Dense(10, activation='softmax')  # 10 possible next logs
])

model.compile(loss='sparse_categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
model.fit(X, y, epochs=10, batch_size=32)

# Detection
def detect_anomaly(log_sequence):
    X_test = np.pad(log_sequence, (10-len(log_sequence), 0))
    X_test = X_test.reshape(1, 10, 1)
    
    predictions = model.predict(X_test)
    next_log_prob = np.max(predictions)
    
    if next_log_prob < 0.3:  # Low probability = anomaly
        return True, next_log_prob
    return False, next_log_prob
```

---

## 🧠 LogREx Approach (My Research!)

### How LogREx Works

```
LogREx = Reasoning-Enabled LLM + Knowledge Graph

1. Knowledge Graph Generation
   ├─ Parse labeled system logs
   ├─ Extract components, events and relationships
   ├─ Build structured Knowledge Graphs
   └─ Capture contextual relationships between log events

2. Summarizer LLM
   ├─ Fine-tuned Mistral-7B
   ├─ Converts long log blocks
   ├─ Generates concise summaries
   └─ Preserves important security context

3. Reasoning LLM
   ├─ Receives summaries + Knowledge Graph context
   ├─ Performs anomaly reasoning
   ├─ Classifies logs as Normal / Anomalous
   └─ Generates human-readable explanations

4. Output
   ├─ Anomaly Label
   ├─ Confidence
   ├─ Reasoning
   └─ Explainable security alert
```

### LogREx Pipeline

```
Raw System Logs
        │
        ▼
Knowledge Graph Generation
        │
        ▼
Summarizer LLM
        │
        ▼
Reasoning LLM
        │
        ▼
Anomaly Classification
+
Explainable Reasoning
```

### Why Knowledge Graphs?

Instead of treating logs as plain text, LogREx models relationships between:

```
Component
     │
     ▼
 Event
     │
     ▼
 Source ───► Destination
```

The Knowledge Graph gives the LLM structured context, allowing it to reason about how different system components interact instead of only learning log sequences.

### LogREx Advantages

```
vs. DeepLog

LogREx:
✓ Explainable AI
✓ Generates human-readable reasoning
✓ Uses Knowledge Graph context
✓ Better contextual understanding
✓ Higher anomaly detection accuracy
✓ Easier for SOC analysts to investigate alerts

DeepLog:
✓ Learns log sequences automatically
✓ Good temporal modeling
✗ Black-box predictions
✗ Doesn't explain why an alert occurred
✗ Limited contextual reasoning
```

### LogREx Architecture

```python
def logrex_pipeline(raw_logs):

    # Step 1: Build Knowledge Graph
    knowledge_graph = build_knowledge_graph(raw_logs)

    # Step 2: Summarize logs
    summary = summarizer_llm(raw_logs)

    # Step 3: Reason over logs using KG context
    anomaly, explanation = reasoning_llm(
        summary=summary,
        knowledge_graph=knowledge_graph
    )

    return {
        "classification": anomaly,
        "reasoning": explanation
    }
```

### Experimental Results

```
Binary Classification (HDFS Dataset)

Fine-tuned Mistral-7B
├─ Precision : 0.662
├─ Recall    : 0.629
└─ F1 Score  : 0.644

LogREx (Mistral + Knowledge Graph)
├─ Precision : 0.813
├─ Recall    : 0.929
└─ F1 Score  : 0.867
```

Compared with existing approaches:

```
Model          F1 Score

Logsy          0.799
DeepLog        0.814
LogRobust      0.852
LogREx         0.867   ✅ Best
```

### Key Innovation

Unlike traditional log anomaly detection systems that only classify anomalies,

**LogREx explains *why* an anomaly occurred.**

It combines:

• Knowledge Graphs for structured context

• Fine-tuned Mistral-7B models

• LLM-based reasoning

to produce accurate, explainable security alerts that SOC analysts can understand and act upon.

## 📊 Evaluation Metrics

```
For log anomaly detection:

Precision = True Positives / (True Positives + False Positives)
├─ Of detected anomalies, how many are real attacks?
└─ Goal: > 95% (few false alarms)

Recall = True Positives / (True Positives + False Negatives)
├─ Of real attacks, how many were detected?
└─ Goal: > 90% (catch most attacks)

F1-Score = 2 × (Precision × Recall) / (Precision + Recall)
├─ Balance between precision and recall
└─ Goal: > 0.90

Mean Time To Detect (MTTD)
├─ How fast after attack starts?
├─ Goal: < 5 minutes
└─ DeepLog: Immediate (per log entry)
└─ LogREx: Immediate (rule matching)

Evaluation Dataset:
├─ HDFS logs (Hadoop Distributed File System)
├─ BGL logs (Blue Gene/L supercomputer)
├─ OpenStack logs
└─ Custom enterprise logs
```

---

## 🔑 Key Takeaways

- **Sequence matters** - logs have temporal order
- **DeepLog catches complex patterns** - LSTM learns automatically
- **LogREx is interpretable** - explicit rules, explains decisions
- **Hybrid approach works best** - DeepLog + LogREx together
- **Template extraction is critical** - garbage in = garbage out
- **Real-time detection possible** - MTTD < 1 minute
- **False positives matter** - analysts will ignore noisy alerts

---

## 📚 Resources

- [DeepLog Paper](https://dl.acm.org/doi/10.1145/3133956.3134015)
- [LogREx Paper](https://link.springer.com/chapter/10.1007/978-3-032-18132-9_3)
- [Log Anomaly Detection Survey](https://arxiv.org/abs/2207.03820)

---

## [⬅️ Day 083](../day083/) | [➡️ Day 085](../day085/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*

**Note:** LogREx is my published research (with Riya, under Prof. Arun Vetriselvi). This day bridges my academic work with practical security implementation.