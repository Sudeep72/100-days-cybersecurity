# Day 091 - Explainable Alert Triage Using LLMs (Inspired by LogREx)

> **Challenge:** 100 Days of Cybersecurity | **Phase:** AI × Security | **Difficulty:** Intermediate-Advanced

---

## 🧠 The Concept

**Alert Triage** = Prioritizing thousands of alerts to identify real threats.

**Problem:** 10,000 alerts/day, 5 analysts.

**Old approach:** ML classifier (binary: real or false positive).

**New approach:** LLM explains WHY it's a real threat (interpretable triage).

This is inspired by ideas explored in my LogREx research, where Knowledge Graphs and Large Language Models are combined to make anomaly detection more explainable.

---

## 🚨 The Alert Triage Problem

```
SIEM generates 10,000 alerts/day:

[08:00] Failed login from IP 203.0.113.1 → False positive (user locked out)
[08:15] Unusual file access from process svchost.exe → Real threat (malware)
[08:30] Potential SQL injection in logs → False positive (test query)
[08:45] Outbound connection to blacklisted IP → Real threat (botnet C2)
[09:00] Process execution from temp directory → Real threat (malware)
... (9,995 more)

Analyst needs to:
├─ Review alerts
├─ Identify false positives
├─ Prioritize real threats
├─ Investigate root cause
└─ Respond

Time per alert: 15 minutes
Alerts per analyst: 4 per hour = 32 per 8-hour day
Coverage: 32/10,000 = 0.3%

99.7% of alerts uninvestigated.
```

---

## 🤖 Using LLM for Explainable Triage

### Approach 1: LLM as Classifier

```python
from anthropic import Anthropic

class AlertTriageWithLLM:
    def __init__(self):
        self.client = Anthropic()
    
    def triage_alert(self, alert_dict):
        """
        Triage alert using Claude with explanations
        """
        
        prompt = f"""
        Analyze this security alert and determine if it's a real threat 
        or a false positive. Explain your reasoning.
        
        Alert Details:
        - Type: {alert_dict['type']}
        - Source IP: {alert_dict['source_ip']}
        - Destination: {alert_dict['destination']}
        - Time: {alert_dict['timestamp']}
        - Process: {alert_dict['process']}
        - Context: {alert_dict['context']}
        
        Provide:
        1. Classification: Real Threat / False Positive / Suspicious
        2. Confidence: 0-100%
        3. Explanation: Why this classification
        4. Risk Score: 0-10
        5. Recommended Action: Investigate / Block / Dismiss / Monitor
        """
        
        response = self.client.messages.create(
            model="claude-opus-4-6",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return response.content[0].text
    
    def batch_triage(self, alerts):
        """Triage multiple alerts"""
        results = []
        for alert in alerts:
            result = {
                'alert_id': alert['id'],
                'triage': self.triage_alert(alert),
                'timestamp': datetime.now()
            }
            results.append(result)
        return results
```

### Approach 2: Structured Output (Claude Format)

```python
import json

def triage_with_structure(alert):
    """
    Get structured JSON response from Claude
    """
    
    prompt = f"""
    Analyze this security alert. Respond in JSON format.
    
    Alert:
    Type: {alert['type']}
    Source IP: {alert['source_ip']}
    Process: {alert['process']}
    Action: {alert['action']}
    
    Return JSON:
    {{
        "classification": "real_threat" | "false_positive" | "suspicious",
        "confidence": 0-100,
        "risk_score": 0-10,
        "explanation": "...",
        "indicators": ["indicator1", "indicator2"],
        "recommendation": "investigate" | "block" | "monitor" | "dismiss",
        "urgency": "critical" | "high" | "medium" | "low"
    }}
    """
    
    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=300,
        messages=[{"role": "user", "content": prompt}]
    )
    
    # Parse JSON response
    try:
        return json.loads(response.content[0].text)
    except:
        return None
```

### Approach 3: Knowledge Graph–Enhanced LLM Triage (Inspired by LogREx)

```python
class KnowledgeGraphAlertTriager:
    def __init__(self):
        self.kg = self.load_knowledge_graph()
        self.summarizer = SummarizerLLM()
        self.reasoner = ReasoningLLM()

    def load_knowledge_graph(self):
        """
        Load a Knowledge Graph built from:
        - Historical security alerts
        - Asset inventory
        - User identities
        - Threat intelligence feeds
        - MITRE ATT&CK techniques
        - Vulnerability data
        """
        return KnowledgeGraph()

    def triage_alert(self, alert):

        # Step 1: Retrieve related entities
        context = self.kg.retrieve_context(alert)

        # Step 2: Enrich alert with security context
        enriched_context = {
            "asset_criticality": context.asset,
            "related_alerts": context.previous_alerts,
            "mitre_techniques": context.attack_mapping,
            "threat_intelligence": context.threat_feed,
            "user_activity": context.user_history
        }

        # Step 3: Summarize the alert
        summary = self.summarizer.generate(
            alert=alert,
            context=enriched_context
        )

        # Step 4: Perform contextual reasoning
        result = self.reasoner.analyze(
            summary=summary,
            context=enriched_context
        )

        return {
            "classification": result.label,
            "confidence": result.confidence,
            "risk_score": result.risk_score,
            "reasoning": result.explanation,
            "recommended_action": result.action,
            "priority": result.priority
        }


# Example

triager = KnowledgeGraphAlertTriager()

alert = {
    "type": "Suspicious PowerShell Execution",
    "host": "WS-104",
    "user": "alice",
    "process": "powershell.exe",
    "command": "EncodedCommand ...",
    "destination_ip": "203.0.113.45"
}

result = triager.triage_alert(alert)

print(result)
```

### Workflow

```
Incoming Security Alert
            │
            ▼
Retrieve Knowledge Graph Context
            │
            ▼
Context Enrichment
(Assets • Users • Threat Intel • MITRE ATT&CK)
            │
            ▼
Summarizer LLM
            │
            ▼
Reasoning LLM
            │
            ▼
Threat Classification
+
Risk Score
+
Human-readable Explanation
+
Recommended Action
```

### Why this approach?

Instead of analyzing an alert in isolation, the LLM reasons over additional security context.

Example:

```
Alert:
PowerShell executed with Base64-encoded command

Knowledge Graph Context:
├─ Host belongs to Finance department
├─ User never uses PowerShell
├─ Similar alert observed yesterday
├─ Destination IP linked to C2 infrastructure
└─ Maps to MITRE ATT&CK T1059

LLM Output:
Classification: Real Threat

Reasoning:
"Encoded PowerShell execution from a finance workstation,
combined with communication to a known malicious IP and
previous related alerts, strongly indicates malicious
command execution."

Recommendation:
Isolate host immediately and investigate lateral movement.
```

This mirrors the reasoning-first philosophy behind **LogREx**—using structured contextual knowledge together with Large Language Models to produce security decisions that analysts can understand, validate, and act upon.

## 📊 Example Impact of LLM-Assisted Alert Triage


### Before LLM Triage

```
Metrics:
├─ Alerts per day: 10,000
├─ Manual review: 0.3% (30 alerts)
├─ False positive rate: 80% (of reviewed)
├─ True positive rate: 20% (of reviewed)
├─ Mean time to detect: 200 days
├─ Breaches from missed alerts: 5 per quarter

Analyst experience:
├─ Overwhelming (can't keep up)
├─ Burnout (reviewing noise)
├─ Context switching (jumps between alerts)
└─ Low morale (feel ineffective)
```

### After LLM Triage

```
Metrics:
├─ Alerts per day: 10,000
├─ LLM pre-filters: 80% likely false positives
├─ Manual review: 2,000 high-priority alerts
├─ False positive rate: 20% (of LLM-filtered)
├─ True positive rate: 80% (of LLM-filtered)
├─ Mean time to detect: 2 hours
├─ Breaches from missed alerts: < 1 per quarter

Analyst experience:
├─ Manageable (can review 2,000/day)
├─ Reduced burnout (less noise)
├─ Better focus (high-confidence alerts)
├─ High effectiveness (catch threats)
└─ Morale: Much improved

Improvement:
├─ MTTD: 200 days → 2 hours (100x faster)
├─ True positives: 20% → 80% (4x better)
├─ Analyst throughput: 30/day → 2,000/day (66x)
```

---

## 🔗 How This Connects to LogREx

My LogREx research combines **Knowledge Graphs** and **Large Language Models** to perform explainable anomaly detection on system logs.

The same idea naturally extends to alert triage.

```
LogREx

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
Human-readable Explanation
```

```
LLM Alert Triage

Security Alert
        │
        ▼
Context Enrichment
        │
        ▼
Knowledge Graph
        │
        ▼
LLM Reasoning
        │
        ▼
Threat Priority
+
Analyst Explanation
```

Similarity

```
✓ Both use structured contextual knowledge

✓ Both leverage LLM reasoning

✓ Both generate human-readable explanations

✓ Both improve analyst decision making

✓ Both focus on explainable AI for cybersecurity
```

Instead of only assigning a probability score, both approaches provide reasoning that analysts can understand, validate, and act upon.

## 🛡️ Key Insights

```
Why LLM for Triage:

1. Contextual Understanding
   ├─ LLM understands threat context
   ├─ Can connect dots (alert A + B = campaign C)
   ├─ Can explain reasoning
   └─ More than just "probability"

2. Explainability
   ├─ Analyst trusts decision with explanation
   ├─ Can verify reasoning
   ├─ Can catch errors
   └─ Can retrain on mistakes

3. Efficiency
   ├─ Pre-filter noise automatically
   ├─ Analyst focuses on high-quality alerts
   ├─ Higher true positive rate
   └─ Faster response

4. Learning
   ├─ Analyst feedback improves prompts
   ├─ Patterns extracted over time
   ├─ System improves continuously
   └─ Adaptation to new threats
```

---

## 🔑 Key Takeaways

- **LLMs excel at contextual reasoning** - not just classification
- **Knowledge Graphs enrich alerts with security context**
- **Explainable AI builds analyst trust**
- **Hybrid AI + Human workflows outperform automation alone**
- **Context-aware triage reduces analyst fatigue**
- **Inspired by LogREx** - using LLM reasoning and structured knowledge to make AI decisions understandable
- **Future SOCs will prioritize explainable AI over black-box predictions**

---

## 📚 Resources

- [My LogREx Paper](https://link.springer.com/chapter/10.1007/978-3-032-18132-9_3) (ICCIS 2025)
- [LLM for Security Tasks](https://arxiv.org/abs/2607.18496)
- [Interpretable ML in Security](https://arxiv.org/html/2407.04009v1)

---

## [⬅️ Day 090](../day090/) | [➡️ Day 092](../day092/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*

**Note:** This project extends ideas explored in my LogREx research. While LogREx applies Knowledge Graphs and Large Language Models to explain anomalies in system logs, this example shows how the same reasoning-first approach can be adapted for security alert triage helping analysts understand not only what is suspicious, but also why it deserves attention.