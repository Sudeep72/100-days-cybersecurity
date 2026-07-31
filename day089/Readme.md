# Day 089 - Adversarial ML: Evading AI-Based Detectors

> **Challenge:** 100 Days of Cybersecurity | **Phase:** AI × Security | **Difficulty:** Advanced

---

## 🧠 The Concept

**Adversarial ML** = Crafting inputs to fool AI systems.

Attacker knows ML model is defending.

Attacker creates inputs that:
- Evade malware detectors
- Bypass spam filters
- Fool intrusion detection
- Confuse threat classification

```
Normal malware: Detected by ML
Adversarially crafted malware: Bypasses ML
```

**The arms race:** Attackers vs. ML detectors.

---

## 🎯 How Adversarial Examples Work

### Basic Concept

```
ML Classifier Trained to Detect Malware:

Input Features: [file_size, entropy, api_calls, imports, ...]

Training Data:
├─ Benign files → Output: 0 (not malware)
├─ Malware → Output: 1 (malware)
└─ Learns decision boundary

Decision Boundary:
"If entropy > 0.8 AND imports > 100 → MALWARE"

Normal Malware:
├─ Entropy: 0.9 ✓
├─ Imports: 150 ✓
└─ Detected: 1 (MALWARE)

Adversarial Malware (same functionality, different encoding):
├─ Entropy: 0.6 ✗ (add dead code to reduce entropy)
├─ Imports: 50 ✗ (obfuscate imports)
└─ Detected: 0 (NOT MALWARE) ← Evasion successful!
```

### Why Adversarial Examples Fool ML

```
ML Decision Surface:

Benign (0)          Malware (1)
  ~~~~                  ~~~~
    ~~~~             ~~~~
       ~~~~~~~~~~~
  
Boundary is learned pattern, not true distinction.

Attacker finds "boundary crossing points":
├─ Minimal change to features
├─ Crosses decision boundary
├─ Changes prediction
└─ But functionality unchanged

Example: Add padding bytes to PE file
├─ Changes file size (feature)
├─ Doesn't affect execution (functionality)
├─ Fools ML (thinks it's benign)
└─ Actually still malware
```

---

## 💀 Adversarial Attack Techniques

### 1. Feature Manipulation

```
Malware Detection Features:
├─ File size
├─ Entropy
├─ Number of API calls
├─ Import count
├─ String patterns
└─ Executable sections

Attack: Malware obfuscation

Normal Malware:
```c
// Decrypt malicious string
char cmd[] = "cmd.exe";
// Execute command
WinExec(cmd);
```
Features: High entropy, many imports, dangerous API calls
Detection: MALWARE ✓

Adversarial Malware:
```c
// Add dead code
for(int i=0; i<1000000; i++) { x++; }

// Dynamically construct string character by character
char cmd[256];
cmd[0] = 'c'; cmd[1] = 'm'; cmd[2] = 'd';
// ... more obfuscation

// Indirect API call
void (*func_ptr)() = &WinExec;
func_ptr(cmd);
```
Features: Lower entropy (dead code), indirect imports (obfuscation)
Detection: BENIGN ✗ (evasion successful)
```

### 2. Adversarial Perturbation

```
Original Spam Email:
"Click here for free prize!"

Features Used by Spam Detector:
├─ Keyword frequency: "free", "click", "win"
├─ Sender reputation: Unknown
├─ URL shortener: Yes
├─ Urgency language: Yes

Detection: SPAM ✓

Adversarial Email (same intent, evades detector):
"Click hre for free prize!" (typo: "hre" not "click")
"C1ick h3r3 for fr33 pr1z3!" (character substitution)
"Get your complimentary gift now!" (synonym replacement)

Features:
├─ Keyword frequency: Lower (typos break matching)
├─ Sender reputation: Same (unchanged)
├─ URL shortener: Same (unchanged)
├─ Urgency language: Removed

Detection: NOT SPAM ✗ (evasion successful)
```

### 3. Evasion of Neural Network Detectors

```
Intrusion Detection System (Neural Network):

Trained on: Network flows (source IP, dest IP, port, protocol, bytes, packets)

Normal Flow:
[192.168.1.1, 8.8.8.8, 53, UDP, 512, 2] → Normal ✓

Attacker Flow (port scan):
[192.168.1.1, 10.0.0.*, 22, TCP, 100, 10000] → Detected ✓

Adversarial Flow (same port scan, evaded):
[192.168.1.1, 10.0.0.*, 53, UDP, 8192, 10000]
               ↑ Change port to 53 (legitimate DNS)
                      ↑ Change protocol to UDP (legitimate DNS)
                                   ↑ Increase payload (looks like data transfer)

Results:
├─ Still scanning (same attacker goal)
├─ Same ports discovered
├─ But looks like legitimate DNS queries
└─ Detector confused: "Looks normal" ✗

Attacker successfully evaded ML detector.
```

### 4. Reverse-Engineering Detector

```
Attacker's Goal: Understand ML detector to craft evasion

Method 1: Black-Box Probing
├─ Send test inputs, observe decisions
├─ Learn decision boundary through experimentation
├─ Eventually understand "what gets flagged"
└─ Craft adversarial examples

Example: Email Spam Detector
├─ Send: "free" → SPAM
├─ Send: "complimentary" → HAM
├─ Send: "prize" → SPAM
├─ Send: "reward" → ?
├─ Continue until boundary mapped
└─ Use map to evade

Method 2: Gradient-Based Attack (if attacker has model)
├─ Compute gradients of loss w.r.t. input
├─ Find direction to cross decision boundary
├─ Perturb input minimally in that direction
├─ Evasion crafted mathematically

Method 3: Substitute Model
├─ Train similar model on public data
├─ Assume it learns similar decision boundary
├─ Use to generate adversarial examples
├─ Test against real detector
└─ Often works (transfer learning)
```

---

## 🛡️ Defenses Against Adversarial Attacks

### 1. Adversarial Training

```
Normal Training:
1. Train on benign + malware samples
2. Model learns: "These features = malware"
3. Model can be evaded by perturbing features

Adversarial Training:
1. Generate adversarial examples (intentionally fool the model)
2. Add adversarial examples to training data
3. Train model on: benign + malware + adversarial_malware
4. Model learns: "These features = malware (even if obfuscated)"
5. Model is harder to evade

Downside:
├─ Computationally expensive
├─ Need to anticipate evasion techniques
├─ Attacker can adapt to adversarial training
└─ Arms race continues
```

### 2. Ensemble Detectors

```
Single Detector:
├─ One model → one decision boundary
├─ If attacker crosses boundary → evasion
└─ Single point of failure

Ensemble (Multiple Detectors):

Detector 1 (Decision Tree): file_size, entropy
Detector 2 (Neural Network): API calls, imports
Detector 3 (SVM): Strings, patterns
Detector 4 (Random Forest): Entropy, file sections

Final Decision: Majority vote

Attack: Evade Detector 1
├─ Attacker manipulates features to fool Tree
├─ But Detectors 2, 3, 4 still detect
├─ Majority vote: MALWARE ✓

Attack: Evade All Detectors
├─ Much harder (would need to fool 4 independent models)
├─ Requires understanding all 4 decision boundaries
├─ More computational cost
└─ Ensemble provides robustness
```

### 3. Behavioral Analysis

```
Feature-Based Detection (Vulnerable):
├─ File size, entropy, imports
├─ Can be obfuscated
└─ Evadable

Behavioral Detection (Harder to evade):
├─ Execute file in sandbox
├─ Observe: Does it try to steal passwords?
├─ Observe: Does it try to encrypt files?
├─ Observe: Does it try to propagate?
├─ Observe: Does it try to hide?
└─ Actual behavior harder to hide

Attacker can hide features, but harder to hide behavior.

Limitation: Slow (requires execution + monitoring)
├─ Can't block instantly
├─ Requires sandbox infrastructure
└─ Adds latency
```

### 4. Human-in-the-Loop

```
Fully Automated:
├─ ML detector makes decision
├─ No human review
└─ If evasion works, attack succeeds

Human-in-the-Loop:
├─ ML detector flags "borderline" cases
├─ Human analyst reviews
├─ Human decides (can catch adversarial examples)
└─ Hybrid approach

Tradeoff:
├─ Slower (requires human)
├─ More expensive (pays analyst)
├─ But catches more attacks (humans catch nuance)
└─ Works well for high-risk decisions
```

---

## 📊 Real-World Examples

### Example 1: Evading Malware Detector

```
Antivirus uses ML detector for unknown files.

Original Malware:
├─ Entropy: 7.8 (encrypted code)
├─ Imports: 200 (many API calls)
├─ Sections: 5 (multiple executable)
└─ Detection: MALWARE ✓

Adversarial Malware:
├─ Add 100MB of zeros (padding)
├─ Entropy: 1.2 (lots of zeros)
├─ Compress imports (indirect calls)
├─ Imports: 50 (hidden)
├─ Sections: 1 (consolidated)
└─ Detection: NOT MALWARE ✗

Functionality: Identical (both execute payload)
Evasion: Successful (beats ML detector)
```

### Example 2: Evading Spam Filter

```
Original Spam:
"FREE MONEY NOW! Click here for $10,000 PRIZE!"

Detection: SPAM (multiple trigger words)

Adversarial Spam:
"FREE MONEY NOW! Click here for $10,000 PRIZE!"
(But with HTML entities: Fr33 M0n3y, Cl1ck, Pr1z3)
(Or: "No Cost Money Soon! Contact us for Reward!")

Techniques:
├─ Character substitution (3 for E, 0 for O)
├─ Synonym replacement (No Cost = Free)
├─ Whitespace insertion (F r e e)
├─ HTML encoding (&#70;ree)
└─ Image embedding (words as images)

Detection: NOT SPAM ✗ (evaded)
Result: Spam delivered (user sees "Free money" when rendered)
```

---

## 🔑 Key Takeaways

- **ML detectors have decision boundaries** - attackers find and cross them
- **Features can be obfuscated** - adversarial examples manipulate features
- **Ensemble defenses better** - single model easier to evade
- **Behavioral analysis harder to evade** - actual behavior harder to hide
- **Arms race is real** - attacker innovation drives defender innovation
- **Perfect defense impossible** - trade-offs between robustness and usability
- **Humans still important** - borderline cases need human judgment

---

## 📚 Resources

- [Adversarial ML Survey](https://arxiv.org/abs/1810.00069)
- [Evasion Attacks on Classifiers](https://arxiv.org/abs/1708.06131)
- [Adversarial Training Paper](https://arxiv.org/abs/1412.6572)

---

## [⬅️ Day 088](../day088/) | [➡️ Day 090](../day090/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*