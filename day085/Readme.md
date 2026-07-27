# Day 085 - Phishing Detection with NLP

> **Challenge:** 100 Days of Cybersecurity | **Phase:** AI × Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Phishing = Fraudulent emails pretending to be legitimate.

**NLP (Natural Language Processing)** = Analyze text to detect phishing.

**Key insight:** Phishing emails have linguistic patterns.

- Urgency ("Act now!")
- Requests for credentials ("Verify your account")
- Suspicious links/attachments
- Grammatical errors (non-native language)

---

## 🎣 Phishing Attacks by Numbers

### The Problem

```
Statistics:
├─ 90% of data breaches start with phishing
├─ 3.4 billion phishing emails sent per day
├─ 15% of people click phishing links
├─ $7.2 billion lost to phishing in 2023
└─ Average cost per breach: $4.5M

Why effective:
├─ Humans are the weakest link
├─ ML detects malware, not social engineering
├─ Personalized phishing (spear phishing) harder to detect
└─ Email filtering alone catches ~95% (5% slip through)
```

### Types of Phishing

```
1. Generic Phishing
   ├─ Mass emails to random addresses
   ├─ "Dear valued customer..."
   ├─ "Verify your account"
   └─ Detection: Easy (obvious patterns)

2. Spear Phishing
   ├─ Targeted to specific people
   ├─ "Hi John, regarding project X..."
   ├─ Uses company/personal context
   └─ Detection: Hard (looks legitimate)

3. Business Email Compromise (BEC)
   ├─ Impersonates CEO/Executive
   ├─ "Transfer $500K to vendor account..."
   ├─ Urgent tone
   └─ Detection: Very hard (from trusted domain)

4. Clone Phishing
   ├─ Exact copy of legitimate email
   ├─ One link changed to malicious
   ├─ Same formatting/signature
   └─ Detection: Very hard (nearly identical)
```

---

## 🔍 NLP Features for Phishing Detection

### Email Content Features

```
Textual Features:
├─ Word frequency (urgent, verify, confirm, action)
├─ Sentiment (positive, negative, neutral)
├─ Email length (phishing often shorter)
├─ Readability score (phishing less professional)
├─ Presence of questions (phishing asks for info)
└─ All caps usage (URGENT, VERIFY, ACT NOW)

Linguistic Red Flags:
├─ Urgency words: "urgent", "immediately", "today", "now"
├─ Authority mimicry: "From: admin@company.com"
├─ Requests: "click here", "verify", "confirm", "update"
├─ Threats: "account closed", "suspended", "compromised"
├─ Unusual grammar: "Please to click..." (non-native)
└─ Hyperlinks: Hidden URLs, mismatched domains

URL/Link Features:
├─ Domain reputation (is it blacklisted?)
├─ URL structure (legitimate vs. fake)
├─ Shortened URLs (hides true destination)
├─ Domain similarity (paypa1.com vs. paypal.com)
└─ Presence of IP addresses (unusual for legitimate)

Attachment Features:
├─ Executable files (.exe, .bat, .scr)
├─ Macro-enabled docs (.doc with VBA)
├─ Double extensions (.pdf.exe)
├─ Suspicious MIME types
└─ File size anomalies
```

### Feature Extraction Code

```python
import re
from textblob import TextBlob
from sklearn.feature_extraction.text import TfidfVectorizer

def extract_phishing_features(email_body, sender, urls, attachments):
    """Extract NLP features for phishing detection"""
    
    features = {}
    
    # Textual features
    blob = TextBlob(email_body)
    features['word_count'] = len(email_body.split())
    features['sentence_count'] = len(blob.sentences)
    features['avg_word_length'] = sum(len(word) for word in email_body.split()) / len(email_body.split())
    
    # Urgency indicators
    urgency_words = ['urgent', 'immediately', 'act now', 'verify', 'confirm', 'update', 'click here', 'suspended']
    features['urgency_score'] = sum(1 for word in urgency_words if word.lower() in email_body.lower())
    
    # Sentiment
    features['polarity'] = blob.sentiment.polarity  # -1 (negative) to 1 (positive)
    features['subjectivity'] = blob.sentiment.subjectivity  # 0 (objective) to 1 (subjective)
    
    # Grammar/spelling
    features['spelling_errors'] = len([word for word in blob.words if word not in dictionary])
    
    # All caps usage
    words = email_body.split()
    caps_words = [w for w in words if w.isupper() and len(w) > 1]
    features['caps_ratio'] = len(caps_words) / len(words) if words else 0
    
    # URL features
    features['url_count'] = len(urls)
    features['suspicious_url_count'] = sum(1 for url in urls if is_suspicious_url(url))
    features['url_domain_mismatch'] = sum(1 for url in urls if url_domain_mismatch(url, sender))
    
    # Attachment features
    features['attachment_count'] = len(attachments)
    features['suspicious_attachment_count'] = sum(1 for att in attachments if is_suspicious_file(att))
    
    # Sender features
    features['sender_reputation'] = get_domain_reputation(sender.split('@')[1])  # 0-100
    features['new_domain'] = 1 if is_new_domain(sender) else 0
    features['spoofed_domain'] = 1 if check_domain_spoofing(sender) else 0
    
    return features
```

---

## 🤖 ML Models for Phishing Detection

### Naive Bayes Classifier

```python
from sklearn.naive_bayes import GaussianNB
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline

# Simple approach: Text-based only
pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(max_features=1000, ngram_range=(1, 2))),
    ('clf', GaussianNB())
])

# Training
pipeline.fit(X_train_text, y_train)

# Prediction
y_pred = pipeline.predict(X_test_text)
y_pred_proba = pipeline.predict_proba(X_test_text)

# Results
accuracy = (y_pred == y_test).mean()
print(f"Accuracy: {accuracy:.3f}")
```

### Random Forest with Feature Engineering

```python
from sklearn.ensemble import RandomForestClassifier
import pandas as pd

# Combine text features + metadata features
X_combined = pd.concat([
    X_tfidf,  # Text features (TF-IDF)
    X_metadata  # Metadata (urgency, sender rep, etc.)
], axis=1)

# Train Random Forest
rf = RandomForestClassifier(n_estimators=100, max_depth=20)
rf.fit(X_combined, y_train)

# Prediction
y_pred = rf.predict(X_combined_test)
y_pred_proba = rf.predict_proba(X_combined_test)

# Feature importance
for feature, importance in sorted(zip(feature_names, rf.feature_importances_), 
                                 key=lambda x: x[1], reverse=True)[:10]:
    print(f"{feature}: {importance:.3f}")
```

### Deep Learning (LSTM)

```python
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout, Embedding

# Text to sequences
tokenizer = tf.keras.preprocessing.text.Tokenizer(num_words=5000)
tokenizer.fit_on_texts(email_texts)
sequences = tokenizer.texts_to_sequences(email_texts)
X = tf.keras.preprocessing.sequence.pad_sequences(sequences, maxlen=200)

# Build LSTM model
model = Sequential([
    Embedding(5000, 128, input_length=200),
    LSTM(64, return_sequences=True),
    Dropout(0.2),
    LSTM(64),
    Dropout(0.2),
    Dense(32, activation='relu'),
    Dense(1, activation='sigmoid')  # Binary: phishing or not
])

model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
model.fit(X_train, y_train, epochs=10, batch_size=32, validation_split=0.2)

# Prediction
y_pred_proba = model.predict(X_test)
y_pred = (y_pred_proba > 0.5).astype(int)
```

---

## 📊 Evaluation on Real Datasets

### Public Datasets

```
ENRON Email Dataset:
├─ 500K legitimate emails
├─ 16K phishing emails
├─ Imbalanced (97% legitimate)
└─ Typical results: 95-98% accuracy

SpamAssassin:
├─ 6,000 ham emails
├─ 1,000 spam emails
├─ Larger spam proportion
└─ Typical results: 92-96% accuracy

Phishing Corpus (PhishTank):
├─ 4,000 confirmed phishing URLs
├─ 4,000 legitimate URLs
├─ URL-based detection
└─ Typical results: 94-99% accuracy

Enron + SpamAssassin Combined:
├─ Typical accuracy: 95%+
├─ Precision: 98% (few false positives)
├─ Recall: 85% (catch most phishing)
└─ F1-Score: 0.91
```

---

## ⚠️ Challenges

### Class Imbalance

```
Real-world email:
├─ Legitimate: 99%
├─ Phishing: 1%
└─ Problem: Model learns to always predict "legitimate"

Solutions:
├─ Oversampling (duplicate phishing examples)
├─ Undersampling (remove legitimate examples)
├─ SMOTE (Synthetic Minority Oversampling)
├─ Class weights (penalize wrong predictions)
└─ Adjustable threshold (predict phishing at 0.3 instead of 0.5)
```

### Adversarial Examples

```
Attacker adapts to detection:
├─ Remove urgency words
├─ Better grammar (hire native English speaker)
├─ Legitimate sender domain (domain spoofing)
├─ Custom payloads (unique per email)
└─ Result: Detectors become obsolete

Solution: Retrain frequently
├─ Weekly or monthly retraining
├─ Incorporate new phishing samples
├─ A/B test detectors
└─ Continuous improvement
```

---

## 🔑 Key Takeaways

- **Text matters** - phishing has linguistic patterns
- **Metadata matters more** - sender, URLs, attachments are strong signals
- **Combine approaches** - text + metadata > either alone
- **Class imbalance is real** - need to handle it
- **Humans + ML best** - user training + automated detection
- **Adversarial arms race** - attackers adapt, detectors must too
- **Real-time scoring** - detect before user opens

---

## 📚 Resources

- [Phishing Detection Survey](https://arxiv.org/abs/2112.07291)
- [ENRON Dataset](https://www.cs.cmu.edu/~enron/)
- [SpamAssassin Corpus](https://spamassassin.apache.org/publiccorpus/)
- [PhishTank](https://phishtank.com/)

---

## [⬅️ Day 084](../day084/) | [➡️ Day 086](../day086/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*