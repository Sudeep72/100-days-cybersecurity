# Day 005 - Firewalls: What They Do and What They Can't Stop

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

A firewall is the first line of defense in any network.

Most people think a firewall = complete protection. It doesn't. A firewall is a gatekeeper - it decides what traffic is allowed in and out based on rules. But gatekeepers can be tricked, bypassed, and walked right past if you know how.

Today: how firewalls work, the different types, and exactly what they can't stop.

---

## 🔥 What is a Firewall?

A firewall monitors and filters network traffic based on a defined set of rules.

At its core, every firewall makes one decision per packet:

```
ALLOW  →  this traffic matches an approved rule
DENY   →  this traffic doesn't match - drop it
LOG    →  record this for analysis
```

Rules are checked top-down. First match wins.

---

## 🗂️ Types of Firewalls

### 1. Packet Filtering Firewall (Stateless)
The oldest and simplest type. Checks each packet in isolation against rules.

Looks at:
- Source IP / Destination IP
- Source Port / Destination Port
- Protocol (TCP, UDP, ICMP)

**Weakness:** Has no memory. Can't tell if a packet is part of an established connection or a new attack. Easy to spoof.

---

### 2. Stateful Inspection Firewall
Tracks the *state* of active connections. Knows if a packet is part of an established, legitimate session.

```
Legitimate: Client sent SYN → Server replied SYN-ACK → This ACK is valid
Attack:     Random ACK arrives with no prior SYN → BLOCKED
```

**Weakness:** Still only inspects up to Layer 4 (Transport). Can't read application-layer content.

---

### 3. Application Layer Firewall (Layer 7 / Next-Gen)
Inspects actual application content - HTTP headers, DNS queries, file contents.

Can block:
- Specific URLs or domains
- Malicious file uploads
- SQL injection patterns in HTTP requests
- Command and control (C2) traffic disguised as normal web traffic

**Weakness:** Expensive to run. Encrypted traffic (HTTPS) is blind unless SSL inspection is configured.

---

### 4. Web Application Firewall (WAF)
Specifically protects web applications. Sits in front of a web server.

Blocks OWASP Top 10 attacks:
- SQL Injection
- Cross-Site Scripting (XSS)
- CSRF

Examples: Cloudflare WAF, AWS WAF, ModSecurity

**Weakness:** WAF rules can be bypassed with obfuscation, encoding tricks, or zero-day payloads.

---

### 5. Next-Generation Firewall (NGFW)
Combines stateful inspection + application awareness + intrusion prevention + threat intelligence.

Examples: Palo Alto Networks, Fortinet, Cisco Firepower

---

## ❌ What Firewalls Can't Stop

This is the most important part.

| Attack | Why Firewalls Fail |
|--------|-------------------|
| Phishing | User clicks a link in email - traffic looks legitimate |
| Insider threats | Attacker is already inside the network |
| Encrypted malware | HTTPS traffic is allowed through - payload hidden inside |
| DNS tunneling | Port 53 is usually open - data smuggled in DNS queries |
| Web app attacks (SQLi, XSS) | Unless WAF is deployed, Layer 7 content isn't inspected |
| Zero-day exploits | No rule exists yet for unknown attacks |
| VPN / Tor traffic | Encrypted and tunneled - appears as normal traffic |
| Social engineering | Firewall can't stop a human making a bad decision |

**The hard truth:** A firewall is necessary but never sufficient. Defense in depth - multiple overlapping controls - is the only real answer.

---

## 🏗️ Firewall Rule Example

A simple rule set for a web server:

```
Rule 1: ALLOW  TCP  any → server:80    (HTTP - web traffic in)
Rule 2: ALLOW  TCP  any → server:443   (HTTPS - secure web traffic in)
Rule 3: ALLOW  TCP  server → any:established  (responses out)
Rule 4: DENY   TCP  any → server:22    (block SSH from internet)
Rule 5: ALLOW  TCP  10.0.0.0/8 → server:22  (allow SSH from internal only)
Rule 6: DENY   any  any → any          (default deny - block everything else)
```

Rule 6 is critical - **default deny**. If no rule explicitly allows traffic, it's blocked. Most breaches happen when this rule is missing or misconfigured.

---

## 💡 The Golden Rule

> A firewall controls *what gets in and out*. It cannot control *what happens inside*, *who you trust*, or *whether that trusted traffic is malicious*.

Once an attacker is past the firewall - through a phishing email, a compromised VPN credential, or a web app vulnerability - the firewall is irrelevant.

This is why detection engineering (Phase 3 of this challenge) exists.

---

## 📚 Resources to Go Deeper
- [Cloudflare: What is a Firewall?](https://www.cloudflare.com/learning/security/what-is-a-firewall/)
- [NIST Guide to Firewalls](https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final)
- [TryHackMe - Firewalls Room](https://tryhackme.com/room/redteamfirewalls)

---

## [⬅️ Day 004](../day004/) | [➡️ Day 006](../day006/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*