# Day 015 - Common Attack Types: A Threat Taxonomy

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

Before you can defend against attacks - or simulate them in a pen test - you need a mental map of what attacks actually exist and how they relate to each other.

This is that map.

Not every attack in detail - we'll go deep on individual ones throughout the challenge. Today is about building the taxonomy so nothing catches you by surprise later.

---

## 🗺️ The Attack Landscape

Attacks can be organised by what they target:

```
┌─────────────────────────────────────────────┐
│              ATTACK TARGETS                 │
├─────────────┬──────────────┬────────────────┤
│   HUMANS    │   NETWORKS   │  APPLICATIONS  │
│  (social)   │  (infra)     │   (software)   │
├─────────────┼──────────────┼────────────────┤
│ Phishing    │ DDoS         │ SQL Injection  │
│ Pretexting  │ MITM         │ XSS            │
│ Vishing     │ Port Scan    │ CSRF           │
│ Baiting     │ ARP Poison   │ Buffer Overflow│
│ Tailgating  │ DNS Spoof    │ RCE            │
│ Quid Pro Quo│ Packet Sniff │ Path Traversal │
└─────────────┴──────────────┴────────────────┘
```

---

## 👤 Category 1: Social Engineering Attacks

Attacks that exploit humans rather than systems. Often the easiest path in.

### Phishing
Mass emails pretending to be a trusted entity. Clicks a link → steals credentials.

**Variants:**
- **Spear phishing** - targeted at a specific person using personal details
- **Whaling** - targeted at executives (CEOs, CFOs)
- **Smishing** - via SMS
- **Vishing** - via voice call

### Pretexting
Attacker fabricates a scenario to extract information.

*"Hi, this is IT support. We've detected unusual activity on your account. I need your password to restore access."*

No malware. No exploit. Just conversation.

### Baiting
Leaving infected USB drives in car parks, lobbies, or post them to targets. Curiosity does the rest.

In a 2016 study, researchers dropped 297 USB drives on a university campus.
98% were picked up. 45% had files opened from them.

### Tailgating / Piggybacking
Following an authorised person into a restricted area without swiping a badge.

The lowest-tech attack imaginable. Remarkably effective.

---

## 🌐 Category 2: Network Attacks

Attacks targeting the infrastructure that carries data.

### Man-in-the-Middle (MITM)
Attacker positions themselves between two communicating parties - intercepting, reading, and potentially modifying traffic.

```
Normal:  Alice ←──────────────────→ Bob
MITM:    Alice ←── Attacker ──→ Bob
                (intercepts everything)
```

**Common setups:** ARP poisoning on local network, rogue Wi-Fi hotspot, SSL stripping

### Denial of Service (DoS) / DDoS
Flood a target with traffic until it can't respond to legitimate users.

DDoS = Distributed - traffic comes from thousands of compromised machines (botnet) making it harder to block.

**Types:** SYN flood, UDP flood, HTTP flood, DNS amplification (Day 4)

### Packet Sniffing
Capturing network traffic to read its contents.

Effective against unencrypted protocols (HTTP, FTP, Telnet).
What Wireshark does - legitimate when you own the network.

### Replay Attack
Capture a valid authentication token or session - then retransmit it to impersonate the user.

---

## 💻 Category 3: Application Attacks

Attacks targeting software vulnerabilities. The majority of real-world breaches start here.

### Injection Attacks
Attacker inserts malicious data that gets executed as code.

- **SQL Injection** - malicious SQL in input fields (Day 26)
- **Command Injection** - shell commands injected into app inputs (Day 34)
- **LDAP Injection, XPath Injection** - similar pattern, different targets

### Cross-Site Scripting (XSS)
Attacker injects malicious JavaScript into a webpage that other users load.

```
Stored XSS: Malicious script saved to database → executes for every visitor
Reflected XSS: Malicious script in URL → executes when victim clicks the link
```

Steals cookies, hijacks sessions, redirects users. (Day 27)

### Cross-Site Request Forgery (CSRF)
Tricks a logged-in user's browser into making a request they didn't intend.

```
User is logged into their bank.
Attacker sends them a link.
Link triggers: POST /transfer?amount=5000&to=attacker
Bank sees the request as coming from the logged-in user.
```

(Day 28)

### Buffer Overflow
Attacker sends more data than a program expects - overwriting adjacent memory.

Classic vulnerability in C/C++ programs. Can lead to arbitrary code execution.
The basis for many famous exploits including MS08-067 (used by Conficker worm).

### Remote Code Execution (RCE)
The worst outcome - attacker runs arbitrary code on the target system.

Often the end result of exploiting another vulnerability (buffer overflow, deserialization, etc.)

### Path Traversal
Attacker uses `../` sequences to access files outside the intended directory.

```
Intended:  /var/www/images/photo.jpg
Traversal: /var/www/images/../../../etc/passwd
```

---

## 🔑 Category 4: Credential-Based Attacks

### Brute Force
Try every possible combination of characters until the password is found.
Automated. Slow against strong passwords. Fast against weak ones.

### Credential Stuffing
Use leaked username/password pairs from one breach to log into other services.

Works because most people reuse passwords.
The 2020 Zoom credential stuffing attack exposed 500,000 accounts this way.

### Password Spraying
Try one common password against many accounts - avoids account lockouts.

```
Instead of: try 1000 passwords against one account (gets locked)
Try: one password ("Winter2024!") against 1000 accounts
```

### Pass-the-Hash
Capture a Windows password hash and use it directly for authentication - without cracking it first.

---

## 🧬 Category 5: Malware

Malicious software designed to disrupt, damage, or gain unauthorised access.

| Type | What it does |
|------|-------------|
| Virus | Attaches to legitimate files, spreads when executed |
| Worm | Self-replicates across networks without user action |
| Trojan | Disguised as legitimate software - installs backdoor |
| Ransomware | Encrypts files, demands payment |
| Spyware | Silently monitors and exfiltrates user activity |
| Rootkit | Hides attacker's presence deep in the OS |
| Keylogger | Records every keystroke |
| Botnet | Network of compromised machines controlled remotely |
| RAT | Remote Access Trojan - full remote control |

---

## 🔗 How Attacks Chain Together

Real attacks rarely use just one technique. They chain:

```
Phase 1 - Recon:      Nmap scan + OSINT → find open port 22 running old OpenSSH
Phase 2 - Initial Access: Exploit SSH vulnerability → get low-privilege shell
Phase 3 - Persistence: Install backdoor (RAT) so access survives reboots
Phase 4 - Privilege Escalation: SUID binary exploit → root access
Phase 5 - Lateral Movement: Use root access to pivot to other machines
Phase 6 - Exfiltration: Copy data out via DNS tunneling (port 53 open)
```

Every phase uses different techniques.
Defenders need to detect any one of them to break the chain.

This is why the MITRE ATT&CK framework (Day 51) maps tactics to techniques - it's built around this attack chain model.

---

## 🔑 Key Takeaways

- Attacks target humans, networks, or applications - often all three in sequence
- Social engineering is frequently the easiest path into a hardened system
- Application vulnerabilities (injection, XSS, CSRF) cause most real-world breaches
- Credential reuse makes credential stuffing devastatingly effective
- Real attacks chain multiple techniques across multiple phases
- Understanding the taxonomy means nothing surprises you later

---

## 📚 Resources to Go Deeper
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - full attack taxonomy used by the industry
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - most critical web app vulnerabilities
- [TryHackMe - Introduction to Cybersecurity path (free)](https://tryhackme.com/module/introduction-to-cyber-security)

---

## [⬅️ Day 014](../day014/) | [➡️ Day 016](../day016/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*