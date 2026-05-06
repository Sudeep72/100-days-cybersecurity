# Day 003 - The OSI Model: Why Every Layer Matters to Attackers

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

Yesterday we covered TCP/IP - the model the internet actually runs on.

Today: the OSI model - the model security professionals *think* in.

OSI has 7 layers vs TCP/IP's 4. It's more granular, which makes it more useful for pinpointing exactly where an attack happens and exactly where a defense should go.

Every certification exam covers this. More importantly - every real-world attack maps to a layer.

---

## 🗂️ The 7 Layers

```
Layer 7 - Application   → What the user interacts with
Layer 6 - Presentation  → Data formatting, encryption, compression
Layer 5 - Session       → Managing connections between apps
Layer 4 - Transport     → End-to-end delivery, ports
Layer 3 - Network       → Routing between networks, IP addresses
Layer 2 - Data Link     → Node-to-node delivery, MAC addresses
Layer 1 - Physical      → Raw bits over cables, Wi-Fi signals
```

**Memory trick:** *"All People Seem To Need Data Processing"* (top to bottom: Application → Physical)  
**Or bottom to top:** *"Please Do Not Throw Sausage Pizza Away"*

---

## 🔍 Each Layer - What It Does & How It Gets Attacked

### Layer 7 - Application
The layer users see. HTTP, HTTPS, FTP, SMTP, DNS.

| What it does | Attack |
|---|---|
| Delivers web pages, email, files | SQL Injection, XSS, phishing, DNS spoofing |

This is where most attacks happen. Web apps live here.

---

### Layer 6 - Presentation
Translates data formats. Handles encryption/decryption and compression.

| What it does | Attack |
|---|---|
| Encodes data (SSL/TLS), compresses files | SSL stripping, malformed data attacks |

---

### Layer 5 - Session
Manages and maintains connections between applications.

| What it does | Attack |
|---|---|
| Opens, manages, closes sessions | Session hijacking, replay attacks |

---

### Layer 4 - Transport
TCP and UDP live here. Ports live here.

| What it does | Attack |
|---|---|
| Reliable (TCP) or fast (UDP) delivery | SYN flood, port scanning, UDP flood |

Port 80 = HTTP. Port 443 = HTTPS. Port 22 = SSH. Port 3389 = RDP.  
Knowing ports = knowing what services to target (or protect).

---

### Layer 3 - Network
IP addresses and routing. Decides *how* packets get from A to B.

| What it does | Attack |
|---|---|
| Routes packets across networks | IP spoofing, routing attacks, ICMP flood |

---

### Layer 2 - Data Link
MAC addresses. Switches operate here.

| What it does | Attack |
|---|---|
| Node-to-node delivery on local network | ARP poisoning, MAC flooding, VLAN hopping |

**ARP poisoning** is how attackers perform man-in-the-middle on a local network - they convince devices that *their* MAC address belongs to the gateway IP.

---

### Layer 1 - Physical
Cables, Wi-Fi signals, network cards. Raw bits.

| What it does | Attack |
|---|---|
| Transmits raw binary data | Physical wiretapping, signal jamming, hardware keyloggers |

---

## 🗺️ Real Attacks Mapped to OSI Layers

| Attack | OSI Layer |
|--------|-----------|
| SQL Injection | Layer 7 (Application) |
| SSL Stripping | Layer 6 (Presentation) |
| Session Hijacking | Layer 5 (Session) |
| SYN Flood | Layer 4 (Transport) |
| IP Spoofing | Layer 3 (Network) |
| ARP Poisoning | Layer 2 (Data Link) |
| Hardware Keylogger | Layer 1 (Physical) |
| Man-in-the-Middle | Layers 2-7 (depends on method) |

---

## 💡 Why This Matters in Real Security Work

When you're analyzing an incident or designing a defense, the OSI model tells you *where* to look and *where* to act.

**Example:** Alert fires - unusual outbound traffic detected.

- Layer 7 check: Is it an app making unexpected HTTP calls? (C2 beaconing)
- Layer 4 check: What port? Unusual port = suspicious service
- Layer 3 check: Where is it going? Known malicious IP?
- Layer 2 check: Which device on the network is the source?

Work the layers. Narrow it down. Find the answer.

---

## 📚 Resources to Go Deeper
- [Professor Messer - OSI Model (free YouTube)](https://www.youtube.com/watch?v=AYgXr1dynKU)
- [Cloudflare: What is the OSI Model?](https://www.cloudflare.com/learning/ddos/glossary/open-systems-interconnection-model-osi/)
- [TryHackMe - OSI Model Room (free)](https://tryhackme.com/room/osimodelzi)

---

## [⬅️ Day 002](../day002/) | [➡️ Day 004](../day004/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*