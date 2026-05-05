# Day 002 - How the Internet Actually Works: TCP/IP Deep Dive

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

Every time you open a browser, send an email, or stream a video - packets are flying across the internet. Understanding how they travel, and where they can be intercepted, is the foundation of network security.

Today: the full journey of a single request, and the attack surface at every step.

---

## 📦 What is TCP/IP?

TCP/IP is the communication model the entire internet runs on. It has 4 layers:

| Layer | Name | What it does | Example Protocols |
|-------|------|-------------|-------------------|
| 4 | Application | What the user sees | HTTP, HTTPS, DNS, FTP |
| 3 | Transport | End-to-end delivery | TCP, UDP |
| 2 | Internet | Routing across networks | IP, ICMP |
| 1 | Network Access | Physical transmission | Ethernet, Wi-Fi |

Data travels **down** the layers when sending, **up** the layers when receiving. Each layer wraps the data in its own header - this is called **encapsulation**.

---

## 🔁 The TCP 3-Way Handshake

Before any data is sent, TCP establishes a connection:

```
Client                    Server
  |  ── SYN ──────────────▶ |   "I want to connect"
  |  ◀─────────── SYN-ACK ─ |   "OK, I'm ready"
  |  ── ACK ──────────────▶ |   "Great, let's go"
  |  ══ DATA FLOWS ════════ |
```

**Why this matters for security:**
- **SYN Flood attack** - attacker sends thousands of SYN packets, never completes the handshake, server runs out of connection slots → DoS
- **TCP Session Hijacking** - attacker predicts sequence numbers and injects packets into an established session

---

## 🌐 What Happens When You Type a URL

```
1. You type: https://google.com
       ↓
2. DNS Lookup → "What's the IP for google.com?"
   Your device asks a DNS resolver → gets back 142.250.80.46
   ⚠ Attack: DNS spoofing returns a malicious IP instead

3. TCP Handshake → Connect to 142.250.80.46:443
   ⚠ Attack: SYN flood, TCP hijacking

4. TLS Handshake → "Prove you're really Google"
   Server sends certificate → your browser verifies it
   ⚠ Attack: SSL stripping (downgrades HTTPS to HTTP)

5. HTTP GET Request → "Give me the homepage"
   ⚠ Attack: Man-in-the-middle intercepts/modifies response

6. Response rendered in browser
```

---

## ⚠️ Attack Surface at Each Layer

| Layer | Protocol | Attack |
|-------|----------|--------|
| Application | HTTP | Injection, XSS, CSRF |
| Application | DNS | DNS spoofing, cache poisoning |
| Transport | TCP | SYN flood, session hijacking |
| Internet | IP | IP spoofing, routing attacks |
| Network Access | ARP | ARP poisoning (MITM on local network) |

---

## 💻 The Code - Packet Analyzer

This script captures live packets and shows you the TCP handshake and DNS queries in real time.

```python
"""
Day 002 - Packet Analyzer
100 Days of Cybersecurity by Sudeep Ravichandran

Shows TCP/IP layers live by capturing and parsing network packets.
Run with: sudo python3 packet_analyzer.py
Requires: sudo apt install python3-scapy
"""

from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
from datetime import datetime
import sys


def analyze_packet(packet):
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # TCP - catch the 3-way handshake
        if TCP in packet:
            flags = packet[TCP].flags
            flag_list = []
            if flags & 0x02: flag_list.append("SYN")
            if flags & 0x10: flag_list.append("ACK")
            if flags & 0x01: flag_list.append("FIN")
            if flags & 0x04: flag_list.append("RST")

            flag_str = ",".join(flag_list) if flag_list else "DATA"
            print(f"[{timestamp}] TCP {src_ip}:{packet[TCP].sport} "
                  f"→ {dst_ip}:{packet[TCP].dport} [{flag_str}]")

            # Highlight handshake steps
            if flag_list == ["SYN"]:
                print(f"  ↳ 🤝 Step 1 — SYN: Client initiating connection")
            elif "SYN" in flag_list and "ACK" in flag_list:
                print(f"  ↳ 🤝 Step 2 — SYN-ACK: Server responding")
            elif flag_list == ["ACK"]:
                print(f"  ↳ 🤝 Step 3 — ACK: Handshake complete, data can flow")

        # UDP — catch DNS queries
        elif UDP in packet:
            if DNS in packet and packet[DNS].qr == 0:  # qr=0 means query
                if DNSQR in packet:
                    domain = packet[DNSQR].qname.decode().rstrip(".")
                    print(f"[{timestamp}] DNS Query: {domain}")
                    print(f"  ↳ 🌐 Resolving IP for: {domain}")
                    print(f"  ↳ ⚠  Attack surface: DNS spoofing could "
                          f"return a malicious IP here")


def main():
    print("=" * 55)
    print("100 Days of Cybersecurity — Day 002")
    print("TCP/IP Packet Analyzer")
    print("=" * 55)
    print("\nCapturing 30 packets... (Ctrl+C to stop early)\n")

    try:
        sniff(prn=analyze_packet, count=30, store=0)
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except PermissionError:
        print("Need root: sudo python3 packet_analyzer.py")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

**To run:**
```bash
sudo apt install python3-scapy
sudo python3 packet_analyzer.py
```

---

## 🔑 Key Takeaways

- TCP/IP has 4 layers — each layer has its own attack surface
- The 3-way handshake (SYN → SYN-ACK → ACK) is what SYN flood attacks exploit
- DNS is the first thing that happens when you visit any site — and one of the most abused protocols
- Every packet travels through multiple hops — any hop can be a point of interception

---

## 📚 Resources to Go Deeper
- [Wireshark — free packet capture tool](https://www.wireshark.org/)
- [Cloudflare: What is TCP/IP?](https://www.cloudflare.com/learning/ddos/glossary/tcp-ip/)
- [TryHackMe — Pre-Security Path (free)](https://tryhackme.com/path/outline/presecurity)

---

## [⬅️ Day 001](../day001/) | [➡️ Day 003](../day003/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*