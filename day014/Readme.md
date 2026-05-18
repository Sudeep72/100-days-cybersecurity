# Day 014 - Wireshark: Reading Network Traffic Like a Conversation

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

Every packet that travels across a network tells a story.

Who sent it. Where it's going. What it contains. When it arrived.

Wireshark lets you read that story in real time - or from a saved capture file. It's the most widely used network protocol analyser in the world, used by security engineers, network admins, malware analysts, and penetration testers daily.

If Nmap tells you what doors exist - Wireshark tells you what's walking through them.

---

## 🖥️ What Wireshark Does

Wireshark captures raw packets from a network interface and decodes them into human-readable format, showing:

- Every packet's source and destination (IP + port)
- The protocol at each layer (Ethernet, IP, TCP, HTTP, DNS...)
- The full content of unencrypted traffic
- Timing between packets
- TCP stream reconstruction (read entire conversations)
- Statistics and graphs of traffic patterns

---

## 🎛️ The Wireshark Interface

```
┌─────────────────────────────────────────────┐
│  Display Filter Bar  [ip.addr == 10.0.0.1] │
├────┬──────────┬────────┬──────────┬─────────┤
│ No │   Time   │ Source │  Dest    │ Protocol│  ← Packet List
├────┴──────────┴────────┴──────────┴─────────┤
│  Frame details - expand each layer          │  ← Packet Details
│  ▶ Ethernet II                              │
│  ▶ Internet Protocol                        │
│  ▶ Transmission Control Protocol            │
│  ▶ Hypertext Transfer Protocol              │
├─────────────────────────────────────────────┤
│  00 1a 2b 3c 4d 5e ...  (raw hex bytes)    │  ← Packet Bytes
└─────────────────────────────────────────────┘
```

---

## 🔍 Display Filters - The Most Important Skill

Captures generate thousands of packets per minute. Filters are how you find what matters.

```wireshark
# Filter by IP address
ip.addr == 192.168.1.1          # any packet involving this IP
ip.src == 192.168.1.1           # packets FROM this IP
ip.dst == 192.168.1.1           # packets TO this IP

# Filter by protocol
tcp                              # all TCP traffic
udp                              # all UDP traffic
http                             # HTTP only (unencrypted web)
dns                              # DNS queries and responses
icmp                             # ping traffic

# Filter by port
tcp.port == 80                   # HTTP
tcp.port == 443                  # HTTPS
tcp.port == 22                   # SSH
tcp.dstport == 3306              # MySQL - who is querying the database?

# Filter by content
http.request.method == "POST"    # form submissions, logins
http contains "password"         # packets containing the word "password"
dns.qry.name contains "google"   # DNS queries for google

# Combine filters
ip.addr == 10.0.0.5 && tcp.port == 80     # HTTP from specific IP
ip.src == 10.0.0.1 || ip.src == 10.0.0.2 # traffic from either IP
!(arp || icmp || dns)                      # exclude noise protocols

# TCP flags - find the handshake
tcp.flags.syn == 1 && tcp.flags.ack == 0   # SYN packets (new connections)
tcp.flags.rst == 1                          # RST packets (connection reset - suspicious)

# Find retransmissions (network issues or evasion)
tcp.analysis.retransmission
```

---

## 🕵️ What to Look For - Security Analysis

### 1. Cleartext Credentials
HTTP traffic (port 80) sends everything unencrypted.

```
Filter: http.request.method == "POST"
Look at: the packet content - sometimes username/password visible in plaintext
```

This is why HTTPS everywhere matters. Pre-2016, most sites sent login forms over plain HTTP.

---

### 2. DNS Queries - What Is This Machine Talking To?
```
Filter: dns
Look for: unusual domains, high-frequency queries, encoded subdomains
```

DNS tunneling looks like normal DNS but queries are:
- Unusually long (data encoded in the domain name)
- High frequency to a single domain
- Random-looking subdomains: `a3f9bx2k.attacker.com`

---

### 3. Port Scans in Traffic
When Nmap scans a network, it leaves a pattern:

```
Filter: tcp.flags.syn == 1 && tcp.flags.ack == 0
Look for: one source IP sending SYN packets to many different destination ports rapidly
```

That's a port scan. In a real environment, this is an immediate alert.

---

### 4. ARP Poisoning (MITM on Local Network)
```
Filter: arp
Look for: one MAC address claiming to be multiple IP addresses
         OR many ARP replies without ARP requests (gratuitous ARP)
```

ARP poisoning is how attackers redirect local network traffic through themselves.

---

### 5. Beaconing - C2 Traffic Pattern
Malware often "phones home" at regular intervals.

```
Filter: ip.dst == <suspicious IP>
Look for: regular intervals (every 60s, every 5 minutes) to same external IP
          small, consistent packet sizes (heartbeat pattern)
```

Beaconing is one of the key patterns threat hunters look for.

---

## 📁 Following a TCP Stream

One of Wireshark's most powerful features - reconstruct an entire conversation:

1. Right-click any packet in a TCP session
2. Select "Follow → TCP Stream"
3. See the full conversation in one window

For unencrypted HTTP traffic - you can read the entire request and response, including any credentials, cookies, or sensitive data.

---

## 💻 Practical Commands - tshark (Terminal Wireshark)

```bash
# tshark is Wireshark's command-line version
# Capture 100 packets on eth0
tshark -i eth0 -c 100

# Read a .pcap file
tshark -r capture.pcap

# Apply a filter
tshark -r capture.pcap -Y "http.request.method == POST"

# Extract specific fields
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e dns.qry.name

# Capture and save to file
tshark -i eth0 -w capture.pcap

# Show DNS queries only
tshark -i eth0 -Y dns -T fields -e dns.qry.name

# Find POST requests and show the content
tshark -r capture.pcap -Y "http.request.method==POST" -V

# Count packets per IP (quick traffic summary)
tshark -r capture.pcap -T fields -e ip.src | sort | uniq -c | sort -rn
```

---

## 🧪 Practice Resources - Free .pcap Files

You don't need to capture live traffic to learn Wireshark. Download practice files:

- [Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures)
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/) - real malware pcaps
- [PicoCTF Wireshark challenges](https://picoctf.org/)

---

## 📝 Analysis Notes Template

When analysing a capture, work through this structure:

```
CAPTURE ANALYSIS - [filename] - [date]

1. HOSTS INVOLVED
   - List unique IPs seen
   - Identify internal vs external

2. PROTOCOLS OBSERVED
   - What protocols are present?
   - Any unexpected protocols?

3. SUSPICIOUS INDICATORS
   - Cleartext credentials?
   - Unusual DNS queries?
   - Port scan patterns?
   - Beaconing behaviour?
   - ARP anomalies?

4. TIMELINE
   - What happened first?
   - Key events in order?

5. CONCLUSION
   - What happened?
   - Is this malicious?
   - What to investigate next?
```

---

## 🔑 Key Takeaways

- Wireshark reads raw network packets - every layer, every field, every byte
- Display filters are the skill - learn them and you can find anything in a capture
- "Follow TCP Stream" reconstructs entire conversations from packets
- HTTP traffic is fully readable - usernames, passwords, cookies, everything
- Beaconing, port scan patterns, DNS tunneling - all visible in packet captures
- tshark brings Wireshark's power to the command line - automatable

---

## 📚 Resources to Go Deeper
- [Wireshark - download free](https://www.wireshark.org/)
- [Wireshark display filter reference](https://www.wireshark.org/docs/dfref/)
- [Malware Traffic Analysis - practice pcaps](https://www.malware-traffic-analysis.net/)
- [TryHackMe - Wireshark Room (free)](https://tryhackme.com/room/wiresharkthebasics)

---

## [⬅️ Day 013](../day013/) | [➡️ Day 015](../day015/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*