# Day 013 - Nmap: Your First Real Recon Tool

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

Before an attacker touches a system, they watch it.

They map out what's there. What ports are open. What services are running. What versions of those services. What operating system.

This is reconnaissance and Nmap is the tool that does it better than anything else.

Used by penetration testers, security engineers, and unfortunately attackers worldwide. Understanding Nmap means understanding how targets get profiled before an attack.

> ⚠️ **Legal note:** Only run Nmap against systems you own or have explicit written permission to test. Scanning systems without permission is illegal in most countries. Use your own machine, a home lab, or platforms like TryHackMe and HackTheBox.

---

## 🗺️ What Nmap Does

Nmap (Network Mapper) sends carefully crafted packets to a target and analyses the responses to determine:

- Which hosts are alive on a network
- Which ports are open on those hosts
- What services are running on those ports
- What version of those services
- What operating system is likely running
- Whether any known vulnerabilities exist (with scripts)

---

## 🔌 Understanding Ports First

Every service on a server listens on a port number (0-65535).

```
Port 22   → SSH (remote login)
Port 25   → SMTP (email sending)
Port 53   → DNS
Port 80   → HTTP (web)
Port 443  → HTTPS (secure web)
Port 3306 → MySQL database
Port 3389 → RDP (Windows remote desktop)
Port 8080 → Alternative HTTP / dev servers
```

An open port = a service listening = a potential entry point.

A port can be in three states:
- **Open** - service is actively listening, will respond
- **Closed** - no service listening, host responds to say "nothing here"
- **Filtered** - firewall is blocking - no response at all

---

## 📖 Nmap Command Reference

### Basic Discovery

```bash
# Check if a host is alive (ping scan - no port scan)
nmap -sn 192.168.1.1

# Scan a single host - top 1000 ports
nmap 192.168.1.1

# Scan a range of IPs
nmap 192.168.1.1-254

# Scan an entire subnet
nmap 192.168.1.0/24

# Scan multiple specific targets
nmap 192.168.1.1 192.168.1.5 10.0.0.1
```

---

### Port Scanning Techniques

```bash
# SYN scan - fast, stealthy (requires root)
# Sends SYN, doesn't complete handshake - less likely to be logged
sudo nmap -sS 192.168.1.1

# TCP connect scan - full handshake (no root needed)
# Louder - logged by target
nmap -sT 192.168.1.1

# UDP scan - checks UDP ports (slower)
sudo nmap -sU 192.168.1.1

# Scan specific ports
nmap -p 22,80,443,3306 192.168.1.1

# Scan all 65535 ports
nmap -p- 192.168.1.1

# Scan top 100 most common ports
nmap --top-ports 100 192.168.1.1
```

---

### Service and Version Detection

```bash
# Detect service versions running on open ports
nmap -sV 192.168.1.1

# Example output:
# PORT   STATE SERVICE VERSION
# 22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
# 80/tcp open  http    Apache httpd 2.4.41
# 3306/tcp open mysql  MySQL 5.7.32

# Detect OS (requires root, not always accurate)
sudo nmap -O 192.168.1.1

# Aggressive scan - OS, version, scripts, traceroute
# Loud - don't use when stealth matters
sudo nmap -A 192.168.1.1
```

---

### Nmap Scripting Engine (NSE)

Nmap has 600+ built-in scripts for vulnerability detection, brute forcing, and enumeration.

```bash
# Run default safe scripts
nmap -sC 192.168.1.1

# Check for specific vulnerability (EternalBlue - MS17-010)
nmap --script smb-vuln-ms17-010 192.168.1.1

# HTTP enumeration
nmap --script http-enum 192.168.1.1

# Check for anonymous FTP login
nmap --script ftp-anon 192.168.1.1

# Brute force SSH (use only on your own systems)
nmap --script ssh-brute 192.168.1.1

# Full vulnerability scan with scripts
sudo nmap -sV --script vuln 192.168.1.1
```

---

### Output and Saving Results

```bash
# Save output to a text file
nmap -oN scan_results.txt 192.168.1.1

# Save in XML format (useful for importing into other tools)
nmap -oX scan_results.xml 192.168.1.1

# Save in all formats at once
nmap -oA scan_results 192.168.1.1

# Verbose output - see what Nmap is doing
nmap -v 192.168.1.1
```

---

### Timing and Stealth

```bash
# Timing templates (T0 = paranoid/slow, T5 = insane/fast)
nmap -T0 192.168.1.1  # very slow, stealthy
nmap -T3 192.168.1.1  # default
nmap -T4 192.168.1.1  # faster - good for labs
nmap -T5 192.168.1.1  # fastest - very noisy

# Fragment packets to evade basic firewalls
nmap -f 192.168.1.1

# Spoof source IP (requires root - advanced)
sudo nmap -S 10.10.10.10 192.168.1.1

# Scan from decoy IPs to confuse logs
sudo nmap -D RND:5 192.168.1.1
```

---

## 💻 The Code - Nmap Automation Script

```bash
#!/bin/bash
# Day 013 - Nmap Recon Script
# 100 Days of Cybersecurity by Sudeep Ravichandran
#
# Runs a structured recon scan against a target.
# ONLY use against systems you own or have permission to test.
#
# Usage: bash nmap_basics.sh <target>
# Example: bash nmap_basics.sh 192.168.1.1

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Usage: bash nmap_basics.sh <target>"
    echo "Example: bash nmap_basics.sh 192.168.1.1"
    exit 1
fi

echo "========================================"
echo " Nmap Recon Script - Day 013"
echo " 100 Days of Cybersecurity"
echo "========================================"
echo " Target: $TARGET"
echo " $(date)"
echo "========================================"
echo ""

# Phase 1: Host Discovery
echo "[Phase 1] Checking if host is alive..."
nmap -sn "$TARGET" 2>/dev/null | grep -E "Host|latency"
echo ""

# Phase 2: Quick Port Scan (top 1000)
echo "[Phase 2] Scanning top 1000 ports..."
nmap -T4 --open "$TARGET" 2>/dev/null
echo ""

# Phase 3: Service Version Detection
echo "[Phase 3] Detecting service versions on open ports..."
nmap -sV -T4 --open "$TARGET" 2>/dev/null
echo ""

# Phase 4: Default Scripts
echo "[Phase 4] Running default NSE scripts..."
nmap -sC -T4 --open "$TARGET" 2>/dev/null
echo ""

# Phase 5: Save full results
OUTFILE="nmap_${TARGET}_$(date +%Y%m%d_%H%M%S)"
echo "[Phase 5] Saving full results to ${OUTFILE}..."
nmap -sV -sC -T4 -oA "$OUTFILE" "$TARGET" 2>/dev/null
echo " Results saved: ${OUTFILE}.nmap / .xml / .gnmap"
echo ""

echo "========================================"
echo " Recon complete."
echo " Review open ports and service versions."
echo " Check versions against CVE databases."
echo "========================================"
```

**To run:**
```bash
chmod +x nmap_basics.sh
bash nmap_basics.sh <your-target-IP>
```

**Practice safely on:**
- Your own local machine: `bash nmap_basics.sh 127.0.0.1`
- TryHackMe VPN targets
- HackTheBox VPN targets

---

## 🔑 Key Takeaways

- Nmap maps what's running on a network before any attack begins
- Open port = service = potential attack surface - every one matters
- `-sV` finds service versions - old versions = known CVEs = known exploits
- NSE scripts extend Nmap into a vulnerability scanner
- Always save results with `-oA` - you'll refer back to them
- T4 is the sweet spot for labs - fast without being unreliable

---

## 📚 Resources to Go Deeper
- [Nmap official docs](https://nmap.org/book/man.html)
- [TryHackMe - Nmap Room (free)](https://tryhackme.com/room/furthernmap)
- [HackTheBox - Starting Point (free)](https://www.hackthebox.com/starting-point)

---

## [⬅️ Day 012](../day012/) | [➡️ Day 014](../day014/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*