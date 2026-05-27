# Day 024 - Vulnerability Scanning with OpenVAS

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Manual enumeration finds what you know to look for.

Vulnerability scanners find what you don't.

A vulnerability scanner takes everything discovered in recon - open ports, running services, version numbers - and systematically checks them against databases of thousands of known CVEs and misconfigurations.

The result: a prioritised list of weaknesses, scored by severity, with remediation advice.

Today: OpenVAS - the most widely used open-source vulnerability scanner.

---

## 🔍 Vulnerability Scanner vs Exploit

Important distinction before we start:

```
Vulnerability Scanner → finds and reports weaknesses
Exploit              → actually takes advantage of them

Scanner: "Port 445 is running SMB. MS17-010 (EternalBlue) may be present."
Exploit: "I'm going to use EternalBlue to get a shell."
```

Scanners are loud - they generate significant network traffic and will almost certainly trigger IDS alerts. In a real engagement, you'd run scanners only after checking the rules of engagement allow it.

---

## 🛠️ OpenVAS - Overview

OpenVAS (Open Vulnerability Assessment System) is the open-source fork of Nessus - the industry standard commercial scanner.

It maintains a database of 80,000+ Network Vulnerability Tests (NVTs) - checks for known vulnerabilities across hundreds of services and applications.

**Part of Greenbone Vulnerability Manager (GVM)**

```
Components:
├── OpenVAS Scanner    → actually sends the probes
├── GVM Daemon         → manages configs, results, reports
└── GSA (Web UI)       → browser interface at https://localhost:9392
```

---

## ⚙️ Installation on Kali Linux

```bash
# Install GVM (includes OpenVAS)
sudo apt update
sudo apt install -y gvm

# Run the setup script (downloads NVT database - takes 15-30 min)
sudo gvm-setup

# Note the admin password printed at the end - save it!

# Start GVM services
sudo gvm-start

# Open browser to:
https://localhost:9392

# Login: admin / (password from setup output)
```

---

## 🖥️ Running Your First Scan (GUI)

```
1. Login to https://localhost:9392

2. Scans → Tasks → New Task (star icon)

3. Configure:
   Name:       "Metasploitable2 Scan"
   Target:     New Target → IP of your lab VM
   Scanner:    OpenVAS Default
   Scan Config: Full and Fast

4. Save → Click Play button on the task

5. Wait 20-60 minutes depending on target

6. Click completed scan → View Report
```

---

## 📊 Understanding the Report

OpenVAS uses CVSS to score findings:

```
Critical  (9.0–10.0) → Fix immediately
High      (7.0–8.9)  → Fix this week
Medium    (4.0–6.9)  → Fix this month
Low       (0.1–3.9)  → Fix when possible
Info      (0.0)      → Informational - no direct risk
```

Each finding includes:
```
Name:        Samba MS-RPC Shell Command Injection
Severity:    High (8.5)
CVE:         CVE-2007-2447
Description: Samba versions 3.0.20–3.0.25rc3 allow remote
             command injection via shell metacharacters.
Solution:    Update Samba to version 3.0.25rc4 or later.
References:  CVE link, vendor advisory
```

---

## 💻 Command Line Scanning with Nmap NSE

If OpenVAS setup is too heavy for your machine - Nmap's vulnerability scripts cover the most critical checks:

```bash
# Full vulnerability scan (NSE)
sudo nmap -sV --script vuln <target-ip> -oN vuln_scan.txt

# Specific checks
sudo nmap --script smb-vuln-ms17-010 <target-ip>    # EternalBlue
sudo nmap --script smb-vuln-ms08-067 <target-ip>    # MS08-067 (Conficker)
sudo nmap --script http-shellshock <target-ip>       # Shellshock
sudo nmap --script ftp-vsftpd-backdoor <target-ip>  # vsftpd backdoor
sudo nmap --script ssl-heartbleed <target-ip>        # Heartbleed

# Safe checks only (less aggressive)
sudo nmap --script "safe and vuln" <target-ip>
```

---

## 🔎 Searchsploit - Finding Exploits for Discovered Versions

Once you have version numbers from scanning - searchsploit finds public exploits:

```bash
# Search for exploits matching a service/version
searchsploit vsftpd 2.3.4
# Exploit: vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)
# Path:    unix/remote/17491.rb

searchsploit samba 3.0
# Exploit: Samba 3.0.20 < 3.0.25rc3 - 'Username' map script
# Path:    unix/remote/16320.rb

searchsploit apache 2.4.18
# Multiple results - review each

# Copy exploit to current directory
searchsploit -m unix/remote/17491.rb

# Open in browser
searchsploit -w vsftpd 2.3.4
```

---

## 📋 Vulnerability Assessment Workflow

```
1. Run Nmap → get open ports + service versions
          ↓
2. Run OpenVAS / Nmap NSE → automated vulnerability checks
          ↓
3. Run Searchsploit → find exploits for discovered versions
          ↓
4. Cross-reference with NVD / CVE Details → verify severity
          ↓
5. Prioritise by:
   → CVSS score (severity)
   → Exploitability (is there a public exploit?)
   → Business impact (what's on that system?)
          ↓
6. Document findings for the report (Day 40)
```

---

## 🧪 Lab Exercise - Scan Metasploitable2

```bash
# Step 1: Nmap version scan (you did this Day 23)
nmap -sV 192.168.56.101 -oN nmap_versions.txt

# Step 2: NSE vulnerability scan
sudo nmap --script vuln 192.168.56.101 -oN vuln_scan.txt

# Step 3: Check specific known vulnerabilities
sudo nmap --script ftp-vsftpd-backdoor 192.168.56.101
sudo nmap --script smb-vuln-ms08-067 192.168.56.101

# Step 4: Searchsploit for key services
searchsploit vsftpd 2.3.4
searchsploit "samba 3.0"
searchsploit "unreal ircd"

# You'll find exploits for all of them.
# Metasploitable2 is deliberately vulnerable to each.
```

---

## ⚠️ Scanner Limitations

Scanners are powerful but have blind spots:

| Limitation | Explanation |
|-----------|-------------|
| False positives | Reports vulnerability that doesn't exist - needs manual verification |
| False negatives | Misses vulnerabilities - especially logic flaws and auth issues |
| Application logic | Can't find IDOR, CSRF, or business logic flaws |
| Authentication required | Some vulnerabilities only visible after logging in |
| Network noise | Generates huge amounts of traffic - highly detectable |
| Version-based only | If vendor removed version strings - scanner may miss CVEs |

**Scanners are a starting point, not a complete answer.**

Manual testing always follows.

---

## 🔑 Key Takeaways

- Vulnerability scanners automate CVE matching against discovered service versions
- OpenVAS is the most capable free scanner - takes time to set up but worth it
- Nmap NSE scripts cover the most critical checks with no extra setup
- Searchsploit maps version numbers to public exploits instantly
- CVSS score + exploitability + business impact = prioritisation
- Scanners miss logic flaws, authentication issues, and custom vulnerabilities - manual testing always follows

---

## 📚 Resources to Go Deeper
- [OpenVAS Documentation](https://docs.greenbone.net/)
- [Nmap NSE Script Database](https://nmap.org/nsedoc/categories/vuln.html)
- [Exploit-DB (Searchsploit source)](https://www.exploit-db.com/)

---

## [⬅️ Day 023](../day023/) | [➡️ Day 025](../day025/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*