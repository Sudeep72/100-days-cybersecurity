# 🧪 Home Lab Setup Guide

> Part of the [100 Days of Cybersecurity](../README.md) challenge - Day 019

A complete guide to setting up a free, legal, isolated security lab for practicing everything in Phase 2 and beyond.

---

## 📋 What You'll Have When Done

```
Your Machine (Host)
├── VirtualBox (free hypervisor)
│   ├── Kali Linux VM        ← your attacker machine
│   └── Metasploitable2 VM   ← deliberately vulnerable target
│       (Host-Only network - completely isolated)
│
└── Online Labs (no local setup needed)
    ├── TryHackMe            ← tryhackme.com (free tier)
    └── HackTheBox           ← hackthebox.com (free tier)
```

**Total cost: $0**
**Time to set up: ~60–90 minutes**

---

## 🖥️ Minimum Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 8GB | 16GB |
| Storage | 50GB free | 100GB free |
| CPU | 4 cores | 6+ cores |
| OS | Windows 10/11, macOS 12+, Linux | Any |

If your machine doesn't meet these - skip to the **Online Labs** section.

---

## Step 1 - Install VirtualBox

VirtualBox is a free hypervisor - it lets you run multiple operating systems inside your main one.

1. Go to: https://www.virtualbox.org/wiki/Downloads
2. Download for your OS (Windows / macOS / Linux)
3. Run the installer - all default settings are fine
4. Also install the **VirtualBox Extension Pack** from the same page

```
✓ Verify installation:
  Open VirtualBox → you should see the main window with no VMs listed
```

---

## Step 2 - Download and Import Kali Linux

Kali Linux is the industry-standard penetration testing distribution.
It comes pre-installed with 600+ security tools.

### Download (Pre-built VirtualBox image - easiest)

1. Go to: https://www.kali.org/get-kali/#kali-virtual-machines
2. Download the **VirtualBox** image (filename ends in `.ova`)
3. File size: ~3GB - will take a while

### Import into VirtualBox

```
VirtualBox → File → Import Appliance → select the .ova file
→ Click Import (keep all defaults)
→ Wait 5–10 minutes
```

### First Boot

```
Double-click Kali VM → click Start
Default credentials:
  Username: kali
  Password: kali
```

### Update Kali (important - do this first)

```bash
sudo apt update && sudo apt upgrade -y
# This takes 10–20 minutes but is important
```

---

## Step 3 - Download Metasploitable2

Metasploitable2 is a Linux VM deliberately built to be vulnerable.
It runs outdated, misconfigured services with known exploits.

**Never expose this VM to the internet.**

### Download

1. Go to: https://sourceforge.net/projects/metasploitable/
2. Download `metasploitable-linux-2.0.0.zip`
3. Extract the zip - you'll get a folder with `.vmdk` files

### Import into VirtualBox

```
VirtualBox → New → Create a new VM

  Name: Metasploitable2
  Type: Linux
  Version: Ubuntu (32-bit)
  RAM: 512MB
  
  → On "Hard Disk" screen:
    Select "Use an existing virtual hard disk file"
    Click folder icon → Add → select Metasploitable.vmdk
  
  → Click Create
```

### Metasploitable2 Default Credentials

```
Username: msfadmin
Password: msfadmin
```

### Services Running (Your Practice Targets)

```
Port 21   → FTP (vsftpd 2.3.4 - has a backdoor)
Port 22   → SSH (weak credentials)
Port 23   → Telnet (unencrypted, weak credentials)
Port 80   → HTTP (DVWA, Mutillidae, WebDAV)
Port 139  → Samba (misconfigured)
Port 445  → SMB
Port 3306 → MySQL (default credentials)
Port 5432 → PostgreSQL (default credentials)
Port 6667 → IRC (UnrealIRCd backdoor)
Port 8180 → Apache Tomcat (default credentials)
```

---

## Step 4 - Configure Host-Only Networking (Critical)

This step creates an isolated network between your VMs.
Metasploitable2 will have no internet access.
Your Kali VM can reach it. Your host machine can reach it.
Nothing else can.

### Create a Host-Only Network

```
VirtualBox → File → Host Network Manager → Create
  IPv4 Address: 192.168.56.1
  IPv4 Mask: 255.255.255.0
  DHCP Server: Enable
  → Click Apply
```

### Set Both VMs to Host-Only

```
For EACH VM (Kali and Metasploitable2):
  Right-click VM → Settings → Network
  Adapter 1 → Attached to: Host-only Adapter
  Name: vboxnet0 (or whatever appeared)
  → OK
```

---

## Step 5 - Verify the Lab Works

### Start both VMs

Boot Metasploitable2 first, then Kali.

### Find Metasploitable's IP (from Kali)

```bash
# Method 1 - Nmap scan of the subnet
sudo nmap -sn 192.168.56.0/24

# Method 2 - ARP scan
sudo arp-scan --localnet

# You should see Metasploitable's IP - something like 192.168.56.101
```

### Verify connectivity

```bash
# From Kali:
ping 192.168.56.101    # should get responses

# Run Nmap to confirm vulnerable services
nmap -sV 192.168.56.101

# You should see 20+ open ports - the lab is working
```

---

## Step 6 - Take a Snapshot (Save Your State)

Before every lab session, take a snapshot of Metasploitable2.

If you accidentally break something during practice - restore the snapshot.

```
Right-click Metasploitable2 → Snapshots → Take Snapshot
Name: "Clean state"
→ OK
```

Do the same for Kali after you finish setting it up.

---

## 🌐 Alternative: Online Labs (No Local Setup Needed)

If you can't run local VMs - these platforms give everything in the browser.

### TryHackMe (Best for Beginners)
- Free tier: dozens of rooms free
- Browser-based - connect via VPN or AttackBox
- Guided rooms with hints
- Link: https://tryhackme.com

**Recommended free rooms to start:**
```
Pre-Security path      → fundamentals
Jr Penetration Tester  → offensive skills
Basic Pentesting       → first full machine
Advent of Cyber        → free every December (24 days of challenges)
```

### HackTheBox
- More realistic, less guidance
- Free machines available (retired machines with public writeups)
- Strong community
- Link: https://www.hackthebox.com

**Start with:**
```
Starting Point → free guided machines
Retired machines → solutions publicly available for learning
```

### Other Free Platforms

| Platform | Best For | Link |
|----------|---------|------|
| OverTheWire | Linux wargames | overthewire.org |
| PicoCTF | CTF for beginners | picoctf.org |
| VulnHub | Downloadable VMs | vulnhub.com |
| OWASP WebGoat | Web vulnerabilities | github.com/WebGoat |
| DVWA | Web app practice | dvwa.co.uk |
| HackThisSite | Web challenges | hackthissite.org |

---

## ✅ Lab Readiness Checklist

```
□ VirtualBox installed and running
□ Kali Linux VM imported and boots successfully
□ Kali updated (sudo apt update && sudo apt full-upgrade -y)
□ Metasploitable2 imported and boots successfully
□ Both VMs on Host-Only network adapter
□ Can ping Metasploitable from Kali terminal
□ Nmap scan of Metasploitable shows 20+ open ports
□ Snapshot taken of both VMs ("Clean state")
□ TryHackMe account created (free)
□ HackTheBox account created (free)
```

---

## 🛠️ Essential Kali Tools Reference

Everything you need is already installed. Here's where to find key tools:

```bash
# Network scanning
nmap, masscan, netdiscover

# Web app testing
burpsuite          # launch from applications menu
nikto -h target    # web vulnerability scanner
gobuster           # directory/file brute force
sqlmap             # SQL injection automation

# Exploitation
msfconsole         # Metasploit Framework
searchsploit term  # search local exploit database

# Password attacks
hashcat            # GPU hash cracking
john               # CPU hash cracking
hydra              # network login brute force

# Sniffing & analysis
wireshark          # packet capture GUI
tshark             # wireshark command line

# Post-exploitation
netcat (nc)        # Swiss army knife for networking
linpeas.sh         # Linux privilege escalation scanner
winpeas.exe        # Windows privilege escalation scanner
```

---

## ⚠️ Lab Safety Rules

1. **Metasploitable2 must never have internet access** - Host-Only networking only
2. **Never run exploits outside your lab** - attacking systems without permission is illegal
3. **Take snapshots before every lab session** - restore if you break something
4. **Keep Kali updated** - `sudo apt update && sudo apt upgrade -y` weekly
5. **Don't save sensitive data inside VMs** - treat them as disposable

---

## 🔗 What This Lab Is Used For

| Challenge Day | Lab Activity |
|--------------|-------------|
| Day 020 | First CTF attempt - TryHackMe Basic Pentesting |
| Day 025 | Metasploit basics against Metasploitable2 |
| Day 026 | SQL injection against DVWA (running on Metasploitable) |
| Day 027 | XSS against Mutillidae (running on Metasploitable) |
| Day 035 | Linux privilege escalation on Metasploitable |
| Day 041+ | HackTheBox machines |

---

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*