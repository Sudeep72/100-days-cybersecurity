# Day 019 - Setting Up a Free Security Home Lab

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

Everything from Day 21 onwards requires a safe, legal environment to practice.

You cannot learn offensive security by reading alone. You need to run exploits, break into machines, capture flags, and analyse malware - without touching anything you don't own.

A home lab is that environment. And you can build one for free.

---

## 🏗️ Lab Architecture

```
Your Machine (Host)
├── VirtualBox / VMware (Hypervisor)
│   ├── Kali Linux VM        ← attacker machine
│   ├── Metasploitable2 VM   ← deliberately vulnerable target
│   └── Windows 10 VM        ← Windows target (optional)
│
└── Online Labs (no local setup needed)
    ├── TryHackMe            ← guided, browser-based
    └── HackTheBox           ← more challenging, realistic
```

---

## 🛠️ Option 1 - Local Lab (Full Control)

### Step 1: Install a Hypervisor (free)

**VirtualBox** (recommended for beginners - completely free)
- Download: https://www.virtualbox.org/
- Supports Windows, macOS, Linux hosts

**VMware Workstation Player** (free for personal use)
- Download: https://www.vmware.com/products/workstation-player.html

---

### Step 2: Download Kali Linux (Attacker Machine)

Kali Linux is the industry-standard penetration testing distro.
Pre-installed with 600+ security tools: Nmap, Metasploit, Burp Suite, Wireshark, Hydra, etc.

```bash
# Download the VirtualBox image (pre-built, no install needed):
https://www.kali.org/get-kali/#kali-virtual-machines

# Default credentials:
Username: kali
Password: kali

# First thing after boot - update:
sudo apt update && sudo apt upgrade -y
```

---

### Step 3: Download Metasploitable2 (Vulnerable Target)

A deliberately vulnerable Linux machine - built to be hacked.
Never expose this to the internet. Local network only.

```
Download: https://sourceforge.net/projects/metasploitable/

Default credentials:
Username: msfadmin
Password: msfadmin

Vulnerable services running on it:
- FTP (vsftpd 2.3.4 - backdoor)
- SSH (weak credentials)
- Telnet (unencrypted)
- HTTP (DVWA, Mutillidae)
- MySQL (default credentials)
- PostgreSQL (default credentials)
- Samba (misconfigured)
```

---

### Step 4: Network Configuration

**Important:** Set both VMs to "Host-Only" network adapter in VirtualBox.

This creates an isolated network between your VMs - no internet access from Metasploitable2.

```
VirtualBox → VM Settings → Network → Adapter 1 → Host-Only Adapter
```

Verify connectivity:
```bash
# From Kali - find Metasploitable's IP
nmap -sn 192.168.56.0/24

# Should see Metasploitable2 responding
ping <metasploitable-ip>
```

---

## 🌐 Option 2 - Online Labs (No Setup Required)

If you don't have hardware for local VMs - these platforms give you everything in the browser.

### TryHackMe (Recommended for beginners)
- Free tier: many rooms free
- Browser-based - no downloads needed
- Guided learning paths
- Link: https://tryhackme.com

**Start with:**
- Pre-Security path (free)
- Jr Penetration Tester path
- Advent of Cyber (free every December)

### HackTheBox
- More realistic, less hand-holding
- Free machines available
- Strong community writeups
- Link: https://www.hackthebox.com

**Start with:**
- Starting Point machines (free, guided)
- Retired machines (free with writeups available)

### Other Free Platforms
| Platform | Best For |
|----------|---------|
| PicoCTF | CTF competitions, beginners |
| OverTheWire | Linux skills, wargames |
| VulnHub | Downloadable vulnerable VMs |
| OWASP WebGoat | Web app vulnerabilities |
| DVWA | Web app practice |

---

## 📦 Essential Tools Already on Kali

```bash
# Network scanning
nmap, masscan, netdiscover

# Web app testing
burpsuite, nikto, gobuster, dirb, sqlmap, wfuzz

# Exploitation
metasploit-framework, searchsploit

# Password attacks
hashcat, john, hydra, medusa

# Wireless
aircrack-ng, wifite

# Forensics & analysis
wireshark, volatility, binwalk, foremost

# OSINT
maltego, recon-ng, theharvester

# Reverse shells & payloads
msfvenom, netcat, socat
```

---

## ✅ Lab Setup Checklist

```
□ Hypervisor installed (VirtualBox or VMware)
□ Kali Linux VM imported and booting
□ Kali updated (sudo apt update && sudo apt upgrade -y)
□ Metasploitable2 VM imported
□ Both VMs on Host-Only network
□ Can ping Metasploitable from Kali
□ TryHackMe account created (free)
□ HackTheBox account created (free)
□ Nmap scan of Metasploitable runs successfully
```

---

## ⚠️ Lab Safety Rules

1. **Never put Metasploitable on a public network** - it will be compromised within minutes
2. **Never run exploits outside your lab** - attacking systems you don't own is illegal
3. **Use snapshots** - VirtualBox lets you save VM state before each lab so you can restore after
4. **Separate your lab from your main machine** - Host-Only networking is mandatory

---

## 🔑 Key Takeaways

- A home lab is non-negotiable for practical security learning
- VirtualBox + Kali + Metasploitable2 = a complete free offensive security lab
- TryHackMe is the best option if you can't run local VMs
- Take VM snapshots before every lab - restore if things break
- Everything from Day 21 onwards assumes you have this lab ready

---

## 📚 Resources
- [Kali Linux documentation](https://www.kali.org/docs/)
- [TryHackMe - Pre-Security path](https://tryhackme.com/path/outline/presecurity)
- [VulnHub - free vulnerable VMs](https://www.vulnhub.com/)

---

## [⬅️ Day 018](../day018/) | [➡️ Day 020](../day020/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*