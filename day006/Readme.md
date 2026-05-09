# Day 006 - Linux for Security Pros: Commands That Actually Matter

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

Almost every security tool runs on Linux.
Almost every server you'll ever attack or defend runs Linux.
Almost every CTF challenge assumes you know Linux.

You don't need to memorize everything. You need to know the commands that come up constantly in security work - recon, investigation, privilege escalation checks, and log analysis.

This is that list.

---

## 📁 Navigation & File System

```bash
pwd                    # where am I right now?
ls -la                 # list all files including hidden, with permissions
cd /var/log            # move to a directory
find / -name "*.conf"  # find all .conf files from root
find / -perm -4000     # find SUID binaries (privesc goldmine)
locate passwd          # fast file search using index
tree -L 2              # visual directory structure, 2 levels deep
```

**Why it matters:** During recon and post-exploitation, knowing where things live is everything. `/etc/passwd`, `/var/log`, `/home`, `/tmp` - these are the first places you look.

---

## 👤 Users & Permissions

```bash
whoami                 # current user
id                     # user ID, group ID, and all groups
cat /etc/passwd        # all user accounts on the system
cat /etc/shadow        # password hashes (root only)
cat /etc/group         # group memberships
last                   # login history
w                      # who is logged in right now
sudo -l                # what can THIS user run as sudo? (privesc check)
```

**Why it matters:** The first thing you do after getting a shell is understand what user you are and what you can do. `sudo -l` is the most important privesc check you'll run.

---

## 🔐 File Permissions

```bash
ls -la /etc/shadow
# -rw-r----- 1 root shadow 1234 Jan 1 00:00 /etc/shadow
#  ↑↑↑ ↑↑↑ ↑↑↑
#  │││ │││ └── others: no permissions
#  │││ └──── group: read only
#  └──── owner: read + write
```

Permission breakdown:
```
r = read    (4)
w = write   (2)
x = execute (1)

rwx = 7, rw- = 6, r-x = 5, r-- = 4
```

```bash
chmod 600 secret.txt   # owner read+write only - good for SSH keys
chmod 644 file.txt     # owner rw, everyone else r - standard for files
chmod +x script.sh     # make executable
chown user:group file  # change ownership
```

---

## 🌐 Networking Commands

```bash
ifconfig               # network interfaces and IPs (older systems)
ip a                   # modern version of ifconfig
ip route               # routing table - where does traffic go?
netstat -tuln          # open ports and listening services
ss -tuln               # modern version of netstat
ping -c 4 8.8.8.8      # test connectivity
traceroute google.com  # trace the route packets take
nslookup google.com    # DNS lookup
dig google.com         # detailed DNS lookup
curl -I https://site.com  # fetch HTTP headers only
wget https://site.com/file  # download a file
```

**Why it matters:** After landing on a system, you need to understand the network topology - what else is reachable? What services are running? Where does traffic go?

---

## 📋 Process & System Recon

```bash
ps aux                 # all running processes with details
ps aux | grep root     # processes running as root
top                    # live process monitor
htop                   # better version of top
kill -9 <PID>          # force kill a process
uname -a               # kernel version (important for kernel exploits)
cat /etc/os-release    # OS version
df -h                  # disk usage
free -h                # memory usage
env                    # environment variables (may contain secrets)
```

**Why it matters:** `uname -a` tells you the kernel version - you can look up kernel exploits for that specific version. `env` sometimes contains API keys, database passwords, or tokens left by developers.

---

## 📜 Log Analysis

```bash
cat /var/log/auth.log       # authentication attempts (SSH logins, sudo)
cat /var/log/syslog         # system events
tail -f /var/log/auth.log   # follow logs in real time
grep "Failed password" /var/log/auth.log   # find failed SSH attempts
grep "Accepted" /var/log/auth.log          # find successful logins
journalctl -u ssh           # SSH service logs (systemd systems)
last -a                     # login history with IPs
lastb                       # failed login attempts
```

**Why it matters:** Log analysis is core to detection engineering and incident response. These commands are what you run when something bad has happened and you're trying to figure out who did what and when.

---

## 🔍 Searching & Text Processing

```bash
grep -r "password" /etc/    # search for "password" recursively in /etc
grep -i "error" logfile.txt # case-insensitive search
grep -v "INFO" logfile.txt  # show lines that DON'T contain INFO
cat file.txt | sort | uniq  # sort and remove duplicates
awk '{print $1}' file.txt   # print first column
sed 's/old/new/g' file.txt  # find and replace
cut -d: -f1 /etc/passwd     # extract usernames from passwd file
wc -l file.txt              # count lines
```

---

## 🔗 The Pipe - The Most Powerful Concept in Linux

```bash
# Count how many failed SSH attempts in the last hour
grep "Failed password" /var/log/auth.log | grep "$(date '+%b %e')" | wc -l

# Find all IPs that failed SSH login more than 10 times
grep "Failed password" /var/log/auth.log | \
  awk '{print $11}' | sort | uniq -c | sort -rn | head -20

# Find world-writable files (misconfiguration risk)
find / -type f -perm -o+w 2>/dev/null | grep -v proc
```

Pipes (`|`) chain commands together. Output of one becomes input of the next. This is how security professionals process millions of log lines in seconds.

---

## 💻 The Code - Security Audit Cheatsheet Script

A script that runs the most important security recon commands and summarizes them in one place.

```bash
#!/bin/bash
# Day 006 - Linux Security Recon Script
# 100 Days of Cybersecurity by Sudeep Ravichandran
#
# Runs key recon commands useful for security assessment.
# Use on systems you own or have permission to audit.
#
# Usage: bash linux_cheatsheet.sh

echo "========================================"
echo " Linux Security Recon - Day 006"
echo " 100 Days of Cybersecurity"
echo "========================================"
echo ""

# ── Current User ──────────────────────────
echo "[ USER CONTEXT ]"
echo "  Current user : $(whoami)"
echo "  User ID info : $(id)"
echo ""

# ── Sudo Privileges ───────────────────────
echo "[ SUDO PRIVILEGES ]"
sudo -l 2>/dev/null | grep -v "^$" | head -20
echo ""

# ── Network Interfaces ────────────────────
echo "[ NETWORK INTERFACES ]"
ip a 2>/dev/null | grep -E "inet |^[0-9]" | awk '{print "  "$0}'
echo ""

# ── Open Ports ────────────────────────────
echo "[ LISTENING SERVICES ]"
ss -tuln 2>/dev/null | grep LISTEN | awk '{print "  "$0}'
echo ""

# ── Running Processes (as root) ───────────
echo "[ PROCESSES RUNNING AS ROOT ]"
ps aux 2>/dev/null | awk '$1=="root" {print "  "$11}' | sort -u | head -15
echo ""

# ── SUID Binaries ─────────────────────────
echo "[ SUID BINARIES (privesc check) ]"
find / -perm -4000 -type f 2>/dev/null | awk '{print "  "$0}'
echo ""

# ── World-Writable Files ──────────────────
echo "[ WORLD-WRITABLE FILES ]"
find /etc /var /tmp -type f -perm -o+w 2>/dev/null \
  | grep -v proc | head -10 | awk '{print "  "$0}'
echo ""

# ── Recent Logins ─────────────────────────
echo "[ RECENT LOGINS ]"
last -a 2>/dev/null | head -10 | awk '{print "  "$0}'
echo ""

# ── Failed SSH Attempts ───────────────────
echo "[ FAILED SSH ATTEMPTS (last 20) ]"
if [ -f /var/log/auth.log ]; then
    grep "Failed password" /var/log/auth.log 2>/dev/null \
      | tail -20 | awk '{print "  "$0}'
elif [ -f /var/log/secure ]; then
    grep "Failed password" /var/log/secure 2>/dev/null \
      | tail -20 | awk '{print "  "$0}'
else
    echo "  Log file not found (try journalctl -u ssh)"
fi
echo ""

# ── Environment Variables ─────────────────
echo "[ ENVIRONMENT VARIABLES (potential secrets) ]"
env 2>/dev/null | grep -iE "key|secret|pass|token|api" \
  | awk '{print "  "$0}'
echo ""

echo "========================================"
echo " Recon complete."
echo "========================================"
```

**To run:**
```bash
chmod +x linux_cheatsheet.sh
bash linux_cheatsheet.sh
```

---

## 🔑 Key Takeaways

- `sudo -l` is the first privesc check you run after getting a shell
- `find / -perm -4000` finds SUID binaries - a common privilege escalation path
- `env` sometimes contains credentials left by developers
- Pipes (`|`) are how you turn raw logs into actionable intelligence
- `/var/log/auth.log` is where SSH attacks and sudo usage are recorded

---

## 📚 Resources to Go Deeper
- [OverTheWire: Bandit](https://overthewire.org/wargames/bandit/) - best free Linux practice for security
- [GTFOBins](https://gtfobins.github.io/) - SUID binary exploitation reference
- [explainshell.com](https://explainshell.com/) - paste any command, get it explained

---

## [⬅️ Day 005](../day005/) | [➡️ Day 007](../day007/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*