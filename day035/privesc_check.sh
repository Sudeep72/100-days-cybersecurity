#!/bin/bash
# Day 035 - Linux Privilege Escalation Checker
# 100 Days of Cybersecurity by Sudeep Ravichandran
#
# Quick manual privesc enumeration script.
# Run after getting a low-privilege shell.
#
# Usage: bash privesc_check.sh

echo "==========================================="
echo " Linux PrivEsc Checker — Day 035"
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