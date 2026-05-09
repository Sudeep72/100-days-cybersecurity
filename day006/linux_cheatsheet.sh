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