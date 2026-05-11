#!/bin/bash
# Day 007 - Permission Auditor
# 100 Days of Cybersecurity by Sudeep Ravichandran
#
# Audits a Linux system for dangerous permission misconfigurations.
# Use on systems you own or have permission to audit.
#
# Usage: bash perm_audit.sh

echo "========================================"
echo " Permission Auditor - Day 007"
echo " 100 Days of Cybersecurity"
echo "========================================"
echo ""

# ── Sensitive Files — Check Permissions ───
echo "[ SENSITIVE FILE PERMISSIONS ]"
sensitive_files=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/sudoers"
    "/etc/crontab"
    "$HOME/.ssh/id_rsa"
    "$HOME/.ssh/authorized_keys"
)

for f in "${sensitive_files[@]}"; do
    if [ -e "$f" ]; then
        perms=$(stat -c "%a %U:%G %n" "$f" 2>/dev/null)
        echo "  $perms"
    fi
done
echo ""

# ── World-Writable Files ──────────────────
echo "[ WORLD-WRITABLE FILES (dangerous) ]"
echo "  Searching... (this may take a moment)"
find /etc /var /usr /tmp -type f -perm -o+w 2>/dev/null \
    | grep -v "/proc" \
    | head -15 \
    | while read f; do echo "  ⚠  $f"; done
echo ""

# ── SUID Binaries ─────────────────────────
echo "[ SUID BINARIES ]"
echo "  Check each against GTFOBins: https://gtfobins.github.io"
find / -perm -4000 -type f 2>/dev/null \
    | while read f; do
        owner=$(stat -c "%U" "$f" 2>/dev/null)
        echo "  [SUID:$owner] $f"
    done
echo ""

# ── SGID Binaries ─────────────────────────
echo "[ SGID BINARIES ]"
find / -perm -2000 -type f 2>/dev/null \
    | while read f; do
        group=$(stat -c "%G" "$f" 2>/dev/null)
        echo "  [SGID:$group] $f"
    done
echo ""

# ── Writable PATH Directories ─────────────
echo "[ PATH DIRECTORY WRITE CHECK ]"
echo "  Current PATH: $PATH"
IFS=':' read -ra PATH_DIRS <<< "$PATH"
for dir in "${PATH_DIRS[@]}"; do
    if [ -w "$dir" ] 2>/dev/null; then
        echo "  ⚠  WRITABLE: $dir — hijacking risk"
    else
        echo "  ✓  $dir"
    fi
done
echo ""

# ── Crontab Check ─────────────────────────
echo "[ CRONTAB PERMISSIONS ]"
for cronfile in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
    if [ -e "$cronfile" ]; then
        perms=$(stat -c "%a" "$cronfile" 2>/dev/null)
        if [ "$perms" -gt "644" ] 2>/dev/null; then
            echo "  ⚠  Loose permissions ($perms): $cronfile"
        else
            echo "  ✓  $cronfile ($perms)"
        fi
    fi
done
echo ""

echo "========================================"
echo " Audit complete."
echo " Review any ⚠  items - these are your risk areas."
echo "========================================"