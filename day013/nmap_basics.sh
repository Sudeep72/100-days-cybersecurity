#!/bin/bash
# Day 013 - Nmap Recon Script
# 100 Days of Cybersecurity by Sudeep Ravichandran
#
# Runs a structured recon scan against a target.
# ONLY use against systems you own or have permission to test.
#
# Usage: bash nmap_basics.sh <target>
# Example: bash nmap_basics.sh 192.168.1.1

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Usage: bash nmap_basics.sh <target>"
    echo "Example: bash nmap_basics.sh 192.168.1.1"
    exit 1
fi

echo "========================================"
echo " Nmap Recon Script - Day 013"
echo " 100 Days of Cybersecurity"
echo "========================================"
echo " Target: $TARGET"
echo " $(date)"
echo "========================================"
echo ""

# Phase 1: Host Discovery
echo "[Phase 1] Checking if host is alive..."
nmap -sn "$TARGET" 2>/dev/null | grep -E "Host|latency"
echo ""

# Phase 2: Quick Port Scan (top 1000)
echo "[Phase 2] Scanning top 1000 ports..."
nmap -T4 --open "$TARGET" 2>/dev/null
echo ""

# Phase 3: Service Version Detection
echo "[Phase 3] Detecting service versions on open ports..."
nmap -sV -T4 --open "$TARGET" 2>/dev/null
echo ""

# Phase 4: Default Scripts
echo "[Phase 4] Running default NSE scripts..."
nmap -sC -T4 --open "$TARGET" 2>/dev/null
echo ""

# Phase 5: Save full results
OUTFILE="nmap_${TARGET}_$(date +%Y%m%d_%H%M%S)"
echo "[Phase 5] Saving full results to ${OUTFILE}..."
nmap -sV -sC -T4 -oA "$OUTFILE" "$TARGET" 2>/dev/null
echo " Results saved: ${OUTFILE}.nmap / .xml / .gnmap"
echo ""

echo "========================================"
echo " Recon complete."
echo " Review open ports and service versions."
echo " Check versions against CVE databases."
echo "========================================"