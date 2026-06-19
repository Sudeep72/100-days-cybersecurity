# Day 047 - Log Analysis: What to Look For and Why

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Logs are the evidence trail of everything that happens on a system.

Every login. Every process execution. Every network connection. Every file access.

The challenge: a busy system generates millions of log lines per day. Maybe 0.001% of them indicate an attack. Finding those lines - without drowning in noise - is log analysis.

This skill is core to SOC work, incident response, detection engineering, and threat hunting. My LogREx research is built on exactly this problem.

---

## 📂 Critical Log Sources - Linux

### /var/log/auth.log (Authentication Events)

```bash
# View all auth events
cat /var/log/auth.log

# SSH brute force - many failures from same IP
grep "Failed password" /var/log/auth.log | head -20

# Successful logins after failures (credential stuffing success)
grep "Accepted password" /var/log/auth.log

# Source IP analysis - who's brute forcing?
grep "Failed password" /var/log/auth.log \
  | awk '{print $11}' \
  | sort | uniq -c | sort -rn | head -10

# Impossible travel - same user, different IPs close in time
grep "Accepted" /var/log/auth.log \
  | awk '{print $9, $11}' \
  | sort
```

**What to look for:**
```
✓ Many failures then success from same IP → successful brute force
✓ Login from new geographic location
✓ Login at unusual hours
✓ Root login via SSH (should almost never happen)
✓ Service account logging in interactively
```

---

### /var/log/syslog (System Events)

```bash
# Kernel messages
grep "kernel" /var/log/syslog | tail -50

# Service start/stop (may indicate attacker manipulation)
grep "systemd" /var/log/syslog | grep -E "start|stop|fail"

# OOM killer - may indicate cryptominer
grep "OOM" /var/log/syslog
grep "Killed process" /var/log/syslog
```

---

### /var/log/apache2/access.log (Web Server)

```bash
# All requests
tail -100 /var/log/apache2/access.log

# 404 errors - scanning/enumeration
grep " 404 " /var/log/apache2/access.log | wc -l

# High 404 count from single IP - directory scanning
grep " 404 " /var/log/apache2/access.log \
  | awk '{print $1}' | sort | uniq -c | sort -rn | head -10

# SQL injection attempts in URLs
grep -E "union|select|insert|drop|%27|%22" /var/log/apache2/access.log -i

# XSS attempts
grep -E "<script|onerror|javascript:" /var/log/apache2/access.log -i

# Webshell access patterns (short requests to .php files returning 200)
grep "\.php" /var/log/apache2/access.log | grep " 200 " | head -20

# User agent analysis - automated scanners
awk '{print $12}' /var/log/apache2/access.log \
  | sort | uniq -c | sort -rn | head -10
```

---

### /var/log/secure or journalctl (System Journal)

```bash
# systemd journal (modern Linux)
journalctl -u ssh --since "1 hour ago"
journalctl -p err --since today
journalctl -f    # follow live

# Sudo usage - who ran what as root?
journalctl | grep "sudo"
grep "sudo" /var/log/auth.log | grep "COMMAND"
```

---

## 📂 Critical Log Sources - Windows

### Windows Event Log (Key Event IDs)

```
Security Events:
4624 → Successful logon
4625 → Failed logon
4648 → Logon with explicit credentials (pass-the-hash indicator)
4672 → Special privileges assigned (admin logon)
4688 → Process creation (with command line if Sysmon enabled)
4698 → Scheduled task created
4702 → Scheduled task modified
4720 → User account created
4726 → User account deleted
4732 → User added to privileged group
4756 → Member added to security-enabled universal group
4771 → Kerberos pre-auth failed (Kerberoasting indicator)
4776 → NTLM authentication attempt

System Events:
7045 → New service installed (persistence indicator)
7034 → Service crashed unexpectedly

PowerShell Events:
4103 → PowerShell module logging
4104 → PowerShell script block logging (encoded commands here)
```

---

## 💻 The Code - Log Parser & Analyser

```python
"""
Day 047 - Log Parser & Analyser
100 Days of Cybersecurity by Sudeep Ravichandran

Parses auth.log and web access logs to surface
suspicious patterns and security-relevant events.

Usage:
  python3 log_parser.py --auth /var/log/auth.log
  python3 log_parser.py --web /var/log/apache2/access.log
  python3 log_parser.py --auth /var/log/auth.log --web access.log

Requires: pip install rich
"""

import re
import sys
import argparse
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich import print as rprint
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None


# ── Patterns ──────────────────────────────────────────────────
PATTERNS = {
    "ssh_fail":    re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)"),
    "ssh_success": re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+)"),
    "ssh_invalid": re.compile(r"Invalid user (\S+) from (\S+)"),
    "sudo":        re.compile(r"sudo:\s+(\S+) : .* COMMAND=(.+)"),
    "new_session": re.compile(r"pam_unix\(su:session\): session opened for user (\S+)"),
}

WEB_INJECTION = re.compile(
    r"(union.*select|select.*from|insert.*into|drop.*table|"
    r"%27|%22|<script|onerror=|javascript:|"
    r"\.\./|etc/passwd|/bin/bash|cmd\.exe)",
    re.IGNORECASE
)

SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|"
    r"nessus|openvas|nuclei|wfuzz|hydra|zgrab)",
    re.IGNORECASE
)


def parse_auth_log(filepath: str):
    """Parse auth.log for security-relevant events."""
    print(f"\n{'='*55}")
    print(f"  AUTH LOG ANALYSIS: {filepath}")
    print(f"{'='*55}\n")

    failed_ips    = Counter()
    failed_users  = Counter()
    success_ips   = Counter()
    success_users = Counter()
    sudo_cmds     = []
    invalid_users = Counter()

    try:
        with open(filepath) as f:
            for line in f:
                # Failed SSH
                m = PATTERNS["ssh_fail"].search(line)
                if m:
                    failed_users[m.group(1)] += 1
                    failed_ips[m.group(2)] += 1
                    continue

                # Successful SSH
                m = PATTERNS["ssh_success"].search(line)
                if m:
                    success_users[m.group(1)] += 1
                    success_ips[m.group(2)] += 1
                    continue

                # Invalid users
                m = PATTERNS["ssh_invalid"].search(line)
                if m:
                    invalid_users[m.group(1)] += 1
                    continue

                # Sudo commands
                m = PATTERNS["sudo"].search(line)
                if m:
                    sudo_cmds.append((m.group(1), m.group(2).strip()))

    except FileNotFoundError:
        print(f"  [!] File not found: {filepath}")
        return

    # ── Report ─────────────────────────────────────────────────

    # Failed logins by IP
    if failed_ips:
        print("[!] TOP IPs WITH FAILED LOGINS (brute force indicator)")
        for ip, count in failed_ips.most_common(10):
            flag = " ← ⚠ HIGH VOLUME" if count > 50 else ""
            print(f"    {count:6} failures  {ip}{flag}")

    # Successful logins
    if success_ips:
        print(f"\n[+] SUCCESSFUL LOGINS")
        for ip, count in success_ips.most_common(10):
            print(f"    {count:6} logins  {ip}")

    # Cross-reference: IPs with both failures and successes
    brute_success = set(failed_ips.keys()) & set(success_ips.keys())
    if brute_success:
        print(f"\n[!!!] POSSIBLE SUCCESSFUL BRUTE FORCE (failures then success):")
        for ip in brute_success:
            print(f"    {ip}  (failed: {failed_ips[ip]}, succeeded: {success_ips[ip]})")

    # Invalid usernames (enumeration)
    if invalid_users:
        print(f"\n[!] INVALID USERNAMES ATTEMPTED (enumeration)")
        for user, count in invalid_users.most_common(10):
            print(f"    {count:6}x  {user}")

    # Sudo usage
    if sudo_cmds:
        print(f"\n[+] SUDO COMMANDS EXECUTED ({len(sudo_cmds)} total)")
        for user, cmd in sudo_cmds[:10]:
            print(f"    {user}: {cmd[:70]}")


def parse_web_log(filepath: str):
    """Parse web access log for attack patterns."""
    print(f"\n{'='*55}")
    print(f"  WEB ACCESS LOG ANALYSIS: {filepath}")
    print(f"{'='*55}\n")

    status_codes  = Counter()
    ip_requests   = Counter()
    injections    = []
    scanner_hits  = []
    path_traverse = []

    log_pattern = re.compile(
        r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d+) (\d+) "[^"]*" "([^"]*)"'
    )

    try:
        with open(filepath) as f:
            for line in f:
                m = log_pattern.search(line)
                if not m:
                    continue

                ip, time, method, path, status, size, ua = m.groups()
                ip_requests[ip] += 1
                status_codes[status] += 1

                # Injection patterns in URL
                if WEB_INJECTION.search(path):
                    injections.append((ip, method, path[:80], status))

                # Scanner user agents
                if SCANNER_UA.search(ua):
                    scanner_hits.append((ip, ua[:50]))

                # Path traversal
                if "../" in path or "..%2F" in path.lower():
                    path_traverse.append((ip, path[:80]))

    except FileNotFoundError:
        print(f"  [!] File not found: {filepath}")
        return

    # ── Report ─────────────────────────────────────────────────

    print(f"[+] REQUEST VOLUME BY IP (top 10)")
    for ip, count in ip_requests.most_common(10):
        flag = " ← ⚠ HIGH VOLUME" if count > 1000 else ""
        print(f"    {count:6}  {ip}{flag}")

    print(f"\n[+] STATUS CODE DISTRIBUTION")
    for code, count in sorted(status_codes.items()):
        bar = "█" * min(count // 10, 40)
        flag = " ← scanning?" if code == "404" and count > 100 else ""
        print(f"    {code}  {count:6}  {bar}{flag}")

    if injections:
        print(f"\n[!!!] INJECTION ATTEMPTS ({len(injections)} found)")
        for ip, method, path, status in injections[:10]:
            print(f"    [{status}] {method} {path}  ({ip})")

    if scanner_hits:
        unique_scanners = Counter(ip for ip, ua in scanner_hits)
        print(f"\n[!] SECURITY SCANNER USER AGENTS")
        for ip, count in unique_scanners.most_common(5):
            print(f"    {ip}  ({count} requests)")

    if path_traverse:
        print(f"\n[!!!] PATH TRAVERSAL ATTEMPTS")
        for ip, path in path_traverse[:10]:
            print(f"    {ip}  {path}")


def main():
    parser = argparse.ArgumentParser(
        description="Log Analyser - Day 047 | 100 Days of Cybersecurity"
    )
    parser.add_argument("--auth", help="Path to auth.log")
    parser.add_argument("--web",  help="Path to web access log")
    args = parser.parse_args()

    if not args.auth and not args.web:
        parser.print_help()
        sys.exit(1)

    print("=" * 55)
    print("  Log Analyser - Day 047")
    print("  100 Days of Cybersecurity")
    print("=" * 55)

    if args.auth:
        parse_auth_log(args.auth)
    if args.web:
        parse_web_log(args.web)


if __name__ == "__main__":
    main()
```

**To run:**
```bash
pip install rich
sudo python3 log_parser.py --auth /var/log/auth.log
python3 log_parser.py --web /var/log/apache2/access.log
```

---

## 🔑 Key Takeaways

- Logs are the evidence trail - what you don't log, you can't detect
- auth.log surfaces brute force, credential stuffing, privilege escalation
- Web logs surface scanning, injection attempts, webshell access
- Cross-referencing failed + successful logins from same IP = successful brute force indicator
- Windows Event ID 4688 (process creation) is the single most valuable Windows log source
- Log analysis is a skill - the patterns matter more than individual lines

---

## 📚 Resources
- [SANS Log Management Cheat Sheet](https://www.sans.org/blog/the-ultimate-list-of-sans-cheat-sheets/)
- [Windows Event ID Reference](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [The DFIR Report - real attack log analysis](https://thedfirreport.com/)

---

## [⬅️ Day 046](../day046/) | [➡️ Day 048](../day048/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*