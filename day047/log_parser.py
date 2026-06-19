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
from collections import Counter

try:
    from rich.console import Console
    console = Console()
    RICH = True
except ImportError:
    RICH = False

PATTERNS = {
    "ssh_fail":    re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)"),
    "ssh_success": re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+)"),
    "ssh_invalid": re.compile(r"Invalid user (\S+) from (\S+)"),
    "sudo":        re.compile(r"sudo:\s+(\S+) : .* COMMAND=(.+)"),
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

LOG_RE = re.compile(
    r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d+) (\d+) "[^"]*" "([^"]*)"'
)


def parse_auth_log(filepath):
    print(f"\n{'='*55}\n  AUTH LOG: {filepath}\n{'='*55}\n")
    failed_ips = Counter()
    success_ips = Counter()
    invalid_users = Counter()
    sudo_cmds = []

    try:
        with open(filepath) as f:
            for line in f:
                m = PATTERNS["ssh_fail"].search(line)
                if m:
                    failed_ips[m.group(2)] += 1
                    continue
                m = PATTERNS["ssh_success"].search(line)
                if m:
                    success_ips[m.group(2)] += 1
                    continue
                m = PATTERNS["ssh_invalid"].search(line)
                if m:
                    invalid_users[m.group(1)] += 1
                    continue
                m = PATTERNS["sudo"].search(line)
                if m:
                    sudo_cmds.append((m.group(1), m.group(2).strip()))
    except FileNotFoundError:
        print(f"  File not found: {filepath}")
        return

    if failed_ips:
        print("[!] TOP FAILED LOGIN IPs")
        for ip, c in failed_ips.most_common(10):
            flag = " ← ⚠ HIGH VOLUME" if c > 50 else ""
            print(f"    {c:6}  {ip}{flag}")

    if success_ips:
        print(f"\n[+] SUCCESSFUL LOGINS")
        for ip, c in success_ips.most_common(10):
            print(f"    {c:6}  {ip}")

    brute_success = set(failed_ips) & set(success_ips)
    if brute_success:
        print(f"\n[!!!] POSSIBLE BRUTE FORCE SUCCESS")
        for ip in brute_success:
            print(f"    {ip}  (failed: {failed_ips[ip]}, success: {success_ips[ip]})")

    if invalid_users:
        print(f"\n[!] INVALID USERNAMES (enumeration)")
        for user, c in invalid_users.most_common(10):
            print(f"    {c:6}x  {user}")

    if sudo_cmds:
        print(f"\n[+] SUDO COMMANDS ({len(sudo_cmds)} total)")
        for user, cmd in sudo_cmds[:10]:
            print(f"    {user}: {cmd[:70]}")


def parse_web_log(filepath):
    print(f"\n{'='*55}\n  WEB LOG: {filepath}\n{'='*55}\n")
    status_codes = Counter()
    ip_requests = Counter()
    injections = []
    scanner_hits = []
    traversals = []

    try:
        with open(filepath) as f:
            for line in f:
                m = LOG_RE.search(line)
                if not m:
                    continue
                ip, _, method, path, status, size, ua = m.groups()
                ip_requests[ip] += 1
                status_codes[status] += 1
                if WEB_INJECTION.search(path):
                    injections.append((ip, method, path[:80], status))
                if SCANNER_UA.search(ua):
                    scanner_hits.append(ip)
                if "../" in path or "..%2f" in path.lower():
                    traversals.append((ip, path[:80]))
    except FileNotFoundError:
        print(f"  File not found: {filepath}")
        return

    print("[+] REQUEST VOLUME BY IP")
    for ip, c in ip_requests.most_common(10):
        flag = " ← ⚠" if c > 1000 else ""
        print(f"    {c:6}  {ip}{flag}")

    print(f"\n[+] STATUS CODES")
    for code, c in sorted(status_codes.items()):
        flag = " ← scanning?" if code == "404" and c > 100 else ""
        print(f"    {code}  {c:6}{flag}")

    if injections:
        print(f"\n[!!!] INJECTION ATTEMPTS ({len(injections)})")
        for ip, method, path, status in injections[:10]:
            print(f"    [{status}] {method} {path}  ({ip})")

    if scanner_hits:
        print(f"\n[!] SCANNER TOOL DETECTED")
        for ip, c in Counter(scanner_hits).most_common(5):
            print(f"    {ip}  ({c} requests)")

    if traversals:
        print(f"\n[!!!] PATH TRAVERSAL ATTEMPTS ({len(traversals)})")
        for ip, path in traversals[:5]:
            print(f"    {ip}  {path}")


def main():
    parser = argparse.ArgumentParser(
        description="Log Analyser - 100 Days of Cybersecurity"
    )
    parser.add_argument("--auth", help="auth.log path")
    parser.add_argument("--web",  help="web access log path")
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