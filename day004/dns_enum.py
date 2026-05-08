"""
Day 004 - DNS Enumerator
100 Days of Cybersecurity by Sudeep Ravichandran

Performs subdomain enumeration to map a target's attack surface.
Only use on domains you own or have explicit permission to test.

Usage: python3 dns_enum.py <domain>
Requires: pip install dnspython
"""

import dns.resolver
import sys
from datetime import datetime


# Common subdomains attackers check first
WORDLIST = [
    "www", "mail", "ftp", "admin", "vpn", "remote", "dev", "staging",
    "test", "api", "portal", "blog", "shop", "app", "secure", "login",
    "webmail", "smtp", "pop", "imap", "ns1", "ns2", "cdn", "static",
    "beta", "old", "backup", "internal", "corp", "intranet", "dashboard",
    "support", "help", "docs", "git", "jenkins", "jira", "confluence"
]


def resolve_subdomain(subdomain, domain):
    """Try to resolve a subdomain. Return IP if found, None if not."""
    target = f"{subdomain}.{domain}"
    try:
        answers = dns.resolver.resolve(target, "A")
        ips = [str(r) for r in answers]
        return target, ips
    except (dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.Timeout,
            dns.exception.DNSException):
        return None, None


def get_dns_records(domain):
    """Fetch common DNS record types for the root domain."""
    records = {}
    record_types = ["A", "MX", "NS", "TXT", "CNAME"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            pass

    return records


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 dns_enum.py <domain>")
        print("Example: python3 dns_enum.py example.com")
        sys.exit(1)

    domain = sys.argv[1].lower().strip()

    print("=" * 55)
    print("100 Days of Cybersecurity - Day 004")
    print("DNS Enumerator")
    print("=" * 55)
    print(f"Target: {domain}")
    print(f"Started: {datetime.now().strftime('%H:%M:%S')}")
    print(f"Checking {len(WORDLIST)} subdomains...\n")

    # Step 1: Get base DNS records
    print("[*] Fetching DNS records for root domain...")
    records = get_dns_records(domain)
    for rtype, values in records.items():
        for val in values:
            print(f"  {rtype:6} → {val}")

    # Step 2: Enumerate subdomains
    print(f"\n[*] Starting subdomain enumeration...")
    found = []

    for word in WORDLIST:
        target, ips = resolve_subdomain(word, domain)
        if target and ips:
            print(f"  [+] FOUND: {target}")
            for ip in ips:
                print(f"        IP: {ip}")
            found.append((target, ips))

    # Step 3: Summary
    print("\n" + "=" * 55)
    print(f"RESULTS: {len(found)} subdomains found")
    print("=" * 55)

    if found:
        print("\nAttack surface discovered:")
        for subdomain, ips in found:
            print(f"  → {subdomain} ({', '.join(ips)})")
        print("\n⚠️  Each subdomain is a potential entry point.")
        print("    Check for exposed admin panels, dev environments,")
        print("    and outdated services on each.")
    else:
        print("No subdomains found from wordlist.")

    print(f"\nFinished: {datetime.now().strftime('%H:%M:%S')}")


if __name__ == "__main__":
    main()