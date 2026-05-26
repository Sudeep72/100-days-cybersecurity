"""
Day 022 - OSINT Toolkit
100 Days of Cybersecurity by Sudeep Ravichandran

Automates passive recon: WHOIS, DNS records,
certificate transparency, and basic Google dork generation.

Usage: python3 osint_toolkit.py <domain>
Requires: pip install requests dnspython python-whois
"""

import whois
import dns.resolver
import requests
import sys
import json
from datetime import datetime


def run_whois(domain):
    print("\n[+] WHOIS LOOKUP")
    print("-" * 40)
    try:
        w = whois.whois(domain)
        print(f"  Registrar    : {w.registrar}")
        print(f"  Created      : {w.creation_date}")
        print(f"  Expires      : {w.expiration_date}")
        print(f"  Name Servers : {w.name_servers}")
        if w.emails:
            print(f"  Emails       : {w.emails}")
    except Exception as e:
        print(f"  WHOIS failed: {e}")


def run_dns(domain):
    print("\n[+] DNS RECORDS")
    print("-" * 40)
    record_types = ["A", "MX", "NS", "TXT", "CNAME"]
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for r in answers:
                print(f"  {rtype:6} → {r}")
        except Exception:
            pass


def run_crt_sh(domain):
    print("\n[+] CERTIFICATE TRANSPARENCY (crt.sh)")
    print("-" * 40)
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=15)
        certs = resp.json()

        subdomains = set()
        for cert in certs:
            name = cert.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if domain in sub and sub != domain:
                    subdomains.add(sub)

        if subdomains:
            print(f"  Found {len(subdomains)} subdomains:")
            for sub in sorted(subdomains)[:20]:
                print(f"  → {sub}")
            if len(subdomains) > 20:
                print(f"  ... and {len(subdomains) - 20} more")
        else:
            print("  No subdomains found in cert logs")
    except Exception as e:
        print(f"  crt.sh failed: {e}")


def generate_dorks(domain):
    print("\n[+] GOOGLE DORKS (search these manually)")
    print("-" * 40)
    dorks = [
        f'site:{domain} filetype:pdf',
        f'site:{domain} inurl:admin',
        f'site:{domain} inurl:login',
        f'site:{domain} intitle:"index of"',
        f'site:{domain} filetype:xls OR filetype:xlsx',
        f'site:github.com "{domain}" password',
        f'site:github.com "{domain}" api_key',
        f'site:github.com "{domain}" secret',
        f'"{domain}" filetype:csv',
    ]
    for dork in dorks:
        print(f"  → {dork}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 osint_toolkit.py <domain>")
        print("Example: python3 osint_toolkit.py example.com")
        sys.exit(1)

    domain = sys.argv[1].lower().strip()

    print("=" * 50)
    print("  OSINT Toolkit - Day 022")
    print("  100 Days of Cybersecurity")
    print("=" * 50)
    print(f"  Target : {domain}")
    print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  ⚠  Passive recon only - no direct target contact")

    run_whois(domain)
    run_dns(domain)
    run_crt_sh(domain)
    generate_dorks(domain)

    print("\n" + "=" * 50)
    print("  Passive recon complete.")
    print("  Review findings before active scanning.")
    print("=" * 50)


if __name__ == "__main__":
    main()