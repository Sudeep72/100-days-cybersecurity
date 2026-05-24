# Day 022 - Passive Recon: OSINT & Footprinting

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

The best recon leaves no trace.

Before touching the target network, before running a single scan - a professional attacker spends hours (sometimes days) collecting intelligence using only publicly available information.

This is OSINT - Open Source Intelligence.

The goal: build a complete picture of the target using only what's already out there. No alerts triggered. No logs generated. No indication the target is being watched.

---

## 🔍 What OSINT Finds

A surprising amount is publicly available for almost any organisation:

```
Domain & IP information     → WHOIS, DNS records, IP ranges
Subdomains                  → DNS brute force, certificate logs
Employee information        → LinkedIn, company website, email format
Technology stack            → Job postings, HTTP headers, Wappalyzer
Leaked credentials          → HaveIBeenPwned, Dehashed, Pastebin
Exposed code                → GitHub, GitLab (API keys, passwords)
Internet-exposed systems    → Shodan, Censys, FOFA
Historical data             → Wayback Machine, cached pages
Documents with metadata     → PDFs, Word docs with author info, GPS coords
```

---

## 🛠️ OSINT Techniques

### 1. WHOIS Lookup
Who registered the domain? When? Contact details?

```bash
whois targetcompany.com

# Returns:
# Registrant: John Smith
# Email: john.smith@targetcompany.com  ← real email format
# Name Servers: ns1.targetcompany.com
# Created: 2010-03-15
# Expires: 2025-03-15  ← if expiring soon - domain hijacking opportunity
```

---

### 2. DNS Enumeration
```bash
# All DNS records
dig targetcompany.com ANY

# Mail servers (MX) - useful for phishing/email attacks
dig targetcompany.com MX

# Zone transfer attempt (often fails but worth trying)
dig axfr @ns1.targetcompany.com targetcompany.com

# Subdomain bruteforce (Day 4 script)
python3 dns_enum.py targetcompany.com
```

---

### 3. Certificate Transparency Logs
Every SSL certificate issued is logged publicly. This is a goldmine for subdomain discovery.

```bash
# No tools needed - just a browser:
https://crt.sh/?q=%.targetcompany.com

# Returns every subdomain that ever had an SSL cert issued
# Finds subdomains that DNS brute force misses
```

---

### 4. Google Dorking
Using advanced Google search operators to find things companies didn't mean to expose.

```
site:targetcompany.com                     → all indexed pages
site:targetcompany.com filetype:pdf        → exposed PDF documents
site:targetcompany.com inurl:admin         → admin panels
site:targetcompany.com inurl:login         → login pages
site:targetcompany.com intitle:"index of"  → directory listings
"targetcompany.com" filetype:xls           → exposed spreadsheets
"@targetcompany.com" filetype:csv          → employee email lists
site:github.com "targetcompany.com"        → code mentioning the company
```

---

### 5. Shodan - The Hacker's Search Engine
Shodan indexes internet-connected devices and their exposed services.

```
shodan search "targetcompany.com"
shodan search "org:Target Company"
shodan search "hostname:targetcompany.com port:22"

# Finds:
# → Exposed RDP ports (3389) - ransomware entry point
# → Unpatched services with version numbers
# → Default login pages
# → Industrial control systems (ICS/SCADA) - terrifying
# → Webcams, printers, routers with default credentials
```

---

### 6. LinkedIn Intelligence
LinkedIn is an intelligence goldmine for attackers.

What you can find without any tools:
```
Employee names + roles       → spear phishing targets
Company structure            → who approves wire transfers? (BEC)
Email format                 → john.smith@ or j.smith@ or jsmith@?
Tech stack clues             → "Terraform, AWS, Kubernetes" in job posts
Internal project names       → sometimes appear in profiles
Contractors + vendors        → third-party attack surface
Recent hires in IT           → new employees = less familiar with security procedures
```

---

### 7. GitHub Recon
Developers accidentally push secrets constantly.

```bash
# Search GitHub for company name + sensitive terms
site:github.com "targetcompany" "api_key"
site:github.com "targetcompany" "password"
site:github.com "targetcompany" "secret"
site:github.com "targetcompany.com" "BEGIN RSA PRIVATE KEY"

# Tools for automated GitHub secret scanning:
# truffleHog, gitleaks, gitrob
```

Real findings from GitHub recon:
- AWS access keys in .env files
- Database passwords in config files
- Private SSH keys committed by accident
- Internal API endpoints and documentation

---

### 8. Metadata from Documents
Public PDFs and Word documents often contain hidden metadata.

```bash
# Extract metadata from a PDF
exiftool company_brochure.pdf

# Returns:
# Author: John Smith                ← employee name
# Creator: Microsoft Word 2019      ← software version
# Producer: macOS 12.3              ← OS version
# GPS coordinates                   ← sometimes in photos
# Last Modified By: Sarah Jones     ← another employee name
```

---

## 💻 The Code - OSINT Toolkit

```python
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
```

**To run:**
```bash
pip install requests dnspython python-whois
python3 osint_toolkit.py example.com
```

---

## 🔑 Key Takeaways

- OSINT leaves zero footprint - the target has no idea they're being watched
- Certificate transparency logs find subdomains that DNS brute force misses
- GitHub is the most underestimated source of leaked credentials and internal data
- Document metadata reveals software versions, employee names, and sometimes GPS data
- LinkedIn tells you the target's tech stack, org structure, and email format without any hacking
- OSINT findings directly feed into every later phase - better recon = better attack paths

---

## 📚 Resources to Go Deeper
- [OSINT Framework](https://osintframework.com/) - visual map of every OSINT tool
- [Shodan](https://www.shodan.io/) - internet device search engine
- [crt.sh](https://crt.sh/) - certificate transparency search
- [IntelTechniques](https://inteltechniques.com/) - advanced OSINT methodology

---

## [⬅️ Day 021](../day021/) | [➡️ Day 023](../day023/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*