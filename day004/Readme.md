# Day 004 - DNS: The Protocol Hackers Love to Abuse

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

DNS - Domain Name System - is the internet's phone book.

You type `google.com`. DNS translates it to `142.250.80.46`. Your browser connects to that IP.

Simple. Elegant. And completely abused by attackers.

Why? Because DNS was designed in 1983 for a trusted academic network. Security was never part of the original design. It was built to be fast and open - not safe.

---

## 🔁 How DNS Resolution Works

```
You type: google.com
       ↓
1. Check local cache - "Have I looked this up before?"
       ↓ (cache miss)
2. Ask Recursive Resolver (usually your ISP or 8.8.8.8)
       ↓
3. Resolver asks Root Nameserver - "Who handles .com?"
       ↓
4. Root says - "Ask the .com TLD nameserver"
       ↓
5. TLD nameserver says - "Ask Google's authoritative nameserver"
       ↓
6. Google's nameserver returns: 142.250.80.46
       ↓
7. Resolver caches the answer, returns it to you
       ↓
Your browser connects to 142.250.80.46
```

Every step is a potential attack point.

---

## ⚠️ DNS Attack Types

### 1. DNS Spoofing / Cache Poisoning
Attacker injects a fake DNS record into a resolver's cache.

```
Legitimate: google.com → 142.250.80.46
Poisoned:   google.com → 10.0.0.1 (attacker's server)
```

Everyone who queries that resolver now gets sent to the attacker's IP. They see a fake site. They enter credentials. Game over.

**Real example:** 2010 - China's DNS servers accidentally leaked, redirecting global traffic including Twitter and YouTube to wrong IPs for hours.

---

### 2. DNS Enumeration
Attackers map out all subdomains of a target before attacking.

```
target.com
├── mail.target.com      → email server (juicy)
├── vpn.target.com       → VPN gateway (very juicy)
├── dev.target.com       → development server (often unprotected)
├── admin.target.com     → admin panel (jackpot)
└── old.target.com       → legacy system (usually vulnerable)
```

Every subdomain is a potential attack surface. Most companies don't even know all their subdomains.

---

### 3. DNS Tunneling
Attackers exfiltrate data or establish C2 (command and control) channels by hiding data inside DNS queries.

```
Normal DNS query:  google.com → IP?
Tunneled query:    c2data.attacker.com → encoded payload inside the query name
```

Firewalls often allow DNS traffic through (port 53). It's a blind spot.

**Tools used:** Iodine, DNScat2

---

### 4. DNS Hijacking
Attacker compromises the DNS registrar or nameserver directly - changing where a domain points at the source.

Harder to pull off. Devastating when it works. Entire domains can be redirected globally.

---

### 5. DDoS via DNS Amplification
Attacker sends a small DNS query spoofing the victim's IP.
DNS server sends a large response to the victim.
Amplification factor: up to 70x.

```
Attacker sends:  50 byte query  → DNS server
DNS server sends: 3,500 byte response → Victim
```

---

## 💻 The Code — DNS Enumerator

This script performs subdomain enumeration on a target domain - the same recon technique attackers use before an engagement.

**Only run this on domains you own or have permission to test.**

```python
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
```

**To run:**
```bash
pip install dnspython
python3 dns_enum.py example.com
```

**Sample output:**
```
[*] Fetching DNS records for root domain...
  A      → 93.184.216.34
  MX     → mail.example.com
  NS     → ns1.example.com

[*] Starting subdomain enumeration...
  [+] FOUND: www.example.com
        IP: 93.184.216.34
  [+] FOUND: mail.example.com
        IP: 93.184.216.100

RESULTS: 2 subdomains found
```

---

## 🔐 Defenses Against DNS Attacks

| Attack | Defense |
|--------|---------|
| DNS Spoofing | DNSSEC (cryptographically signs DNS records) |
| DNS Tunneling | Monitor for unusually long/encoded DNS queries |
| DNS Hijacking | MFA on domain registrar accounts, registry lock |
| DNS Amplification | Rate limiting on open resolvers, BCP38 filtering |
| Enumeration | Don't expose unnecessary subdomains, use split-horizon DNS |

---

## 🔑 Key Takeaways

- DNS was designed for a trusted network in 1983 - security was never built in
- Every subdomain is part of your attack surface - most orgs don't know all of theirs
- DNS traffic (port 53) is often allowed through firewalls - attackers exploit this for tunneling
- DNSSEC exists but adoption is still low - most DNS traffic is still unauthenticated

---

## 📚 Resources to Go Deeper
- [How DNS Works (comic)](https://howdns.works/)
- [DNSSEC explained - Cloudflare](https://www.cloudflare.com/dns/dnssec/how-dnssec-works/)
- [DNSdumpster - passive DNS recon tool](https://dnsdumpster.com/)

---

## [⬅️ Day 003](../day003/) | [➡️ Day 005](../day005/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*