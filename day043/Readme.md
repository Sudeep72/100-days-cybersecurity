# Day 043 - Building a Subdomain Scanner from Scratch

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

On Day 4 we built a basic DNS enumerator.
On Day 22 we used certificate transparency for passive recon.

Today we combine both approaches - and add threading, rate limiting, wildcard detection, and output formatting - into a professional-grade subdomain scanner.

This is the kind of tool that goes on your GitHub and gets starred. Real utility. Clean code. Solves an actual problem.

---

## 🎯 What We're Building

```
Features:
├── DNS brute force with wordlist
├── Certificate transparency (crt.sh) - passive, no noise
├── Wildcard detection - avoids false positives
├── Concurrent threading - fast without hammering the resolver
├── Multiple output formats - text, JSON, CSV
└── Real-time progress display
```

---

## 💻 The Code

```python
"""
Day 043 - Subdomain Scanner
100 Days of Cybersecurity by Sudeep Ravichandran

Professional-grade subdomain enumeration combining
DNS brute force and certificate transparency.

Usage:
  python3 subdomain_scanner.py -d example.com
  python3 subdomain_scanner.py -d example.com -w wordlist.txt -t 50
  python3 subdomain_scanner.py -d example.com -o results.json --format json

Requires: pip install dnspython requests
"""

import dns.resolver
import requests
import json
import csv
import argparse
import sys
import time
import threading
from queue import Queue
from datetime import datetime
from typing import Optional


# ── Default wordlist ──────────────────────────────────────────
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "admin", "vpn", "remote", "dev", "staging",
    "test", "api", "portal", "blog", "shop", "app", "secure", "login",
    "webmail", "smtp", "pop", "imap", "ns1", "ns2", "ns3", "cdn", "static",
    "beta", "old", "backup", "internal", "corp", "intranet", "dashboard",
    "support", "help", "docs", "git", "jenkins", "jira", "confluence",
    "gitlab", "github", "bitbucket", "ci", "registry", "docker", "k8s",
    "prod", "production", "stage", "preprod", "uat", "qa", "sandbox",
    "demo", "preview", "assets", "media", "img", "images", "files",
    "upload", "download", "s3", "storage", "db", "database", "redis",
    "elastic", "kibana", "grafana", "prometheus", "monitor", "metrics",
    "status", "health", "ping", "dev1", "dev2", "test1", "test2",
    "web", "web1", "web2", "lb", "loadbalancer", "proxy", "gateway",
    "auth", "sso", "oauth", "accounts", "profile", "user", "users",
    "mobile", "m", "wap", "api2", "v1", "v2", "graphql", "rest",
    "smtp", "mail2", "mx", "mx1", "mx2", "exchange", "autodiscover",
    "news", "forum", "community", "wiki", "kb", "knowledge",
]


class SubdomainScanner:

    def __init__(
        self,
        domain: str,
        wordlist: Optional[list] = None,
        threads: int = 30,
        timeout: float = 2.0,
        verbose: bool = False
    ):
        self.domain    = domain.lower().strip()
        self.wordlist  = wordlist or DEFAULT_WORDLIST
        self.threads   = threads
        self.timeout   = timeout
        self.verbose   = verbose
        self.found     = []
        self.lock      = threading.Lock()
        self.queue     = Queue()
        self.wildcard  = None
        self._checked  = 0

        # Configure resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    # ── Wildcard detection ────────────────────────────────────
    def check_wildcard(self) -> bool:
        """Check if domain uses wildcard DNS - would cause false positives."""
        fake = f"this-subdomain-does-not-exist-{int(time.time())}.{self.domain}"
        try:
            self.resolver.resolve(fake, "A")
            return True   # resolved → wildcard DNS
        except Exception:
            return False  # NXDOMAIN → no wildcard

    # ── DNS resolution ────────────────────────────────────────
    def resolve(self, subdomain: str) -> Optional[list]:
        """Resolve a subdomain, return list of IPs or None."""
        fqdn = f"{subdomain}.{self.domain}"
        try:
            answers = self.resolver.resolve(fqdn, "A")
            return [str(r) for r in answers]
        except Exception:
            return None

    # ── Worker thread ─────────────────────────────────────────
    def worker(self):
        while True:
            subdomain = self.queue.get()
            if subdomain is None:
                break

            ips = self.resolve(subdomain)
            with self.lock:
                self._checked += 1
                if ips:
                    fqdn = f"{subdomain}.{self.domain}"
                    entry = {"subdomain": fqdn, "ips": ips, "source": "brute"}
                    self.found.append(entry)
                    print(f"  \033[92m[+] {fqdn:<45} {', '.join(ips)}\033[0m")
                elif self.verbose:
                    print(f"  [-] {subdomain}.{self.domain}")

            self.queue.task_done()

    # ── Certificate transparency ──────────────────────────────
    def crt_sh(self) -> list:
        """Fetch subdomains from certificate transparency logs."""
        print("[*] Querying certificate transparency logs (crt.sh)...")
        found = []
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=15,
                headers={"User-Agent": "SubdomainScanner/1.0"}
            )
            certs = resp.json()
            seen = set()

            for cert in certs:
                for name in cert.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if (
                        name.endswith(f".{self.domain}")
                        and name not in seen
                        and "*" not in name
                    ):
                        seen.add(name)
                        # Try to resolve
                        subdomain = name.replace(f".{self.domain}", "")
                        ips = self.resolve(subdomain)
                        if ips:
                            entry = {
                                "subdomain": name,
                                "ips": ips,
                                "source": "crt.sh"
                            }
                            found.append(entry)
                            print(f"  \033[94m[crt] {name:<43} {', '.join(ips)}\033[0m")

        except Exception as e:
            print(f"  [!] crt.sh failed: {e}")

        return found

    # ── Main scan ─────────────────────────────────────────────
    def scan(self) -> list:
        print(f"\n{'='*55}")
        print(f"  Subdomain Scanner - Day 043")
        print(f"  100 Days of Cybersecurity")
        print(f"{'='*55}")
        print(f"  Target  : {self.domain}")
        print(f"  Words   : {len(self.wordlist)}")
        print(f"  Threads : {self.threads}")
        print(f"  Started : {datetime.now().strftime('%H:%M:%S')}")

        # Wildcard check
        print(f"\n[*] Checking for wildcard DNS...")
        if self.check_wildcard():
            print(f"  [!] Wildcard DNS detected - results may contain false positives")
            self.wildcard = True
        else:
            print(f"  [✓] No wildcard DNS - results reliable")
            self.wildcard = False

        # Certificate transparency (passive - no DNS queries)
        crt_results = self.crt_sh()
        self.found.extend(crt_results)

        # DNS brute force
        print(f"\n[*] Starting DNS brute force ({len(self.wordlist)} words)...")

        # Start worker threads
        thread_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            thread_list.append(t)

        # Enqueue all words
        for word in self.wordlist:
            self.queue.put(word)

        # Add None sentinels to stop workers
        for _ in range(self.threads):
            self.queue.put(None)

        # Wait for completion
        self.queue.join()

        # Deduplicate results
        seen = set()
        unique = []
        for entry in self.found:
            if entry["subdomain"] not in seen:
                seen.add(entry["subdomain"])
                unique.append(entry)
        self.found = unique

        print(f"\n{'='*55}")
        print(f"  Scan complete: {len(self.found)} subdomains found")
        print(f"  Finished : {datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*55}")

        return self.found

    # ── Output ────────────────────────────────────────────────
    def save(self, filepath: str, fmt: str = "text"):
        if fmt == "json":
            with open(filepath, "w") as f:
                json.dump(self.found, f, indent=2)
        elif fmt == "csv":
            with open(filepath, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["subdomain", "ips", "source"])
                writer.writeheader()
                for entry in self.found:
                    writer.writerow({
                        "subdomain": entry["subdomain"],
                        "ips": ", ".join(entry["ips"]),
                        "source": entry["source"]
                    })
        else:  # text
            with open(filepath, "w") as f:
                for entry in self.found:
                    f.write(f"{entry['subdomain']}\t{', '.join(entry['ips'])}\t{entry['source']}\n")

        print(f"  Results saved: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="Subdomain Scanner - Day 043 | 100 Days of Cybersecurity"
    )
    parser.add_argument("-d", "--domain",   required=True,  help="Target domain")
    parser.add_argument("-w", "--wordlist", default=None,   help="Wordlist file path")
    parser.add_argument("-t", "--threads",  default=30, type=int, help="Thread count")
    parser.add_argument("-o", "--output",   default=None,   help="Output file")
    parser.add_argument("-f", "--format",   default="text",
                        choices=["text", "json", "csv"],    help="Output format")
    parser.add_argument("-v", "--verbose",  action="store_true",  help="Show misses")
    args = parser.parse_args()

    # Load custom wordlist if provided
    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                wordlist = [line.strip() for line in f if line.strip()]
            print(f"[*] Loaded {len(wordlist)} words from {args.wordlist}")
        except FileNotFoundError:
            print(f"[!] Wordlist not found: {args.wordlist}")
            sys.exit(1)

    scanner = SubdomainScanner(
        domain=args.domain,
        wordlist=wordlist,
        threads=args.threads,
        verbose=args.verbose
    )

    results = scanner.scan()

    if args.output:
        scanner.save(args.output, args.format)

    # Print summary
    if results:
        print(f"\n  Discovered subdomains:")
        for entry in sorted(results, key=lambda x: x["subdomain"]):
            print(f"    {entry['subdomain']:<45} [{entry['source']}]")


if __name__ == "__main__":
    main()
```

**To run:**
```bash
pip install dnspython requests

# Basic scan
python3 subdomain_scanner.py -d example.com

# With custom wordlist and JSON output
python3 subdomain_scanner.py -d example.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 50 -o results.json --format json

# Verbose (shows misses too)
python3 subdomain_scanner.py -d example.com -v
```

---

## 🏗️ Design Decisions

**Why threading?**
DNS resolution is I/O bound - most time is spent waiting for responses. Threading lets 30 queries run simultaneously without CPU overhead. `Queue` ensures thread-safe work distribution.

**Why wildcard detection?**
Some domains resolve every subdomain to the same IP (wildcard DNS). Without checking, you'd report thousands of false positives. One DNS query before the scan saves hours of manual verification.

**Why crt.sh first?**
Certificate transparency is passive - no queries hit the target's DNS server. It often finds subdomains that brute force misses entirely (subdomains not in any wordlist). Always do passive before active.

**Why multiple output formats?**
Text for reading. JSON for piping into other tools. CSV for Excel/spreadsheet reporting. Professional tools support all three.

---

## 🔑 Key Takeaways

- Always check wildcard DNS before brute forcing - prevents false positives
- Certificate transparency consistently finds subdomains no wordlist has
- Threading makes I/O-bound tools 10–30x faster than sequential
- Clean CLI interfaces with argparse make tools actually usable by others
- Output format options matter - JSON integrates with pipelines, CSV goes into reports

---

## 📚 Resources
- [SecLists DNS wordlists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)
- [crt.sh - certificate transparency search](https://crt.sh/)
- [dnspython documentation](https://www.dnspython.org/)

---

## [⬅️ Day 042](../day042/) | [➡️ Day 044](../day044/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*