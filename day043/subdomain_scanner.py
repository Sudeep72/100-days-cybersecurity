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


DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "admin", "vpn", "remote", "dev", "staging",
    "test", "api", "portal", "blog", "shop", "app", "secure", "login",
    "webmail", "smtp", "pop", "imap", "ns1", "ns2", "ns3", "cdn", "static",
    "beta", "old", "backup", "internal", "corp", "intranet", "dashboard",
    "support", "help", "docs", "git", "jenkins", "jira", "confluence",
    "gitlab", "ci", "registry", "docker", "k8s", "prod", "production",
    "stage", "preprod", "uat", "qa", "sandbox", "demo", "preview",
    "assets", "media", "img", "images", "files", "upload", "download",
    "s3", "storage", "db", "database", "redis", "elastic", "kibana",
    "grafana", "prometheus", "monitor", "metrics", "status", "health",
    "auth", "sso", "oauth", "accounts", "profile", "mobile", "m",
    "api2", "v1", "v2", "graphql", "rest", "autodiscover", "exchange",
    "news", "forum", "community", "wiki", "kb",
]


class SubdomainScanner:

    def __init__(self, domain, wordlist=None, threads=30, timeout=2.0, verbose=False):
        self.domain   = domain.lower().strip()
        self.wordlist = wordlist or DEFAULT_WORDLIST
        self.threads  = threads
        self.timeout  = timeout
        self.verbose  = verbose
        self.found    = []
        self.lock     = threading.Lock()
        self.queue    = Queue()
        self.wildcard = None

        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def check_wildcard(self):
        fake = f"this-does-not-exist-{int(time.time())}.{self.domain}"
        try:
            self.resolver.resolve(fake, "A")
            return True
        except Exception:
            return False

    def resolve(self, subdomain):
        fqdn = f"{subdomain}.{self.domain}"
        try:
            answers = self.resolver.resolve(fqdn, "A")
            return [str(r) for r in answers]
        except Exception:
            return None

    def worker(self):
        while True:
            subdomain = self.queue.get()
            if subdomain is None:
                break
            ips = self.resolve(subdomain)
            with self.lock:
                if ips:
                    fqdn = f"{subdomain}.{self.domain}"
                    entry = {"subdomain": fqdn, "ips": ips, "source": "brute"}
                    self.found.append(entry)
                    print(f"  \033[92m[+] {fqdn:<45} {', '.join(ips)}\033[0m")
                elif self.verbose:
                    print(f"  [-] {subdomain}.{self.domain}")
            self.queue.task_done()

    def crt_sh(self):
        print("[*] Querying certificate transparency (crt.sh)...")
        found = []
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=15,
                headers={"User-Agent": "SubdomainScanner/1.0"}
            )
            seen = set()
            for cert in resp.json():
                for name in cert.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{self.domain}") and name not in seen and "*" not in name:
                        seen.add(name)
                        subdomain = name.replace(f".{self.domain}", "")
                        ips = self.resolve(subdomain)
                        if ips:
                            entry = {"subdomain": name, "ips": ips, "source": "crt.sh"}
                            found.append(entry)
                            print(f"  \033[94m[crt] {name:<43} {', '.join(ips)}\033[0m")
        except Exception as e:
            print(f"  [!] crt.sh failed: {e}")
        return found

    def scan(self):
        print(f"\n{'='*55}")
        print(f"  Subdomain Scanner - Day 043")
        print(f"  100 Days of Cybersecurity")
        print(f"{'='*55}")
        print(f"  Target  : {self.domain}")
        print(f"  Words   : {len(self.wordlist)}")
        print(f"  Threads : {self.threads}")
        print(f"  Started : {datetime.now().strftime('%H:%M:%S')}")

        print(f"\n[*] Checking for wildcard DNS...")
        if self.check_wildcard():
            print(f"  [!] Wildcard DNS detected")
            self.wildcard = True
        else:
            print(f"  [✓] No wildcard")
            self.wildcard = False

        crt_results = self.crt_sh()
        self.found.extend(crt_results)

        print(f"\n[*] DNS brute force ({len(self.wordlist)} words, {self.threads} threads)...")

        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            threads.append(t)

        for word in self.wordlist:
            self.queue.put(word)
        for _ in range(self.threads):
            self.queue.put(None)

        self.queue.join()

        # Deduplicate
        seen = set()
        unique = []
        for entry in self.found:
            if entry["subdomain"] not in seen:
                seen.add(entry["subdomain"])
                unique.append(entry)
        self.found = unique

        print(f"\n{'='*55}")
        print(f"  Found: {len(self.found)} subdomains")
        print(f"  Done : {datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*55}")
        return self.found

    def save(self, filepath, fmt="text"):
        if fmt == "json":
            with open(filepath, "w") as f:
                json.dump(self.found, f, indent=2)
        elif fmt == "csv":
            with open(filepath, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["subdomain", "ips", "source"])
                w.writeheader()
                for e in self.found:
                    w.writerow({"subdomain": e["subdomain"], "ips": ", ".join(e["ips"]), "source": e["source"]})
        else:
            with open(filepath, "w") as f:
                for e in self.found:
                    f.write(f"{e['subdomain']}\t{', '.join(e['ips'])}\t{e['source']}\n")
        print(f"  Saved: {filepath}")


def main():
    parser = argparse.ArgumentParser(description="Subdomain Scanner - 100 Days of Cybersecurity")
    parser.add_argument("-d", "--domain",   required=True)
    parser.add_argument("-w", "--wordlist", default=None)
    parser.add_argument("-t", "--threads",  default=30, type=int)
    parser.add_argument("-o", "--output",   default=None)
    parser.add_argument("-f", "--format",   default="text", choices=["text","json","csv"])
    parser.add_argument("-v", "--verbose",  action="store_true")
    args = parser.parse_args()

    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                wordlist = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            print(f"Wordlist not found: {args.wordlist}")
            sys.exit(1)

    scanner = SubdomainScanner(args.domain, wordlist, args.threads, verbose=args.verbose)
    results = scanner.scan()

    if args.output:
        scanner.save(args.output, args.format)

    if results:
        print(f"\n  Subdomains found:")
        for e in sorted(results, key=lambda x: x["subdomain"]):
            print(f"    {e['subdomain']:<45} [{e['source']}]")


if __name__ == "__main__":
    main()