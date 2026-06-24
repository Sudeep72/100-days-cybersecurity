"""
===============================================================================
Day 052 - Threat Intelligence: IOCs, TTPs & Intelligence Feeds
===============================================================================

Challenge : 100 Days of Cybersecurity
Phase     : Defensive Security
Difficulty: Intermediate

===============================================================================
THE CONCEPT
===============================================================================

Detection engineering tells you HOW to detect.

Threat intelligence tells you WHAT to detect and WHY it matters.

Threat intelligence is information about:

- Active threat actors
- Emerging threats
- Campaigns currently in progress
- Infrastructure used by attackers
- Techniques being used in attacks
- Industries being targeted

Applied correctly, threat intelligence turns reactive security into
proactive security.

===============================================================================
INTELLIGENCE PYRAMID
===============================================================================

                Strategic
           (Nation States,
        Geopolitical Context)

                 /\
                /  \

             Operational
       (Campaigns, Toolkits,
         Infrastructure)

                /\
               /  \

              Tactical
       (TTPs - Attacker Behavior)

               /\
              /  \

             Technical
      (IOCs - IPs, Domains,
       URLs, Hashes)

Most organizations operate at the Technical level.

Most valuable intelligence exists at the Tactical level.

IOCs may expire within hours or days.

TTPs can remain useful for months or years.

===============================================================================
IOCs - INDICATORS OF COMPROMISE
===============================================================================

Specific artifacts observed during or after an attack.

Examples:

IP Addresses:
    10.0.0.5

Domains:
    malware-c2.evil.com

URLs:
    https://evil.com/payload.exe

File Hashes:
    MD5
    SHA1
    SHA256

Email Addresses:
    attacker@phishing.com

Registry Keys:
    HKCU\\Software\\MalwareName

Mutex Names:
    Global\\MalwareMutex_v2

User Agents:
    Mozilla/5.0 (custom malware)

SSL Certificate Hashes:
    Attacker certificate fingerprints

------------------------------------------------------------------------------
IOC LIMITATIONS
------------------------------------------------------------------------------

1. IP addresses change frequently.

2. Domains get burned and replaced quickly.

3. Malware hashes change after recompilation.

4. IOC matching alone is not enough for detection.

5. Attackers can rotate infrastructure rapidly.

===============================================================================
TTPs - TACTICS, TECHNIQUES & PROCEDURES
===============================================================================

TTPs describe attacker behavior.

Example:

Tactic:
    Lateral Movement

Technique:
    Pass-the-Hash (MITRE ATT&CK T1550.002)

Procedure:
    Uses Mimikatz to dump NTLM hashes from LSASS.

    Uses Impacket psexec.py to authenticate to internal hosts
    using stolen hashes.

Why TTPs Matter:

Even if attackers:

    - Change IP addresses
    - Change domains
    - Recompile malware

They often continue using the same successful procedures.

TTP-based detection focuses on behavior rather than tools.

===============================================================================
THREAT INTELLIGENCE FEEDS
===============================================================================

------------------------------------------------------------------------------
FREE FEEDS
------------------------------------------------------------------------------

1. AlienVault OTX (Open Threat Exchange)

Website:
    https://otx.alienvault.com/

API:
    https://otx.alienvault.com/api/v1/

Provides:
    - Community-sourced IOCs
    - Threat reports
    - Threat sharing

------------------------------------------------------------------------------
2. VirusTotal
------------------------------------------------------------------------------

Website:
    https://www.virustotal.com/

Provides:
    - File reputation
    - URL reputation
    - Domain reputation
    - IP reputation

API:
    Free tier with rate limits

------------------------------------------------------------------------------
3. abuse.ch Feeds
------------------------------------------------------------------------------

URLhaus:
    Malicious URLs

MalwareBazaar:
    Malware hashes and samples

ThreatFox:
    Context-rich IOCs

Benefits:
    - Free
    - Machine readable
    - Community maintained

------------------------------------------------------------------------------
4. AbuseIPDB
------------------------------------------------------------------------------

Website:
    https://www.abuseipdb.com/

Provides:
    - Crowdsourced malicious IP data

API:
    Free tier (1000 checks/day)

------------------------------------------------------------------------------
5. Shodan
------------------------------------------------------------------------------

Website:
    https://www.shodan.io/

Provides:
    - Internet exposed assets
    - Infrastructure discovery
    - Threat hunting support

------------------------------------------------------------------------------
6. CISA Known Exploited Vulnerabilities (KEV)
------------------------------------------------------------------------------

Website:
    https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Provides:
    - CVEs actively exploited in the wild
    - Patch prioritization guidance

===============================================================================
COMMERCIAL FEEDS
===============================================================================

- CrowdStrike Falcon Intelligence
- Mandiant Threat Intelligence
- Recorded Future
- Palo Alto Unit 42
- IBM X-Force

===============================================================================
STIX & TAXII
===============================================================================

------------------------------------------------------------------------------
STIX
(Structured Threat Information eXpression)
------------------------------------------------------------------------------

JSON-based standard for representing threat intelligence.

Example:

{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--abc123",
  "name": "Malicious C2 Domain",
  "pattern": "[domain-name:value = 'malware-c2.evil.com']",
  "pattern_type": "stix",
  "valid_from": "2024-01-15T00:00:00Z",
  "labels": ["malicious-activity"],
  "kill_chain_phases": [
    {
      "kill_chain_name": "mitre-attack",
      "phase_name": "command-and-control"
    }
  ]
}

------------------------------------------------------------------------------
TAXII
(Trusted Automated eXchange of Intelligence Information)
------------------------------------------------------------------------------

Protocol used for distributing STIX threat intelligence.

Typical Flow:

Threat Feed
     |
     v
   TAXII
     |
     v
Threat Intel Platform
     |
     v
SIEM / SOC / Detection Platform

===============================================================================
IOC ENRICHER TOOL
===============================================================================

Features:

✓ IP Reputation Checks
✓ Domain Reputation Checks
✓ Hash Reputation Checks
✓ AbuseIPDB Integration
✓ VirusTotal Integration
✓ URLhaus Integration
✓ MalwareBazaar Integration
✓ Batch IOC Processing
✓ Automatic IOC Type Detection

===============================================================================
USAGE
===============================================================================

Single IP:

    python3 ioc_enricher.py --ip 1.2.3.4

Single Domain:

    python3 ioc_enricher.py --domain evil.com

Single Hash:

    python3 ioc_enricher.py --hash abc123...

IOC File:

    python3 ioc_enricher.py --file iocs.txt

===============================================================================
REQUIREMENTS
===============================================================================

Install:

    pip install requests

Environment Variables:

    export VT_API_KEY="your_virustotal_key"
    export ABUSEIPDB_KEY="your_abuseipdb_key"

===============================================================================
IOC ENRICHER CODE
===============================================================================
"""

import argparse
import os
import re
import sys
import time
import requests

VT_KEY = os.environ.get("VT_API_KEY", "")
ABUSE_KEY = os.environ.get("ABUSEIPDB_KEY", "")
TIMEOUT = 10


def check_ip_abuseipdb(ip):
    """Check IP reputation against AbuseIPDB."""

    if not ABUSE_KEY:
        return {"error": "ABUSEIPDB_KEY not set"}

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSE_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": True
            },
            timeout=TIMEOUT
        )

        data = response.json().get("data", {})

        return {
            "source": "AbuseIPDB",
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A"),
            "is_tor": data.get("isTor", False),
            "last_reported": data.get("lastReportedAt", "Never")
        }

    except Exception as e:
        return {"error": str(e)}


def check_ip_virustotal(ip):
    """Check IP reputation against VirusTotal."""

    if not VT_KEY:
        return {"error": "VT_API_KEY not set"}

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_KEY},
            timeout=TIMEOUT
        )

        data = response.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})

        return {
            "source": "VirusTotal",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "country": data.get("country", "N/A"),
            "as_owner": data.get("as_owner", "N/A")
        }

    except Exception as e:
        return {"error": str(e)}


def check_hash_virustotal(file_hash):
    """Check file hash reputation against VirusTotal."""

    if not VT_KEY:
        return {"error": "VT_API_KEY not set"}

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": VT_KEY},
            timeout=TIMEOUT
        )

        if response.status_code == 404:
            return {
                "source": "VirusTotal",
                "result": "Hash not found"
            }

        data = response.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})

        return {
            "source": "VirusTotal",
            "name": data.get("meaningful_name", "Unknown"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "type": data.get("type_description", "N/A"),
            "size": data.get("size", "N/A"),
            "first_seen": data.get("first_submission_date", "N/A")
        }

    except Exception as e:
        return {"error": str(e)}


def check_domain_urlhaus(domain):
    """Check domain against URLhaus."""

    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            timeout=TIMEOUT
        )

        data = response.json()

        if data.get("query_status") == "no_results":
            return {
                "source": "URLhaus",
                "result": "No results"
            }

        urls = data.get("urls", [])

        return {
            "source": "URLhaus",
            "domain": domain,
            "url_count": len(urls),
            "status": data.get("query_status"),
            "recent_urls": [u.get("url", "") for u in urls[:3]],
            "tags": list({
                tag
                for u in urls
                for tag in u.get("tags", [])
                if tag
            })
        }

    except Exception as e:
        return {"error": str(e)}


def check_hash_malwarebazaar(file_hash):
    """Check file hash against MalwareBazaar."""

    try:
        response = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={
                "query": "get_info",
                "hash": file_hash
            },
            timeout=TIMEOUT
        )

        data = response.json()

        if data.get("query_status") == "hash_not_found":
            return {
                "source": "MalwareBazaar",
                "result": "Not found"
            }

        sample = data.get("data", [{}])[0]

        return {
            "source": "MalwareBazaar",
            "file_name": sample.get("file_name", "N/A"),
            "file_type": sample.get("file_type", "N/A"),
            "signature": sample.get("signature", "Unknown"),
            "tags": sample.get("tags", []),
            "first_seen": sample.get("first_seen", "N/A"),
            "reporter": sample.get("reporter", "N/A")
        }

    except Exception as e:
        return {"error": str(e)}


def print_result(result, ioc_type, value):
    """Display enrichment results."""

    print("\n" + "=" * 60)
    print(f"IOC TYPE : {ioc_type.upper()}")
    print(f"IOC VALUE: {value}")
    print("=" * 60)

    if "error" in result:
        print("ERROR:", result["error"])
        return

    for key, val in result.items():
        if key == "source":
            continue

        if isinstance(val, list):
            print(f"{key}:")
            for item in val:
                print(f"  - {item}")
        else:
            print(f"{key}: {val}")


def enrich_ip(ip):
    print(f"\n[*] Enriching IP: {ip}")

    print_result(check_ip_abuseipdb(ip), "ip", ip)
    time.sleep(1)

    print_result(check_ip_virustotal(ip), "ip", ip)


def enrich_domain(domain):
    print(f"\n[*] Enriching Domain: {domain}")

    print_result(check_domain_urlhaus(domain), "domain", domain)


def enrich_hash(file_hash):
    print(f"\n[*] Enriching Hash: {file_hash}")

    print_result(check_hash_virustotal(file_hash), "hash", file_hash)
    time.sleep(1)

    print_result(check_hash_malwarebazaar(file_hash), "hash", file_hash)


def process_file(filepath):
    """Process IOC file."""

    ip_regex = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
    hash_regex = re.compile(r"^[a-fA-F0-9]{32,64}$")
    domain_regex = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}"
        r"[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
    )

    try:
        with open(filepath, "r") as f:

            for line in f:
                ioc = line.strip()

                if not ioc or ioc.startswith("#"):
                    continue

                if ip_regex.match(ioc):
                    enrich_ip(ioc)

                elif hash_regex.match(ioc):
                    enrich_hash(ioc)

                elif domain_regex.match(ioc):
                    enrich_domain(ioc)

                else:
                    print(f"[?] Unknown IOC type: {ioc}")

                time.sleep(0.5)

    except FileNotFoundError:
        print(f"File not found: {filepath}")


def main():

    parser = argparse.ArgumentParser(
        description="IOC Enricher - Day 052 | 100 Days of Cybersecurity"
    )

    parser.add_argument("--ip", help="IP address")
    parser.add_argument("--domain", help="Domain")
    parser.add_argument("--hash", help="MD5/SHA1/SHA256 hash")
    parser.add_argument("--file", help="IOC file")

    args = parser.parse_args()

    if not any([args.ip, args.domain, args.hash, args.file]):
        parser.print_help()
        sys.exit(1)

    if args.ip:
        enrich_ip(args.ip)

    if args.domain:
        enrich_domain(args.domain)

    if args.hash:
        enrich_hash(args.hash)

    if args.file:
        process_file(args.file)


if __name__ == "__main__":
    main()