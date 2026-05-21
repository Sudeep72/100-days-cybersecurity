"""
Day 018 - CVE Lookup Tool
100 Days of Cybersecurity by Sudeep Ravichandran

Fetches CVE details from the NVD API including CVSS score,
description, and affected software.

Usage: python3 cve_lookup.py CVE-2021-44228
Requires: pip install requests
"""

import requests
import sys
import json
from datetime import datetime


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve(cve_id):
    """Fetch CVE details from the NVD API."""
    print(f"\n[*] Looking up {cve_id}...")

    try:
        response = requests.get(
            NVD_API,
            params={"cveId": cve_id},
            timeout=10,
            headers={"User-Agent": "100DaysCyberSec-CVELookup/1.0"}
        )
        response.raise_for_status()
        return response.json()

    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        return None


def parse_cvss_score(metrics):
    """Extract CVSS score and severity from metrics."""
    # Try CVSS v3.1 first, then v3.0, then v2
    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version_key in metrics and metrics[version_key]:
            metric = metrics[version_key][0]
            if "cvssData" in metric:
                data = metric["cvssData"]
                score = data.get("baseScore", "N/A")
                severity = data.get("baseSeverity", "N/A")
                vector = data.get("vectorString", "N/A")
                version = data.get("version", "N/A")
                return score, severity, vector, version
    return "N/A", "N/A", "N/A", "N/A"


def severity_bar(score):
    """Visual severity indicator."""
    try:
        s = float(score)
        if s >= 9.0:
            return "🔴 CRITICAL"
        elif s >= 7.0:
            return "🟠 HIGH"
        elif s >= 4.0:
            return "🟡 MEDIUM"
        elif s > 0:
            return "🟢 LOW"
        else:
            return "⚪ NONE"
    except (ValueError, TypeError):
        return "❓ UNKNOWN"


def display_cve(data):
    """Display formatted CVE information."""
    if not data or "vulnerabilities" not in data or not data["vulnerabilities"]:
        print("[-] CVE not found or no data available.")
        return

    vuln = data["vulnerabilities"][0]["cve"]
    cve_id = vuln.get("id", "N/A")

    # Description
    descriptions = vuln.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d["lang"] == "en"),
        "No description available"
    )

    # Dates
    published = vuln.get("published", "N/A")[:10] if vuln.get("published") else "N/A"
    modified = vuln.get("lastModified", "N/A")[:10] if vuln.get("lastModified") else "N/A"

    # CVSS
    metrics = vuln.get("metrics", {})
    score, severity, vector, cvss_version = parse_cvss_score(metrics)

    # References
    references = vuln.get("references", [])

    print("\n" + "=" * 60)
    print(f"  {cve_id}")
    print("=" * 60)
    print(f"\n  Severity  : {severity_bar(score)} ({score})")
    print(f"  CVSS v{cvss_version}  : {vector}")
    print(f"  Published : {published}")
    print(f"  Modified  : {modified}")
    print(f"\n  Description:")
    # Wrap description at 55 chars
    words = description.split()
    line = "    "
    for word in words:
        if len(line) + len(word) > 60:
            print(line)
            line = "    " + word + " "
        else:
            line += word + " "
    if line.strip():
        print(line)

    if references:
        print(f"\n  References ({min(3, len(references))} of {len(references)}):")
        for ref in references[:3]:
            print(f"    → {ref.get('url', 'N/A')}")

    print("\n" + "=" * 60)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 cve_lookup.py <CVE-ID>")
        print("Examples:")
        print("  python3 cve_lookup.py CVE-2021-44228  (Log4Shell)")
        print("  python3 cve_lookup.py CVE-2017-0144   (EternalBlue)")
        print("  python3 cve_lookup.py CVE-2014-0160   (Heartbleed)")
        sys.exit(1)

    cve_id = sys.argv[1].upper().strip()

    if not cve_id.startswith("CVE-"):
        print("[-] CVE ID must be in format: CVE-YYYY-NNNNN")
        sys.exit(1)

    print("=" * 60)
    print("  CVE Lookup Tool - Day 018")
    print("  100 Days of Cybersecurity")
    print("=" * 60)

    data = fetch_cve(cve_id)
    if data:
        display_cve(data)


if __name__ == "__main__":
    main()