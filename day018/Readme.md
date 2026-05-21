# Day 018 - CVEs: How Vulnerabilities Get Discovered, Named, and Exploited

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

Every major breach you've ever heard of has a CVE behind it.

EternalBlue - CVE-2017-0144. Used by WannaCry to infect 200,000 machines in 150 countries.
Log4Shell - CVE-2021-44228. Affected hundreds of millions of Java applications overnight.
Heartbleed - CVE-2014-0160. Exposed private keys of 17% of all HTTPS servers.

CVE stands for Common Vulnerabilities and Exposures. It's the universal naming system for publicly known security vulnerabilities. Understanding how vulnerabilities move from discovery to exploitation is fundamental to both offensive and defensive security.

---

## 🔄 The Vulnerability Lifecycle

```
1. Discovery        → Researcher or attacker finds the vulnerability
2. Responsible Disclosure → Researcher notifies the vendor privately
3. Patch Development → Vendor develops and tests a fix
4. CVE Assignment   → Vulnerability gets a CVE ID and public record
5. Public Disclosure → Vulnerability and patch announced publicly
6. Exploitation Window → Gap between patch release and organisations applying it
7. Patch Applied    → Organisations update - window closes
```

The most dangerous moment is step 6 - the exploitation window.

When a CVE goes public, every attacker in the world sees it simultaneously.
Security teams race to patch. Attackers race to exploit.
The average organisation takes 60–150 days to patch critical vulnerabilities.

---

## 🏷️ Anatomy of a CVE

```
CVE-2021-44228 (Log4Shell)

CVE   → Common Vulnerabilities and Exposures
2021  → Year it was assigned
44228 → Unique identifier within that year
```

The CVE record contains:
- Description of the vulnerability
- Affected software and versions
- CVSS score (severity rating)
- References (patches, advisories, PoC code)

---

## 📊 CVSS - How Severity is Scored

CVSS (Common Vulnerability Scoring System) scores vulnerabilities from 0.0 to 10.0.

```
0.0       → None
0.1–3.9   → Low
4.0–6.9   → Medium
7.0–8.9   → High
9.0–10.0  → Critical
```

CVSS is calculated from metrics including:

**Attack Vector** - How is it exploited?
- Network (remotely exploitable) → higher score
- Physical (attacker must be present) → lower score

**Attack Complexity** - How hard is it to exploit?
- Low (straightforward) → higher score
- High (requires specific conditions) → lower score

**Privileges Required** - What access does the attacker need first?
- None (unauthenticated) → higher score
- Admin required → lower score

**User Interaction** - Does a victim need to do something?
- None (no action needed) → higher score
- Required (victim must click) → lower score

**Impact** - What happens when it's exploited?
- Confidentiality / Integrity / Availability impact rated separately

**Log4Shell score: 10.0 (Critical)**
- Exploitable remotely
- No authentication required
- No user interaction
- Full RCE (complete CIA triad impact)

---

## 🔍 Zero-Days vs Known CVEs

### Known CVE
Vulnerability is public. Patch exists (or is coming). Defenders can act.

### Zero-Day (0-day)
Vulnerability unknown to the vendor and public. No patch exists.
Attacker exploits it before anyone knows to defend against it.

Zero-days are valuable:
- Nation-state hackers pay millions for them
- Sold on black markets
- Used in targeted attacks where stealth matters

Most attacks don't use zero-days - they use unpatched known CVEs because that's easier.

The Equifax breach used a CVE that had a patch available for months.

---

## 🛠️ Where to Look Up CVEs

```
NVD (National Vulnerability Database):  https://nvd.nist.gov/
MITRE CVE List:                         https://cve.mitre.org/
CVE Details:                            https://www.cvedetails.com/
Exploit-DB:                             https://www.exploit-db.com/
GitHub Advisory Database:              https://github.com/advisories
Vendor advisories:                      Microsoft, Cisco, Apple, etc.
```

---

## 💻 The Code - CVE Lookup Tool

```python
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
```

**To run:**
```bash
pip install requests
python3 cve_lookup.py CVE-2021-44228
python3 cve_lookup.py CVE-2017-0144
python3 cve_lookup.py CVE-2014-0160
```

---

## 🔑 Key Takeaways

- Every public vulnerability has a CVE ID - the universal language of security advisories
- CVSS scores (0–10) measure severity across attack vector, complexity, impact
- The exploitation window between patch release and application is where most breaches happen
- Zero-days are unknown to vendors - far rarer and more expensive than known CVEs
- Most breaches use known, patched CVEs - organisations just didn't update in time
- Always subscribe to NVD alerts for software you use in production

---

## 📚 Resources to Go Deeper
- [NVD - National Vulnerability Database](https://nvd.nist.gov/)
- [CVE Details - searchable CVE database](https://www.cvedetails.com/)
- [Exploit-DB - public exploit repository](https://www.exploit-db.com/)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)

---

## [⬅️ Day 017](../day017/) | [➡️ Day 019](../day019/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*