# Day 052 - Threat Intelligence: IOCs, TTPs & Feeds

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Detection engineering tells you *how* to detect attacks.

Threat intelligence tells you *what* to detect - and *why it matters right now*.

It's information about current threats: which groups are active, which techniques they use, which infrastructure they operate, and which sectors they target. Applied correctly, it converts reactive security into proactive security.

---

## 🔺 Intelligence Pyramid

```
            Strategic            ← geopolitical context, nation-state actors
              /    \
           Operational           ← campaigns, toolkits, infrastructure
            /        \
          Tactical               ← TTPs - actual attack behaviours
          /            \
       Technical                 ← IOCs - IPs, hashes, domains
```

Most teams operate at Technical (IOCs). The most valuable tier is Tactical (TTPs).

**IOCs expire in days. TTPs remain valid for months or years.**

---

## 📍 IOC Types

```
IP Addresses     → C2 servers, scanning infrastructure
Domains          → malware download sites, C2 hostnames
File Hashes      → MD5/SHA256 of malware samples
URLs             → payload delivery links
Email addresses  → phishing sender addresses
Registry keys    → persistence locations
Mutex names      → unique strings in malware
SSL cert hashes  → fingerprints of attacker infrastructure
```

---

## 📡 Free Threat Intelligence Sources

| Source | What It Provides | API |
|--------|-----------------|-----|
| [AlienVault OTX](https://otx.alienvault.com/) | Community IOCs, threat reports | Free |
| [VirusTotal](https://www.virustotal.com/) | File/URL/IP/domain reputation | Free (limited) |
| [URLhaus](https://urlhaus.abuse.ch/) | Malicious URLs | Free |
| [MalwareBazaar](https://bazaar.abuse.ch/) | Malware samples + hashes | Free |
| [ThreatFox](https://threatfox.abuse.ch/) | IOCs with context | Free |
| [AbuseIPDB](https://www.abuseipdb.com/) | Malicious IP reports | Free (1000/day) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Actively exploited CVEs | Free |

---

## 🔄 STIX - Intelligence Format

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "name": "Malicious C2 Domain",
  "pattern": "[domain-name:value = 'malware-c2.evil.com']",
  "valid_from": "2024-01-15T00:00:00Z",
  "labels": ["malicious-activity"],
  "kill_chain_phases": [
    {"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}
  ]
}
```

STIX is the standard format. TAXII is the protocol for distributing it.

---

## 💻 The Code

See `ioc_enricher.py` - queries AbuseIPDB, VirusTotal, URLhaus, and MalwareBazaar automatically.

```bash
pip install requests

# Set API keys (free registration)
export VT_API_KEY="your_key"
export ABUSEIPDB_KEY="your_key"

# Enrich an IP
python3 ioc_enricher.py --ip 1.2.3.4

# Enrich a domain (no API key needed for URLhaus)
python3 ioc_enricher.py --domain suspicious-domain.com

# Enrich a hash
python3 ioc_enricher.py --hash abc123...

# Process a file of IOCs
python3 ioc_enricher.py --file iocs.txt
```

---

## 🔑 Key Takeaways

- IOCs (IPs, hashes, domains) expire fast - TTPs (behaviours) last much longer
- Free feeds (URLhaus, MalwareBazaar, AbuseIPDB) cover the majority of commodity threats
- STIX/TAXII are the standard formats for sharing and consuming intel
- CISA KEV is the highest-priority feed - actively exploited CVEs need immediate patching
- Intel without action is just information - the value is in the detection rules it drives

---

## 📚 Resources
- [AlienVault OTX](https://otx.alienvault.com/)
- [abuse.ch feeds](https://abuse.ch/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [MISP - open source TI platform](https://www.misp-project.org/)

---

## [⬅️ Day 051](../day051/) | [➡️ Day 053](../day053/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*