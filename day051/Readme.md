# Day 051 - The MITRE ATT&CK Framework: A Defender's Map

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Every attacker follows a pattern.

They may use different tools. Different exploits. Different entry points. But the fundamental techniques - how they establish persistence, how they move laterally, how they exfiltrate data - follow recognisable patterns.

MITRE ATT&CK is a knowledge base that documents every known attacker technique, organised by the phase of the attack they occur in. It's the most widely referenced framework in defensive security.

For detection engineers, ATT&CK is both a detection gap analyser and a priority list. For threat hunters, it's the playbook.

---

## 🗺️ ATT&CK Structure

```
14 Tactics (the "why" - adversary goal)
    └── Techniques (the "how" - method used)
            └── Sub-techniques (specific implementation)
```

### The 14 Tactics

```
TA0001 - Reconnaissance        Find targets and information
TA0002 - Resource Development  Build infrastructure for attack
TA0003 - Initial Access        Get into the target environment
TA0004 - Execution             Run malicious code
TA0005 - Persistence           Maintain foothold across reboots
TA0006 - Privilege Escalation  Get higher permissions
TA0007 - Defense Evasion       Avoid detection
TA0008 - Credential Access     Steal credentials
TA0009 - Discovery             Learn the environment
TA0010 - Lateral Movement      Move through the network
TA0011 - Collection            Gather target data
TA0040 - Impact                Disrupt, destroy, or manipulate
TA0042 - Resource Development  Acquire capabilities
TA0043 - Reconnaissance        Active/passive recon
```

---

## 🎯 Key Techniques by Phase

### Initial Access (TA0003)

| Technique | ID | What It Is |
|-----------|-----|-----------|
| Phishing | T1566 | Malicious emails with links/attachments |
| Valid Accounts | T1078 | Using legitimate credentials |
| Exploit Public-Facing App | T1190 | Exploiting vulnerable web apps |
| Supply Chain Compromise | T1195 | Backdooring software before delivery |

---

### Execution (TA0004)

| Technique | ID | What It Is |
|-----------|-----|-----------|
| PowerShell | T1059.001 | Executing commands via PowerShell |
| Windows Command Shell | T1059.003 | cmd.exe execution |
| User Execution | T1204 | Victim runs the malicious file |
| Scheduled Task | T1053.005 | Running code via schtasks |

---

### Persistence (TA0005)

| Technique | ID | What It Is |
|-----------|-----|-----------|
| Scheduled Task | T1053.005 | Code runs on schedule |
| Registry Run Keys | T1547.001 | Execute on startup via registry |
| Create Account | T1136 | New user for persistent access |
| SSH Authorized Keys | T1098.004 | Add SSH key for backdoor access |
| Web Shell | T1505.003 | Upload shell to web server |

---

### Credential Access (TA0006)

| Technique | ID | What It Is |
|-----------|-----|-----------|
| LSASS Memory | T1003.001 | Mimikatz credential dump |
| Brute Force | T1110 | Guessing passwords |
| Credential Stuffing | T1110.004 | Using leaked credentials |
| Kerberoasting | T1558.003 | Extract service account hashes |

---

### Lateral Movement (TA0010)

| Technique | ID | What It Is |
|-----------|-----|-----------|
| Pass-the-Hash | T1550.002 | Authenticate with NTLM hash |
| Remote Services | T1021 | SSH, RDP, WMI, PSExec |
| Lateral Tool Transfer | T1570 | Move tools between hosts |

---

### Defense Evasion (TA0005)

| Technique | ID | What It Is |
|-----------|-----|-----------|
| Obfuscated Files | T1027 | Encoded/encrypted payloads |
| Masquerading | T1036 | Rename malware as legit tool |
| Disable Logging | T1562.002 | Turn off event logging |
| LOLBAS | T1218 | Living Off the Land - use built-in tools |

---

## 💻 The Code - ATT&CK Mapper

```python
"""
Day 051 - ATT&CK Mapper
100 Days of Cybersecurity by Sudeep Ravichandran

Maps IOCs and log patterns to MITRE ATT&CK techniques.
Uses the ATT&CK TAXII server to fetch current technique data.

Usage:
  python3 attack_mapper.py --ioc "powershell -enc"
  python3 attack_mapper.py --list-tactics
  python3 attack_mapper.py --technique T1059.001

Requires: pip install requests
"""

import requests
import json
import sys
import argparse
from typing import Optional

ATTACK_API = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Curated IOC → technique mapping (common patterns)
IOC_TECHNIQUE_MAP = {
    # Execution
    "powershell -enc":          ("T1059.001", "PowerShell", "Execution"),
    "powershell -encodedcommand":("T1059.001", "PowerShell", "Execution"),
    "cmd.exe /c":               ("T1059.003", "Windows Command Shell", "Execution"),
    "wscript.exe":              ("T1059.005", "Visual Basic", "Execution"),
    "mshta.exe":                ("T1218.005", "Mshta", "Defense Evasion"),
    "regsvr32":                 ("T1218.010", "Regsvr32", "Defense Evasion"),

    # Persistence
    "schtasks /create":         ("T1053.005", "Scheduled Task", "Persistence"),
    "reg add.*run":             ("T1547.001", "Registry Run Keys", "Persistence"),
    "authorized_keys":          ("T1098.004", "SSH Authorized Keys", "Persistence"),

    # Credential Access
    "sekurlsa":                 ("T1003.001", "LSASS Memory", "Credential Access"),
    "mimikatz":                 ("T1003.001", "LSASS Memory", "Credential Access"),
    "hashdump":                 ("T1003.002", "Security Account Manager", "Credential Access"),
    "kerberoast":               ("T1558.003", "Kerberoasting", "Credential Access"),

    # Discovery
    "net user":                 ("T1087.001", "Local Account", "Discovery"),
    "net localgroup":           ("T1069.001", "Local Groups", "Discovery"),
    "whoami /priv":             ("T1033", "System Owner/User Discovery", "Discovery"),
    "ipconfig":                 ("T1016", "System Network Config Discovery", "Discovery"),
    "arp -a":                   ("T1018", "Remote System Discovery", "Discovery"),

    # Lateral Movement
    "pass-the-hash":            ("T1550.002", "Pass the Hash", "Lateral Movement"),
    "psexec":                   ("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
    "wmiexec":                  ("T1047", "Windows Management Instrumentation", "Lateral Movement"),

    # Exfiltration
    "/dev/tcp/":                ("T1048.003", "Exfil over Unencrypted Protocol", "Exfiltration"),
    "dns tunneling":            ("T1048.001", "Exfil over Alt Protocol: DNS", "Exfiltration"),

    # Defense Evasion
    "vssadmin delete":          ("T1490", "Inhibit System Recovery", "Impact"),
    "bcdedit.*recoveryenabled": ("T1490", "Inhibit System Recovery", "Impact"),
    "wevtutil cl":              ("T1070.001", "Clear Windows Event Logs", "Defense Evasion"),
}

TACTICS = {
    "TA0001": "Reconnaissance",
    "TA0002": "Resource Development",
    "TA0003": "Initial Access",
    "TA0004": "Execution",
    "TA0005": "Persistence",
    "TA0006": "Privilege Escalation",
    "TA0007": "Defense Evasion",
    "TA0008": "Credential Access",
    "TA0009": "Discovery",
    "TA0010": "Lateral Movement",
    "TA0011": "Collection",
    "TA0040": "Impact",
}

KEY_TECHNIQUES = {
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Attackers use PowerShell to execute commands, often with encoded payloads to evade detection.",
        "detection": "Monitor process creation for powershell.exe with -enc, -EncodedCommand, or IEX flags.",
        "mitigations": ["PowerShell Constrained Language Mode", "Script Block Logging (4104)", "AppLocker"],
        "data_sources": ["Process creation (4688)", "PowerShell logs (4103/4104)"]
    },
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Targeted phishing with malicious attachments designed for specific individuals.",
        "detection": "Email gateway scanning, Office document macro alerting, user reporting.",
        "mitigations": ["Email filtering", "Disable macros by default", "User awareness training"],
        "data_sources": ["Email logs", "Process creation from Office apps", "File events"]
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "tactic": "Credential Access",
        "description": "Accessing LSASS process memory to extract credentials, the technique used by Mimikatz.",
        "detection": "Monitor process access events to lsass.exe (Sysmon Event 10).",
        "mitigations": ["Credential Guard", "Protected Users group", "Run LSASS as PPL"],
        "data_sources": ["Process access events", "Windows Defender alerts"]
    },
    "T1053.005": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "description": "Creating scheduled tasks to maintain persistence or execute code at specific times.",
        "detection": "Monitor schtasks.exe execution and Windows Event 4698.",
        "mitigations": ["Restrict schtasks permissions", "Monitor task creation events"],
        "data_sources": ["Process creation (4688)", "Security log (4698)"]
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Attempting to gain access by systematically guessing credentials.",
        "detection": "High volume of authentication failures from single source.",
        "mitigations": ["Account lockout policy", "MFA", "Rate limiting"],
        "data_sources": ["Authentication logs", "Windows Event 4625"]
    },
}


def map_ioc(ioc_string: str):
    """Map an IOC string to ATT&CK techniques."""
    print(f"\n[*] Mapping IOC: '{ioc_string}'\n")
    found = False

    for pattern, (tid, tname, tactic) in IOC_TECHNIQUE_MAP.items():
        if pattern.lower() in ioc_string.lower():
            print(f"  [+] Technique: {tid} - {tname}")
            print(f"      Tactic:    {tactic}")
            print(f"      ATT&CK:    https://attack.mitre.org/techniques/{tid.replace('.', '/')}/")

            # Show details if we have them
            if tid in KEY_TECHNIQUES:
                details = KEY_TECHNIQUES[tid]
                print(f"      Detection: {details['detection']}")
                print(f"      Mitigate:  {', '.join(details['mitigations'][:2])}")
            print()
            found = True

    if not found:
        print("  No matching technique found in local mapping.")
        print("  Search manually: https://attack.mitre.org/")


def show_technique(technique_id: str):
    """Show details for a specific technique."""
    tid = technique_id.upper()
    if tid in KEY_TECHNIQUES:
        t = KEY_TECHNIQUES[tid]
        print(f"\n{'='*55}")
        print(f"  {tid} - {t['name']}")
        print(f"  Tactic: {t['tactic']}")
        print(f"{'='*55}")
        print(f"\n  Description:\n    {t['description']}")
        print(f"\n  Detection:\n    {t['detection']}")
        print(f"\n  Mitigations:")
        for m in t['mitigations']:
            print(f"    → {m}")
        print(f"\n  Data Sources:")
        for d in t['data_sources']:
            print(f"    → {d}")
        print(f"\n  Reference: https://attack.mitre.org/techniques/{tid.replace('.','/')}/")
    else:
        print(f"  Technique {tid} not in local database.")
        print(f"  View online: https://attack.mitre.org/techniques/{tid.replace('.','/') }/")


def list_tactics():
    print("\n[+] MITRE ATT&CK Enterprise Tactics\n")
    for tid, name in TACTICS.items():
        print(f"  {tid}  {name}")
        print(f"         https://attack.mitre.org/tactics/{tid}/")


def main():
    parser = argparse.ArgumentParser(
        description="ATT&CK Mapper - Day 051 | 100 Days of Cybersecurity"
    )
    parser.add_argument("--ioc", help="Map an IOC string to ATT&CK technique")
    parser.add_argument("--technique", help="Show details for a technique (e.g. T1059.001)")
    parser.add_argument("--list-tactics", action="store_true", help="List all 14 tactics")
    args = parser.parse_args()

    print("=" * 55)
    print("  ATT&CK Mapper - Day 051")
    print("  100 Days of Cybersecurity")
    print("=" * 55)

    if args.ioc:
        map_ioc(args.ioc)
    elif args.technique:
        show_technique(args.technique)
    elif args.list_tactics:
        list_tactics()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```

**To run:**
```bash
python3 attack_mapper.py --ioc "powershell -enc"
python3 attack_mapper.py --technique T1059.001
python3 attack_mapper.py --list-tactics
```

---

## 🗺️ ATT&CK Navigator

ATT&CK Navigator is a web app that visualises your detection coverage as a heatmap over the full ATT&CK matrix.

```
Access: https://mitre-attack.github.io/attack-navigator/

Use cases:
→ Colour techniques green where you have detections
→ Identify gaps (uncoloured techniques)
→ Compare coverage across teams
→ Track improvement over time
→ Visualise threat actor TTPs
```

---

## 🔑 Key Takeaways

- ATT&CK maps 14 tactics → hundreds of techniques → thousands of sub-techniques
- Every detection rule should be tagged to an ATT&CK technique
- Use Navigator to visualise coverage gaps - that's your detection engineering backlog
- The same technique can appear across multiple tactics (e.g. scheduled tasks = persistence + execution)
- ATT&CK is updated regularly - new techniques added as attackers evolve
- Threat intelligence reports map to ATT&CK techniques - lets you prioritise relevant detections

---

## 📚 Resources
- [MITRE ATT&CK](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [ATT&CK for Splunk app](https://splunkbase.splunk.com/app/4617)
- [Atomic Red Team - test your detections](https://github.com/redcanaryco/atomic-red-team)

---

## [⬅️ Day 050](../day050/) | [➡️ Day 052](../day052/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*