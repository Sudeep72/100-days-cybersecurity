"""
Day 051 - ATT&CK Mapper
100 Days of Cybersecurity by Sudeep Ravichandran

Maps IOCs and log patterns to MITRE ATT&CK techniques.

Usage:
  python3 attack_mapper.py --ioc "powershell -enc"
  python3 attack_mapper.py --technique T1059.001
  python3 attack_mapper.py --list-tactics
"""

import sys
import argparse

IOC_MAP = {
    "powershell -enc":           ("T1059.001", "PowerShell", "Execution"),
    "powershell -encodedcommand":("T1059.001", "PowerShell", "Execution"),
    "cmd.exe /c":                ("T1059.003", "Windows Command Shell", "Execution"),
    "mshta.exe":                 ("T1218.005", "Mshta", "Defense Evasion"),
    "regsvr32":                  ("T1218.010", "Regsvr32", "Defense Evasion"),
    "schtasks /create":          ("T1053.005", "Scheduled Task", "Persistence"),
    "authorized_keys":           ("T1098.004", "SSH Authorized Keys", "Persistence"),
    "sekurlsa":                  ("T1003.001", "LSASS Memory", "Credential Access"),
    "mimikatz":                  ("T1003.001", "LSASS Memory", "Credential Access"),
    "kerberoast":                ("T1558.003", "Kerberoasting", "Credential Access"),
    "net user":                  ("T1087.001", "Local Account", "Discovery"),
    "whoami /priv":              ("T1033",     "System Owner Discovery", "Discovery"),
    "arp -a":                    ("T1018",     "Remote System Discovery", "Discovery"),
    "psexec":                    ("T1021.002", "SMB Admin Shares", "Lateral Movement"),
    "/dev/tcp/":                 ("T1048.003", "Exfil over Unencrypted Proto", "Exfiltration"),
    "vssadmin delete":           ("T1490",     "Inhibit System Recovery", "Impact"),
    "wevtutil cl":               ("T1070.001", "Clear Windows Event Logs", "Defense Evasion"),
}

TECHNIQUES = {
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "detection": "Monitor powershell.exe with -enc, -EncodedCommand, IEX flags",
        "mitigations": ["PowerShell Constrained Language Mode", "Script Block Logging"],
        "sources": ["Process creation (4688)", "PowerShell logs (4103/4104)"]
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "tactic": "Credential Access",
        "detection": "Monitor process access to lsass.exe (Sysmon Event 10)",
        "mitigations": ["Credential Guard", "Protected Users group", "LSASS as PPL"],
        "sources": ["Process access events", "Windows Defender alerts"]
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "tactic": "Persistence",
        "detection": "Monitor schtasks.exe and Windows Event 4698",
        "mitigations": ["Restrict schtasks permissions", "Monitor task creation"],
        "sources": ["Process creation (4688)", "Security log (4698)"]
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "detection": "High volume of auth failures from single source",
        "mitigations": ["Account lockout", "MFA", "Rate limiting"],
        "sources": ["Auth logs", "Windows Event 4625"]
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "detection": "Monitor vssadmin, bcdedit, wbadmin commands",
        "mitigations": ["Backup offsite", "Restrict vssadmin access"],
        "sources": ["Process creation (4688)", "Command line audit"]
    },
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


def map_ioc(ioc):
    print(f"\n[*] Mapping: '{ioc}'\n")
    found = False
    for pattern, (tid, tname, tactic) in IOC_MAP.items():
        if pattern.lower() in ioc.lower():
            print(f"  [+] {tid} - {tname} ({tactic})")
            print(f"      https://attack.mitre.org/techniques/{tid.replace('.','/')}/")
            if tid in TECHNIQUES:
                t = TECHNIQUES[tid]
                print(f"      Detect: {t['detection']}")
            print()
            found = True
    if not found:
        print("  No match. Search: https://attack.mitre.org/")


def show_technique(tid):
    tid = tid.upper()
    if tid in TECHNIQUES:
        t = TECHNIQUES[tid]
        print(f"\n{'='*50}")
        print(f"  {tid} - {t['name']} ({t['tactic']})")
        print(f"{'='*50}")
        print(f"\n  Detection: {t['detection']}")
        print(f"\n  Mitigations:")
        for m in t['mitigations']:
            print(f"    → {m}")
        print(f"\n  Data Sources:")
        for s in t['sources']:
            print(f"    → {s}")
        print(f"\n  Reference: https://attack.mitre.org/techniques/{tid.replace('.','/') }/")
    else:
        print(f"  Not in local DB. View: https://attack.mitre.org/techniques/{tid.replace('.','/') }/")


def list_tactics():
    print("\n[+] MITRE ATT&CK Tactics\n")
    for tid, name in TACTICS.items():
        print(f"  {tid}  {name}")


def main():
    parser = argparse.ArgumentParser(description="ATT&CK Mapper - 100 Days of Cybersecurity")
    parser.add_argument("--ioc", help="Map IOC to ATT&CK technique")
    parser.add_argument("--technique", help="Show technique details (e.g. T1059.001)")
    parser.add_argument("--list-tactics", action="store_true")
    args = parser.parse_args()

    print("=" * 50)
    print("  ATT&CK Mapper - Day 051")
    print("  100 Days of Cybersecurity")
    print("=" * 50)

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