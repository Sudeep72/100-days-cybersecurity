# Day 060 - Ransomware: How It Works & How to Detect It

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate-Advanced

---

## 🧠 The Concept

Ransomware is the most financially damaging cyberattack today.

It encrypts your files. Deletes backups. Exfiltrates data. Then demands payment or faces public exposure.

The average ransom demand: $5.3 million (2023).

The average cost of recovery: $18.4 million.

Understanding how ransomware works is the difference between paying millions and stopping it before encryption starts.

---

## 🔄 Ransomware Lifecycle

```
STAGE 1: INITIAL ACCESS (Days 0-7)
├─ Phishing email with malicious attachment
├─ Exposed RDP / VPN (weak credentials)
├─ Unpatched vulnerability (CVE exploitation)
├─ Supply chain compromise (trojanized software)
└─ Insider threat / credential sale

STAGE 2: PERSISTENCE (Days 1-14)
├─ Install persistence mechanism (scheduled task, service)
├─ Create backup access (secondary credentials)
├─ Establish C2 communication
├─ Disable security tools (EDR, antivirus)
└─ Blend in with normal activity

STAGE 3: RECONNAISSANCE (Days 3-30)
├─ Map network infrastructure
├─ Identify high-value targets (databases, file servers)
├─ Find backup systems (to delete them)
├─ Locate admin credentials (to escalate)
└─ Estimate ransom amount (based on company size)

STAGE 4: LATERAL MOVEMENT (Days 7-30)
├─ Move from compromised host to other systems
├─ Escalate privileges (become domain admin)
├─ Access backup infrastructure
├─ Delete shadow copies (Windows backup)
├─ Disable recovery options
└─ Export credentials for future use

STAGE 5: EXFILTRATION (Days 20-45)
├─ Steal sensitive data (PII, trade secrets, IP)
├─ Upload to attacker server (double extortion)
├─ Prepare data for public release
└─ Often exfil before encryption (insurance policy)

STAGE 6: ENCRYPTION (Day ~45)
├─ Deploy encryption payload across network
├─ Encrypt files (all documents, databases, configs)
├─ Leave ransom note (README.txt or HTML popup)
├─ Contact target with payment instructions
└─ Set deadline (usually 7-14 days)
```

**Critical observation:** Attackers spend 30-45 days inside before encrypting.

This is a 30-45 day window to detect and stop them.

---

## 🔐 Encryption Methods

### Symmetric Encryption (Fast)

```
Attacker generates: random key (256-bit AES)
Attacker encrypts: all files using this key
Problem: Attacker and victim both need the key to decrypt

How it works:
  1. Generate random AES-256 key
  2. Encrypt all files with this key
  3. Encrypt the key itself with attacker's RSA public key
  4. Delete the original AES key (only encrypted copy remains)
  5. Victim can't decrypt without attacker's RSA private key

Why it's secure (for attacker):
  ├─ AES-256 is unbreakable (can't brute force 2^256 possibilities)
  ├─ Key is encrypted with RSA (can't recover without private key)
  └─ Only attacker has the RSA private key
```

### Hybrid Encryption (Real-world)

```
Attacker generates: local AES key (per file or per system)
Attacker encrypts:
  ├─ Files with AES key (fast)
  ├─ AES key with attacker's RSA public key (secure)

Recovery options:
  ❌ Brute force AES key (impossible - 2^256 attempts)
  ❌ Recover deleted key (deleted and overwritten)
  ❌ Decrypt without private key (mathematically impossible)

Only option: Pay ransom to get attacker's RSA private key
```

---

## 📊 Ransomware Families & Tactics

### Notable Ransomware Groups

```
CONTI / BlackCat
├─ Double extortion (encrypt + exfil)
├─ 30-45 day dwell time before encryption
├─ Targets: Healthcare, Finance, Manufacturing
└─ Average ransom: $2.5M - $10M

LockBit
├─ Most prolific ransomware (2023-2024)
├─ Bug bounty program (paid researchers to find escapes)
├─ Targets: All sectors
└─ Average ransom: $1M - $5M

Cl0p
├─ Targets zero-day vulnerabilities
├─ Recently exploited MOVEit Transfer (CVE-2023-34362)
├─ Affects: Fortune 500 companies
└─ Average ransom: $5M+

Rhysida
├─ Emerging threat (2023)
├─ Targets: Critical infrastructure
├─ Uses: Wiper malware after exfil
└─ Average ransom: $500K - $2M

Play / Alphv
├─ Targets: US infrastructure
├─ Double extortion
└─ Average ransom: $1M - $3M
```

---

## 🚩 Detection Indicators

### File-Level Indicators

```
Encrypted Files
├─ New file extensions added (.xyz, .conti, .locked, .encrypted)
├─ Files completely unreadable (random binary data)
├─ File permissions changed (read-only, system attribute)
└─ File timestamps modified (encryption time)

Ransomware Behavior
├─ Mass file modifications in short time window
├─ Many file access/creation events
├─ Files deleted then recreated (overwrite pattern)
├─ Bulk writes to file system (encryption writes)
└─ Sequential file access pattern (encryption iteration)
```

### Process-Level Indicators

```
Suspicious Processes
├─ Unknown binary with high file I/O
├─ Process writing to unusual locations (/tmp, /var/tmp, root)
├─ Processes spawning other processes (distribution)
├─ Process with elevated privileges writing everywhere
├─ DLL injection (legitimate process compromised)

Persistence Mechanisms
├─ New scheduled tasks created
├─ New services installed
├─ Registry Run keys modified
├─ Cron jobs created (Linux)
├─ Browser extensions installed (unusual)
```

### Network-Level Indicators

```
C2 Communication
├─ Outbound connections to unknown IPs
├─ Traffic on unusual ports (8080, 4444, 5555)
├─ Large data transfers outbound (exfiltration)
├─ DNS queries for suspicious domains
├─ Connections to known Tor nodes

Lateral Movement
├─ SMB traffic to other hosts (445)
├─ RDP connections (3389)
├─ WinRM traffic (5985)
├─ Admin share access (\\host\c$)
└─ Multiple logons from single user
```

### System-Level Indicators

```
Shadow Copy Deletion (CRITICAL)
├─ vssadmin delete shadows (VSS deletion)
├─ wmic shadowcopy delete (WMI method)
├─ diskpart commands (partition manipulation)
└─ Recovery option disabling (bcdedit)

AV/Security Tool Tampering
├─ Windows Defender disabled
├─ AV service stopped
├─ Firewall rules modified
├─ EDR agent uninstalled
├─ Event logs cleared

User Activity
├─ Interactive logon to service account
├─ Unusual logon hours (3am access)
├─ Account creation (backdoor account)
├─ Password changes (persistence)
└─ Group membership modifications
```

---

## 🛡️ Detection Rules (Sigma/YARA)

### Sigma Rule: Shadow Copy Deletion

```yaml
title: Shadow Copy Deletion
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith:
      - '\vssadmin.exe'
      - '\wmic.exe'
      - '\diskpart.exe'
    CommandLine|contains:
      - 'delete shadows'
      - 'shadowcopy delete'
      - 'clean config all'
  condition: selection
falsepositives:
  - Legitimate system maintenance (rare)
level: critical
tags:
  - attack.impact
  - ransomware
```

### YARA Rule: Ransomware Strings

```yara
rule Ransomware_StringIndicators {
    strings:
        $msg1 = "your files have been encrypted" nocase
        $msg2 = "ransom" nocase
        $msg3 = "bitcoin" nocase
        $msg4 = "decrypt" nocase
        $file1 = "readme.txt" nocase
        $file2 = "recovery_key" nocase
        $reg1 = "vssadmin"
        $reg2 = "bcdedit"
    condition:
        (2 of ($msg*)) or (1 of ($file*)) or (1 of ($reg*))
}
```

---

## 📋 Detection Checklist

```
EARLY WARNING SIGNS (Days 1-30)
☐ Monitor for initial access (phishing, exploits)
☐ Track process execution (unknown binaries)
☐ Monitor outbound connections (C2 communication)
☐ Alert on credential compromise (unusual logons)
☐ Monitor for privilege escalation
☐ Track lateral movement (admin shares, RDP)
☐ Monitor for persistence mechanisms
☐ Alert on backup access (backup deletion attempts)

IMMINENT ENCRYPTION (Days 40-45)
☐ Shadow copy deletion attempt (CRITICAL)
☐ Recovery option disabling (CRITICAL)
☐ Mass file modifications (CRITICAL)
☐ AV/EDR tampering (HIGH)
☐ Event log clearing (HIGH)
☐ Unusual account activity (HIGH)

POST-ENCRYPTION (Too late, but investigate)
☐ Capture ransom note content
☐ Identify encryption algorithm (some may have escapes)
☐ Collect IOCs (IPs, domains, wallets)
☐ Preserve evidence for forensics
☐ Determine scope of encryption
☐ Check for exfiltrated data
```

---

## 🔄 Response Strategy

### Containment (First 4 Hours)

```
IMMEDIATE ACTIONS
1. Isolate infected host (disconnect network)
2. Alert incident response team
3. Preserve evidence (don't reboot)
4. Check for lateral movement (hunt for others infected)
5. Identify patient zero (where it came from)
6. Backup all current logs (for forensics)
7. Preserve ransom note (for analysis)
```

### Investigation (Hours 4-24)

```
FORENSIC ANALYSIS
├─ Memory dump (before shutdown)
├─ Disk forensics (find encryption tool)
├─ Timeline reconstruction (initial access to encryption)
├─ Lateral movement identification (compromised hosts)
├─ Credential analysis (what accounts were used)
├─ Backup integrity check (were backups already deleted?)
└─ Data exfiltration assessment (what was stolen?)
```

### Recovery (Days 1-7)

```
SHORT-TERM RECOVERY
├─ Validate backup integrity (are they actually clean?)
├─ Restore from pre-incident backups
├─ Verify restoration is complete and functional
├─ Monitor for re-infection
└─ Apply security patches

DECISION POINT: Pay Ransom?
├─ Estimated cost: Recovery from backups vs. ransom
├─ FBI guidance: DON'T PAY (funds criminals)
├─ Insurance: Check coverage
├─ Notification: Required by law in most jurisdictions
└─ Reputation: Paying publicizes vulnerability
```

---

## 🔑 Key Takeaways

- **30-45 day dwell time = detection window** - attackers spend month+ before encrypting
- **Shadow copy deletion is critical indicator** - alert immediately
- **Double extortion is standard** - assume data was exfiltrated
- **Backups are target #1** - attackers delete them first
- **Recovery from backup beats ransom** - invest in backup resilience
- **FBI: Don't pay ransom** - funds criminals, no guarantee of decryption
- **Early detection saves millions** - detect at day 10, not day 45

---

## 💰 Economics of Ransomware

```
Cost to deploy ransomware: $0 (tools are free/open-source)
Cost to encrypt your files: $0 (computer does the work)
Cost of ransom demand: $1M - $10M
Cost of recovery without ransom: $2M - $20M
Cost of downtime (per day): $100K - $1M

ROI for attackers: Infinite (1 successful ransom = $5M+)

Why it works: It's cheaper to pay than to recover
→ This is why you need preparation (backups, segmentation)
```

---

## 📚 Resources

- [CISA Ransomware Guidance](https://www.cisa.gov/ransomware)
- [FBI: Ransomware Playbook](https://www.fbi.gov/investigate/cyber)
- [No More Ransom Project](https://www.nomoreransom.org/)
- [Ransomware Tracking Sites](https://ransomware.live/)

---

## [⬅️ Day 059](../day059/) | [➡️ Day 061](../day061/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*