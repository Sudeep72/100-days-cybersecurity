# Day 050 - Writing Detection Rules: Sigma & YARA

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

SPL queries detect in Splunk. KQL detects in Sentinel. ESQL detects in Elastic.

Every SIEM has its own language. Every rule has to be rewritten for every platform.

Sigma solves this - a vendor-neutral detection rule format that compiles to any SIEM's query language. Write once, deploy everywhere.

YARA solves a different problem - detecting malware patterns in files and memory. The standard tool for malware analysis and file-based threat hunting.

Today: writing real detection rules in both formats.

---

## 🔷 Sigma Rules

### Format

```yaml
title: Descriptive title of what this detects
id: unique-uuid-here
status: stable | test | experimental
description: |
  What this rule detects and why it matters.
references:
  - https://attack.mitre.org/techniques/T1059/
author: Your Name
date: 2024/01/15
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 4688
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
      - 'IEX'
      - 'Invoke-Expression'
  condition: selection
falsepositives:
  - Legitimate PowerShell automation scripts
  - Software deployment tools
level: high
```

---

### Core Detection Fields

```yaml
# String matching
field: value                    # exact match
field|contains: value           # contains substring
field|startswith: value         # starts with
field|endswith: value           # ends with
field|contains|all:             # all values must match
  - value1
  - value2
field|contains|any:             # any value matches
  - value1
  - value2
field|re: pattern               # regex match

# Null checks
field: null                     # field is empty
field|exists: true              # field must exist

# Numeric
field|gt: 100                   # greater than
field|lt: 100                   # less than
```

---

### Condition Logic

```yaml
condition: selection            # simple match
condition: selection and not filter   # with exclusion
condition: 1 of selection*      # any of selection_1, selection_2...
condition: all of selection*    # all selections must match
condition: selection | count() > 10  # aggregate threshold
```

---

## 📝 10 Production-Ready Sigma Rules

### Rule 1 - PowerShell Encoded Command

```yaml
title: PowerShell Encoded Command Execution
id: 7f1a3e5b-2c4d-4a6f-8e9b-1d3f5a7c9e2b
status: stable
description: Detects PowerShell executing base64-encoded commands,
  commonly used to obfuscate malicious scripts.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: Sudeep Ravichandran - 100 Days of Cybersecurity
date: 2024/01/15
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc '
      - '-EncodedCommand'
      - ' -e '
  filter_legitimate:
    ParentImage|contains:
      - '\sccm\'
      - '\ansible\'
  condition: selection and not filter_legitimate
falsepositives:
  - SCCM / Ansible automation (filtered above)
  - Some deployment tools
level: medium
```

---

### Rule 2 - Office Application Spawning Shell

```yaml
title: Office Application Spawning Command Shell
id: 3b5d1a9c-8f2e-4c7a-b1d3-6e8f2a4c6b8d
status: stable
description: Detects Microsoft Office applications spawning
  cmd.exe or PowerShell - classic macro malware indicator.
references:
  - https://attack.mitre.org/techniques/T1566/001/
author: Sudeep Ravichandran - 100 Days of Cybersecurity
date: 2024/01/15
tags:
  - attack.initial_access
  - attack.t1566.001
  - attack.execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|contains:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
  condition: selection
falsepositives:
  - Legitimate Office macros (rare)
level: high
```

---

### Rule 3 - LSASS Memory Access (Credential Dumping)

```yaml
title: LSASS Memory Access - Credential Dumping
id: 9a2c4e6f-1b3d-5f7a-c9e1-3b5d7f9a1c3e
status: stable
description: Detects access to LSASS process memory,
  used by Mimikatz and similar tools to dump credentials.
references:
  - https://attack.mitre.org/techniques/T1003/001/
author: Sudeep Ravichandran - 100 Days of Cybersecurity
date: 2024/01/15
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1038'
      - '0x40'
      - '0x1fffff'
  filter_legitimate:
    SourceImage|contains:
      - '\MsMpEng.exe'
      - '\svchost.exe'
      - '\taskmgr.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - AV/EDR products accessing LSASS (filtered)
level: critical
```

---

### Rule 4 - Scheduled Task Creation (Persistence)

```yaml
title: Scheduled Task Created via Command Line
id: 5c7e9a1b-3d5f-7a9c-e1b3-5d7f9a1b3c5e
status: stable
description: Detects scheduled task creation via schtasks.exe,
  a common persistence mechanism.
references:
  - https://attack.mitre.org/techniques/T1053/005/
author: Sudeep Ravichandran - 100 Days of Cybersecurity
date: 2024/01/15
tags:
  - attack.persistence
  - attack.t1053.005
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains: '/create'
  filter_system:
    User|contains:
      - 'SYSTEM'
      - 'LOCAL SERVICE'
  condition: selection and not filter_system
falsepositives:
  - Legitimate software installers
  - IT automation tools
level: medium
```

---

### Rule 5 - Linux Reverse Shell via Bash

```yaml
title: Linux Bash Reverse Shell
id: 1a3c5e7f-9b1d-3f5a-7c9e-1b3d5f7a9c1e
status: stable
description: Detects reverse shell execution patterns via bash,
  commonly used for post-exploitation.
references:
  - https://attack.mitre.org/techniques/T1059/004/
author: Sudeep Ravichandran - 100 Days of Cybersecurity
date: 2024/01/15
tags:
  - attack.execution
  - attack.t1059.004
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: '/bash'
    CommandLine|contains:
      - '/dev/tcp/'
      - '/dev/udp/'
      - 'bash -i'
      - '>&'
  condition: selection
falsepositives:
  - Security testing in authorised environments
level: high
```

---

### Rule 6 - New Local Admin Account Created

```yaml
title: New Local Administrator Account Created
id: 7f9a1c3e-5b7d-9f1a-3c5e-7b9d1f3a5c7e
status: stable
description: Detects creation of new local administrator accounts,
  commonly used for persistence after compromise.
references:
  - https://attack.mitre.org/techniques/T1136/001/
author: Sudeep Ravichandran - 100 Days of Cybersecurity
date: 2024/01/15
tags:
  - attack.persistence
  - attack.t1136.001
logsource:
  product: windows
  service: security
detection:
  selection_created:
    EventID: 4720
  selection_admin:
    EventID: 4732
    GroupName: 'Administrators'
  condition: selection_created or selection_admin
falsepositives:
  - IT helpdesk creating accounts
  - Onboarding processes
level: medium
```

---

## 🔶 YARA Rules

YARA identifies files or memory regions based on patterns - strings, byte sequences, and conditions.

### Basic Structure

```yara
rule RuleName {
    meta:
        description = "What this rule detects"
        author      = "Your Name"
        date        = "2024-01-15"
        reference   = "https://..."
        hash        = "md5 of sample"

    strings:
        $str1 = "suspicious string"
        $str2 = "another indicator"
        $hex1 = { 6A 40 68 00 30 00 00 68 14 00 }   // hex bytes
        $re1  = /[A-Z0-9._%+-]+@malware\.com/         // regex

    condition:
        any of them
        // or: all of them
        // or: $str1 and $str2
        // or: 2 of ($str*)
        // or: filesize < 1MB and $str1
}
```

---

### YARA Rule 1 - Mimikatz Strings

```yara
rule Mimikatz_Strings {
    meta:
        description = "Detects Mimikatz credential dumping tool"
        author      = "Sudeep Ravichandran - 100 Days of Cybersecurity"
        reference   = "https://attack.mitre.org/software/S0002/"
        severity    = "CRITICAL"

    strings:
        $s1 = "mimikatz" nocase
        $s2 = "sekurlsa::logonpasswords" nocase
        $s3 = "lsadump::dcsync" nocase
        $s4 = "privilege::debug" nocase
        $s5 = "SekurLSA" nocase
        $hex = { 6D 69 6D 69 6B 61 74 7A }   // "mimikatz" in hex

    condition:
        2 of them
}
```

---

### YARA Rule 2 - Webshell Patterns

```yara
rule Generic_Webshell {
    meta:
        description = "Detects common PHP/ASP webshell patterns"
        author      = "Sudeep Ravichandran - 100 Days of Cybersecurity"
        severity    = "HIGH"

    strings:
        $php1 = "<?php system(" nocase
        $php2 = "<?php exec(" nocase
        $php3 = "<?php passthru(" nocase
        $php4 = "<?php shell_exec(" nocase
        $php5 = "eval(base64_decode(" nocase
        $php6 = "eval(gzinflate(" nocase
        $asp1 = "cmd.exe /c" nocase
        $asp2 = "Response.Write(Shell(" nocase

    condition:
        any of ($php*) or any of ($asp*)
}
```

---

### YARA Rule 3 - Ransomware Indicators

```yara
rule Generic_Ransomware_Indicators {
    meta:
        description = "Generic ransomware behavioural indicators"
        author      = "Sudeep Ravichandran - 100 Days of Cybersecurity"
        severity    = "CRITICAL"

    strings:
        $ransom1 = "your files have been encrypted" nocase
        $ransom2 = "send bitcoin" nocase
        $ransom3 = "your personal id" nocase
        $ransom4 = "decrypt your files" nocase
        $ransom5 = ".onion" nocase
        $shadow1 = "vssadmin delete shadows" nocase
        $shadow2 = "wbadmin delete" nocase
        $shadow3 = "bcdedit /set recoveryenabled no" nocase

    condition:
        2 of ($ransom*) or any of ($shadow*)
}
```

---

### Running YARA

```bash
# Install
sudo apt install yara

# Scan a single file
yara rule.yar suspicious_file.exe

# Scan a directory recursively
yara -r rule.yar /var/www/html/

# Scan running processes (memory)
sudo yara rule.yar -p <PID>

# Scan all processes
sudo yara rule.yar $(ls /proc/[0-9]*/exe 2>/dev/null | sed 's|/exe||;s|/proc/||')

# Multiple rules
yara rule1.yar rule2.yar rule3.yar target.exe

# Use a rules directory
yara /etc/yara/rules/ target.exe
```

---

### Converting Sigma to SIEM Queries

```bash
# Install sigmac
pip install sigmatools

# Convert to Splunk SPL
sigmac -t splunk rule.yml

# Convert to Elastic KQL
sigmac -t es-qs rule.yml

# Convert to Microsoft Sentinel KQL
sigmac -t ala rule.yml

# Convert to QRadar AQL
sigmac -t qradar rule.yml

# Batch convert entire directory
sigmac -t splunk -r ./rules/ -o splunk_rules.txt
```

---

## 🔑 Key Takeaways

- Sigma = vendor-neutral detection rule format - write once, deploy to any SIEM
- YARA = file/memory pattern matching - essential for malware analysis and hunting
- Always include false positive analysis in rules - noise kills detection programs
- Tag rules with MITRE ATT&CK techniques - enables coverage gap analysis
- Start with `level: medium` - tune down noise before raising to high/critical
- The Sigma rules community (GitHub) has thousands of production-ready rules to learn from

---

## 📚 Resources
- [Sigma Rules - GitHub](https://github.com/SigmaHQ/sigma)
- [YARA Documentation](https://yara.readthedocs.io/)
- [Uncoder.io - Sigma converter (online)](https://uncoder.io/)
- [YARA Rules Repository](https://github.com/Yara-Rules/rules)

---

## [⬅️ Day 049](../day049/) | [➡️ Day 051](../day051/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*