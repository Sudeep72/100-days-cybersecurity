# Day 057 - Malware Analysis 101: Static vs Dynamic

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

You've found a suspicious file.

Is it malware? What does it do? What systems does it target? Where does it exfiltrate data to?

Malware analysis is the process of dissecting a sample to extract these answers.

Two approaches: **static** (without running it) and **dynamic** (in a controlled environment).

---

## 🔍 Static Analysis - No Execution

Examine the file without running it.

**Safe, fast, but limited:**
- Can't see runtime behavior
- Obfuscated code is hard to read
- Can miss dynamically loaded payloads

### File Hashing & Reputation

```bash
# Compute hashes
md5sum suspicious.exe
sha256sum suspicious.exe

# Check VirusTotal (free)
curl https://www.virustotal.com/api/v3/files/<HASH> \
  -H "x-apikey: YOUR_API_KEY"

# Results: number of AV engines flagging it
```

### Strings Extraction

```bash
# Extract readable text (ASCII + Unicode)
strings suspicious.exe

# Look for:
  URLs/domains → C2 infrastructure
  IP addresses → attacker infrastructure
  API calls → what the malware imports
  Registry keys → persistence locations
  Error messages → debugging leftover clues
  File paths → where it installs itself

# Example:
strings suspicious.exe | grep -E "http|cmd|powershell|registry|services"
```

### Static Disassembly

```
Tool: IDA Pro, Ghidra (free)

What you see:
  Assembly code (CPU instructions)
  Function entry points
  String references
  Import tables (what libraries it uses)
  Suspicious patterns

Limitations:
  Takes hours to analyze complex malware
  Requires assembly knowledge
  Obfuscated code is intentionally unreadable
  Packed malware needs unpacking first
```

### PE File Analysis

```
Windows executables (.exe, .dll) are Portable Executable (PE) files.

Structure:
  DOS header
  PE signature
  File header (machine type, number of sections, etc.)
  Optional header (subsystem, required OS version, etc.)
  Section headers (.text, .data, .rsrc, etc.)
  Sections themselves

Tools:
  PEiD → Detect packer, compiler
  Exiftool → Extract metadata
  PEview / pestudio → GUI PE analysis
  Radare2 → Binary analysis

Look for:
  Suspicious imports (WinAPI for network access, registry, process creation)
  Entry point anomalies
  Packed/encrypted sections (entropy analysis)
  Unusual timestamps (added later by malware author)
  Digital signatures (signed malware)
```

### Entropy Analysis

```
High entropy in a section = likely encrypted/compressed payload

Normal code section:  entropy ~3.0-4.0
Encrypted data:      entropy ~7.5-8.0

Example:
  .text section (code) - low entropy (readable)
  .data section - medium entropy (strings + data)
  .payload section - high entropy (encrypted malware payload)
```

---

## 🏃 Dynamic Analysis - Controlled Execution

Run the malware in an isolated lab environment.

**Advantages:**
- See actual behavior
- Observe C2 communications
- Capture data exfiltration
- Understand command execution
- Real-time API call monitoring

**Risks:**
- Malware escapes sandbox
- Network propagation
- Crashes lab environment
- Detection evasion (malware checks for sandbox)

### Sandbox Setup

```
Isolated VM (not on production network)
├─ Windows guest image
├─ Network isolated (no internet, internal network only)
├─ Monitoring tools (API hooks, network capture, registry monitoring)
├─ Snapshot before infection
└─ Disposable (can be wiped after analysis)

Monitoring Tools
├─ Process Monitor (Procmon) → File/registry/network access
├─ API Monitor → API calls in real-time
├─ Wireshark → Network traffic capture
├─ RegShot → Registry changes before/after
├─ Autoruns → Persistence mechanisms
└─ Task Manager → Process tree
```

### What to Monitor

```
File Operations
├─ Dropped files (where, names, modifications)
├─ Temp folder usage
├─ System32 modifications
├─ Registry hive writes
└─ Recovery/backup modifications

Registry Changes
├─ HKLM\Software\Microsoft\Windows\CurrentVersion\Run (persistence)
├─ Services created (persistence)
├─ Scheduled tasks (persistence)
├─ DNS cache changes
└─ Network adapter settings

Network Activity
├─ DNS queries (resolving C2 domains)
├─ Outbound connections (where does it call home?)
├─ Data exfiltration (what's being stolen?)
├─ Port usage (unusual ports?)
└─ Protocol analysis (HTTP, HTTPS, DNS, custom)

Process Behavior
├─ Child processes spawned (cmd.exe, powershell.exe)
├─ Injection into legitimate processes
├─ Termination of security tools
├─ Memory access patterns
└─ Privilege escalation attempts
```

### Detection Evasion

Malware often detects sandboxes and behaves differently.

```
Sandbox Detection Techniques
├─ Check for virtualization (CPUID, MAC addresses, driver names)
├─ Look for analysis tools (Process names, registry keys)
├─ Check file system artifacts (typical sandbox paths)
├─ Monitor execution time (sandbox may be slow)
├─ Check for debuggers attached
└─ Timeout mechanism (only run if patience threshold exceeded)

Evasion Examples
├─ Sleep 1 minute before any activity
├─ Check for Wireshark, Procmon, IDA running
├─ Refuse to run in VirtualBox, VMware, Hyper-V
├─ Destroy itself if running as admin (sandboxes often run with elevated privs)
└─ Use legitimate tools (PowerShell, WMI) to avoid suspicion
```

---

## 🏭 Automated Analysis Services

```
VirusTotal
├─ Hash lookup: is this sample known malware?
├─ Sandbox analysis: run it safely, see results
├─ Detection: 60+ antivirus engines scan it
└─ Comments: other analysts share findings

ANY.RUN
├─ Automated malware analysis sandbox
├─ Interactive: watch the malware run in real-time
├─ Network analysis: see C2 communications
├─ Payloads: download extracted IOCs
└─ Free tier available

Hybrid Analysis
├─ Automated behavioral analysis
├─ VPC detection
├─ Yara rule generation
└─ Threat intel integration

Joe Security
├─ Hybrid static/dynamic analysis
├─ Behavioral indicators
├─ APT-level analysis
└─ Commercial focus
```

---

## 📋 Malware Analysis Checklist

### Static Phase
```
☐ Compute MD5/SHA256 hash
☐ Check VirusTotal for known malware
☐ Extract strings (urls, IPs, registry keys)
☐ PE file analysis (imports, sections, entropy)
☐ Check digital signature (signed malware?)
☐ Examine resource section (embedded payloads?)
☐ Metadata analysis (compile time, author info)
☐ Packer detection (is it packed/encrypted?)
☐ YARA scanning (known malware family signatures)
```

### Dynamic Phase
```
☐ Create isolated lab environment
☐ Take baseline snapshot
☐ Enable monitoring (Procmon, Wireshark, RegShot)
☐ Execute malware (controlled click)
☐ Observe for ~5 minutes (initial behavior)
☐ Capture network traffic (DNS, outbound connections)
☐ Registry changes analysis
☐ Files dropped analysis
☐ Process tree inspection
☐ Restore from snapshot (cleanup)
☐ Document all findings
```

### IOC Extraction
```
IPs → Block on firewall
Domains → DNS sinkhole or block
URLs → Web proxy block
File paths → Detection rule
Registry keys → YARA/Sigma rule
Processes → Behavior rule
Filehashes → Blocklist
C2 protocol patterns → IDS signature
```

---

## 🔑 Key Takeaways

- **Static first** - always, unless you're confident in your lab isolation
- **Hash checking saves time** - VirusTotal often has existing analysis
- **Strings are powerful** - malware often embeds configuration plaintext
- **Sandbox evasion is common** - advanced malware detects and resists analysis
- **Document everything** - build IOCs for detection rules
- **Network traffic tells the story** - C2 communications expose attacker intent

---

## 🛠️ Recommended Tools

| Tool | Use |
|------|-----|
| **VirusTotal** | Quick reputation check (free) |
| **Ghidra** | Disassembly and decompilation (free) |
| **Procmon** | File/registry monitoring (free) |
| **Wireshark** | Network traffic analysis (free) |
| **PEStudio** | PE file analysis (free) |
| **ANY.RUN** | Sandbox analysis (free tier) |
| **IDA Pro** | Advanced disassembly (commercial) |

---

## 📚 Resources

- [Ghidra](https://ghidra-sre.org/)
- [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/)
- [ANY.RUN Sandbox](https://any.run/)
- [VirusTotal](https://www.virustotal.com/)

---

## [⬅️ Day 056](../day056/) | [➡️ Day 058](../day058/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*