# Day 056 - Digital Forensics: Disk & Memory Analysis

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate-Advanced

---

## 🧠 The Concept

After detection and containment comes investigation.

Digital forensics is the science of extracting evidence from digital systems - memory, disks, network traffic - to understand what an attacker did, how long they were inside, and where the evidence is.

It's detective work. And it requires precision.

---

## 🔍 Two Domains

### Memory Forensics (RAM)

Everything running on a system lives in RAM:
- Processes and their command-line arguments
- Open files and network connections
- Cached credentials (plaintext sometimes)
- Injected code (malware payloads)
- Encryption keys in memory

**Critical:** Volatile. Lost when system shuts down.

**Best practice:** Capture memory **before** containment actions that might restart the system.

### Disk Forensics (Storage)

Persistent evidence:
- File system metadata (creation time, modification time, access time)
- Deleted files (not really deleted, just marked as deleted)
- Unallocated space (where deleted files hide)
- File slack space (end of files before next file starts)
- Registry hives (Windows system configuration)
- Log files (application, system, security)

**Resilient but not immutable:** Can be overwritten. Act fast.

---

## 💾 Memory Forensics - Volatility

**Volatility** is the standard open-source memory analysis framework.

### Key Volatility Commands

```bash
# List all running processes
volatility -f memory.dmp windows.pslist

# Show process tree (parent-child relationships)
volatility -f memory.dmp windows.pstree

# Extract command-line arguments for each process
volatility -f memory.dmp windows.cmdline

# Show network connections and listening ports
volatility -f memory.dmp windows.netscan

# List loaded DLLs (dynamic libraries) for a process
volatility -f memory.dmp windows.dlllist --pid=<PID>

# Extract injected code / shellcode
volatility -f memory.dmp windows.malfind

# List open files
volatility -f memory.dmp windows.handles | grep File

# Dump a specific process' memory to disk (for offline analysis)
volatility -f memory.dmp windows.memmap --pid=<PID> --dump

# Extract strings from a process
volatility -f memory.dmp windows.psxview  # show hidden processes

# Timeline of process creation
volatility -f memory.dmp windows.timeline
```

### What to Look For in Memory

```
Suspicious Processes
├─ rundll32.exe with no arguments (malware launcher)
├─ svchost.exe with unusual parent (not services.exe)
├─ explorer.exe running from temp folder
├─ powershell.exe child of Office apps (document-based attack)
└─ cmd.exe with network connections

Code Injection
├─ Process with mapped DLL from temp folder
├─ Malfind output showing shellcode
├─ Process with RWX memory permissions
└─ Unsigned DLL in system process

Credential Stealing
├─ lsass.exe being accessed by suspicious process
├─ SAM registry hive in memory
├─ Cached NTLM hashes
└─ Plaintext passwords in process memory

Network Activity
├─ Unexpected outbound connections from process
├─ Connections to known C2 IPs
├─ Large data transfers
└─ Connections on unusual ports
```

---

## 💾 Disk Forensics

### Chain of Custody

Before touching any forensic evidence:

```
1. Document everything
   ├─ Date/time of seizure
   ├─ Hardware serial numbers
   ├─ Witness signatures
   └─ Location and condition

2. Compute hash of entire disk
   md5sum /dev/sda > disk.md5
   
   SHA256 is more forensically sound.

3. Make forensic image (bit-by-bit copy)
   dcfldd if=/dev/sda of=disk.img
   
   Do NOT mount or access original disk.
   Always work on the image copy.

4. Verify image integrity
   md5sum disk.img  # Should match original
```

### Key File System Artifacts

```
Windows NTFS
├─ $MFT (Master File Table)
│  └─ File metadata: name, timestamps, size, permissions
│
├─ $Logfile
│  └─ File system journal (transactions)
│
├─ $UsnJrnl
│  └─ USN Journal (all file modifications)
│
├─ Recycle Bin ($Recycle.Bin)
│  └─ Deleted files (with metadata)
│
└─ Alternate Data Streams (ADS)
   └─ Hidden data attached to files

Linux ext4 / BTRFS
├─ inode table
│  └─ File metadata
│
├─ Journal
│  └─ File system changes
│
└─ Inode indirect blocks
   └─ Unallocated space with deleted file data
```

### Windows Registry (Forensic Gold)

```
HKLM\SAM
├─ Password hashes (NTLM/LM)
└─ User accounts and groups

HKLM\SYSTEM
├─ System configuration
├─ Network adapters (IP history)
├─ Services and drivers
└─ Device info (USB devices plugged in)

HKLM\SECURITY
├─ LSA secrets
└─ Cached domain passwords

HKCU\Software\Microsoft\Windows\CurrentVersion
├─ Installed programs
├─ Run / RunOnce keys (persistence)
└─ Open files

HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer
├─ Recently opened files
├─ Search history
└─ USB device history

ShellBags (folder view settings)
├─ Directories browsed by user
└─ Can reveal where attacker looked
```

### Timeline Building

```
File Timestamps (3 times in NTFS):
  MAC (Modified, Accessed, Created)
  
Example suspicious timeline:
  ├─ 2024-01-10 10:15 - User files accessed (normal)
  ├─ 2024-01-12 02:34 - Suspicious exe created (attacker)
  ├─ 2024-01-12 02:35 - PowerShell run (attacker lateral move)
  ├─ 2024-01-12 02:40 - Large file exfil (attacker data theft)
  ├─ 2024-01-13 09:30 - User logs in normally
  └─ 2024-01-13 10:00 - Malware detected in SIEM
  
Gap between compromise (1/12 2:34) and detection (1/13 10:00) = 31.5 hours
```

---

## 🛠️ Forensic Tools

| Tool | Purpose |
|------|---------|
| **Volatility** | Memory analysis, processes, network, injected code |
| **Autopsy** | Disk image analysis, file recovery, timeline |
| **EnCase** | Commercial forensic platform (industry standard) |
| **FTK (Forensic Toolkit)** | Disk analysis, evidence examination |
| **The Sleuth Kit (TSK)** | Command-line file system analysis |
| **YARA** | Pattern matching in files and memory |
| **Strings** | Extract readable text from binary files |
| **ExifTool** | Metadata extraction (photos, docs) |

---

## 📋 Forensic Investigation Checklist

```
MEMORY ANALYSIS (if available)
☐ Capture memory immediately (before system shutdown)
☐ Hash memory dump for chain of custody
☐ List all processes (pslist, pstree)
☐ Check for hidden processes (psxview, psscan)
☐ Extract injected code (malfind)
☐ Network connections from processes
☐ Dump suspicious process memory to disk
☐ Look for credential artifacts (lsass, SAM)

DISK ANALYSIS
☐ Create forensic image of disk
☐ Compute and verify MD5/SHA256 hash
☐ Mount image read-only (NEVER mount original)
☐ Extract system hives (SAM, SECURITY, SYSTEM, SOFTWARE)
☐ Parse registry for persistence (Run keys, Services, Scheduled Tasks)
☐ Timeline of file modifications (focus on suspicious timeframes)
☐ Recover deleted files from unallocated space
☐ Check for alternate data streams (attacker hiding spots)
☐ Extract recent documents, search history, web history

ARTIFACT ANALYSIS
☐ Malware samples → VirusTotal, YARA scanning
☐ Network IOCs → Blocklist for reputation
☐ File hashes → Cross-reference incident databases
☐ Command line arguments → Understand attack flow
☐ Service names / drivers → Check for rootkits

EVIDENCE PRESERVATION
☐ Document all findings with timestamps
☐ Chain of custody maintained throughout
☐ Write-blocking for all forensic work
☐ Hash verification at each step
☐ Secure evidence storage
```

---

## 🔑 Key Takeaways

- **Volatility is free and powerful** - master the basic commands
- **Memory is volatile** - capture before shutdown
- **Timeline is king** - understand the attacker's progression
- **Registry is forensic gold** - where persistence lives
- **Chain of custody matters** - for legal admissibility
- **Deleted files aren't deleted** - can be recovered from unallocated space

---

## 📚 Resources

- [Volatility Framework](https://www.volatilityfoundation.org/)
- [The Sleuth Kit](https://www.sleuthkit.org/)
- [NIST Digital Forensics](https://www.nist.gov/itl/ssd/computer-security-resource-center)
- [Autopsy](https://www.sleuthkit.org/autopsy/)

---

## [⬅️ Day 055](../day055/) | [➡️ Day 057](../day057/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*