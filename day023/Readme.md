# Day 023 - Active Recon: Banner Grabbing & Service Enumeration

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Passive recon (Day 22) tells you what's publicly documented.

Active recon tells you what's actually running.

The difference: active recon involves direct contact with the target. Packets leave your machine and hit theirs. Logs may be generated. IDS may trigger. You're no longer invisible.

This is why passive recon always comes first - you want to know as much as possible before making any noise.

Active recon answers the critical questions:
- What services are actually listening?
- What version of each service?
- What information do those services volunteer?
- What's the web application structure?

---

## 🏷️ Banner Grabbing

When you connect to a service, it often announces itself.

This announcement is called a **banner** - and it's gold for an attacker.

```bash
# Netcat - raw TCP connection, grab whatever the service sends
nc -v targetip 22
# SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8
#   ↳ OpenSSH version, Ubuntu version - check both for CVEs

nc -v targetip 21
# 220 ProFTPD 1.3.5 Server
#   ↳ FTP server and version

nc -v targetip 25
# 220 mail.target.com ESMTP Postfix
#   ↳ Mail server software

# Curl - grab HTTP headers
curl -I https://target.com
# Server: Apache/2.4.18 (Ubuntu)
# X-Powered-By: PHP/7.2.1
# X-Frame-Options: SAMEORIGIN
#   ↳ Web server, PHP version, security headers (or lack of)

# Telnet - alternative to netcat
telnet targetip 80
GET / HTTP/1.0
# Returns full HTTP response headers
```

---

## 🔎 Service Enumeration - By Port

### SSH (Port 22)
```bash
# Version detection
nmap -sV -p 22 targetip

# Check supported authentication methods
nmap --script ssh-auth-methods targetip

# Enumerate algorithms (weak algorithms = attack surface)
nmap --script ssh2-enum-algos targetip
```

---

### FTP (Port 21)
```bash
# Check for anonymous login (no credentials needed)
nmap --script ftp-anon targetip

# Manual check
ftp targetip
# Name: anonymous
# Password: (blank or any email)

# If anonymous login works - list everything
ls -la
get sensitive_file.txt
```

---

### HTTP/HTTPS (Ports 80/443)
```bash
# Web server fingerprinting
whatweb https://target.com

# Nikto - web server vulnerability scanner
nikto -h https://target.com

# Directory and file enumeration
gobuster dir -u https://target.com \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,txt,bak \
  -t 50

# Alternative: feroxbuster (faster, recursive)
feroxbuster -u https://target.com \
  -w /usr/share/wordlists/dirb/common.txt

# Virtual host enumeration (find hidden subdomains)
gobuster vhost -u https://target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

---

### SMB (Ports 139/445) - Windows File Sharing
```bash
# Enumerate shares, users, OS info
enum4linux -a targetip

# Null session check (unauthenticated access)
smbclient -L //targetip -N

# List shares
smbmap -H targetip

# Check for EternalBlue (MS17-010)
nmap --script smb-vuln-ms17-010 targetip

# Access a share
smbclient //targetip/sharename -N
```

---

### SMTP (Port 25) - Email Server
```bash
# Enumerate valid email users
nmap --script smtp-enum-users targetip

# Manual VRFY command (checks if user exists)
nc targetip 25
EHLO test
VRFY admin@target.com
VRFY root@target.com
```

---

### MySQL (Port 3306)
```bash
# Check for unauthenticated access
nmap --script mysql-empty-password targetip

# Try default credentials
mysql -h targetip -u root -p
# (try blank password, 'root', 'password', 'mysql')

# Enumerate databases if access gained
show databases;
use mysql;
select user, password from user;
```

---

### RDP (Port 3389) - Windows Remote Desktop
```bash
# Check if RDP is running
nmap -p 3389 targetip

# Check for BlueKeep (CVE-2019-0708)
nmap --script rdp-vuln-ms12-020 targetip

# Check encryption level
nmap --script rdp-enum-encryption targetip
```

---

## 💻 The Code - Recon Enumerator

```python
"""
Day 023 - Active Recon Enumerator
100 Days of Cybersecurity by Sudeep Ravichandran

Performs banner grabbing and service enumeration
against a target IP. Use only on systems you own
or have explicit permission to test.

Usage: python3 recon_enum.py <target-ip>
Requires: pip install requests
"""

import socket
import subprocess
import sys
import requests
from datetime import datetime


TIMEOUT = 3

COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017:"MongoDB",
}


def grab_banner(ip, port):
    """Attempt to grab a service banner via raw TCP."""
    try:
        s = socket.socket()
        s.settimeout(TIMEOUT)
        s.connect((ip, port))

        # Send HTTP request for web ports
        if port in [80, 8080, 8443, 443]:
            s.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        else:
            s.send(b"\r\n")

        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        return banner[:200] if banner else None
    except Exception:
        return None


def check_port(ip, port):
    """Check if a port is open."""
    try:
        s = socket.socket()
        s.settimeout(TIMEOUT)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False


def grab_http_headers(ip, port=80):
    """Grab HTTP response headers."""
    scheme = "https" if port in [443, 8443] else "http"
    try:
        resp = requests.get(
            f"{scheme}://{ip}:{port}",
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=False
        )
        interesting = ["Server", "X-Powered-By", "X-Frame-Options",
                       "Content-Security-Policy", "X-AspNet-Version"]
        headers = {}
        for h in interesting:
            if h in resp.headers:
                headers[h] = resp.headers[h]
        return headers, resp.status_code
    except Exception:
        return {}, None


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 recon_enum.py <target-ip>")
        sys.exit(1)

    target = sys.argv[1]

    print("=" * 55)
    print("  Active Recon Enumerator - Day 023")
    print("  100 Days of Cybersecurity")
    print("=" * 55)
    print(f"  Target : {target}")
    print(f"  Time   : {datetime.now().strftime('%H:%M:%S')}")
    print(f"  ⚠  Only use on systems you own / have permission\n")

    open_ports = []

    print("[*] Scanning common ports...")
    for port, service in COMMON_PORTS.items():
        if check_port(target, port):
            open_ports.append((port, service))
            print(f"  [+] {port:5}/tcp  OPEN  {service}")

    if not open_ports:
        print("  No common ports open")
        return

    print(f"\n[*] Banner grabbing on {len(open_ports)} open ports...")
    for port, service in open_ports:
        print(f"\n  ── {service} (:{port}) ──")

        # HTTP header grab for web ports
        if port in [80, 443, 8080, 8443]:
            headers, status = grab_http_headers(target, port)
            if status:
                print(f"    HTTP Status : {status}")
            for k, v in headers.items():
                print(f"    {k} : {v}")
            if not headers:
                print("    No interesting headers found")
        else:
            banner = grab_banner(target, port)
            if banner:
                first_line = banner.split("\n")[0]
                print(f"    Banner: {first_line}")
            else:
                print("    No banner received")

    print("\n" + "=" * 55)
    print(f"  Found {len(open_ports)} open ports.")
    print("  Next steps:")
    print("  → Search versions against CVE databases")
    print("  → Check for default credentials")
    print("  → Run service-specific NSE scripts")
    print("=" * 55)


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    main()
```

**To run against your lab VM:**
```bash
pip install requests
python3 recon_enum.py 192.168.56.101
```

---

## 🔑 Key Takeaways

- Active recon touches the target - logs may be generated, IDS may trigger
- Banners volunteer software versions - versions map to CVEs
- Anonymous FTP and null SMB sessions are still found in the wild regularly
- HTTP headers reveal server software, frameworks, and missing security controls
- Enumeration order: ports → banners → service-specific scripts → default credentials
- Always save output - you'll refer back to it during exploitation

---

## 📚 Resources to Go Deeper
- [SecLists - wordlists for enumeration](https://github.com/danielmiessler/SecLists)
- [Gobuster](https://github.com/OJ/gobuster)
- [Enum4linux](https://github.com/CiscoCXSecurity/enum4linux)

---

## [⬅️ Day 022](../day022/) | [➡️ Day 024](../day024/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*