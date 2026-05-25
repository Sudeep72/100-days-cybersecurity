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