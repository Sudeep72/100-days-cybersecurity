# Day 030 - Authentication Attacks: Brute Force & Credential Stuffing

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Authentication is the front door of every application.

Most applications protect that door with a username and password. Both of those can be attacked - by guessing passwords, by reusing credentials stolen from other breaches, or by exploiting how the authentication mechanism itself is implemented.

Today: the three main credential attacks, how they work, and how to defend against each.

---

## 🔨 Attack 1 - Brute Force

Try every possible password combination until one works.

```
Username: admin
Passwords tried: a, b, c, ... aa, ab, ... password, password1, password123...
```

**Pure brute force** - tries every character combination.
Effective against short passwords. Impractical against long ones.

```
6-char password (lowercase only): 26^6 = 308 million combinations
8-char password (mixed):          94^8 = 6 quadrillion combinations
```

**Dictionary attack** - tries words from a wordlist instead of every combination.
Much faster. Most people use real words.

```bash
# rockyou.txt - 14 million real passwords from 2009 breach
# Most common: 123456, password, 12345678, qwerty, abc123...
wc -l /usr/share/wordlists/rockyou.txt
# 14,344,391
```

### Hydra - Network Login Brute Force

```bash
# SSH brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.101

# Multiple usernames
hydra -L users.txt -P passwords.txt ssh://192.168.56.101

# HTTP POST form login
hydra -l admin -P rockyou.txt 192.168.56.101 \
  http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"

# FTP brute force
hydra -l admin -P rockyou.txt ftp://192.168.56.101

# RDP brute force
hydra -l administrator -P rockyou.txt rdp://192.168.56.101

# Limit threads to avoid lockout
hydra -l admin -P rockyou.txt ssh://192.168.56.101 -t 4 -W 3

# Verbose output
hydra -l admin -P rockyou.txt ssh://192.168.56.101 -V
```

---

## 🔑 Attack 2 - Credential Stuffing

Use leaked username/password pairs from one breach to attack other services.

Works because most people reuse passwords.

```
Step 1: Download leaked credential database
        (HaveIBeenPwned lists 12 billion+ compromised accounts)

Step 2: Take username:password pairs from breach
        john@gmail.com:Football123
        sarah@yahoo.com:Summer2019!

Step 3: Try same credentials on other sites
        Netflix, Spotify, Amazon, banking sites

Step 4: Many logins succeed - people use the same password everywhere
```

**Scale:** Automated tools try millions of credential pairs per hour.

**Real example:** 2020 - 500,000 Zoom credentials stuffed and sold. Users hadn't changed passwords after unrelated breaches.

### Detecting Credential Stuffing

Patterns that distinguish stuffing from normal logins:
```
→ High volume of failed logins across many different accounts
→ Logins from unexpected geographic locations
→ Many accounts attempted from single IP or IP range
→ Login attempts at unusual hours
→ User agents that don't match real browsers
```

---

## 🌊 Attack 3 - Password Spraying

Avoid account lockouts by trying one password against many accounts.

```
Brute force:  try 1000 passwords against admin → account locked after 5 attempts
Spraying:     try "Winter2024!" against 1000 accounts → never triggers lockout
```

```bash
# Common spray passwords to try:
# [Month][Year]!     → January2024!
# [Company][Year]!   → Acme2024!
# [Season][Year]!    → Winter2024!
# Welcome1           → very common default
# Password1          → meets most complexity requirements
# [Company]123       → CompanyName123
```

**Why it works:** Password policies often require complexity but not uniqueness or rotation. Many users pick predictable patterns that meet the policy.

---

## 💻 The Code - Auth Attack Demo

```python
"""
Day 030 - Authentication Attack Demo
100 Days of Cybersecurity by Sudeep Ravichandran

Demonstrates brute force and credential stuffing attacks
alongside defences: rate limiting, account lockout, MFA.

Run: python3 auth_attack_demo.py
Requires: pip install flask
"""

from flask import Flask, request, jsonify, session
import secrets
import time
from collections import defaultdict

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Mock user database
USERS = {
    "admin":  "SuperSecret123!",
    "alice":  "password123",
    "bob":    "letmein",
    "carol":  "Winter2024!",
}

# Track failed attempts
failed_attempts  = defaultdict(int)       # ip → count
lockout_until    = defaultdict(float)     # username → timestamp
request_times    = defaultdict(list)      # ip → [timestamps]

MAX_ATTEMPTS     = 5
LOCKOUT_SECONDS  = 300   # 5 minutes
RATE_LIMIT       = 10    # max requests per minute per IP


def is_rate_limited(ip):
    now = time.time()
    # Keep only attempts in last 60 seconds
    request_times[ip] = [t for t in request_times[ip] if now - t < 60]
    request_times[ip].append(now)
    return len(request_times[ip]) > RATE_LIMIT


def is_locked_out(username):
    if lockout_until[username] > time.time():
        remaining = int(lockout_until[username] - time.time())
        return True, remaining
    return False, 0


# ── Vulnerable - no protections ──────────────────────────────

@app.route("/login/vulnerable", methods=["POST"])
def login_vulnerable():
    """❌ No rate limiting, no lockout, no MFA."""
    data = request.json
    username = data.get("username", "")
    password = data.get("password", "")

    if USERS.get(username) == password:
        return jsonify({"status": "success", "user": username})
    return jsonify({"status": "failed", "message": "Invalid credentials"})


# ── Secure - rate limiting + lockout ─────────────────────────

@app.route("/login/secure", methods=["POST"])
def login_secure():
    """✅ Rate limiting + account lockout + timing-safe comparison."""
    ip = request.remote_addr
    data = request.json
    username = data.get("username", "")
    password = data.get("password", "")

    # ✅ Rate limiting by IP
    if is_rate_limited(ip):
        return jsonify({
            "status": "error",
            "message": "Too many requests - slow down"
        }), 429

    # ✅ Account lockout check
    locked, remaining = is_locked_out(username)
    if locked:
        return jsonify({
            "status": "locked",
            "message": f"Account locked. Try again in {remaining}s"
        }), 423

    # ✅ Timing-safe comparison (prevents timing attacks)
    stored = USERS.get(username, "")
    if stored and secrets.compare_digest(stored, password):
        failed_attempts[username] = 0  # reset on success
        return jsonify({"status": "success", "user": username})

    # ✅ Increment failed attempts
    failed_attempts[username] += 1
    if failed_attempts[username] >= MAX_ATTEMPTS:
        lockout_until[username] = time.time() + LOCKOUT_SECONDS
        return jsonify({
            "status": "locked",
            "message": f"Too many failures. Account locked for {LOCKOUT_SECONDS}s"
        }), 423

    remaining_attempts = MAX_ATTEMPTS - failed_attempts[username]
    return jsonify({
        "status": "failed",
        "message": f"Invalid credentials. {remaining_attempts} attempts remaining"
    })


@app.route("/status")
def status():
    """Show current lockout and attempt status."""
    return jsonify({
        "failed_attempts": dict(failed_attempts),
        "locked_accounts": {
            u: f"locked for {int(t - time.time())}s"
            for u, t in lockout_until.items()
            if t > time.time()
        }
    })


if __name__ == "__main__":
    print("=" * 55)
    print("  Auth Attack Demo - Day 030")
    print("  100 Days of Cybersecurity")
    print("=" * 55)
    print("\nVulnerable: POST /login/vulnerable")
    print("Secure:     POST /login/secure")
    print("Status:     GET  /status")
    print("\nTest brute force on vulnerable:")
    print('  for p in 123456 password letmein password123; do')
    print('    curl -s -X POST http://127.0.0.1:5000/login/vulnerable \\')
    print('    -H "Content-Type: application/json" \\')
    print('    -d \'{"username":"alice","password":"\'$p\'"}\'; echo')
    print('  done')
    print("\nServer: http://127.0.0.1:5000\n")
    app.run(debug=False)
```

**To run:**
```bash
pip install flask
python3 auth_attack_demo.py
```

---

## 🛡️ Defences

| Defence | What It Stops |
|---------|--------------|
| Account lockout | Brute force - locks after N failures |
| Rate limiting | All automated attacks - limits attempts per IP/minute |
| MFA | Credential stuffing - stolen password alone isn't enough |
| CAPTCHA | Automated attacks - requires human interaction |
| Password breach check | Stuffing - reject passwords found in breach databases |
| Anomaly detection | Stuffing - flag logins from new locations/devices |
| Timing-safe comparison | Timing attacks - response time doesn't leak info |

**HaveIBeenPwned API** - check if a password appears in known breaches:
```python
import hashlib, requests

def is_pwned(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    return suffix in resp.text
```

---

## 🔑 Key Takeaways

- Brute force + dictionary attacks are automated - weak passwords fall in seconds
- 14 million real passwords are in rockyou.txt - if yours is there, it's compromised
- Credential stuffing exploits password reuse - one breach compromises many accounts
- Password spraying avoids lockouts by attacking breadth rather than depth
- Rate limiting + account lockout + MFA defeats all three attack types
- `secrets.compare_digest()` prevents timing attacks - always use it for credential checks

---

## 📚 Resources
- [HaveIBeenPwned](https://haveibeenpwned.com/) - check breach exposure
- [Hydra documentation](https://github.com/vanhauser-thc/thc-hydra)
- [TryHackMe - Authentication Bypass](https://tryhackme.com/room/authenticationbypass)

---

## [⬅️ Day 029](../day029/) | [➡️ Day 031](../day031/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*