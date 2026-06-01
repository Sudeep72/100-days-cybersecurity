# Burp Suite Workflow Reference

> Part of the [100 Days of Cybersecurity](../README.md) challenge - Day 029

A practical reference for web application penetration testing with Burp Suite Community Edition. Covers every tool, every shortcut, and a structured testing workflow.

---

## ⚙️ Initial Setup

### Browser Proxy Configuration

**Firefox (recommended):**
```
Settings → General → Network Settings → Manual proxy configuration
HTTP Proxy:  127.0.0.1    Port: 8080
HTTPS Proxy: 127.0.0.1    Port: 8080
☑ Also use this proxy for HTTPS
```

**Chrome (via FoxyProxy extension):**
```
Install FoxyProxy Standard extension
Add proxy: 127.0.0.1:8080
Enable for target domains only
```

### Install Burp CA Certificate (for HTTPS)

```
1. With Burp running and proxy configured:
   Navigate to: http://burpsuite  (or http://127.0.0.1:8080)

2. Click "CA Certificate" → download cacert.der

3. Firefox:
   Settings → Privacy & Security → Certificates → View Certificates
   Authorities tab → Import → select cacert.der
   ☑ Trust this CA to identify websites
   ☑ Trust this CA to identify email users

4. Chrome:
   Settings → Privacy → Security → Manage Certificates
   Authorities → Import → cacert.der
```

### Burp Startup Checklist

```
□ Proxy listener active on 127.0.0.1:8080
  Proxy → Options → Proxy Listeners → 8080 running

□ CA certificate installed in browser

□ Target scope defined
  Target → Scope → Include → add target domain

□ Out-of-scope requests dropped
  Proxy → Options → Miscellaneous
  ☑ Drop all out-of-scope requests

□ Intercept OFF for passive browsing
  Proxy → Intercept → Intercept is off
```

---

## 🔀 Proxy

### Intercept Mode

```
Intercept ON  → every request pauses and waits for your action
Intercept OFF → requests pass through but are still logged

Keyboard: Ctrl+T → toggle intercept

When a request is paused:
  Forward  → send unchanged
  Drop     → block request entirely
  Action   → opens context menu
  Open in browser → open URL in Burp's embedded browser
```

### Context Menu - Right-click any request

```
Send to Repeater         → manual testing (Ctrl+R)
Send to Intruder         → fuzzing/brute force (Ctrl+I)
Send to Sequencer        → token randomness analysis
Send to Comparer         → diff two requests
Send to Decoder          → encode/decode values
Copy URL                 → copy full request URL
Copy as curl command     → reproduce request in terminal
Show response in browser → view response without proxy
```

### HTTP History - Key Columns

```
# → request number
Method → GET/POST/PUT/DELETE
URL → full request path
Params → ✓ if request has parameters (high priority targets)
Edited → ✓ if you've modified this request
Status → HTTP response code
Length → response size (different = interesting)
MIME type → json/html/script/image
Title → page title
Comment → your notes
```

### HTTP History Filters

```
Filter bar → click to open filter settings

Show only:
  ☑ In-scope items only (after setting scope)
  ☑ Show only parameterised requests
  ☑ Status codes: 200, 301, 302, 403, 500

Search: Ctrl+F → search across all history
```

---

## 🔁 Repeater

The most-used tool. Modify and resend requests manually.

### Workflow

```
1. Find interesting request in Proxy History
2. Right-click → Send to Repeater (Ctrl+R)
3. Modify the request
4. Click Send (Ctrl+Enter)
5. Analyse response
6. Repeat
```

### What to Test in Repeater

**SQL Injection:**
```
Original:  id=1
Test:      id=1'          → SQL error?
           id=1 OR 1=1--  → different data returned?
           id=1 UNION SELECT null,null-- → column count?
```

**XSS:**
```
Original:  search=hello
Test:      search=<script>alert(1)</script>
           search=<img src=x onerror=alert(1)>
           search="><svg onload=alert(1)>
→ Does payload appear unescaped in response?
```

**IDOR:**
```
Original:  GET /api/users/1337
Test:      GET /api/users/1
           GET /api/users/1338
→ Does it return another user's data?
```

**Auth bypass:**
```
Original:  Authorization: Bearer eyJ...
Test:      Remove header entirely → 401 or 200?
           Change user ID in JWT payload
           Add ?admin=true parameter
```

**CSRF token removal:**
```
Original:  POST /transfer csrf_token=abc123&amount=100
Test:      POST /transfer amount=100  (remove token)
→ Does it still succeed?
```

**HTTP method switching:**
```
Original:  GET /api/admin → 403
Test:      POST /api/admin → 200?
           PUT /api/admin  → 200?
           HEAD /api/admin → 200?
```

### Repeater Tips

```
Keyboard shortcuts:
  Ctrl+Enter    → send request
  Ctrl+Z        → undo changes
  Ctrl+Shift+Z  → redo

Right-click request → Change request method
→ Burp auto-converts GET ↔ POST

Inspector panel (right side):
→ Parsed view of headers, params, cookies
→ Click values to edit inline

Response tabs:
  Pretty   → formatted/highlighted
  Raw      → exact bytes
  Hex      → hex view
  Render   → rendered HTML (visual)
```

---

## 🎯 Intruder

Automate requests with varying payloads.

### Attack Types

```
Sniper
→ One payload list, one position at a time
→ Best for: single parameter fuzzing, password brute force
→ Requests = len(payloads)

Battering Ram
→ Same payload inserted into all positions simultaneously
→ Best for: same value needed in multiple fields
→ Requests = len(payloads)

Pitchfork
→ Multiple payload lists, one per position, iterated in parallel
→ Best for: username + password pairs (same index)
→ Requests = len(shortest list)

Cluster Bomb
→ Multiple payload lists, every combination
→ Best for: small lists, finding valid credential pairs
→ Requests = product of all list lengths
   ⚠ 100 users × 1000 passwords = 100,000 requests
```

### Positions Tab

```
Clear §   → remove all markers
Add §     → mark selection as payload position
Auto §    → Burp marks all parameters automatically

Payload marker syntax:
  username=§admin§&password=§password§
              ↑ position 1       ↑ position 2
```

### Payloads Tab

```
Payload type options:
  Simple list    → load a wordlist file
  Runtime file   → stream from file (large lists)
  Numbers        → sequential/random numbers (good for IDOR)
  Dates          → date formats
  Character fuzz → special characters for injection testing
  Null payloads  → repeat same request N times

Payload processing:
  Add prefix     → admin_ before each word
  Add suffix     → @company.com after each word
  Match/replace  → transform payload values
  URL encode     → encode special characters
  Base64 encode  → encode payload
```

### Common Intruder Attacks

**Directory brute force:**
```
Request: GET /§FUZZ§ HTTP/1.1
Payload: /usr/share/wordlists/dirb/common.txt
Attack:  Sniper
Filter:  Status ≠ 404
```

**Login brute force:**
```
Request: POST /login username=admin&password=§FUZZ§
Payload: /usr/share/wordlists/rockyou.txt
Attack:  Sniper
Filter:  Length differs from failed login response
         OR Status = 302 (redirect on success)
```

**Credential stuffing:**
```
Request: POST /login username=§USER§&password=§PASS§
Payloads:
  Position 1: usernames.txt
  Position 2: passwords.txt
Attack:  Pitchfork (keeps user/pass pairs together)
Filter:  Status = 200 or 302
```

**IDOR enumeration:**
```
Request: GET /api/users/§1§
Payload: Numbers - from 1 to 1000, step 1
Attack:  Sniper
Filter:  Status = 200, Length > baseline
```

**Password spraying:**
```
Request: POST /login username=§USER§&password=Winter2024!
Payload: company_usernames.txt
Attack:  Sniper
Filter:  Status ≠ 401
```

### Results Analysis

```
Columns to sort by:
  Status  → 200/302 = success, 404 = not found, 403 = forbidden
  Length  → different length from baseline = interesting
  Time    → longer response time = blind SQLi / SSRF candidate

Right-click result → Show response
→ See full server response for that payload
```

---

## 🔍 Target → Site Map

```
After browsing with proxy active:
Target → Site Map → shows full application structure

Useful views:
  By host      → all endpoints per domain
  By content   → grouped by file type
  Parameterised → only endpoints with parameters (high value targets)

Right-click endpoint → Scan / Send to Repeater / Spider
```

---

## 🔬 Decoder

Quickly encode and decode values without leaving Burp.

```
Paste value → select encoding → decoded/encoded appears

Supported:
  URL encoding     → %20, %27, %3C
  HTML entities    → &lt; &gt; &amp;
  Base64           → encode/decode
  ASCII hex        → hex representation
  Gzip             → compress/decompress
  Zlib             → compress/decompress

Smart decode → Burp detects and decodes automatically

Useful for:
  → Decoding JWT tokens (base64 each section)
  → Decoding base64 IDs before testing IDOR
  → URL-encoding payloads that get filtered
  → Decoding cookie values
```

---

## 🔄 Comparer

Highlight differences between two requests or responses.

```
Use cases:
  → Compare response for valid vs invalid credentials
    (length/content difference reveals enumeration)
  
  → Compare response with/without CSRF token
    (if identical → CSRF protection missing)
  
  → Compare response for different user IDs
    (if different → IDOR confirmed)

How to use:
  Right-click any request/response → Send to Comparer
  Comparer tab → select two items → Compare
  Words view → highlights word-level differences
  Bytes view → highlights byte-level differences
```

---

## ⚡ Sequencer

Analyse randomness of tokens - session cookies, CSRF tokens, password reset links.

```
Capture → Session token handling → Start live capture
→ Burp collects 100+ token samples
→ Analyses entropy and randomness
→ Low entropy = predictable tokens = session hijacking possible
```

---

## 🧩 Extensions (BApp Store)

```
Proxy → Options → BApp Store (or Extender → BApp Store)

Must-have free extensions:

Autorize
→ Tests every request as a lower-privileged user automatically
→ Catches IDOR and broken access control without manual testing

Logger++
→ Better request logging with grep/filter
→ Saves history to CSV for reporting

JSON Beautifier
→ Auto-formats JSON request/response bodies

Hackvertor
→ Complex encoding transformations
→ Useful for WAF bypass

Param Miner
→ Discovers hidden parameters via brute force
→ Finds parameters that affect application behaviour

Software Vulnerability Scanner
→ Passive checks for common vulnerabilities
→ No active scanning (Community compatible)
```

---

## 📋 Structured Testing Workflow

```
Phase 1 - Passive Mapping
□ Set scope (Target → Scope)
□ Intercept OFF
□ Browse entire application - every page, every feature
□ Review HTTP History - understand all endpoints

Phase 2 - Attack Surface Identification
□ Filter history: parameterised requests only
□ Note all input points: GET params, POST body, cookies, headers, JSON
□ Identify authentication mechanisms
□ Note file upload points
□ Find admin/sensitive functionality

Phase 3 - Manual Testing (Repeater)
□ Test each parameter for SQLi (add ')
□ Test each output point for XSS
□ Test numeric IDs for IDOR
□ Test CSRF token removal
□ Test HTTP method switching
□ Test auth on all admin endpoints

Phase 4 - Automated Testing (Intruder)
□ Fuzz promising injection points
□ Brute force login if rate limiting absent
□ Enumerate valid IDs if IDOR suspected
□ Directory brute force for hidden endpoints

Phase 5 - Document
□ Screenshot every finding in Repeater
□ Note exact request/response for report
□ CVSS score each finding
□ Write reproduction steps
```

---

## ⌨️ Essential Keyboard Shortcuts

```
Ctrl+R          → Send to Repeater
Ctrl+I          → Send to Intruder
Ctrl+Enter      → Send request (Repeater)
Ctrl+T          → Toggle intercept
Ctrl+F          → Search in HTTP History
Ctrl+Z          → Undo (Repeater)
Ctrl+Shift+P    → Send to Proxy
Ctrl+Shift+U    → URL encode selection
Ctrl+Shift+H    › HTML encode selection
```

---

## 💾 Saving Work

```
Save project: Burp → Project → Save project file (.burp)
Saves: HTTP history, Repeater tabs, Intruder configs, notes

Export findings: Target → Site Map → right-click → Save selected items
Export as: XML, HTML, CSV

Save Intruder results: right-click results → Save results → CSV
```

---

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*