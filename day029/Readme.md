# Day 029 - Burp Suite: Web App Proxy Masterclass

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Every web app vulnerability we've covered - SQLi, XSS, CSRF, IDOR - was found and exploited manually.

Burp Suite is what makes that systematic.

It sits between your browser and the target, intercepts every request and response, and gives you complete control over what gets sent. It's the standard tool for web application penetration testing - used by every professional security researcher.

---

## 🏗️ Core Components

```
Proxy      → intercepts browser ↔ server traffic
Repeater   → modify and resend individual requests
Intruder   → automated fuzzing and brute force
Scanner    → automated vulnerability detection (Pro only)
Decoder    → encode/decode URL, Base64, HTML, hex
Comparer   → diff two requests or responses
Logger     → full request/response history
```

---

## ⚙️ Setup

```
1. Download Burp Suite Community (free):
   https://portswigger.net/burp/communitydownload

2. Configure browser proxy:
   Firefox → Settings → Network → Manual proxy
   HTTP Proxy: 127.0.0.1  Port: 8080

3. Install Burp CA certificate (for HTTPS):
   Browser → http://burpsuite → Download CA Certificate
   Firefox → Settings → Certificates → Import
   Check both "Trust for websites" boxes

4. Verify:
   Go to any HTTP site → Burp Proxy → Intercept tab
   Should see the request appear
```

---

## 🔀 Proxy - Intercepting Requests

The foundation. Every request passes through here.

```
Proxy → Intercept → Intercept is ON

Browse to target → request appears in Burp

Right-click → Send to Repeater    (manual testing)
Right-click → Send to Intruder    (fuzzing)
Right-click → Send to Scanner     (automated check)

Forward  → send original request
Drop     → block the request
Action   → modify before forwarding
```

**HTTP History tab** - even with intercept OFF, all traffic is logged here. Browse the target normally, then go back and review every request.

---

## 🔁 Repeater - Manual Testing

Send a request to Repeater → modify → send → see response. Repeat.

This is where you test every vulnerability manually.

```
SQLi testing:
Original:  username=alice&password=test
Modified:  username=alice'--&password=test
→ Click Send → check response for login success or SQL error

XSS testing:
Original:  search=hello
Modified:  search=<script>alert(1)</script>
→ Check if payload appears in response unescaped

IDOR testing:
Original:  GET /api/orders/1042
Modified:  GET /api/orders/1041
→ Does it return another user's data?

CSRF testing:
Remove the csrf_token parameter entirely
→ Does the server still accept the request?
```

**Keyboard shortcuts:**
```
Ctrl+R      → Send to Repeater
Ctrl+Shift+R → Send to Repeater and switch to it
Ctrl+Enter  → Send request (in Repeater)
```

---

## 🎯 Intruder - Automated Fuzzing

Intruder automates sending many requests with varied payloads.

### Attack Types

```
Sniper      → one payload position, iterate through wordlist
             Best for: single parameter fuzzing, password brute force

Battering Ram → same payload in all positions simultaneously
             Best for: same value in multiple fields

Pitchfork   → multiple positions, parallel wordlists
             Best for: username + password lists together

Cluster Bomb → multiple positions, all combinations
             Best for: small wordlists, finding valid pairs
```

### Brute Force Login with Intruder

```
1. Capture login POST request in Proxy
2. Send to Intruder
3. Positions tab → Clear § → select password value → Add §
4. Payloads tab → Load wordlist (/usr/share/wordlists/rockyou.txt)
5. Start Attack
6. Sort by Length or Status - different response = valid password
```

### Directory Fuzzing

```
1. Send GET / to Intruder
2. Change path to /§test§
3. Mark §test§ as payload position
4. Load wordlist: /usr/share/wordlists/dirb/common.txt
5. Start Attack → look for 200/301 status codes
```

---

## 🔍 Finding Vulnerabilities - Workflow

```bash
# Step 1: Map the application
# Browse every page with Proxy recording
# Check HTTP History - understand every endpoint

# Step 2: Identify injection points
# Every parameter in every request is a potential target
# GET params, POST body, cookies, headers, JSON values

# Step 3: Test each point in Repeater
# SQLi:  add ' and observe errors/behaviour change
# XSS:   add <script>alert(1)</script>
# IDOR:  change numeric IDs
# Auth:  remove/modify tokens

# Step 4: Automate with Intruder
# Fuzz parameters that show promise
# Brute force login endpoints
# Enumerate valid IDs
```

---

## 📝 Burp Workflow Reference

```
Target → Scope → set target scope (avoid testing out-of-scope)
Proxy  → HTTP History → right-click interesting requests → Send to Repeater
Repeater → modify → Ctrl+Enter → check response
Intruder → set positions → load payloads → start attack → analyse results
Decoder → paste encoded value → decode → modify → encode back
Comparer → paste two responses → Compare → see differences highlighted
```

---

## 💡 Pro Tips

```
1. Set scope first
   Target → Scope → Include → add target domain
   Proxy → Options → "Drop all out-of-scope requests"
   Keeps history clean

2. Use Match and Replace
   Proxy → Options → Match and Replace
   Auto-replace values in every request
   Useful for: always adding a header, replacing a token

3. Save your work
   Project → Save → .burp file
   Saves entire session including history, Repeater tabs, notes

4. Burp Collaborator (Pro)
   Out-of-band testing - detects blind SQLi, SSRF, blind XSS
   Community: use interactsh as free alternative

5. Extensions (BApp Store)
   Autorize    → automated IDOR/access control testing
   Logger++    → better request logging
   JSON Beautifier → format JSON responses
   Hackvertor  → encoding transformations
   SQLiPy      → SQLMap integration
```

---

## 🔑 Key Takeaways

- Burp Proxy intercepts everything - you see exactly what the browser sends and receives
- Repeater is where manual vulnerability testing happens - modify, send, observe
- Intruder automates repetitive testing - brute force, fuzzing, enumeration
- HTTP History records all traffic passively - browse first, analyse after
- Set scope before testing - stay legal and keep history clean
- PortSwigger Web Academy uses Burp for all labs - best free practice environment

---

## 📚 Resources
- [Burp Suite Community - free download](https://portswigger.net/burp/communitydownload)
- [PortSwigger Web Academy - all labs use Burp](https://portswigger.net/web-security)
- [TryHackMe - Burp Suite Room](https://tryhackme.com/room/burpsuitebasics)

---

## [⬅️ Day 028](../day028/) | [➡️ Day 030](../day030/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*