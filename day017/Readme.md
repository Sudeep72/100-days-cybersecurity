# Day 017 - OWASP Top 10: The Web Hacker's Bible

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

If you work in web security - offensive or defensive - the OWASP Top 10 is the document you live by.

OWASP (Open Worldwide Application Security Project) publishes a list of the 10 most critical web application security risks, updated every few years based on real-world data from hundreds of organisations.

It's not a complete list of every web vulnerability. It's the 10 that cause the most damage, most often, in production systems right now.

Every item on this list has caused major breaches. Every item is preventable.

---

## 📋 OWASP Top 10 (2021 Edition)

```
A01 - Broken Access Control
A02 - Cryptographic Failures
A03 - Injection
A04 - Insecure Design
A05 - Security Misconfiguration
A06 - Vulnerable and Outdated Components
A07 - Identification and Authentication Failures
A08 - Software and Data Integrity Failures
A09 - Security Logging and Monitoring Failures
A10 - Server-Side Request Forgery (SSRF)
```

---

## A01 - Broken Access Control 🏆 (#1 Most Critical)

Users accessing data or performing actions they shouldn't be able to.

We covered this in detail on Day 11 - IDOR, privilege escalation, missing authorisation checks.

**Example:**
```
Normal user visits: /admin/users
Server doesn't check if user is admin → full admin panel exposed
```

**Prevention:** Enforce access control server-side. Deny by default. Log access failures.

---

## A02 - Cryptographic Failures

Sensitive data exposed because of weak or missing encryption.

Previously called "Sensitive Data Exposure" - the name change reflects that the root cause is always a cryptography failure.

**Examples:**
- Passwords stored as MD5 or plain text (Day 9 - LinkedIn breach)
- Credit card data transmitted over HTTP
- Weak TLS configuration (TLS 1.0, RC4 cipher)
- Hardcoded encryption keys in source code

**Prevention:** Use TLS everywhere. Hash passwords with bcrypt/Argon2. Never store what you don't need.

---

## A03 - Injection

Untrusted data sent to an interpreter as part of a command or query.

**Types:**
- SQL Injection (Day 26 - deep dive)
- Command Injection (Day 34)
- LDAP Injection
- XPath Injection
- Template Injection

**Example:**
```sql
Input:  ' OR '1'='1
Query:  SELECT * FROM users WHERE username='' OR '1'='1'
Result: Returns all users - authentication bypassed
```

**Prevention:** Parameterised queries. Input validation. WAF.

---

## A04 - Insecure Design

Security flaws baked into the design before a single line of code is written.

This is different from implementation bugs - the design itself is wrong.

**Examples:**
- "Forgot password" that emails plaintext passwords (the system stores them plaintext by design)
- Security questions as the only account recovery option
- No rate limiting designed into authentication flows (enables brute force)
- Business logic that allows a negative quantity in a shopping cart to get a refund

**Prevention:** Threat modelling. Security requirements from day one. Secure design patterns.

---

## A05 - Security Misconfiguration

Default settings, incomplete configuration, open cloud storage, verbose error messages.

The most common finding in real penetration tests.

**Examples:**
- Default admin credentials never changed (admin/admin, admin/password)
- S3 bucket left publicly readable (Capital One breach, Day 68)
- Detailed error messages exposing stack traces and database info
- Unnecessary services and ports left open
- Directory listing enabled on web server

**Prevention:** Hardening guides. Automated configuration scanning. Remove defaults.

---

## A06 - Vulnerable and Outdated Components

Using libraries, frameworks, or components with known vulnerabilities.

**Examples:**
- Log4Shell (2021) - critical RCE in Log4j, used in millions of Java applications
- Heartbleed - vulnerability in OpenSSL affected 17% of all HTTPS servers
- Equifax breach (2017) - attackers exploited an unpatched Apache Struts vulnerability, exposed 147 million records

**Prevention:** Software composition analysis (SCA). Patch management. Subscribe to security advisories.

---

## A07 - Identification and Authentication Failures

Weaknesses in authentication that allow attackers to impersonate users.

**Examples:**
- No brute force protection (unlimited login attempts)
- Weak password requirements
- Session tokens that don't expire
- Credentials transmitted over HTTP
- No MFA on sensitive accounts

**Prevention:** MFA. Strong password policy. Secure session management. Rate limiting on login.

---

## A08 - Software and Data Integrity Failures

Code and infrastructure that doesn't verify integrity of updates and critical data.

**Examples:**
- Insecure deserialisation - attacker manipulates serialised objects to execute code
- CI/CD pipeline with no code signing - malicious commits get auto-deployed
- Auto-update mechanisms that don't verify signatures

**Real example:** SolarWinds attack (2020) - malicious code injected into a legitimate software update, delivered to 18,000 organisations including US government agencies.

**Prevention:** Code signing. Verify update integrity. Secure CI/CD pipelines.

---

## A09 - Security Logging and Monitoring Failures

Attackers rely on the fact that most organisations won't detect them in time.

The average time to identify a breach is **207 days**. The average time to contain it is **73 more days**.

280 days of undetected access.

**Examples:**
- Login failures not logged
- No alerting on privilege escalation attempts
- Logs stored on the compromised system (attacker deletes them)
- No SIEM correlation (just raw logs nobody reads)

**Prevention:** Centralised logging. SIEM alerts. Incident response plan. Test your detection.

(This is what Phase 3 of this challenge - Days 46–65 - is all about.)

---

## A10 - Server-Side Request Forgery (SSRF)

Application fetches a remote resource without validating the user-supplied URL.

Attacker tricks the server into making requests to internal systems the attacker can't reach directly.

**Example:**
```
Normal:  POST /fetch?url=https://external-site.com/image.jpg

Attack:  POST /fetch?url=http://169.254.169.254/latest/meta-data/
         ↳ This is the AWS instance metadata endpoint
         ↳ Returns temporary AWS credentials
         ↳ Attacker now has cloud access
```

This is exactly how the Capital One breach worked in 2019 (Day 68).

**Prevention:** Allowlist valid URLs. Block internal IP ranges. Disable unnecessary URL fetch features.

---

## 🗺️ Quick Reference Card

| # | Vulnerability | Simplest Example | Core Fix |
|---|--------------|-----------------|---------|
| A01 | Broken Access Control | User accesses /admin without being admin | Server-side auth checks |
| A02 | Cryptographic Failures | Password stored as MD5 | bcrypt + TLS everywhere |
| A03 | Injection | SQL injection in login form | Parameterised queries |
| A04 | Insecure Design | No rate limiting on login | Threat model upfront |
| A05 | Misconfiguration | Default credentials never changed | Hardening + scanning |
| A06 | Outdated Components | Unpatched Log4j in prod | Patch management |
| A07 | Auth Failures | No brute force protection | MFA + rate limiting |
| A08 | Integrity Failures | Unsigned software updates | Code signing |
| A09 | Logging Failures | No alerts on failed logins | SIEM + centralised logs |
| A10 | SSRF | Server fetches internal metadata | URL allowlisting |

---

## 🔑 Key Takeaways

- Broken Access Control is #1 - and it's not because it's technically complex. It's because it's consistently overlooked.
- Most OWASP Top 10 vulnerabilities are preventable with basic security practices
- A06 (outdated components) causes some of the largest breaches - Equifax, Log4Shell
- A09 (logging failures) is what lets attackers stay hidden for 207 days on average
- This list is the foundation of web app pen testing - every item gets a deep dive in Phase 2

---

## 📚 Resources to Go Deeper
- [OWASP Top 10 Official](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy (free)](https://portswigger.net/web-security) - hands-on labs for every vulnerability
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/) - deliberately vulnerable app for practice

---

## [⬅️ Day 016](../day016/) | [➡️ Day 018](../day018/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*