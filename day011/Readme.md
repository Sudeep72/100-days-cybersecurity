# Day 011 - Authentication vs Authorization: Not the Same Thing

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

Two words. Constantly confused. Completely different.

Getting them mixed up in a real system leads to security vulnerabilities that hand attackers exactly what they want - access to things they should never reach.

**Authentication** → Who are you?
**Authorization** → What are you allowed to do?

One comes before the other. Both can fail independently.

---

## 🔑 Authentication - Proving Identity

Authentication is the process of verifying that you are who you claim to be.

You prove identity using one or more of three factors:

```
Something you KNOW   → password, PIN, security question
Something you HAVE   → phone (OTP), hardware key (YubiKey), smart card
Something you ARE    → fingerprint, face ID, retina scan
```

### Single Factor Authentication (SFA)
Just a password. Most common. Most easily bypassed.

### Multi-Factor Authentication (MFA)
Two or more factors combined.

```
Password (something you know)
+
OTP from your phone (something you have)
= Much harder to bypass
```

An attacker who steals your password still can't log in without your phone.

### Common Authentication Attacks
| Attack | What Happens |
|--------|-------------|
| Brute force | Try every password combination |
| Credential stuffing | Use leaked username/password pairs from other breaches |
| Phishing | Trick user into entering credentials on a fake site |
| MFA fatigue | Spam MFA push notifications until user approves out of frustration |
| Pass-the-hash | Steal the password hash and use it directly without cracking |
| Session hijacking | Steal the session token after authentication, bypass login entirely |

---

## 🚪 Authorization - What You're Allowed to Do

Authorization happens after authentication. You've proven who you are - now the system decides what you can access.

```
Authenticated user: sudeep@company.com ✓

Authorization checks:
→ Can Sudeep read /reports/q4_financials.pdf?     YES
→ Can Sudeep edit /reports/q4_financials.pdf?     NO
→ Can Sudeep access /admin/user_management?       NO
→ Can Sudeep delete another user's account?       NO
```

### Authorization Models

**Role-Based Access Control (RBAC)**
Users are assigned roles. Roles have permissions.
```
Role: Admin     → full access
Role: Editor    → read + write
Role: Viewer    → read only
Role: Guest     → public content only
```
Simple to manage. Most common model.

**Attribute-Based Access Control (ABAC)**
More granular. Access depends on attributes of the user, resource, and environment.
```
Allow access IF:
  user.department == "Finance"
  AND resource.classification == "Internal"
  AND time.hour BETWEEN 9 AND 17
  AND user.location == "Office"
```

**Principle of Least Privilege (PoLP)**
Every user, service, and system gets only the minimum permissions needed to do their job.

A developer doesn't need access to the production database.
A customer service rep doesn't need access to the billing system.
An intern doesn't need admin rights.

Least privilege is not a feature, it's a mindset.

---

## ⚠️ Common Authorization Vulnerabilities

### 1. Insecure Direct Object Reference (IDOR)
User accesses a resource by manipulating an identifier - and the server doesn't check if they're allowed.

```
Legitimate request:
GET /api/invoices/1042  → returns YOUR invoice

Attacker changes the number:
GET /api/invoices/1041  → returns SOMEONE ELSE'S invoice

If the server doesn't verify ownership → data breach.
```

IDOR is consistently in the OWASP Top 10. Simple to exploit, often overlooked.

---

### 2. Privilege Escalation
A low-privilege user gains higher privileges than they should have.

**Horizontal:** Access another user's data at the same privilege level
**Vertical:** Gain higher privileges (regular user → admin)

```
Horizontal: you access another customer's order history
Vertical:   you change your account role from "user" to "admin"
```

---

### 3. Broken Access Control
The application fails to enforce what users can and can't do.

```
Admin panel at /admin/dashboard
→ Requires login: YES
→ Checks if logged-in user is admin: NO

Any logged-in user who knows the URL gets admin access.
```

Broken Access Control was #1 in the OWASP Top 10 2021.

---

## 🔄 Authentication vs Authorization - Side by Side

| | Authentication | Authorization |
|--|---------------|--------------|
| Question | Who are you? | What can you do? |
| When | First | After authentication |
| Example success | Login succeeds | Can view this page |
| Example failure | Wrong password | 403 Forbidden |
| HTTP status on failure | 401 Unauthorized | 403 Forbidden |
| Common attacks | Brute force, phishing | IDOR, privilege escalation |

Note the HTTP status codes:
- **401** = not authenticated (you haven't proved who you are)
- **403** = not authorized (we know who you are - you just can't do this)

---

## 💡 Real-World Example - Putting It Together

```
Scenario: A hospital web app

Authentication: Nurse logs in with username + password + MFA ✓
Authorization:
  → Can view patient records for their ward?         YES
  → Can view patient records for another ward?       NO
  → Can edit medication orders?                      NO (doctor only)
  → Can access admin billing panel?                  NO
  → Can view their own HR file?                      YES

A misconfigured authorization check on medication orders
→ Nurse accidentally (or maliciously) changes a dose
→ Patient harmed

This isn't a hypothetical. Medical system breaches happen.
Authorization bugs in healthcare have real consequences.
```

---

## 🔑 Key Takeaways

- Authentication = proving identity. Authorization = what you're allowed to do.
- 401 = not authenticated. 403 = not authorized. Know the difference.
- IDOR is one of the most common and easy-to-miss authorization bugs
- Principle of Least Privilege: give the minimum access needed. Always.
- Broken Access Control was the #1 vulnerability in OWASP Top 10 2021

---

## 📚 Resources to Go Deeper
- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [PortSwigger - IDOR Labs (free)](https://portswigger.net/web-security/access-control/idor)
- [TryHackMe - Authentication Bypass Room](https://tryhackme.com/room/authenticationbypass)

---

## [⬅️ Day 010](../day010/) | [➡️ Day 012](../day012/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*