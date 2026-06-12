# Day 040 - Writing a Professional Penetration Test Report

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

The report is the product.

Everything else - the scanning, the exploitation, the post-exploitation - is research. The report is what the client pays for. It's how technical findings become remediated vulnerabilities. It's how a penetration test creates actual security improvement.

A great pen test with a poor report wastes everyone's time.
An average pen test with a great report drives real change.

Today: the structure, the language, and the mindset of professional pen test reporting.

---

## 📋 Report Structure

```
1. Cover Page
2. Table of Contents
3. Executive Summary          ← non-technical, for management
4. Scope and Methodology
5. Risk Summary / Findings Overview
6. Detailed Findings          ← technical, for security team
7. Appendices
```

---

## 📊 Section 1 - Executive Summary

Written for the CISO, the board, and non-technical stakeholders.

No jargon. No commands. Business language only.

**What it covers:**
```
- What was tested and when
- Overall security posture (one honest sentence)
- Number of findings by severity
- The two or three most critical issues in plain English
- Business impact of those issues
- Recommended priority actions
```

**Example paragraph:**
```
During the five-day assessment, the testing team identified 14 
vulnerabilities across the in-scope web applications and internal 
network segment. Of these, 3 were rated Critical - meaning an 
attacker with basic skills could gain complete control of internal 
systems and access customer data. The most significant finding was 
an unauthenticated remote code execution vulnerability on the 
customer portal, which could allow an external attacker to access 
the production database containing 1.2 million customer records 
without requiring valid credentials.
```

Note: no CVE numbers. No exploit names. No commands.

Business impact only.

---

## ⚠️ Section 2 - Risk Summary

A table giving management a quick overview of all findings.

| # | Finding | Severity | Affected System |
|---|---------|----------|-----------------|
| 1 | Unauthenticated RCE on customer portal | Critical | portal.company.com |
| 2 | SQL Injection in search functionality | High | portal.company.com |
| 3 | Default credentials on network switch | High | 192.168.1.1 |
| 4 | Unpatched Apache 2.4.18 | Medium | 192.168.1.50 |
| 5 | Missing security headers | Low | All web properties |

Severity follows CVSS scoring or the agreed framework.

---

## 🔍 Section 3 - Detailed Findings

One page per finding. Always the same structure.

### Finding Template

```markdown
## Finding 001: SQL Injection in Login Form

**Severity:** High (CVSS 8.1)
**Affected URL:** https://portal.company.com/login
**CWE:** CWE-89 - Improper Neutralisation of SQL Commands

### Description
The login form at /login is vulnerable to SQL injection via the 
username parameter. User-supplied input is concatenated directly 
into a SQL query without parameterisation, allowing an attacker 
to manipulate the database query logic.

### Steps to Reproduce
1. Navigate to https://portal.company.com/login
2. Enter the following payload in the username field:
   admin'--
3. Enter any value in the password field
4. Click Login
5. Observe successful authentication without valid credentials

### Evidence
[Screenshot: successful login with SQLi payload]
[Screenshot: server response showing admin dashboard]

Request:
POST /login HTTP/1.1
Host: portal.company.com
Content-Type: application/x-www-form-urlencoded

username=admin'--&password=anything

Response:
HTTP/1.1 302 Found
Location: /dashboard/admin

### Impact
An attacker who exploits this vulnerability can:
- Bypass authentication and access any account including admin
- Extract the entire user database including email addresses and 
  password hashes
- Potentially modify or delete database records

### Recommendation
Implement parameterised queries (prepared statements) for all 
database interactions. Example fix:

// Vulnerable
$query = "SELECT * FROM users WHERE username='" . $username . "'";

// Secure
$stmt = $pdo->prepare("SELECT * FROM users WHERE username=?");
$stmt->execute([$username]);

Additionally, implement a Web Application Firewall (WAF) as a 
defence-in-depth measure.

### References
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- PortSwigger SQLi: https://portswigger.net/web-security/sql-injection
```

---

## 🎯 Severity Ratings

Use CVSS 3.1 or agree a custom framework with the client.

```
Critical (9.0–10.0)
→ Immediate action required
→ Unauthenticated RCE, direct access to sensitive data
→ Example: vsftpd backdoor (CVSS 10.0)

High (7.0–8.9)
→ Address within 1 week
→ Authenticated RCE, significant data exposure, bypass of key controls
→ Example: SQL injection with data extraction

Medium (4.0–6.9)
→ Address within 1 month
→ Limited impact, requires preconditions, information disclosure
→ Example: Reflected XSS, outdated software with no public exploit

Low (0.1–3.9)
→ Address at next maintenance window
→ Minor information disclosure, best practice deviation
→ Example: Missing security headers, verbose error messages

Informational
→ No direct security impact - observation or suggestion
→ Example: Weak TLS cipher suite (no practical attack exists)
```

---

## ✍️ Writing Style

**Be specific. Be factual. Avoid vague language.**

```
Vague:   "The system had some security issues."
Better:  "The login form at /login is vulnerable to SQL injection."

Vague:   "An attacker could potentially access data."
Better:  "An unauthenticated attacker can extract all 47,000 user 
         records from the production database in under 60 seconds 
         using automated tooling."

Vague:   "Password security could be improved."
Better:  "The MD5 hashes extracted from the database were cracked 
         within 4 minutes using a standard dictionary attack. 
         18 of 20 sample hashes yielded plaintext passwords."
```

**Always lead with impact.**

The defender reading this needs to understand why they should care before they understand how it works.

---

## 💻 The Code - Report Template Generator

```python
"""
Day 040 - Pen Test Report Template Generator
100 Days of Cybersecurity by Sudeep Ravichandran

Generates a structured markdown pen test report template.

Usage: python3 pentest_report_template.py
"""

from datetime import datetime


def generate_report(
    client="[Client Name]",
    tester="[Tester Name]",
    start_date="[Start Date]",
    end_date="[End Date]",
    scope="[In-Scope Systems]"
):
    today = datetime.now().strftime("%Y-%m-%d")

    return f"""# Penetration Test Report

**Client:**     {client}
**Tester:**     {tester}
**Test Period:** {start_date} - {end_date}
**Report Date:** {today}
**Classification:** CONFIDENTIAL

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scope and Methodology](#scope-and-methodology)
3. [Risk Summary](#risk-summary)
4. [Detailed Findings](#detailed-findings)
5. [Appendices](#appendices)

---

## Executive Summary

During the assessment period ({start_date} to {end_date}), [Tester Name] 
conducted a penetration test of [describe systems]. The assessment identified 
**[X]** vulnerabilities: **[X] Critical**, **[X] High**, **[X] Medium**, 
**[X] Low**, and **[X] Informational**.

The most significant finding was [brief plain-English description of top 
finding and its business impact].

Immediate remediation is recommended for all Critical and High findings.

---

## Scope and Methodology

### Scope

**In-scope systems:**
{scope}

**Out-of-scope:**
- [List out-of-scope items]

**Test type:** [Black box / Grey box / White box]
**Test period:** {start_date} to {end_date}

### Methodology

Testing followed the Penetration Testing Execution Standard (PTES) and 
OWASP Testing Guide. Phases:

1. Reconnaissance - passive and active information gathering
2. Vulnerability Analysis - automated and manual testing
3. Exploitation - controlled exploitation of identified vulnerabilities
4. Post-Exploitation - demonstrating real-world impact
5. Reporting - documenting findings with remediation guidance

---

## Risk Summary

| # | Finding | Severity | System |
|---|---------|----------|--------|
| 001 | [Finding Title] | Critical | [System] |
| 002 | [Finding Title] | High | [System] |
| 003 | [Finding Title] | Medium | [System] |
| 004 | [Finding Title] | Low | [System] |

---

## Detailed Findings

---

### Finding 001: [Title]

**Severity:** Critical
**CVSS Score:** [Score]
**Affected System:** [URL or IP]
**CWE:** [CWE-XXX - Name]

#### Description
[Clear explanation of the vulnerability. What is it? Why does it exist?]

#### Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]
4. [Observe result]

#### Evidence
[Screenshots, request/response pairs, tool output]

#### Impact
[What can an attacker do? What data is at risk? What systems are affected?]

#### Recommendation
[Specific, actionable fix. Include code examples where applicable.]

#### References
- [Link 1]
- [Link 2]

---

### Finding 002: [Title]

[Repeat structure for each finding]

---

## Appendices

### Appendix A - Tools Used

| Tool | Purpose |
|------|---------|
| Nmap | Port scanning and service enumeration |
| Burp Suite | Web application testing |
| Metasploit | Exploitation framework |
| [Others] | [Purpose] |

### Appendix B - Timeline

| Date | Activity |
|------|---------|
| {start_date} | Engagement start, initial reconnaissance |
| [Date] | [Activity] |
| {end_date} | Engagement end, report writing |

### Appendix C - Vulnerability Severity Definitions

| Severity | CVSS Range | Definition |
|----------|-----------|------------|
| Critical | 9.0–10.0 | Immediate exploitation possible with severe impact |
| High | 7.0–8.9 | Significant impact, likely to be exploited |
| Medium | 4.0–6.9 | Limited impact or requires preconditions |
| Low | 0.1–3.9 | Minimal impact, best practice deviation |
| Info | 0.0 | Observation with no direct security impact |

---

*This report is confidential and intended solely for {client}.*
"""


if __name__ == "__main__":
    report = generate_report(
        client="Acme Corp",
        tester="Sudeep Ravichandran",
        start_date="2025-01-06",
        end_date="2025-01-10",
        scope="portal.acmecorp.com, 192.168.1.0/24"
    )

    filename = f"pentest_report_{datetime.now().strftime('%Y%m%d')}.md"
    with open(filename, "w") as f:
        f.write(report)

    print(f"Report template generated: {filename}")
    print("Fill in the [bracketed] sections with your findings.")
```

**To run:**
```bash
python3 pentest_report_template.py
# Generates: pentest_report_YYYYMMDD.md
```

---

## 🔑 Key Takeaways

- The report is the product - it's why clients hire pen testers
- Executive summary: no jargon, business impact only, written for non-technical readers
- Each finding needs: description, reproduction steps, evidence, impact, and recommendation
- Lead every finding with impact - why should the reader care?
- Be specific: actual numbers, actual URLs, actual commands - not vague generalisations
- Severity ratings should be consistent and justified - not subjective

---

## 📚 Resources
- [PTES Technical Guidelines](http://www.pentest-standard.org/index.php/Reporting)
- [HackTricks - Report Writing](https://book.hacktricks.xyz/)
- [Sample Pentest Reports - GitHub](https://github.com/juliocesarfort/public-pentesting-reports)

---

## [⬅️ Day 039](../day039/) | [➡️ Day 041](../day041/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*