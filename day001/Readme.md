# Day 001 - The CIA Triad: The Foundation of Everything in Cybersecurity

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

Before tools, before hacking, before anything - every security professional thinks through one lens:

**The CIA Triad.**

It stands for **Confidentiality, Integrity, and Availability**. Every attack ever launched violates at least one of these. Every defense ever built protects at least one of them.

---

## 🔒 Confidentiality
> *"Only the right people can see this."*

Information is accessible only to those authorized to access it.

**How it's protected:**
- Encryption (AES-256 for data at rest, TLS for data in transit)
- Access controls and role-based permissions
- Multi-factor authentication (MFA)

**How it's attacked:**
- Data breaches (unauthorized access to databases)
- Man-in-the-middle attacks (intercepting traffic)
- Phishing (stealing credentials)

---

## 🔐 Integrity
> *"This data hasn't been tampered with."*

Information is accurate and hasn't been modified by unauthorized parties.

**How it's protected:**
- Cryptographic hashing (SHA-256 - even 1 changed bit = completely different hash)
- Digital signatures
- File Integrity Monitoring (FIM)

**How it's attacked:**
- SQL Injection (directly modifying database records)
- Supply chain attacks (poisoning software before it reaches you)
- Man-in-the-middle (altering data in transit)

---

## 🟢 Availability
> *"The system works when I need it."*

Systems and data are accessible to authorized users when they need them.

**How it's protected:**
- Redundancy, load balancing, failover systems
- DDoS protection (Cloudflare, AWS Shield)
- Tested backup and disaster recovery plans

**How it's attacked:**
- Distributed Denial of Service (DDoS) - flood the server until it collapses
- Ransomware - encrypt everything, demand payment to restore access
- Physical attacks (cutting power, destroying hardware)

---

## 🗺️ Real-World Attack Mapping

| Attack | Confidentiality | Integrity | Availability |
|--------|:--------------:|:---------:|:------------:|
| Ransomware | ✅ (data stolen first) | ✅ (data encrypted) | ✅ (primary goal) |
| Data Breach | ✅ | - | - |
| SQL Injection | ✅ | ✅ | - |
| DDoS | - | - | ✅ |
| Phishing | ✅ | - | - |
| Website Defacement | - | ✅ | - |
| Insider Threat | ✅ | ✅ | ✅ |

---

## 💡 The Key Insight

When you read about any attack - past, present, or future - ask yourself:
**Which of the three did it violate? How? What control failed?**

That single habit will make you think like a security professional.

---

## 📚 Resources to Go Deeper
- [NIST SP 800-12: An Introduction to Information Security](https://csrc.nist.gov/publications/detail/sp/800-12/rev-1/final)
- [OWASP Security Principles](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [Professor Messer - CIA Triad (free YouTube)](https://youtu.be/SBcDGb9l6yo?si=knRlL-xLK67TrbrT)

---


## [➡️ Day 002 - How the Internet Actually Works](../day002/)
 
*Part of my [100 Days of Cybersecurity](../README.md) challenge.*