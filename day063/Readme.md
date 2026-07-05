# Day 063 - Zero Trust Architecture: The Security Model

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

For 30 years, security was built on the **perimeter model**:

```
"If you're inside the firewall, you're trusted."
```

This created a hard outer shell and soft inside - a candy security model.

Once an attacker got inside, they had free reign.

**Zero Trust** flips this: **Never trust. Always verify.**

Every access. Every user. Every device. Every request. Verified and authenticated.

---

## 🏗️ Perimeter Model (Old)

```
Internet
    ↓
FIREWALL (hard wall)
    ↓
Internal Network (soft inside)
    ├─ Servers access each other freely
    ├─ Users access everything
    ├─ No internal firewalls
    └─ "If you're on our network, you're trusted"

Problem:
├─ One compromise = full network access
├─ Lateral movement is trivial
├─ Insider threats have zero obstacles
└─ Ransomware spreads across entire network
```

---

## 🔐 Zero Trust Model (New)

```
                    Trust Boundaries
                         ↓
┌─────────────────────────────────────────┐
│  User (untrusted) ←→ Device (untrusted) │  ← Verify identity
└─────────────────────────────────────────┘
                ↓
         Identity Verification
    (MFA, device health check)
                ↓
┌─────────────────────────────────────────┐
│    Access Control Proxy (Gatekeeper)    │  ← Verify privilege
│ (BeyondCorp, Conditional Access, etc.)  │
└─────────────────────────────────────────┘
                ↓
         Privilege Verification
    (What are you authorized for?)
                ↓
┌─────────────────────────────────────────┐
│         Segmented Resources             │
│  (Database, file server, app)           │  ← Each requires auth
└─────────────────────────────────────────┘

Trust Principles:
├─ Every user must authenticate (MFA required)
├─ Every device must be healthy (EDR, patched, encrypted)
├─ Every request must be authorized (least privilege)
├─ Every session must be monitored (logging, behavior analysis)
└─ Assume everything could be compromised (continuous verification)
```

---

## 🔑 Zero Trust Pillars

### 1. Identity & Access Management (IAM)

```
Requirement: Verify who you are

Implementation:
├─ Multi-factor authentication (MFA)
│  ├─ Something you know (password)
│  ├─ Something you have (phone, hardware key)
│  └─ Something you are (biometric)
│
├─ Passwordless authentication
│  ├─ Hardware security keys (FIDO2)
│  ├─ Biometric (Windows Hello, Touch ID)
│  └─ App-based approval
│
├─ Single Sign-On (SSO)
│  ├─ Azure AD / Okta / Auth0
│  ├─ Centralized identity
│  └─ Easier to revoke access
│
└─ Conditional Access
   ├─ Require MFA if accessing from unfamiliar location
   ├─ Block login from risky countries
   └─ Require device health check
```

### 2. Device Trust & Security

```
Requirement: Device must be healthy and owned by you

Implementation:
├─ Device enrollment (register with corporate)
├─ Mobile Device Management (MDM)
│  ├─ Screen lock enforcement
│  ├─ Encryption required
│  ├─ Antivirus running
│  └─ OS/app patches current
│
├─ Endpoint Detection & Response (EDR)
│  ├─ Real-time monitoring
│  ├─ Threat hunting
│  └─ Incident response
│
├─ Device compliance check
│  ├─ Firewall enabled?
│  ├─ Antivirus current?
│  ├─ OS patched?
│  ├─ Disk encrypted?
│  └─ Required apps installed?
│
└─ Network access control (NAC)
   ├─ Unmanaged devices = network quarantine
   ├─ Vulnerable devices = restricted access
   └─ Compliant devices = full access
```

### 3. Network Segmentation

```
Requirement: Isolate critical resources

Implementation:
├─ Microsegmentation
│  ├─ Not: one firewall for whole network
│  ├─ Not: trust everything inside
│  └─ Instead: every resource has its own firewall
│
├─ Zero Trust Network Access (ZTNA / BeyondCorp)
│  ├─ No VPN (outdated)
│  ├─ Every resource requires authentication
│  ├─ Every connection is encrypted
│  └─ Only authorized users see authorized resources
│
└─ Segment by function
   ├─ Database segment (pay special attention)
   ├─ Application segment (moderate restrictions)
   ├─ User/workstation segment (general access)
   └─ IoT segment (highly restricted)
```

### 4. Least Privilege Access (LPA)

```
Requirement: Users get only the access they need

Implementation:
├─ Role-Based Access Control (RBAC)
│  ├─ Sales role = access CRM, email
│  ├─ Engineering role = access code repos, production (restricted)
│  └─ Admin role = access to systems (but still MFA+logging)
│
├─ Just-in-Time (JIT) Access
│  ├─ Normal user = no admin rights
│  ├─ Need admin? Request via ticketing system
│  ├─ Get 1-hour admin access (auto-revoke)
│  └─ All actions logged
│
├─ Attribute-Based Access Control (ABAC)
│  ├─ Access = user + device + location + time + context
│  ├─ Example: "Finance analyst can access payroll DB only from office workstation during business hours"
│  └─ Denies: "Finance analyst from home + weekends"
│
└─ Regular access reviews
   ├─ Quarterly: do employees still need this access?
   ├─ Remove stale access
   └─ Manager sign-off required
```

### 5. Continuous Monitoring & Verification

```
Requirement: Verify every session and request

Implementation:
├─ Behavioral analytics
│  ├─ User normally logs in at 9am, not 3am
│  ├─ User normally accesses CRM, not database
│  ├─ User normally from US, not Russia
│  └─ Anomaly = re-authenticate or block
│
├─ Session monitoring
│  ├─ What is the user doing?
│  ├─ What data are they accessing?
│  ├─ How much data are they moving?
│  └─ Real-time alerts on suspicious activity
│
├─ Data access logging
│  ├─ Who accessed what file?
│  ├─ When was it accessed?
│  ├─ What was done with it? (read/copy/modify/delete)
│  └─ Can be used to detect exfiltration
│
└─ Encryption everywhere
   ├─ Data in transit (TLS)
   ├─ Data at rest (AES)
   └─ Even if network is compromised, data is unreadable
```

---

## 🔄 Zero Trust Implementation Journey

### Phase 1: Discovery & Assessment

```
├─ Catalog all users, devices, resources
├─ Map current access patterns
├─ Identify sensitive resources (databases, IP, PII)
├─ Document compliance requirements
└─ Assess current tooling gaps
```

### Phase 2: Identity Layer (6-12 months)

```
├─ Deploy MFA organization-wide
├─ Implement SSO (Azure AD, Okta)
├─ Enforce conditional access policies
├─ Deploy EDR on all endpoints
└─ Enable device health checks (Intune, Jamf)
```

### Phase 3: Network Segmentation (12-18 months)

```
├─ Deploy Zero Trust Network Access (Cloudflare, Palo Alto)
├─ Segment critical resources (databases, file servers)
├─ Implement internal firewalls (microsegmentation)
├─ Deploy DLP (Data Loss Prevention) tools
└─ Move away from VPN
```

### Phase 4: Monitoring & Enforcement (Ongoing)

```
├─ Deploy behavioral analytics (UEBA)
├─ Implement real-time threat detection
├─ Create incident response playbooks
├─ Conduct regular access reviews
└─ Continuous tuning and improvement
```

---

## 📊 Real-World Example

### Before Zero Trust
```
Attacker compromises John's laptop (phishing)
    ↓
Once inside, attacker has same access as John
    ↓
John is in Finance, accesses:
├─ Payroll database (unprotected, no additional auth)
├─ Bank account transfer system (unprotected)
└─ Personal data of all 5,000 employees
    ↓
Attacker steals everything in 2 hours
    ↓
Detection: 3 months later (when regulators call)

Cost: $50M (fines, remediation, breach notification, lawsuits)
```

### After Zero Trust
```
Attacker compromises John's laptop (phishing)
    ↓
Laptop is infected, EDR detects immediately
    ↓
Attacker tries to access payroll database
├─ System requires separate authentication (not just laptop compromise)
├─ System requires MFA (attacker doesn't have John's phone)
└─ System logs access (suspicious access pattern flagged)
    ↓
Access DENIED
User gets alert: "Someone tried to access payroll database as you"
    ↓
Laptop is isolated, cleaned, case closed within 4 hours

Cost: $50K (incident response, laptop replacement)
```

---

## 🛠️ Key Technologies

| Technology | Purpose |
|------------|---------|
| **Azure AD / Okta** | Centralized identity + conditional access |
| **Okta / Auth0** | Authentication platform |
| **Cloudflare / Palo Alto Prisma** | Zero Trust Network Access |
| **Microsoft Intune / Jamf** | Device management + compliance |
| **CrowdStrike / Microsoft Defender** | EDR (Endpoint Detection & Response) |
| **Splunk / ELK** | Logging and behavioral analytics |
| **Zscaler / Fortinet** | Secure web gateway + ZTNA |

---

## 🔑 Key Principles

```
1. Never Trust, Always Verify
   ├─ User logged in 5 minutes ago? Still must verify each request
   └─ Device was compliant yesterday? Still must check today

2. Assume Compromise
   ├─ Any user could be compromised
   ├─ Any device could be malware-infected
   ├─ Any credential could be stolen
   └─ Design for "worst case"

3. Verify Explicitly
   ├─ Use all available data (identity, device, location, behavior)
   ├─ Make decisions based on complete context
   └─ Don't make assumptions

4. Secure by Default
   ├─ Deny all, allow only what's needed
   ├─ Principle of least privilege
   └─ Regular access reviews

5. Encrypt Everything
   ├─ Data in transit (TLS)
   ├─ Data at rest (AES)
   └─ Even if network is breached, data remains protected
```

---

## 🔑 Key Takeaways

- **Perimeter model is broken** - once inside, attacker has free reign
- **Zero Trust assumes nothing** - every access is verified
- **Identity is the new perimeter** - protect identities, everything else follows
- **Least privilege prevents damage** - compromise affects only what that user could access
- **Monitoring catches breach early** - behavioral anomalies trigger before data is stolen
- **Implementation is journey, not project** - takes 2-3 years to fully implement

---

## 📚 Resources

- [NIST Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [Google BeyondCorp](https://research.google/pubs/beyondcorp-a-new-approach-to-enterprise-security/)
- [Forrester Zero Trust eBook](https://www.forrester.com/)

---

## [⬅️ Day 062](../day062/) | [➡️ Day 064](../day064/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*