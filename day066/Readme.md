# Day 066 - Cloud Security 101: Shared Responsibility Model

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Cloud Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Cloud security is different from on-premise security.

You don't own the hardware. You don't own the network. You don't own the hypervisor.

**Shared Responsibility Model** defines what AWS/Azure/GCP secures vs. what you secure.

Understanding this boundary is the foundation of cloud security.

---

## 🏢 Shared Responsibility Model

### Traditional On-Premise (You Own Everything)

```
┌─────────────────────────────────────┐
│  Application & Data                 │  ← You
├─────────────────────────────────────┤
│  Operating System                   │  ← You
├─────────────────────────────────────┤
│  Hypervisor / VM                    │  ← You
├─────────────────────────────────────┤
│  Server Hardware                    │  ← You
├─────────────────────────────────────┤
│  Network Equipment                  │  ← You
├─────────────────────────────────────┤
│  Physical Security & Building       │  ← You
├─────────────────────────────────────┤
│  Utilities & Redundancy             │  ← You
└─────────────────────────────────────┘

Result: You own security. You own failures. You own everything.
```

### AWS Cloud (Shared Responsibility)

```
┌─────────────────────────────────────┐
│  Application & Data                 │  ← YOU
├─────────────────────────────────────┤
│  Access Management (IAM)            │  ← YOU
├─────────────────────────────────────┤
│  Encryption (in transit & at rest)  │  ← YOU
├─────────────────────────────────────┤
│  Operating System Patches           │  ← YOU
├─────────────────────────────────────┤
│  Firewall Configuration             │  ← YOU
├─────────────────────────────────────┤
│  Network Configuration              │  ← YOU
├─────────────────────────────────────┤
│  Operating System (for RDS)         │  ← AWS (you configure)
├─────────────────────────────────────┤
│  Hypervisor / Virtualization        │  ← AWS
├─────────────────────────────────────┤
│  Server Hardware                    │  ← AWS
├─────────────────────────────────────┤
│  Network Infrastructure             │  ← AWS
├─────────────────────────────────────┤
│  Physical Security & Data Centers   │  ← AWS
├─────────────────────────────────────┤
│  Utilities & Redundancy             │  ← AWS
└─────────────────────────────────────┘

Result: AWS secures infrastructure. You secure your stuff on top of it.
```

---

## 📋 What You're Responsible For

### 1. Identity & Access Management (IAM)

```
AWS provides the tools. You define the policy.

Your responsibility:
├─ Create IAM users (with least privilege)
├─ Assign roles based on job functions
├─ Enforce MFA for all users
├─ Rotate access keys regularly
├─ Review permissions quarterly
└─ Detect and revoke compromised credentials

Example mistake:
├─ Root AWS account used for daily work (should not happen)
├─ EC2 instances with admin credentials in environment variables
├─ S3 buckets with public read access (accidentally)
├─ IAM policy grants overly broad permissions
└─ Old employees still have active API keys
```

### 2. Data Security

```
Encryption at rest:
├─ EBS volumes: use AWS KMS encryption (you manage key)
├─ S3 buckets: enable server-side encryption (SSE-S3 or SSE-KMS)
├─ RDS databases: enable encryption at rest
├─ Backups: ensure encrypted
└─ You decide: managed by AWS or you manage key

Encryption in transit:
├─ TLS for all API calls (HTTPS)
├─ VPN for database connections
├─ SSL/TLS for application traffic
└─ Prevent man-in-the-middle attacks

Data classification:
├─ What data is sensitive? (PII, financial, health, IP)
├─ How should it be protected?
├─ Where should it be stored?
├─ Who can access it?
└─ How long should it be retained?
```

### 3. Network Security

```
Virtual Private Cloud (VPC):
├─ Design: public subnets vs. private subnets
├─ Routing: where does traffic go?
├─ Network ACLs: firewall rules at subnet level
├─ Security Groups: firewall rules at instance level
└─ NAT Gateway: hide internal IPs from internet

Firewall rules:
├─ Principle of least privilege
├─ Inbound: only needed ports
├─ Outbound: restrict to necessary destinations
├─ Default: deny all, allow specific
└─ Review regularly

Network segmentation:
├─ Web servers in public subnet
├─ App servers in private subnet
├─ Database in private subnet
├─ Backup in isolated subnet
└─ No direct internet access for sensitive systems
```

### 4. Application & Data

```
You are responsible for:
├─ Code quality (vulnerabilities in your app)
├─ Secrets management (API keys, passwords)
├─ Input validation (prevent injection attacks)
├─ Logging & monitoring
├─ Incident response
├─ Data disposal (deletion, archiving)
└─ Compliance (meeting regulatory requirements)

Examples:
├─ SQL injection in your web app (your fault)
├─ Unpatched library with known CVE (your fault)
├─ Weak password policy (your fault)
├─ Data exfiltration undetected (your fault)
└─ Customer data left unencrypted (your fault)
```

---

## 🔐 What AWS is Responsible For

### Infrastructure

```
Hardware:
├─ Physical servers (security, maintenance, replacement)
├─ Storage systems (disk redundancy, repair)
├─ Network hardware (routers, switches, cables)
└─ All underlying infrastructure

Data Center:
├─ Physical access controls (guards, cameras, badges)
├─ Environmental controls (temperature, fire suppression)
├─ Power & redundancy (multiple power grids, backup generators)
├─ Disaster recovery
└─ Geographic distribution (multiple regions/AZs)

Hypervisor & Virtualization:
├─ Isolating customer VMs (nobody sees your data on shared hardware)
├─ Managing compute resources
├─ Patching hypervisor
└─ Preventing neighbor VMs from accessing your data
```

### Managed Services

```
If you use RDS (Relational Database Service):
├─ AWS patches the OS ✓
├─ AWS patches the database software ✓
├─ AWS backs up your data ✓
├─ AWS handles failover/redundancy ✓
└─ You still encrypt the data ✗ (your key)
└─ You still manage access ✗ (IAM + network rules)

If you use EC2 (self-managed servers):
├─ AWS patches the hypervisor ✓
├─ AWS provides the OS image ✓
├─ You patch the OS ✗
├─ You manage the application ✗
└─ You configure the network ✗

Key difference:
├─ Less you do = less you secure
├─ More AWS does = less responsibility on you
└─ But: less you do = less control
```

---

## ⚠️ Common Cloud Security Mistakes

### 1. Overly Open Security Groups

```
WRONG:
resource "aws_security_group" "web" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # ← OPEN TO INTERNET
  }
}

RIGHT:
resource "aws_security_group" "web" {
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # ← Only HTTP
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # ← Only HTTPS
  }
}
```

### 2. Public S3 Buckets

```
WRONG:
aws s3api put-bucket-acl --bucket my-bucket --acl public-read

Result: Anyone on the internet can read every file in the bucket.

Many breaches from misconfigured S3 buckets:
├─ Exposed customer data (millions of records leaked)
├─ Exposed credentials (API keys in configs)
├─ Exposed source code (proprietary algorithms)

RIGHT:
aws s3api put-bucket-acl --bucket my-bucket --acl private

Even better:
├─ Enable block public access
├─ Enable versioning
├─ Enable encryption
├─ Enable logging
└─ Regular audits
```

### 3. Hardcoded Credentials

```
WRONG:
# In your code or config files:
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

If committed to GitHub:
├─ Public repositories: anyone can access
├─ Private repositories: employees can access
├─ Compromised: attacker can use credentials
└─ Damage: attacker can spin up 1000 instances, incur massive bills

RIGHT:
# Use IAM roles (attach to EC2, not stored in code)
# Use AWS Secrets Manager (managed, encrypted, rotated)
# Use temporary credentials (token with expiration)
└─ Never hardcode, never commit to git
```

### 4. No Encryption

```
WRONG:
resource "aws_db_instance" "main" {
  allocated_storage    = 100
  engine               = "postgres"
  instance_class       = "db.t3.medium"
  storage_encrypted    = false  # ← DATA AT REST UNENCRYPTED
}

If someone gains access to AWS account:
├─ They can read all database contents
├─ No encryption protecting data
└─ Likely breach

RIGHT:
resource "aws_db_instance" "main" {
  allocated_storage    = 100
  engine               = "postgres"
  instance_class       = "db.t3.medium"
  storage_encrypted    = true   # ← DATA AT REST ENCRYPTED
  kms_key_id           = aws_kms_key.db.arn  # ← With your key
}

Also: TLS for connections, backups encrypted, logs encrypted
```

### 5. No MFA on Root Account

```
WRONG:
AWS root account (email + password only)
├─ Attacker gets email password
├─ Attacker logs in to AWS account
├─ Complete access to all resources
└─ Can delete everything, incur massive charges

Result: Many AWS accounts hacked this way

RIGHT:
AWS root account (email + password + MFA)
├─ Attacker gets email password
├─ Attacker logs in attempt
├─ MFA challenge: need hardware key or phone
├─ Attacker doesn't have MFA device
└─ Access denied

Also:
├─ Don't use root account for daily work
├─ Create IAM users instead
├─ Root account = emergency only
└─ Enforce MFA on all users (with SCP)
```

---

## 📊 Key Responsibilities Checklist

### Your Responsibility (Always)

```
☐ Identity & Access Management
  ☐ Create users with least privilege
  ☐ Enforce MFA
  ☐ Rotate credentials
  ☐ Regular access reviews

☐ Data Security
  ☐ Encrypt sensitive data
  ☐ Manage encryption keys
  ☐ Classify data by sensitivity
  ☐ Implement DLP (Data Loss Prevention)

☐ Network Configuration
  ☐ Design VPC architecture
  ☐ Configure Security Groups
  ☐ Network segmentation
  ☐ Review ingress/egress rules

☐ Application & Code
  ☐ Secure coding practices
  ☐ Input validation
  ☐ Dependency scanning
  ☐ Secrets management

☐ Monitoring & Logging
  ☐ Enable CloudTrail
  ☐ Enable VPC Flow Logs
  ☐ Monitor for anomalies
  ☐ Incident response
```

### AWS Responsibility (Always)

```
☐ Physical Security
  ☐ Data center access
  ☐ Environmental controls
  ☐ Fire suppression

☐ Infrastructure
  ☐ Hypervisor patching
  ☐ Hardware maintenance
  ☐ Network redundancy

☐ Managed Service Patching
  ☐ RDS OS patching
  ☐ ElastiCache patching
  ☐ Managed service updates
```

---

## 🔑 Key Takeaways

- **Shared responsibility is not shared blame** - you own your stuff
- **Misconfiguration is #1 cloud breach cause** - wrong IAM, open bucket, exposed creds
- **Least privilege applies to cloud** - every role, every permission, every instance
- **Encryption is your job** - AWS provides tools, you must use them
- **AWS does not manage your data** - you do
- **Monitoring is your job** - CloudTrail, VPC Flow Logs, application logs

---

## 📚 Resources

- [AWS Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/)
- [Azure Responsibility Matrix](https://docs.microsoft.com/en-us/azure/security/fundamentals/shared-responsibility)
- [GCP Shared Responsibilities](https://cloud.google.com/architecture/devops-org-shared-responsibility)

---

## [⬅️ Day 065: Phase 3 Capstone](../day065/) | [➡️ Day 067](../day067/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*

**Welcome to Phase 4: Cloud Security!**

15 days covering AWS IAM, S3 misconfigurations, cloud attacks, DevSecOps, and infrastructure-as-code security.