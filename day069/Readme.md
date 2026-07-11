# Day 069 - Cloud Attack Techniques: How Attackers Compromise AWS

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Cloud Security | **Difficulty:** Advanced

---

## 🧠 The Concept

Understanding how attackers compromise cloud infrastructure helps you defend it.

Cloud attacks follow patterns:

```
Initial Access → Persistence → Reconnaissance → Privilege Escalation → Exfiltration
```

Same phases as on-premise, but using cloud-specific tools.

---

## 🔓 Attack Vector 1: Compromised IAM Credentials

### How it Happens

```
Attack Steps:

1. Developer commits AWS key to GitHub (accidental)
   └─ Key is: AKIAIOSFODNN7EXAMPLE

2. Attacker scans GitHub for AWS keys (automated)
   └─ Finds key within minutes

3. Attacker tests key (is it valid?)
   ```
   aws sts get-caller-identity --access-key-id AKIAIOSFODNN7EXAMPLE
   ```
   └─ Returns: Account ID, User, ARN → KEY WORKS

4. Attacker explores what the key can do
   ```
   aws ec2 describe-instances
   aws s3 ls
   aws iam list-users
   ```

5. If developer had full access: attacker has full account access

6. Attacker escalates privileges (if possible)
   └─ Assume a role with more permissions

7. Attacker installs persistence
   └─ Creates new IAM user, adds to admin group

8. Attacker exfiltrates data
   └─ Copies S3 buckets to attacker-controlled bucket

9. Attacker deletes logs
   ```
   aws logs delete-log-group --log-group-name /aws/lambda/my-app
   ```

10. Discovery: Customer reports breach
```

### Detection

```
CloudTrail Logs:
├─ Multiple AWS API calls from unusual IP
├─ Calls from geographic location user never visited
├─ API calls at unusual time (2am for dayshift worker)
├─ Calls from public IP (not corporate network)
└─ High-volume API calls (exfiltration)

UEBA:
├─ User normally uses console (click)
├─ Suddenly using CLI (API calls)
├─ User never creates IAM users
├─ Suddenly: creates 5 new users

Alerts:
├─ "Access key used from public IP"
├─ "IAM user created outside normal hours"
├─ "Large S3 copy operation (exfil)"
└─ "CloudTrail logs deleted"
```

### Prevention

```
☐ Never hardcode AWS keys in code
☐ Use roles for EC2, Lambda, etc. (temporary creds)
☐ Rotate access keys every 90 days
☐ Delete old access keys immediately
☐ Scan GitHub, GitLab for AWS keys (tools exist)
☐ Enable MFA on all IAM users
☐ Monitor CloudTrail for leaked key patterns
☐ Set IP restrictions on IAM policy
☐ Implement credential scanning in CI/CD
```

---

## 🔓 Attack Vector 2: Metadata Service Exploitation (EC2)

### How it Happens

```
Every EC2 instance has a metadata service:
├─ IP: 169.254.169.254 (instance can access)
├─ Returns: Instance role credentials, user data, tags
└─ Used by applications to get temporary credentials

Attack flow:

1. Attacker gains initial access (web app RCE, etc.)

2. Attacker queries metadata service from compromised instance
   ```
   curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
   ```
   └─ Returns: Role name

3. Attacker fetches role credentials
   ```
   curl http://169.254.169.254/latest/meta-data/iam/security-credentials/my-role/
   ```
   └─ Returns: AccessKeyId, SecretAccessKey, Token, Expiration

4. Attacker uses credentials to:
   ├─ Access other AWS resources
   ├─ Escalate privileges
   ├─ Move laterally
   └─ Exfiltrate data

5. Detection: Hard (credentials are legitimate for that role)
```

### Prevention

```
IMDSv2 (mandatory):
├─ Requires token (more secure than IMDSv1)
├─ Prevents SSRF attacks from accessing metadata
├─ Cost: Zero (free upgrade)

Enable on all instances:
```
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-token required \
  --http-put-response-hop-limit 1
```

☐ Use IMDSv2 only (disable IMDSv1)
☐ Set hop limit to 1 (only instance can access, not containers)
☐ Monitor unexpected metadata access
```

---

## 🔓 Attack Vector 3: Overly Permissive IAM Policies

### How it Happens

```
Company structure:
├─ Developer role: needs to push code to S3
├─ But admin gave them: full AWS access

Developer's credentials compromised.

Attacker can:
├─ Delete all backups
├─ Modify database (ransomware)
├─ Create admin users (persistence)
├─ Export all data (exfil)
└─ Disable CloudTrail (hide tracks)

All because developer had overly broad permissions.
```

### Detection

```
IAM Access Analyzer:
├─ Shows unused permissions
├─ Shows external access (cross-account, federated)
├─ Highlights risky policies (full wildcard access)

CloudTrail:
├─ User's access patterns change
├─ Suddenly: delete operations (never happened before)
├─ Suddenly: cross-account access
└─ Unusual resource types accessed
```

### Prevention

```
Least Privilege:
☐ Developer needs: CodeCommit push + S3 read
☐ Give ONLY: codecommit:GitPush, s3:GetObject
☐ Nothing else (no IAM, no deletion, no cross-account)

Implement:
├─ Service Control Policies (SCP) to limit actions
├─ Permission boundaries (max permissions a role can have)
├─ Regular access reviews (quarterly)
├─ Automated removal of unused permissions
```

---

## 🔓 Attack Vector 4: Supply Chain / Compromised Application

### How it Happens

```
1. Attacker compromises popular OSS library
   └─ Adds backdoor: connects to C2 on startup

2. Your app updates dependency
   ```
   npm install @popular-lib@latest
   ```
   └─ Unknowingly installs backdoored version

3. App deploys to AWS
   └─ Docker image now contains backdoor

4. Container starts
   └─ Backdoor connects to attacker's server

5. Attacker has code execution inside your VPC
   └─ Can access database, other services, metadata

6. Attacker escalates using compromised app
```

### Detection

```
Container scanning:
├─ Scan images for known vulnerabilities (CVEs)
├─ Scan for suspicious behavior (outbound C2 connections)
├─ SBOM (Software Bill of Materials) verification

Runtime monitoring:
├─ EDR/container monitoring
├─ Suspicious outbound connections
├─ Unusual process execution
├─ Unexpected resource access
```

### Prevention

```
☐ Scan dependencies for vulnerabilities (Snyk, Dependabot)
☐ Use Software Bill of Materials (SBOM)
☐ Sign and verify container images
☐ Use private registry (not Docker Hub)
☐ Scan containers for malware/suspicious behavior
☐ Network policies (restrict outbound to known services)
☐ Pod security policies (restrict capabilities)
☐ Supply chain verification (GPG signing, checksums)
```

---

## 🔓 Attack Vector 5: Privilege Escalation (IAM)

### How it Happens

```
1. Attacker has limited IAM user (e.g., developer)

2. Attacker finds misconfigured policy:
   ```
   {
     "Effect": "Allow",
     "Action": "iam:CreateAccessKey",
     "Resource": "*"
   }
   ```
   (Developer can create access keys for ANY user, including admin)

3. Attacker creates new access key for admin user
   ```
   aws iam create-access-key --user-name admin
   ```

4. Attacker now has admin credentials
   └─ Full account access

5. Attacker uses admin to:
   ├─ Create backdoor users
   ├─ Export all data
   ├─ Delete backups
   └─ Disable security monitoring
```

### Common Escalation Paths

```
Vulnerable Permissions:
├─ iam:CreateAccessKey on * (create keys for any user)
├─ iam:AttachUserPolicy on * (grant permissions to users)
├─ sts:AssumeRole on * (assume any role)
├─ ec2:RunInstances + iam:PassRole (run instances with high-priv role)
├─ lambda:InvokeFunction on * (invoke lambda with high privs)
└─ Many others...

Tools:
├─ CloudGoat (demonstrates escalation paths)
├─ IAM Role Enumeration (find exploitable roles)
└─ ScoutSuite (audits IAM permissions)
```

### Prevention

```
☐ Remove wildcard (*) resources from policies
☐ Use permission boundaries (max what a role can do)
☐ Regular access reviews (find over-privileged users)
☐ IAM Access Analyzer (find external access, wildcards)
☐ Least privilege from day 1
☐ Test IAM policies (can user escalate?)
```

---

## 🔓 Attack Vector 6: Lateral Movement (Instance → RDS)

### How it Happens

```
1. Attacker compromises EC2 instance (initial access)

2. Attacker finds RDS instance in same VPC
   ```
   aws rds describe-db-instances
   ```

3. Attacker gets database credentials (from environment, config files)
   └─ App has: DB_PASSWORD=admin123

4. Attacker connects to RDS
   ```
   mysql -h rds-instance.amazonaws.com -u admin -padmin123
   ```

5. Attacker dumps entire database
   └─ Customer data, secrets, etc.

6. Attacker escalates:
   ├─ Modify data (ransomware)
   ├─ Create backdoor account
   └─ Enable suspicious features (log exfil)
```

### Detection

```
CloudTrail:
├─ RDS describe calls from unexpected source
├─ RDS modify calls (backup disable, parameter group change)
├─ Unusual database user creation

Database Logs:
├─ Unexpected login from EC2 instance
├─ Bulk data export (SELECT * queries)
├─ Failed login attempts (brute force)

VPC Flow Logs:
├─ EC2 → RDS traffic (unusual)
├─ Large data transfer from RDS
```

### Prevention

```
Network Segmentation:
☐ RDS in private subnet (no internet access)
☐ EC2 accesses RDS only if needed
☐ Security group: EC2 → RDS (tight ingress)
☐ NACLs: restrict traffic

Credentials:
☐ Use IAM database authentication (temporary creds)
☐ Don't hardcode passwords (use Secrets Manager)
☐ Rotate database passwords regularly
☐ Use strong passwords (generator)

Monitoring:
☐ Enable database activity logging
☐ Alert on unexpected queries (bulk export)
☐ Monitor failed login attempts
```

---

## 📊 Attack Timeline (Complete Breach)

```
T+0:00 - Attacker finds AWS key on GitHub
T+0:05 - Key validated (still active, full permissions)
T+0:10 - Attacker explores account (list buckets, instances)
T+0:20 - Attacker finds sensitive S3 bucket (customer data)
T+0:25 - Attacker copies bucket to attacker-owned bucket
T+1:00 - Attacker creates IAM user for persistence
T+1:05 - Attacker enables "assume role" permissions
T+2:00 - Attacker creates backup of RDS database
T+3:00 - Attacker deletes CloudTrail logs (cover tracks)
T+4:00 - Attacker disables CloudWatch alarms
T+24:00 - Customer reports unusual activity (too late)

Detection Opportunities Missed:
├─ CloudTrail shows key used from public IP (not detected)
├─ Large S3 copy operation (not alerted)
├─ IAM user created outside business hours (not monitored)
├─ CloudTrail logs deleted (not detected - logs already gone!)
└─ RDS backup creation (RDS monitoring not enabled)

Outcome:
├─ 1 million customer records exfiltrated
├─ Full AWS account compromised
├─ Attacker had 24 hours undetected
└─ Backup deletion meant no clean recovery
```

---

## 🔑 Key Takeaways

- **Cloud attacks follow patterns** - same phases as on-premise (recon → access → persist → exfil)
- **Credentials are the #1 entry point** - protect keys, rotate regularly, monitor usage
- **Misconfiguration enables lateral movement** - overly broad policies, security group gaps
- **Logging is critical** - CloudTrail must be enabled and protected (immutable logs)
- **Detection is harder in cloud** - legitimate API calls hide malicious ones
- **Monitoring CloudTrail is your best defense** - unusual patterns = compromised account

---

## 📚 Resources

- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
- [MITRE ATT&CK for Cloud](https://attack.mitre.org/platforms/iaas/)
- [CloudGoat (Attack Simulator)](https://github.com/RhinoSecurityLabs/cloudgoat)

---

## [⬅️ Day 068](../day068/) | [➡️ Day 070](../day070/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*