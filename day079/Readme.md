# Day 079 - Cloud Incident Response: What's Different

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Cloud Security | **Difficulty:** Advanced

---

## 🧠 The Concept

Cloud incidents are fundamentally different from on-premise incidents.

**On-Premise IR:** Isolate the server, capture disk, investigate locally.

**Cloud IR:** Attacker has API access, can delete logs, spin up 100 instances, move across accounts.

Different threats = different response procedures.

---

## 🔄 Cloud vs. On-Premise Incident Response

### On-Premise Incident

```
Timeline: Attacker breaks in → Spreads → Detected → Network isolated → Investigation → Recovery

Advantages:
├─ Physical isolation possible (unplug network cable)
├─ Logs stored locally (hard to delete)
├─ Single administrative domain
└─ Slower attacker movement (one network)

Disadvantages:
├─ Manual actions needed (lots of manual work)
├─ Slower detection (requires manual monitoring)
├─ Limited visibility (only what you instrument)
└─ High cost (physical response team)
```

### Cloud Incident

```
Timeline: Attacker gains API key → Exploits permissions → Deletes logs → Exfiltrates data → Moves to other accounts

Differences:
├─ Attacker doesn't need physical access (API only)
├─ Can delete CloudTrail logs (cover tracks)
├─ Can spin up 1000 instances (massive scale)
├─ Can assume cross-account roles (lateral movement)
├─ Can modify security groups (create backdoor)
└─ All in seconds (before you can detect)

Advantages:
├─ Instant isolation possible (disable IAM role)
├─ API-based response (no physical dispatch)
├─ Massive logging (CloudTrail logs everything)
├─ Automation possible (playbooks, Lambda)
└─ Global visibility (AWS organization level)

Disadvantages:
├─ Attacker can delete logs (cover tracks)
├─ Attacker can disable monitoring (GuardDuty, CloudTrail)
├─ Attacker can create backdoors (persistence)
├─ Credential compromise = account compromise
└─ Scale problem (1000s of resources)
```

---

## 🚨 Cloud Incident Response Phases

### Phase 1: Detection (Minutes)

```
Alert fires: GuardDuty, CloudTrail, or monitoring system

Signals:
├─ Unusual API activity (bulk operations)
├─ Failed login attempts (brute force)
├─ Privilege escalation attempt (AssumeRole)
├─ CloudTrail disabled (attacker hiding)
├─ Data exfiltration (large S3 download)
└─ Resource creation spike (1000 instances)

First Actions:
├─ Confirm alert is real (not false positive)
├─ Gather initial evidence (CloudTrail logs, GuardDuty finding)
├─ Estimate scope (how many resources affected?)
└─ Activate incident response team
```

### Phase 2: Containment (Minutes to Hours)

```
Goal: Stop attacker's access and lateral movement

Immediate Actions:
├─ Revoke compromised credentials (disable IAM user/role)
├─ Reset passwords (all affected accounts)
├─ Enable MFA on remaining accounts
├─ Review active sessions (terminate attacker's session)
├─ Lock down IAM policies (deny all, allow nothing)
└─ Review access keys (disable any created by attacker)

Network Containment:
├─ Review security groups (attacker may have created backdoor rule)
├─ Review network ACLs
├─ Check for VPN/proxy connections to unknown IPs
└─ Review route tables (unusual routing?)

Database Containment:
├─ Change database passwords (attacker may have extracted)
├─ Review database user access logs
├─ Check for unusual queries (exfiltration, deletion)
└─ Restore to backup point (before compromise)

Example Timeline:

T+0:00 - Alert fires: Unusual AssumeRole activity
T+0:05 - Security team paged
T+0:10 - Confirm real incident (not false positive)
T+0:15 - Disable attacker's IAM user
T+0:16 - All active sessions terminated (user force logged out)
T+0:17 - CloudTrail audit begins
T+0:20 - Check S3 for data exfiltration
T+0:25 - Found: 10GB of customer data copied to attacker bucket
T+0:30 - Block attacker AWS account (deny all actions)
T+0:35 - Notify legal/compliance
T+0:60 - Database passwords reset
T+1:00 - Complete containment (attacker locked out)
```

### Phase 3: Investigation & Forensics (Hours to Days)

```
Goal: Understand what happened

Evidence Gathering:
├─ CloudTrail logs (every API call attacker made)
├─ VPC Flow Logs (network connections)
├─ Guard Duty findings (threat detection)
├─ Application logs (what did attacker do?)
├─ IAM Access Analyzer (who had access to what?)
└─ S3 access logs (who downloaded what?)

Timeline Construction:
├─ When did compromise start?
├─ What was the initial access vector?
├─ How did attacker escalate privileges?
├─ What data was accessed/exfiltrated?
├─ How long were they in the system?
└─ What backdoors did they create?

Forensic Analysis:
├─ Capture CloudTrail logs (immutable storage)
├─ Capture VPC Flow Logs
├─ Memory dump of affected instances
├─ Disk snapshot of affected instances
├─ Database transaction logs
└─ Application logs (before attacker deletion)

Questions to Answer:
├─ Root cause: How did they get in?
├─ Patient zero: Which user/system first?
├─ Scope: How many resources affected?
├─ Data exposure: What was accessed?
├─ Persistence: What backdoors remain?
└─ Availability: What was deleted/modified?

Example Investigation:

1. Parse CloudTrail logs
   ├─ Find first suspicious API call
   ├─ Timestamp: 2024-01-15T10:30:00Z (AssumeRole)
   ├─ Source IP: 203.0.113.1 (attacker IP)
   ├─ User: service-account
   ├─ Escalated to: AdminRole
   └─ Conclusion: Service account was compromised 2 days ago

2. Trace lateral movement
   ├─ AssumeRole → Access S3 (list buckets)
   ├─ S3 list → Download backups (100GB)
   ├─ S3 copy → Copy to external bucket
   ├─ RDS access → Dump database (customer records)
   └─ IAM creation → Create backdoor user

3. Determine scope
   ├─ Affected: 5 S3 buckets, 1 RDS database, 2 EC2 instances
   ├─ Exfiltrated: 100GB (customer data, configs, source code)
   ├─ Modified: 3 security group rules added (for persistence)
   ├─ Created: 2 new IAM users (backdoor accounts)
   └─ Deleted: CloudTrail logs for 2024-01-14 (cover tracks)
```

### Phase 4: Eradication (Hours to Days)

```
Goal: Remove all attacker access and backdoors

Remove Compromised Credentials:
├─ Delete attacker-created IAM users
├─ Revoke attacker-created access keys
├─ Delete attacker-created roles
├─ Remove attacker from all groups
└─ Verify no remaining access

Remove Backdoors:
├─ Remove attacker-created security group rules
├─ Delete attacker-created EC2 instances
├─ Remove attacker-modified IAM policies
├─ Delete attacker-created Lambda functions
└─ Check for CloudWatch alarms disabled by attacker

Patch Vulnerabilities:
├─ What was the initial access vector?
├─ Fix that vulnerability (update app, patch, credentials)
├─ Review for similar vulnerabilities
└─ Implement compensating controls

Rotate Credentials:
├─ Password reset for all affected users
├─ Generate new database passwords
├─ Rotate service account credentials
├─ Update secrets in Secrets Manager
└─ Restart applications (pick up new creds)

Example Eradication:

1. Remove attacker's IAM user
   ```
   aws iam delete-user --user-name attacker-created-user
   ```

2. Remove backdoor security group rule
   ```
   aws ec2 revoke-security-group-ingress \
     --group-id sg-0123456789 \
     --cidr 203.0.113.1/32 \
     --protocol tcp \
     --port 443
   ```

3. Restore database from backup (before compromise)
   ```
   aws rds restore-db-instance-from-db-snapshot \
     --db-instance-identifier prod-restored \
     --db-snapshot-identifier before-compromise
   ```

4. Rotate service account password
   ```
   aws secretsmanager update-secret \
     --secret-id prod/service-account \
     --secret-string '{"password":"NewSecurePassword123!"}'
   ```
```

### Phase 5: Recovery (Days to Weeks)

```
Goal: Restore systems to normal operation

Service Restoration:
├─ Verify clean instances running
├─ Point load balancer to clean instances
├─ Monitor for anomalies (did attacker disable monitoring?)
├─ Gradually bring services online
└─ Test applications (ensure data integrity)

Data Validation:
├─ Verify data integrity (no corruption/deletion)
├─ Compare restored data to backup checksums
├─ Check application consistency
└─ Validate customer data (spot check)

Monitoring Hardening:
├─ Verify CloudTrail logging (re-enabled, logs protected)
├─ Verify GuardDuty (re-enabled, alerts configured)
├─ Verify CloudWatch alarms (re-enabled)
├─ Add monitoring for indicators of compromise
└─ Implement detection rules for attack patterns

Access Control Review:
├─ Verify all IAM policies (least privilege)
├─ Review all service accounts (necessary?)
├─ Review all API keys (old ones deleted?)
├─ MFA enforced on all users
└─ Quarterly access review scheduled
```

### Phase 6: Post-Incident Review (Days to Weeks)

```
Goal: Learn and prevent recurrence

Timeline Validation:
├─ Reconstruct complete attack timeline
├─ Validate detective controls (did they alert?)
├─ Identify detection gaps (what wasn't detected?)
└─ Calculate MTTD (mean time to detect)

Root Cause Analysis:
├─ How did attacker get initial access?
├─ Why weren't they detected sooner?
├─ Why could they escalate privileges?
├─ Why could they delete logs?
└─ Why could they create backdoors?

Lessons Learned:
├─ Detection gaps (add new rules)
├─ Prevention gaps (implement controls)
├─ Response gaps (improve playbooks)
└─ Communication gaps (improve notifications)

Improvements Implemented:
├─ New detection rules added
├─ Vulnerabilities patched
├─ Controls implemented
├─ Playbooks updated
├─ Training conducted
└─ Timeline: Complete within 30 days
```

---

## 📋 Cloud Incident Response Playbook

```
INCIDENT RESPONSE PLAYBOOK

Alert: Unusual AssumeRole Activity

Severity: CRITICAL

Detection:
├─ GuardDuty finding: UnauthorizedAPI:IAMUser/PrivilegeEscalation
├─ CloudTrail alert: AssumeRole by service account from unknown IP
└─ Source: 203.0.113.1 (external IP)

Immediate Actions (T+0:00 to T+0:30):
├─ Page on-call security engineer
├─ Confirm alert is real (pull CloudTrail, verify finding)
├─ Disable service account (aws iam deactivate-login-profile)
├─ Revoke all access keys (aws iam delete-access-key)
├─ Terminate all active sessions (aws iam delete-user-login-profile)
├─ Review assumed roles (what did attacker access?)
└─ Enable CloudTrail integrity validation (if not already)

Investigation (T+0:30 to T+4:00):
├─ Extract CloudTrail logs (all API calls by attacker)
├─ Timeline analysis (when did compromise start?)
├─ Lateral movement check (other accounts accessed?)
├─ Data exfiltration check (S3 downloads, database dumps?)
├─ Persistence check (backdoor IAM users/roles created?)
└─ Generate incident report

Containment (T+0:00 to T+1:00):
├─ Disable service account
├─ Review and lock down IAM policies
├─ Check security groups (remove backdoor rules)
├─ Reset database passwords
├─ Verify CloudTrail is running and logging
└─ Verify GuardDuty is running

Eradication (T+1:00 to T+8:00):
├─ Delete attacker-created IAM users
├─ Remove attacker-created access keys
├─ Remove security group rules created by attacker
├─ Delete EC2 instances created by attacker
├─ Rotate all service account credentials
├─ Restore database from backup (if data was modified)
└─ Scan for malware/backdoors on affected instances

Recovery (T+8:00 to 48 hours):
├─ Verify services running cleanly
├─ Test applications (data integrity)
├─ Restore monitoring (CloudTrail, GuardDuty, alarms)
├─ Monitor for attacker return (IPs, accounts, domains)
└─ Prepare for communication with customers (if data was exposed)

Post-Incident (Days 3-30):
├─ Complete root cause analysis
├─ Document lessons learned
├─ Implement improvements
├─ Conduct lessons-learned meeting
├─ Update policies and procedures
└─ Schedule training
```

---

## 🔑 Key Differences from On-Premise IR

```
On-Premise                          Cloud
─────────────────────────────────────────────────────
Server: Physical location known      Server: Unknown region (could be any AWS region)
Isolation: Unplug network cable      Isolation: Disable IAM role (instant)
Detection: Manual monitoring         Detection: CloudTrail (automatic)
Logs: Stored locally (hard to delete) Logs: CloudTrail (easier to delete)
Scale: Single server                 Scale: 1000 instances in seconds
Lateral Movement: Network             Lateral Movement: IAM roles, cross-account
Credential: Username/password        Credential: Access keys, temporary tokens
Persistence: Rootkit, backdoor       Persistence: IAM users, security groups
Cost: High (physical dispatch)       Cost: Potentially lower (API automation)
Speed: Hours (manual actions)        Speed: Minutes (API automation)
```

---

## 🔑 Key Takeaways

- **Cloud incidents are faster** - attacker can do in seconds what takes hours on-premise
- **Logs are critical** - CloudTrail is your best evidence (protect it)
- **Immutable logging** - store CloudTrail logs in separate account, S3 with versioning
- **Automation matters** - playbooks and Lambda automate response
- **Cross-account blast radius** - assume attacker can move between accounts
- **API-based IR** - you can automate containment with code

---

## 📚 Resources

- [AWS Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/)
- [NIST Computer Security Incident Handling](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [Cloud Security Alliance IR Guide](https://cloudsecurityalliance.org/)

---

## [⬅️ Day 078](../day078/) | [➡️ Day 080](../day080/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*