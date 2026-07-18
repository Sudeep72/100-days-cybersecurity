# Day 076 - Secrets Management: Vault & AWS Secrets Manager

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Cloud Security | **Difficulty:** Intermediate-Advanced

---

## 🧠 The Concept

Secrets = passwords, API keys, tokens, credentials.

**Never hardcode secrets in code.**

Yet 70% of breaches involve stolen credentials.

**Secrets Management** = centralized, encrypted, audited storage for secrets.

```
Hardcoded Secrets → Exposed in git → Attacker finds → Full access
vs.
Secrets Manager → Encrypted → Audited → Auto-rotated → Limited blast radius
```

---

## 🔓 The Problem with Hardcoded Secrets

### In Code

```python
# WRONG: Hardcoded in code
import boto3

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASSWORD = "admin123"

s3 = boto3.client('s3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY
)

# Problem:
# ├─ Exposed in git history (forever)
# ├─ Visible in docker image layers
# ├─ Visible in logs
# ├─ Shared with all developers
# └─ Can't rotate without code change
```

### In Environment Variables

```bash
# WRONG: In .env file
AWS_ACCESS_KEY_ID="AKIA..."
AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG..."
DB_PASSWORD="admin123"

# Problem:
# ├─ File gets committed (easy to miss)
# ├─ Visible in process list (ps aux shows env vars)
# ├─ Shared with all team members
# ├─ Can't rotate without restart
# └─ If attacker gains shell access, all secrets visible
```

### In Configuration Files

```json
{
  "database": {
    "host": "db.example.com",
    "username": "admin",
    "password": "admin123"
  },
  "aws": {
    "access_key": "AKIA...",
    "secret_key": "wJalrXUtnFEMI/K7MDENG..."
  }
}
```

---

## 🔐 Secrets Management Solutions

### AWS Secrets Manager

```bash
# Create secret
aws secretsmanager create-secret \
  --name prod/database/password \
  --secret-string '{"username":"admin","password":"MySecurePassword123!"}'

# Retrieve secret
aws secretsmanager get-secret-value \
  --secret-id prod/database/password

# Output:
# {
#   "SecretString": "{\"username\":\"admin\",\"password\":\"MySecurePassword123!\"}",
#   "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/database/password-abcd1234",
#   "VersionId": "12345678-1234-1234-1234-123456789012",
#   "LastAccessedDate": "2024-01-15T10:30:00Z"
# }

# Auto-rotate every 30 days
aws secretsmanager rotate-secret \
  --secret-id prod/database/password \
  --rotation-rules AutomaticallyAfterDays=30
```

### HashiCorp Vault

```bash
# Start Vault
vault server -config=config.hcl

# Create secret
vault kv put secret/prod/database \
  username=admin \
  password=MySecurePassword123!

# Retrieve secret
vault kv get secret/prod/database

# Output:
# ====== Data ======
# Key         Value
# ---         -----
# password    MySecurePassword123!
# username    admin

# Rotate secret
vault kv put secret/prod/database password=NewPassword123!

# Audit log (who accessed what, when)
vault audit list
vault audit enable file file_path=/var/log/vault-audit.log
```

### Using Secrets in Applications

```python
# RIGHT: Fetch from Secrets Manager at runtime
import json
import boto3

secrets_client = boto3.client('secretsmanager')

def get_database_password():
    response = secrets_client.get_secret_value(
        SecretId='prod/database/password'
    )
    secret = json.loads(response['SecretString'])
    return secret['password']

# Application code
db_password = get_database_password()
# Use password
# Do NOT store in memory longer than needed
```

---

## 🔒 Secrets Management Best Practices

### 1. Principle of Least Privilege

```bash
# Create IAM policy for application
# Only grant access to specific secrets

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/app/*"
    }
  ]
}

# Application can ONLY read secrets it needs
# Can't access other secrets (finance, hr, etc.)
```

### 2. Rotation

```bash
# Automatic rotation
aws secretsmanager rotate-secret \
  --secret-id prod/database/password \
  --rotation-rules AutomaticallyAfterDays=30 \
  --rotation-lambda-arn arn:aws:lambda:us-east-1:123456789012:function:RotateSecret

# Lambda function handles rotation:
# 1. Generate new password
# 2. Update database
# 3. Store new password in Secrets Manager
# 4. Delete old password
```

### 3. Encryption

```bash
# Secrets Manager uses KMS encryption
# Encrypt with customer-managed key (not AWS-managed)

aws secretsmanager create-secret \
  --name prod/api/key \
  --secret-string "sk_live_xyz123" \
  --kms-key-id arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012

# Only users with KMS key access can decrypt secret
```

### 4. Auditing

```bash
# CloudTrail logs all secret access

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=prod/database/password

# Output:
# EventTime: 2024-01-15T10:30:00Z
# EventName: GetSecretValue
# Username: app-service-role
# SourceIPAddress: 10.0.0.5
# ResourceName: prod/database/password
```

### 5. Version Control

```bash
# Secrets Manager keeps version history

aws secretsmanager describe-secret \
  --secret-id prod/database/password

# Output includes:
# VersionIdsToStages:
#   12345678-current: [AWSCURRENT]
#   87654321-previous: [AWSPREVIOUS]
#   55555555-old: []

# Rollback to previous version if needed
aws secretsmanager update-secret-version-stage \
  --secret-id prod/database/password \
  --version-stage AWSCURRENT \
  --moving-to-version-id 87654321-previous
```

---

## 🛠️ Vault vs. Secrets Manager

```
Feature                     Vault           Secrets Manager
─────────────────────────────────────────────────────────────
Self-Hosted                 Yes             No (AWS-managed)
Multi-Cloud Support         Yes             AWS only
Dynamic Secrets             Yes             Limited
Path-Based Access           Yes             ARN-based
Encryption                  Yes             KMS
Audit Logging               Yes             CloudTrail
Cost                        Infrastructure  Per secret + usage
Setup Complexity            High            Low
Rotation Support            Yes             Yes
PKI/Certificates            Yes             Limited
```

---

## 📋 Secrets Management Checklist

```
Implementation
☐ All secrets moved out of code
☐ All secrets moved out of env vars
☐ Secrets Manager/Vault deployed
☐ KMS encryption enabled
☐ IAM policies restrict access (least privilege)
☐ Audit logging enabled

Secret Lifecycle
☐ Secret creation documented
☐ Secret owner assigned
☐ Rotation schedule defined
☐ Automated rotation configured
☐ Manual rotation procedure documented
☐ Secret deletion procedure defined

Access Control
☐ Only apps needing secret have access
☐ No human access to secrets (except emergency)
☐ Service accounts used (not personal)
☐ Quarterly access review
☐ Stale access removed

Monitoring
☐ CloudTrail logs all secret access
☐ Alerts on unusual access patterns
☐ Alerts on failed rotation
☐ Alerts on secret near expiration
☐ Dashboard for secret metrics

Incident Response
☐ Playbook for compromised secret
☐ Immediate rotation procedure
☐ Audit of who had access
☐ Scope determination (what was accessed?)
☐ Investigation of usage
☐ Root cause analysis
```

---

## 🎯 Incident: Compromised Secret

```
Timeline:

T+0:00 - Secret compromised (attacker finds in old git commit)
T+0:05 - Attacker uses secret to access AWS account
T+0:10 - Attacker reads S3 buckets
T+0:15 - Attacker escalates privileges
T+0:20 - Attacker creates backdoor account
T+0:25 - Attacker exfiltrates data
T+1:00 - Breach detected (access pattern anomaly)

Without Secrets Management:
├─ Secret still valid (only way to revoke: deploy new code)
├─ Takes 1 hour to update secret everywhere
├─ Attacker has 1 hour of undetected access
├─ Data breach impact: High

With Secrets Management:
├─ Alert fires: Unusual secret access pattern
├─ Immediately rotate secret (1 second)
├─ Old secret invalidated
├─ Attacker's access revoked instantly
├─ New secret deployed to apps
├─ Audit trail: who accessed, when, from where
└─ Data breach impact: Minimal
```

---

## 🔑 Key Takeaways

- **Never hardcode secrets** - git history is forever
- **Use managed service** - Secrets Manager or Vault
- **Encrypt secrets** - use KMS or Vault encryption
- **Rotate regularly** - automate rotation every 30-90 days
- **Audit access** - log every secret read
- **Least privilege** - only apps that need secret can access
- **Incident response** - have plan for compromised secret

---

## 📚 Resources

- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
- [HashiCorp Vault](https://www.vaultproject.io/)
- [OWASP Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

---

## [⬅️ Day 075](../day075/) | [➡️ Day 077](../day077/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*