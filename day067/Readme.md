# Day 067 - AWS IAM: Permissions, Roles & Least Privilege

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Cloud Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

AWS IAM (Identity & Access Management) is the most critical control in cloud security.

Get IAM right, and 90% of cloud security problems disappear.

Get IAM wrong, and an attacker with 1 compromised credential has full access to your AWS account.

**IAM defines:** Who can do what, on which resources, from where, and under what conditions.

---

## 🔑 IAM Concepts

### Users vs. Roles

```
IAM User
├─ Real person or application
├─ Has permanent credentials (access key, password)
├─ Example: engineer@company.com
├─ Credentials stay until you revoke them
└─ Risk: Credentials can leak and stay valid for months

IAM Role
├─ Does NOT have permanent credentials
├─ Temporary credentials (valid for 1 hour by default)
├─ Assumed by user/service/Lambda
├─ Example: EC2-to-S3-access role
├─ Credentials auto-expire
└─ Lower risk: Credentials expire automatically
```

### Policies

```
A policy is a JSON document that defines permissions:

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}

Components:
├─ Effect: Allow or Deny
├─ Action: What API calls are allowed
├─ Resource: Which resources (buckets, instances, etc.)
├─ Condition: Additional restrictions (IP, time, MFA)
└─ Principal: Who this applies to (user, role, service)
```

### Least Privilege

```
Principle: Give user ONLY the permissions they need, nothing more.

WRONG:
├─ Developer gets AdministratorAccess (full AWS account access)
├─ Developer only needs to push to S3 and read logs
├─ If credential compromised: attacker has full access

RIGHT:
├─ Developer gets role with:
│  ├─ s3:PutObject on specific bucket
│  ├─ logs:DescribeLogGroups on specific log group
│  └─ Nothing else
└─ If credential compromised: attacker can only use S3 + logs

Cost of mistake:
├─ Developer AWS key leaked on GitHub
├─ Attacker assumes their role
├─ Attacker: SpinUp 1000 GPU instances
├─ Bill: $100,000 in 2 hours
└─ Root cause: Over-privileged developer account
```

---

## 🏗️ IAM Architecture

```
AWS Account Root
├─ Email + password only
├─ Full access (don't use for daily work!)
└─ Enable MFA immediately

├─ Users (people)
│  ├─ Engineer (developer role)
│  ├─ Operations (DevOps role)
│  └─ Finance (read-only access to billing)
│
├─ Roles (for services/cross-account)
│  ├─ EC2-to-S3 (EC2 reads from S3)
│  ├─ Lambda-to-DynamoDB (Lambda writes to DB)
│  └─ Cross-Account (another company's AWS account)
│
└─ Groups (organize users)
   ├─ Developers (DeveloperPolicy)
   ├─ DevOps (DevOpsPolicy)
   └─ Finance (BillingViewerPolicy)
```

---

## 🔐 IAM Best Practices

### 1. Never Use Root Account

```
Root account = email + password

WRONG:
├─ Using root for daily work
├─ Storing root credentials
├─ Sharing root credentials
└─ Root account without MFA

RIGHT:
├─ Create IAM users for daily work
├─ Lock root account (secure, rarely accessed)
├─ Root = emergency only
├─ Root always has MFA enabled
└─ Store root credentials in secure vault
```

### 2. Enforce MFA Everywhere

```
All users should have MFA:
├─ Console login: MFA device (phone app, hardware key)
├─ API access: MFA device (for sensitive operations)
├─ Admin users: Hardware MFA key (U2F, Yubikey)
└─ Enforce via SCP (Service Control Policy)

Why:
├─ Password leaked? MFA stops attacker.
├─ Brute force attack? MFA stops attacker.
├─ Phishing? Attacker needs actual MFA device (hard).
└─ Cost of MFA: $0. Cost of account compromise: millions.
```

### 3. Use Roles, Not Users for Applications

```
WRONG:
resource "aws_iam_user" "app_user" {
  name = "myapp"
}

resource "aws_iam_access_key" "app_key" {
  user = aws_iam_user.app_user.name
}

Problem:
├─ Credentials hardcoded in application
├─ Credentials never expire (until manually rotated)
├─ Credentials leaked = full access to attacker

RIGHT:
resource "aws_iam_role" "app_role" {
  name = "myapp"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

Benefit:
├─ EC2 assumes role automatically
├─ Temporary credentials (1 hour)
├─ Credentials auto-expire
├─ Application never stores credentials
└─ Attacker can't get long-lived creds
```

### 4. Implement Least Privilege

```
Step 1: Identify what the user needs
├─ Developer needs: push code to CodeCommit, read logs

Step 2: Create minimal policy
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codecommit:GitPush",
        "codecommit:PutFile"
      ],
      "Resource": "arn:aws:codecommit:us-east-1:123456789:my-repo"
    },
    {
      "Effect": "Allow",
      "Action": "logs:DescribeLogStreams",
      "Resource": "arn:aws:logs:us-east-1:123456789:log-group:/myapp:*"
    }
  ]
}

Step 3: Attach to user
Step 4: Verify user can do their job
Step 5: Verify user CANNOT do anything else
```

### 5. Regular Access Reviews

```
Quarterly access reviews:
├─ Does this developer still need S3 access? No → remove
├─ Does this contractor still work here? No → deactivate
├─ Does this role still exist? No → delete
├─ Are there dormant IAM users? Yes → clean up
└─ Do permission boundaries match current role?

Automation:
├─ AWS IAM Access Analyzer (shows unused permissions)
├─ Custom scripts (inventory all users + last login time)
├─ Deactivate > 30 days inactive
└─ Delete > 90 days inactive
```

---

## 🚨 Common IAM Mistakes

### 1. Overly Permissive Policies

```
WRONG:
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
}

This grants all S3 actions on all buckets.
Attacker with this: can delete all backups, exfiltrate all data.

RIGHT:
{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:PutObject"
  ],
  "Resource": "arn:aws:s3:::my-bucket/uploads/*"
}

Only GetObject + PutObject on specific bucket and path.
```

### 2. Inline Policies

```
WRONG:
Attaching policies directly to user (inline policies).

Problem:
├─ Hard to reuse (same policy on 100 users = manual work)
├─ Hard to modify (change 1 permission = update 100 users)
├─ Hard to audit (policy buried in user config)

RIGHT:
Create managed policy:
├─ Give policy descriptive name
├─ Attach to users/roles
├─ Update once = affects all users
├─ Easy to audit (policy is independent resource)
```

### 3. Credential Rotation Not Enforced

```
WRONG:
Developer creates access key in 2023.
Never rotates it.
In 2024, they accidentally push it to GitHub.
Key is still valid (now 1 year old).
Attacker uses it.

RIGHT:
Enforce credential rotation:
├─ Create policy requiring keys < 90 days old
├─ AWS: iam:GetAccessKeyLastUsed (check age)
├─ Automate key rotation (create new, retire old)
├─ SCP can enforce deletion of old keys

Example SCP:
{
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "NumericLessThan": {
      "aws:AccessKeyAge": "7776000"  # 90 days in seconds
    }
  }
}
```

### 4. Cross-Account Access Without Conditions

```
WRONG:
Account A trusts Account B (completely).
Developer in Account B can access everything in Account A.

Problem:
├─ No separation of duties
├─ No condition restrictions (time, IP, MFA)
├─ Account B compromise = Account A compromise

RIGHT:
Trust Account B, but with conditions:
├─ Require MFA
├─ Restrict to specific IP range
├─ Restrict to specific time window
├─ Restrict to specific resources

Example:
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::ACCOUNT-B:role/developer"
  },
  "Action": "sts:AssumeRole",
  "Condition": {
    "IpAddress": {
      "aws:SourceIp": "10.0.0.0/8"
    },
    "Bool": {
      "aws:MultiFactorAuthPresent": "true"
    }
  }
}
```

---

## 📋 IAM Security Checklist

```
Root Account
☐ Root account email is secure (strong password)
☐ Root account has MFA enabled
☐ Root account credentials locked in vault
☐ Root account rarely used (emergency only)
☐ CloudTrail monitoring root account usage

Users
☐ No root account usage for daily work
☐ Users have only required permissions (least privilege)
☐ All users have MFA enabled
☐ Unused users are deactivated/deleted
☐ Inactive users (>30 days) flagged for review

Access Keys
☐ Access keys < 90 days old
☐ Unused access keys are deleted
☐ Keys are rotated on schedule
☐ No keys in code or configs (use roles)
☐ Old keys are deactivated before deletion

Policies
☐ Policies use managed, not inline
☐ Policies follow least privilege principle
☐ Overly permissive actions (*, "All") removed
☐ Resource ARNs are specific (not *)
☐ Wildcard resources limited to necessary actions

Roles
☐ Applications use roles, not users
☐ Cross-account access has conditions (MFA, IP, time)
☐ Trust relationships are minimal
☐ Service roles have time-limited credentials

Monitoring
☐ CloudTrail logs all IAM changes
☐ Alerts on suspicious IAM activity
☐ Quarterly access reviews scheduled
☐ IAM Access Analyzer findings reviewed
☐ CloudTrail integrity validation enabled
```

---

## 🔑 Key Takeaways

- **IAM is your first line of defense** - get it right, and most attacks are prevented
- **Least privilege prevents damage** - compromise affects only what that credential can access
- **Roles expire, users don't** - use roles for applications, users for people
- **MFA is non-negotiable** - single line of defense against credential theft
- **Access reviews are mandatory** - old credentials and unused users are liabilities
- **Audit everything** - CloudTrail is your best friend

---

## 📚 Resources

- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
- [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer.html)

---

## [⬅️ Day 066](../day066/) | [➡️ Day 068](../day068/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*