# Day 068 - S3 Misconfigurations: A Real-World Epidemic

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Cloud Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Amazon S3 (Simple Storage Service) is the most commonly used AWS service.

And it's misconfigured constantly.

**Public S3 buckets** are the #1 cause of data breaches from cloud misconfigurations.

A bucket that's meant to be private gets set to public by accident. Then millions of records leak.

---

## 🔓 How S3 Gets Misconfigured

### 1. Accidental Public ACL

```
Default S3 bucket: PRIVATE (good)

Developer accidentally runs:
aws s3api put-bucket-acl --bucket my-bucket --acl public-read

Now: EVERYONE on the internet can read every file.

Result:
├─ Attacker scans for public buckets (takes 1 second)
├─ Finds your bucket
├─ Reads all files
├─ Extracts data
└─ Sells on dark web

Cost: Millions in breach notification, fines, lawsuits
```

### 2. Public Bucket Policy

```
Developer intends to allow CloudFront to read bucket:

{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::my-bucket/*"
}

But uses Principal: "*" instead of CloudFront's service principal.

Result: ANYONE can read bucket.

Better:
{
  "Effect": "Allow",
  "Principal": {
    "Service": "cloudfront.amazonaws.com"
  },
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::my-bucket/*"
}

Only CloudFront can read, not the internet.
```

### 3. Logging Disabled

```
S3 Bucket Access Logs:
├─ Record who accessed what files
├─ Record when access happened
├─ Record success/failure
└─ Critical for detecting breaches

WRONG:
Bucket has no logging enabled.
Attacker reads all files.
You never know.
(No logs = no evidence)

RIGHT:
Enable access logging:
├─ Logs go to separate bucket (read-only)
├─ Can detect exfiltration
├─ Can recover from breach faster
└─ Have evidence for legal action
```

### 4. No Encryption

```
WRONG:
Bucket stores customer credit card numbers (unencrypted).
Attacker gains AWS access somehow.
Reads all files plaintext.
Steals 1 million credit cards.

RIGHT:
Bucket has encryption enabled (SSE-S3 or SSE-KMS):
├─ Data at rest is encrypted
├─ Attacker reads: gets encrypted bytes
├─ Useless without encryption key
└─ Customer data protected
```

### 5. No Versioning / MFA Delete

```
WRONG:
Bucket has no versioning.
Attacker overwrites all files (ransomware style).
Deletes originals permanently.
You have no backup.

RIGHT:
Enable versioning:
├─ Every change creates new version
├─ Can recover any old version
├─ Ransomware overwrites file? Restore old version.

Even better: Enable MFA Delete
├─ Deletion requires MFA
├─ Attacker can't delete without your phone
└─ Extra protection layer
```

---

## 📊 Real-World Breaches (S3 Misconfig)

```
Deep Purple (2017)
├─ Misconfigured S3 bucket
├─ 198 million voter records leaked
├─ Anyone could read bucket
├─ No credentials needed
└─ Cost: Incalculable

Capital One (2019)
├─ Misconfigured security group + S3 permissions
├─ 106 million customers' data exposed
├─ Attacker accessed logs, database credentials
├─ Attacker dumped entire database
└─ Cost: $100M+ in fines + settlement

Facebook (2019)
├─ 419 million phone numbers
├─ Stored in misconfigured S3 buckets
├─ Accessible to anyone
└─ Cost: Brand damage, FTC fines

Lessons:
├─ Misconfiguration = most common breach cause
├─ Not a sophisticated hack
├─ Not a zero-day exploit
├─ Just: wrong permission setting
└─ Affects millions of records
```

---

## 🔐 S3 Security Layers

### Layer 1: Block Public Access (AWS Account Level)

```
AWS setting that prevents ANY bucket from being public:

aws s3api put-account-public-access-block \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

Effect:
├─ Even if developer runs "put-bucket-acl public"
├─ AWS blocks it (account-level setting overrides)
├─ Bucket stays private
└─ Prevents accidental public buckets

RECOMMENDATION:
Enable on all AWS accounts. Non-negotiable.
```

### Layer 2: Bucket ACL (Private)

```
Default: PRIVATE (only owner can read)

Should only be changed if you have a specific reason.

aws s3api put-bucket-acl --bucket my-bucket --acl private
```

### Layer 3: Bucket Policy (Specific Access)

```
If you need to grant access, be SPECIFIC:

Right:
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::123456789012:user/specific-user"
  },
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::my-bucket/public/*"
}

Wrong:
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "*",
  "Resource": "*"
}
```

### Layer 4: Encryption

```
Enable by default:

aws s3api put-bucket-encryption \
  --bucket my-bucket \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

Or with KMS (your key):

aws s3api put-bucket-encryption \
  --bucket my-bucket \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/12345678"
      }
    }]
  }'
```

### Layer 5: Versioning & MFA Delete

```
Enable versioning:

aws s3api put-bucket-versioning \
  --bucket my-bucket \
  --versioning-configuration Status=Enabled

Enable MFA delete (requires root credentials + MFA):

aws s3api put-bucket-versioning \
  --bucket my-bucket \
  --versioning-configuration Status=Enabled,MFADelete=Enabled
```

### Layer 6: Access Logging

```
Enable S3 Access Logs:

aws s3api put-bucket-logging \
  --bucket my-bucket \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "my-logging-bucket",
      "TargetPrefix": "s3-access-logs/"
    }
  }'

Logs record:
├─ Who accessed (IP address, user)
├─ What files (object key)
├─ When (timestamp)
├─ Success/failure
└─ Bytes transferred
```

---

## 🔍 Audit: Find Misconfigured Buckets

```bash
# List all buckets
aws s3 ls

# Check each bucket's public access settings
for bucket in $(aws s3 ls | awk '{print $3}'); do
  echo "Checking $bucket..."
  
  # Check ACL
  aws s3api get-bucket-acl --bucket $bucket
  
  # Check bucket policy (should be private by default)
  aws s3api get-bucket-policy --bucket $bucket 2>/dev/null || echo "  No policy (good)"
  
  # Check block public access settings
  aws s3api get-public-access-block --bucket $bucket
  
  # Check encryption
  aws s3api get-bucket-encryption --bucket $bucket 2>/dev/null || echo "  No encryption!"
  
  # Check versioning
  aws s3api get-bucket-versioning --bucket $bucket
  
  # Check logging
  aws s3api get-bucket-logging --bucket $bucket 2>/dev/null || echo "  No logging!"
done
```

---

## 📋 S3 Security Checklist

```
Every S3 Bucket Should Have:

Access Control
☐ Block Public Access enabled (account-level + bucket-level)
☐ Bucket ACL set to PRIVATE
☐ Bucket policy reviewed (no "Principal": "*")
☐ Only specific IAM principals have access
☐ Regular access audits (quarterly)

Encryption
☐ Server-side encryption enabled (SSE-S3 or SSE-KMS)
☐ Client-side encryption for sensitive data
☐ KMS keys managed (not shared, rotated)
☐ Encryption keys have access controls (IAM)

Versioning & Recovery
☐ Versioning enabled
☐ MFA Delete enabled (for sensitive buckets)
☐ Backup bucket exists (separate account if possible)
☐ Retention policies defined (how long to keep?)
☐ Deletion protection enabled

Logging & Monitoring
☐ S3 Access Logs enabled
☐ CloudTrail logs S3 API calls
☐ Alerts configured (unexpected access)
☐ Logs retained (for compliance, typically 1-7 years)
☐ Logs are centralized (separate immutable bucket)

Governance
☐ Bucket naming convention (tags for owner, sensitivity)
☐ Bucket inventory (know what buckets exist)
☐ Bucket lifecycle policies (delete old objects)
☐ Cross-region replication (for DR)
☐ CORS configured (if needed, restricted)

Compliance
☐ Meets regulatory requirements (HIPAA, GDPR, PCI)
☐ Data classification applied (sensitivity labels)
☐ Encryption key rotation enabled
☐ Access documentation (who accesses, why)
☐ Audit trails preserved (immutable logs)
```

---

## 🔑 Key Takeaways

- **Public buckets are a real threat** - most common cloud data leak source
- **Misconfiguration, not compromise** - no hack needed, just wrong setting
- **Block Public Access is non-negotiable** - enable at account level
- **Encryption is your job** - AWS provides tools, you must use them
- **Logging catches breaches** - without logs, you don't know you're breached
- **Regular audits find gaps** - quarterly bucket reviews mandatory

---

## 🛠️ Tools

```
AWS tools:
├─ S3 Block Public Access (console, CLI, API)
├─ Access Analyzer (free, shows public/shared buckets)
├─ Config Rules (automated compliance checking)
└─ CloudTrail (logs all API calls)

Third-party:
├─ ScoutSuite (free cloud auditor)
├─ Prowler (free security auditor)
├─ CloudMapper (visualize AWS)
└─ Dome9 (CSPM platform)
```

---

## 📚 Resources

- [AWS S3 Security](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security.html)
- [S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [S3 Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/BestPractices.html)

---

## [⬅️ Day 067](../day067/) | [➡️ Day 069](../day069/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*