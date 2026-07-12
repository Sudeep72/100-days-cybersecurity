# Day 070 - AWS CloudTrail: Logging & Monitoring Everything

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Cloud Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

CloudTrail is AWS's audit log.

Every API call to AWS (console click, CLI command, API call) is logged.

If you don't have CloudTrail enabled, you're flying blind. A breach happens and you have no evidence.

**CloudTrail is the foundation of cloud security.**

---

## 📋 What CloudTrail Logs

### API Calls

```
Example: aws s3 ls

CloudTrail logs:

{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAJ45Q7YFFAREXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/alice",
    "accountId": "123456789012",
    "invokeId": "alice",
    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "sessionContext": {
      "sessionIssueTime": "2024-01-15T10:30:00Z",
      "webIdFederationData": {},
      "attributes": {
        "mfaAuthenticated": "false",
        "creationDate": "2024-01-15T10:30:00Z"
      }
    }
  },
  "eventTime": "2024-01-15T10:30:45Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "ListBuckets",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "192.0.2.1",
  "userAgent": "aws-cli/2.13.0",
  "requestParameters": null,
  "responseElements": null,
  "additionalEventData": null,
  "requestId": "EXAMPLE3E-12CF-11E3-895E-UE5E7EXAMPLE",
  "eventID": "1",
  "eventType": "AwsApiCall",
  "recipientAccountId": "123456789012"
}
```

**Records:**
- WHO made the call (user, role, IP)
- WHAT they did (ListBuckets)
- WHEN they did it (2024-01-15T10:30:45Z)
- FROM WHERE (192.0.2.1)
- RESULT (success, error)

### Management Events vs. Data Events

```
Management Events (default, always logged):
├─ IAM changes (create user, attach policy)
├─ EC2 operations (start instance, modify security group)
├─ S3 bucket operations (create bucket, change ACL)
├─ RDS operations (create database, modify parameters)
└─ Everything that changes configuration

Data Events (optional, high volume):
├─ S3 GetObject, PutObject (who accessed what files)
├─ DynamoDB GetItem, PutItem
├─ Lambda Invoke
└─ High volume (can be expensive to log)
```

---

## 🚀 CloudTrail Setup

### Enable CloudTrail (Organization-wide)

```bash
# Enable CloudTrail in organization
aws cloudtrail put-organization-trail \
  --name "organization-trail" \
  --s3-bucket-name "cloudtrail-logs-bucket" \
  --is-multi-region-trail \
  --enable-log-file-validation

# Verify
aws cloudtrail describe-trails
```

### Send Logs to S3 (Immutable)

```bash
# Create S3 bucket for CloudTrail logs
aws s3api create-bucket \
  --bucket cloudtrail-logs-123456789012 \
  --region us-east-1

# Block public access
aws s3api put-public-access-block \
  --bucket cloudtrail-logs-123456789012 \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Enable versioning (prevent deletion)
aws s3api put-bucket-versioning \
  --bucket cloudtrail-logs-123456789012 \
  --versioning-configuration Status=Enabled

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket cloudtrail-logs-123456789012 \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

# Enable MFA delete (prevent deletion without MFA)
aws s3api put-bucket-versioning \
  --bucket cloudtrail-logs-123456789012 \
  --versioning-configuration Status=Enabled,MFADelete=Enabled
```

### Send Logs to CloudWatch

```bash
# Create IAM role for CloudTrail to write logs
aws iam create-role \
  --role-name CloudTrailCloudWatchRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }]
  }'

# Create log group
aws logs create-log-group \
  --log-group-name /aws/cloudtrail/organization

# Configure CloudTrail to send to CloudWatch
aws cloudtrail put-event-selectors \
  --trail-name organization-trail \
  --log-file-validation-enabled \
  --cloud-watch-logs-group-arn "arn:aws:logs:us-east-1:123456789012:log-group:/aws/cloudtrail/organization:*" \
  --cloud-watch-logs-role-arn "arn:aws:iam::123456789012:role/CloudTrailCloudWatchRole"
```

---

## 🔍 Parsing CloudTrail Logs

### Query with CloudTrail Insights

```
Detects unusual activity automatically:
├─ Unusual API call patterns
├─ Error rate spikes
├─ Resource creation spikes
└─ Access pattern changes
```

### Query with Athena (SQL)

```sql
-- Find all IAM user creations
SELECT
  userIdentity.principalId,
  eventTime,
  sourceIPAddress,
  requestParameters
FROM cloudtrail_logs
WHERE eventName = 'CreateUser'
ORDER BY eventTime DESC;

-- Find all S3 bucket deletions
SELECT
  userIdentity.principalId,
  eventTime,
  sourceIPAddress,
  requestParameters
FROM cloudtrail_logs
WHERE eventName = 'DeleteBucket';

-- Find all console logins
SELECT
  userIdentity.principalId,
  eventTime,
  sourceIPAddress,
  userAgent
FROM cloudtrail_logs
WHERE eventName = 'ConsoleLogin'
ORDER BY eventTime DESC;

-- Find all failed API calls
SELECT
  userIdentity.principalId,
  eventName,
  errorCode,
  errorMessage,
  sourceIPAddress
FROM cloudtrail_logs
WHERE errorCode IS NOT NULL
ORDER BY eventTime DESC;
```

### Query with CloudWatch Logs Insights

```
# High-volume API calls from single source
fields sourceIPAddress, eventName, @timestamp
| stats count() as count by sourceIPAddress, eventName
| filter count > 100
| sort count desc

# IAM changes by user
fields userIdentity.principalId, eventName, @timestamp
| filter eventSource = 'iam.amazonaws.com'
| stats count() as count by userIdentity.principalId, eventName
| sort count desc

# Failed authentication attempts
fields sourceIPAddress, userIdentity.principalId, @timestamp
| filter errorCode like /Unauthorized|Forbidden|AccessDenied/
| stats count() as failed_attempts by sourceIPAddress
| filter failed_attempts > 10
```

---

## 📊 Key Metrics to Monitor

```
API Anomalies:
├─ Unusual geographic location (API call from Russia when user is in US)
├─ Unusual time of day (2am API calls for dayshift worker)
├─ Unusual volume (1000 API calls in 1 minute)
├─ Unusual user agent (CLI from never-used IP)
└─ Unusual service (user accessing EC2 when they normally use S3)

Configuration Changes:
├─ IAM user/role creation
├─ Policy attachment/modification
├─ Security group modification
├─ RDS parameter change
├─ S3 bucket ACL/policy change
└─ VPC change

Sensitive Actions:
├─ Assume role (cross-account access)
├─ Create/delete backups
├─ Disable logging
├─ Delete logs
├─ Delete resources (especially backups)
└─ Modify credentials

Red Flags:
├─ CloudTrail disabled
├─ CloudTrail logs deleted
├─ S3 bucket ACL changed to public
├─ Root account activity
├─ MFA disabled
├─ Mass resource deletion
└─ Bulk data download
```

---

## 🚨 Detection Rules (CloudWatch Logs)

```
Rule 1: CloudTrail Disabled
{
  ($.eventName = DeleteTrail) ||
  ($.eventName = StopLogging) ||
  ($.eventName = DeleteFlowLogs)
}
Action: CRITICAL alert (attacker hiding tracks)

Rule 2: IAM User Created
{
  ($.eventName = CreateUser) &&
  ($.requestParameters.userName != "expected-admin")
}
Action: High alert (unauthorized user creation)

Rule 3: Root Account Activity
{
  ($.userIdentity.type = "Root") &&
  ($.eventName != "ConsoleLogin")
}
Action: Critical alert (root doing something other than login)

Rule 4: S3 ACL Modified to Public
{
  ($.eventName = PutBucketAcl) &&
  ($.requestParameters.bucketName = "*") &&
  ($.requestParameters.acl = "public-read")
}
Action: High alert (bucket exposed to internet)

Rule 5: Large Data Download
{
  ($.eventName = GetObject) &&
  ($.requestParameters.key = "*") &&
  (count > 1000) in 5 minutes
}
Action: High alert (possible exfiltration)

Rule 6: MFA Disabled
{
  ($.eventName = DeactivateMFADevice)
}
Action: Critical alert (account security reduced)

Rule 7: Assume Role (Cross-Account)
{
  ($.eventName = AssumeRole) &&
  ($.userIdentity.accountId != $.requestParameters.roleArn.accountId)
}
Action: Medium alert (cross-account access)

Rule 8: Mass Deletion
{
  ($.eventName = "Delete*") &&
  (count > 10) in 1 minute
}
Action: Critical alert (potential ransomware or sabotage)
```

---

## 📋 CloudTrail Security Checklist

```
Enablement
☐ CloudTrail enabled on all accounts
☐ Multi-region trail (covers all regions)
☐ Organization trail (covers all accounts)
☐ Management events logged (configuration changes)
☐ Data events logged (S3, DynamoDB - optional but recommended)

Log Storage
☐ S3 bucket for logs is private (Block Public Access enabled)
☐ S3 bucket versioning enabled (prevent deletion)
☐ S3 bucket encryption enabled (AES-256)
☐ S3 bucket MFA delete enabled (prevent accidental deletion)
☐ S3 bucket has separate account (defense in depth)

Log Integrity
☐ Log file validation enabled (detect tampering)
☐ Logs sent to CloudWatch (real-time monitoring)
☐ Logs sent to Splunk/ELK (long-term analysis)
☐ Logs retained (1-7 years depending on compliance)

Monitoring
☐ CloudTrail Insights enabled (automatic anomaly detection)
☐ CloudWatch alarms on critical events
☐ Athena queries run regularly (manual threat hunting)
☐ Dashboard for CloudTrail metrics
☐ Integration with SIEM (Splunk, ELK, etc.)

Alerting
☐ Alert on CloudTrail disabled/logs deleted
☐ Alert on IAM user creation
☐ Alert on root account activity
☐ Alert on S3 public access
☐ Alert on privilege escalation attempts
☐ Alert on cross-account access
☐ Alert on mass deletion
☐ Alert on unusual geographic locations

Incident Response
☐ Playbook for CloudTrail-based incidents
☐ Procedures for log analysis
☐ Procedures for evidence preservation
☐ Integration with IR tools
```

---

## 🔑 Key Takeaways

- **CloudTrail is mandatory** - no exceptions, no excuses
- **Logs must be immutable** - S3 versioning + MFA delete prevents attacker deletion
- **Real-time monitoring** - CloudWatch Logs Insights catches attacks as they happen
- **Threat hunting** - Athena queries find patterns humans would miss
- **Log retention matters** - GDPR/HIPAA require 1-7 years of logs
- **Disable detection** - attackers will try to disable CloudTrail first

---

## 📚 Resources

- [AWS CloudTrail Best Practices](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html)
- [CloudTrail Log Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/eventlog.html)
- [CloudTrail Insights](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-insights-events.html)

---

## [⬅️ Day 069](../day069/) | [➡️ Day 071](../day071/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*