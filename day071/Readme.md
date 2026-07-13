# Day 071 - AWS GuardDuty: Intelligent Threat Detection

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Cloud Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

GuardDuty is AWS's threat detection service.

It analyzes CloudTrail, VPC Flow Logs, and DNS logs to find suspicious patterns.

Machine learning finds attacks you might miss.

---

## 🤖 How GuardDuty Works

```
Data Sources:
├─ CloudTrail logs (API activity)
├─ VPC Flow Logs (network traffic)
├─ DNS logs (domain queries)
└─ S3 data protection

Machine Learning:
├─ Detects unusual API patterns (anomaly detection)
├─ Detects known threats (threat intel database)
├─ Detects network anomalies (traffic baseline)
├─ Detects cryptocurrency mining (compute anomalies)
└─ Detects privilege escalation (IAM pattern changes)

Output:
├─ Findings (potential threats)
├─ Severity levels (Low, Medium, High)
├─ Recommended actions
└─ Integration with SIEM
```

---

## 🚨 Finding Types

### Finding Type 1: Cryptocurrency Mining

```
Finding: EC2/CryptoCurrency.B!DNS
Severity: HIGH

What it detects:
├─ EC2 instance querying known cryptocurrency mining pools
├─ High CPU usage on instance
├─ Outbound connections to mining infrastructure
└─ Unusual network patterns from instance

Example:
{
  "finding_type": "EC2/CryptoCurrency.B!DNS",
  "severity": "HIGH",
  "title": "EC2 instance is performing DNS lookups associated with cryptocurrency mining pools",
  "description": "EC2 instance i-1234567890abcdef0 is performing DNS lookups associated with cryptocurrency mining pools",
  "instance_id": "i-1234567890abcdef0",
  "domain_names": [
    "stratum.mining.pool.example.com",
    "mining.pool2.example.com"
  ]
}

Action:
├─ Isolate instance (security group: deny all)
├─ Capture forensics (memory, disk)
├─ Analyze for rootkit/malware
├─ Terminate if confirmed
└─ Investigate lateral movement
```

### Finding Type 2: Suspicious IAM Activity

```
Finding: IAM/AnomalousAPICall.Unauthorized
Severity: MEDIUM

What it detects:
├─ User making API calls they never made before
├─ Unusual API patterns for role
├─ Privilege escalation attempts
└─ Cross-account access anomalies

Example:
{
  "finding_type": "IAM/AnomalousAPICall.Unauthorized",
  "severity": "MEDIUM",
  "title": "An IAM user principal has attempted to assume an IAM role that is associated with an unusual resource",
  "principal_id": "AIDAJ45Q7YFFAREXAMPLE",
  "api_calls": [
    "AssumeRole",
    "GetSecurityCredential"
  ],
  "target_role": "arn:aws:iam::123456789012:role/AdminRole"
}

Action:
├─ Review IAM policy changes
├─ Check for privilege escalation
├─ Verify if user should have cross-account access
├─ Consider revoking credentials
└─ Review what user accessed with new permissions
```

### Finding Type 3: Suspicious Network Activity

```
Finding: EC2/MaliciousIPCaller
Severity: HIGH

What it detects:
├─ Instance communicating with known malicious IP
├─ Command & Control (C2) communication
├─ Botnet activity
└─ Exploit server communication

Example:
{
  "finding_type": "EC2/MaliciousIPCaller",
  "severity": "HIGH",
  "title": "EC2 instance i-1234567890abcdef0 is communicating with IP 203.0.113.1 which is known to be malicious",
  "instance_id": "i-1234567890abcdef0",
  "remote_ip": "203.0.113.1",
  "port": 443,
  "threat_name": "Backdoor.Linux!C2",
  "threat_purpose": "Command & Control"
}

Action:
├─ Isolate instance immediately
├─ Capture all connections (VPC Flow Logs)
├─ Analyze what commands were executed
├─ Check for data exfiltration
├─ Investigate how malware got there
└─ Rebuild instance from clean backup
```

### Finding Type 4: Suspicious S3 Activity

```
Finding: S3/BucketEnumeration.Likely
Severity: MEDIUM

What it detects:
├─ User/role enumerating S3 buckets
├─ Attempting access to restricted buckets
├─ Unauthorized S3 operations
└─ Potential data reconnaissance

Example:
{
  "finding_type": "S3/BucketEnumeration.Likely",
  "severity": "MEDIUM",
  "title": "A principal has executed a high volume of S3 operations, which may indicate reconnaissance activity",
  "principal_id": "AIDAJ45Q7YFFAREXAMPLE",
  "operation": "ListBuckets",
  "operations_count": 1000,
  "time_period": "5 minutes"
}

Action:
├─ Check if user should be accessing S3
├─ Review S3 access logs
├─ Check for data downloads
├─ Consider restricting S3 permissions
└─ Investigate intent
```

---

## 🔧 GuardDuty Setup

### Enable GuardDuty (Organization-wide)

```bash
# Enable on single account
aws guardduty create-detector \
  --finding-publishing-frequency FIFTEEN_MINUTES \
  --enable

# Enable for entire organization
aws organizations enable-all-features
aws guardduty create-organization-admin-account \
  --admin-account-id 123456789012

# Enable on all accounts in organization
aws guardduty create-members \
  --detector-id <detector-id> \
  --account-details '[{
    "AccountId": "111111111111",
    "Email": "security@account1.example.com"
  }]'
```

### Configure Findings

```bash
# Set finding publishing frequency
aws guardduty update-detector \
  --detector-id <detector-id> \
  --finding-publishing-frequency FIFTEEN_MINUTES  # or HOURLY, or SIX_HOURS

# Export findings to CloudWatch
# (automatic on creation)

# Export findings to S3 (for long-term storage)
aws guardduty create-publishing-destination \
  --detector-id <detector-id> \
  --destination-type S3 \
  --destination-properties 'DestinationArn=arn:aws:s3:::guardduty-findings'
```

### Integrate with SIEM

```bash
# Create CloudWatch event rule for GuardDuty findings
aws events put-rule \
  --name guardduty-findings \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "severity": [4, 7, 8]  # High and medium severity
    }
  }' \
  --state ENABLED

# Send findings to SNS (alerts)
aws events put-targets \
  --rule guardduty-findings \
  --targets "Id"="1","Arn"="arn:aws:sns:us-east-1:123456789012:guardduty-alerts"

# Send findings to EventBridge for Lambda processing
# (can auto-remediate suspicious findings)
```

---

## 📊 GuardDuty Finding Severity

```
Low Severity (Informational)
├─ Unusual activity but not immediately threatening
├─ Requires investigation but not emergency
└─ Example: Unusual API call pattern

Medium Severity (Investigation Needed)
├─ Suspicious behavior, likely security issue
├─ Should be reviewed within hours
└─ Example: IAM privilege escalation attempt

High Severity (Critical)
├─ Strong evidence of attack
├─ Requires immediate action
├─ Example: C2 communication, cryptocurrency mining, data exfiltration
```

---

## 🛡️ Auto-Remediation with GuardDuty

```python
# Lambda function to auto-remediate GuardDuty findings

import boto3
import json

guardduty = boto3.client('guardduty')
ec2 = boto3.client('ec2')

def lambda_handler(event, context):
    # Parse GuardDuty finding
    finding = event['detail']
    
    # Extract details
    severity = finding['severity']
    finding_type = finding['type']
    instance_id = finding.get('resource', {}).get('instanceDetails', {}).get('instanceId')
    
    # Auto-remediation for HIGH severity findings
    if severity == 8 and instance_id:  # 8 = HIGH
        if 'CryptoCurrency' in finding_type:
            # Isolate instance (remove from security group)
            ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=['sg-isolated']  # sg with no outbound access
            )
            print(f"Isolated instance {instance_id} due to cryptomining")
        
        elif 'MaliciousIPCaller' in finding_type:
            # Terminate compromised instance
            ec2.terminate_instances(InstanceIds=[instance_id])
            print(f"Terminated instance {instance_id} due to C2 communication")
    
    # Notify security team
    sns = boto3.client('sns')
    sns.publish(
        TopicArn='arn:aws:sns:us-east-1:123456789012:security-alerts',
        Subject=f'GuardDuty Finding: {finding_type}',
        Message=json.dumps(finding, indent=2)
    )
    
    return {
        'statusCode': 200,
        'body': 'GuardDuty finding processed'
    }
```

---

## 📋 GuardDuty Best Practices

```
Enablement
☐ GuardDuty enabled on all accounts
☐ Enabled at organization level (applies to all accounts)
☐ 30-day trial to evaluate (free, non-invasive)
☐ Findings exported to S3 (long-term retention)

Configuration
☐ Finding publishing frequency: 15 minutes (real-time alerts)
☐ Finding retention: >= 90 days
☐ Malware protection: Enabled (scans EBS volumes)
☐ S3 protection: Enabled (scans S3 access patterns)

Monitoring
☐ High/Medium findings trigger alerts (SNS, email)
☐ All findings exported to CloudWatch Logs
☐ Dashboard for GuardDuty metrics
☐ Weekly review of findings summary

Response
☐ Playbook for High severity findings
☐ Incident response on C2, cryptomining, privilege escalation
☐ Auto-remediation for critical findings (Lambda)
☐ Integration with SIEM (Splunk, ELK)

Improvement
☐ Quarterly review of false positives (tune alerts)
☐ Machine learning feedback (mark findings as accurate/inaccurate)
☐ Threat intel updates (GuardDuty automatically updates)
☐ Coverage gaps (what findings are we missing?)
```

---

## 🔑 Key Takeaways

- **GuardDuty detects what humans miss** - ML finds patterns across millions of events
- **Real-time alerts** - findings published every 15 minutes
- **No infrastructure to manage** - AWS-managed, automatic updates
- **Cost-effective** - pay per finding, usually < $1000/month
- **Integration-friendly** - works with SIEM, SOAR, Lambda
- **Machine learning improves over time** - better detection as it learns your baseline

---

## 💰 Cost Model

```
GuardDuty pricing:
├─ CloudTrail: $2 per 100,000 events
├─ VPC Flow Logs: $0.50 per GB
├─ DNS Logs: Included
└─ Malware Protection: $5 per instance/month

Typical organization (50 accounts):
├─ CloudTrail cost: ~$500/month
├─ VPC Flow Logs cost: ~$200/month (depends on traffic)
├─ Malware Protection: ~$250/month (50 instances × $5)
└─ Total: ~$950/month

Benefit:
├─ Detects: Cryptocurrency mining ($10K+ stolen)
├─ Detects: Unauthorized access (prevents breach)
├─ Detects: Data exfiltration (catches before large download)
└─ ROI: 50-100x (one prevented incident pays for years of GuardDuty)
```

---

## 📚 Resources

- [AWS GuardDuty Documentation](https://docs.aws.amazon.com/guardduty/)
- [GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-findings.html)
- [GuardDuty Best Practices](https://docs.aws.amazon.com/guardduty/latest/ug/best-practices.html)

---

## [⬅️ Day 070](../day070/) | [➡️ Day 072](../day072/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*