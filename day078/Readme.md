# Day 078 - IaC Security: Scanning Terraform for Misconfigurations

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Cloud Security | **Difficulty:** Intermediate-Advanced

---

## 🧠 The Concept

Infrastructure-as-Code (Terraform, CloudFormation, Kubernetes YAML) = infrastructure defined as code.

Same security principles apply as code security.

**IaC scanning = find misconfigurations before deployment**

```
Misconfigured Terraform → Scanned by tfsec → Vulnerabilities found → Developer fixes → Deployed secure
vs.
Misconfigured Terraform → Deployed → Attacker exploits → Breach
```

---

## 🔍 Common Terraform Misconfigurations

### 1. Public S3 Bucket

```hcl
# WRONG
resource "aws_s3_bucket" "data" {
  bucket = "company-data"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"  # ← Everyone can read!
}

# tfsec output:
# [aws-s3-block-public-acls] S3 Bucket does not have ACL set to block public access
# CRITICAL

# RIGHT
resource "aws_s3_bucket" "data" {
  bucket = "company-data"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### 2. Unencrypted Database

```hcl
# WRONG
resource "aws_db_instance" "prod" {
  allocated_storage    = 100
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  username            = "admin"
  password            = "insecure_password"
  storage_encrypted   = false  # ← NOT encrypted!
  publicly_accessible = true   # ← Exposed to internet!
}

# tfsec output:
# [aws-rds-enable-storage-encryption] RDS database is not encrypted
# CRITICAL
# [aws-rds-publicly-accessible-database] RDS database is publicly accessible
# CRITICAL

# RIGHT
resource "aws_db_instance" "prod" {
  allocated_storage    = 100
  engine              = "postgres"
  engine_version      = "14.7"
  instance_class      = "db.t3.medium"
  username            = "admin"
  password            = random_password.db.result
  storage_encrypted   = true
  kms_key_id          = aws_kms_key.db.arn
  publicly_accessible = false
  multi_az            = true
  backup_retention_period = 30
}

resource "random_password" "db" {
  length  = 32
  special = true
}
```

### 3. Overly Permissive Security Group

```hcl
# WRONG
resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # ← ANYONE can access!
  }
}

# tfsec output:
# [aws-vpc-no-public-ingress-sgr] An ingress security group rule allows traffic from /0
# HIGH

# RIGHT
resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Only HTTP
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Only HTTPS
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

### 4. No Logging

```hcl
# WRONG
resource "aws_s3_bucket" "data" {
  bucket = "company-data"
  # Missing: access logging, versioning
}

# tfsec output:
# [aws-s3-enable-bucket-logging] S3 bucket does not have logging enabled
# MEDIUM

# RIGHT
resource "aws_s3_bucket" "data" {
  bucket = "company-data"
}

resource "aws_s3_bucket_logging" "data" {
  bucket = aws_s3_bucket.data.id

  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "data-logs/"
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id

  versioning_configuration {
    status = "Enabled"
  }
}
```

### 5. Hardcoded Secrets

```hcl
# WRONG
resource "aws_db_instance" "prod" {
  password = "MyPassword123!"  # ← Hardcoded!
}

# tfsec output:
# [aws-rds-hardcoded-db-password] RDS database has a hardcoded password
# CRITICAL

# RIGHT
resource "random_password" "db" {
  length  = 32
  special = true
}

resource "aws_secretsmanager_secret" "db_password" {
  name = "prod/database/password"
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id      = aws_secretsmanager_secret.db_password.id
  secret_string  = random_password.db.result
}

resource "aws_db_instance" "prod" {
  password = random_password.db.result
  # Password automatically stored in Secrets Manager
}
```

---

## 🛠️ IaC Scanning Tools

### tfsec (Terraform-Specific)

```bash
# Install
wget https://github.com/aquasecurity/tfsec/releases/download/v1.26.0/tfsec-linux-amd64
chmod +x tfsec-linux-amd64

# Scan
./tfsec-linux-amd64 . -f json > report.json

# Output:
# [aws-s3-block-public-acls] S3 Bucket does not have ACL set to block public access
# File: main.tf:10-15
# Severity: CRITICAL
# Remediation: Enable block_public_access_block
```

### Checkov (Multi-Cloud)

```bash
# Install
pip install checkov

# Scan
checkov -d . --framework terraform --output json > report.json

# Output:
# Check: CKV_AWS_20 "S3 Bucket has public access block"
# FAILED for resource: aws_s3_bucket.data
# File: main.tf:1-10
```

### Terraform Validate (Built-in)

```bash
# Basic validation
terraform validate

# Output:
# Success! The configuration is valid.
# or
# Error: Unsupported block type
```

---

## 🚀 CI/CD Integration

```yaml
# GitHub Actions: IaC Security
name: IaC Security
on: [pull_request, push]

jobs:
  terraform:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Terraform Format Check
        run: terraform fmt -check -recursive

      - name: Terraform Validate
        run: terraform validate

      - name: tfsec Scan
        run: |
          wget https://github.com/aquasecurity/tfsec/releases/download/v1.26.0/tfsec-linux-amd64
          chmod +x tfsec-linux-amd64
          ./tfsec-linux-amd64 . --format json > tfsec-report.json
          # Fail on CRITICAL findings
          if grep -q '"severity":"CRITICAL"' tfsec-report.json; then
            cat tfsec-report.json | jq '.[] | select(.severity=="CRITICAL")'
            exit 1
          fi

      - name: Checkov Scan
        run: |
          pip install checkov
          checkov -d . --framework terraform --output json > checkov-report.json
          # Fail on high-severity findings
          if grep -q '"check_result":{"result":"failed"}' checkov-report.json; then
            exit 1
          fi

      - name: Plan & Review
        if: github.event_name == 'pull_request'
        run: |
          terraform init
          terraform plan -out=tfplan
          # Show plan in PR comment
          echo "## Terraform Plan" >> $GITHUB_STEP_SUMMARY
          terraform show -no-color tfplan >> $GITHUB_STEP_SUMMARY
```

---

## 📋 IaC Security Checklist

```
Storage (S3)
☐ Block public access enabled (account + bucket level)
☐ Bucket ACL set to private
☐ Encryption enabled (SSE-S3 or SSE-KMS)
☐ Versioning enabled
☐ Access logging enabled
☐ Lifecycle policies configured
☐ MFA delete enabled (optional)

Compute (EC2)
☐ Security groups follow least privilege
☐ No SSH/RDP from 0.0.0.0/0
☐ EBS encryption enabled
☐ IMDSv2 required (for metadata access)
☐ Instance role has least privilege

Databases (RDS)
☐ Encryption enabled
☐ KMS key (not AWS-managed)
☐ Multi-AZ enabled
☐ Backup retention >= 30 days
☐ Publicly accessible = false
☐ Enhanced monitoring enabled

Networking (VPC)
☐ Private subnets for databases
☐ NAT Gateway for outbound
☐ Network ACLs configured
☐ VPC Flow Logs enabled

IAM
☐ No wildcard actions (*)
☐ No wildcard resources (*)
☐ Specific resource ARNs
☐ Conditions on cross-account access
☐ Inline policies avoided

Logging
☐ CloudTrail enabled
☐ S3 access logs enabled
☐ VPC Flow Logs enabled
☐ Log retention configured

Encryption
☐ Data in transit: TLS enforced
☐ Data at rest: KMS encryption
☐ Key rotation enabled
☐ Key access controlled
```

---

## 🔑 Key Takeaways

- **IaC = auditable infrastructure** - version control everything
- **Scan before deploy** - find misconfigs in dev (cheap fix)
- **Multiple tools** - tfsec + Checkov catch different issues
- **Fail the build** - don't deploy misconfigured infrastructure
- **Code review** - Terraform changes should be reviewed like code
- **Test with terraform plan** - see what will be deployed

---

## 📚 Resources

- [Terraform Best Practices](https://www.terraform.io/cloud-docs/recommended-practices)
- [tfsec Rules](https://aquasecurity.github.io/tfsec/)
- [Checkov Rules](https://www.checkov.io/1.Welcome/What%20is%20Checkov)

---

## [⬅️ Day 077](../day077/) | [➡️ Day 079](../day079/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*