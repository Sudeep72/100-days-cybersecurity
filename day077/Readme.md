# Day 077 - DevSecOps: Shifting Security Left in CI/CD

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Cloud Security | **Difficulty:** Intermediate-Advanced

---

## 🧠 The Concept

Traditional: Code → Deploy → Security Review → "Wait, vulnerability found" → Hotfix

DevSecOps: Code → Security Scan → Build → Deploy (only if secure)

**Security moves LEFT in the development timeline.**

Find vulnerabilities before production (cheap to fix).
Not after production (expensive to fix).

---

## 🔄 DevSecOps Pipeline

```
Developer Commits Code
    ↓
[1] PRE-COMMIT SCAN
├─ Detect secrets (hardcoded passwords, keys)
├─ Check code quality (code smells)
└─ Format checking (lint)
    ↓
[2] PULL REQUEST CHECKS
├─ SAST (Static Application Security Testing)
│  ├─ SonarQube: Find bugs, vulnerabilities
│  ├─ Semgrep: Pattern-based security checks
│  └─ Bandit: Python security scanner
├─ Dependency scanning
│  ├─ Snyk: Find vulnerable dependencies
│  ├─ Safety: Python vulnerability scanner
│  └─ npm audit: Node.js vulnerability scanner
└─ Secret scanning
   ├─ TruffleHog: Find hardcoded secrets
   └─ Detect-secrets: Baseline secret detection
    ↓
[3] BUILD STAGE
├─ Container scanning
│  ├─ Trivy: Find vulnerabilities in image
│  ├─ Grype: Vulnerability scanner
│  └─ Clair: Registry scanner
├─ Malware scanning
│  └─ ClamAV: Detect malware in image
├─ Secret scanning
│  └─ TruffleHog: Secrets in image layers
└─ Image signing
   └─ Cosign: Sign and verify images
    ↓
[4] TEST STAGE
├─ DAST (Dynamic Application Security Testing)
│  ├─ OWASP ZAP: Automated penetration testing
│  └─ Burp Suite: Web application scanner
├─ Infrastructure scanning
│  ├─ Checkov: IaC vulnerability scanner
│  └─ tfsec: Terraform security scanner
└─ Load testing
   └─ k6: Identify DoS vulnerabilities
    ↓
[5] DEPLOY STAGE
├─ Policy enforcement
│  ├─ OPA/Rego: Admission control
│  └─ Falco: Runtime security
├─ Deployment verification
│  ├─ Only approved images
│  ├─ Signed manifests
│  └─ Audit trail
└─ Continuous monitoring
   ├─ Real-time threat detection
   └─ Alert on anomalies
```

---

## 🛠️ CI/CD Security Tools

### Secret Scanning

```bash
# Pre-commit hook
git config core.hooksPath .git/hooks
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
detect-secrets scan --baseline .secrets.baseline
git diff --cached | grep -i "password\|secret\|key"
if [ $? -eq 0 ]; then
  echo "Secrets detected! Commit blocked."
  exit 1
fi
EOF
chmod +x .git/hooks/pre-commit
```

### SAST (Static Application Security Testing)

```yaml
# GitHub Actions: SonarQube scan
name: SAST Scan
on: [pull_request]
jobs:
  sonarqube:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: SonarQube Scan
        uses: SonarSource/sonarcloud-github-action@master
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

### Dependency Scanning

```yaml
# GitHub Actions: Check dependencies
name: Dependency Check
on: [pull_request]
jobs:
  dependencies:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Python Dependencies
        run: pip install safety && safety check
      - name: Node Dependencies
        run: npm audit
      - name: Snyk Scan
        uses: snyk/actions/setup@master
        run: snyk test
```

### Container Scanning

```yaml
# Container scan before push
name: Container Security
on: [push]
jobs:
  container:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build Image
        run: docker build -t app:${{ github.sha }} .
      - name: Scan with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: app:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-results.sarif'
      - name: Check Results
        run: |
          if grep -q "CRITICAL\|HIGH" trivy-results.sarif; then
            echo "Vulnerabilities found!"
            exit 1
          fi
      - name: Push Image
        if: success()
        run: docker push app:${{ github.sha }}
```

### IaC Scanning

```yaml
# Scan Terraform before deployment
name: Infrastructure Security
on: [pull_request]
jobs:
  terraform:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: tfsec Scan
        run: |
          tfsec . --format json > tfsec-report.json
          if grep -q "severity=CRITICAL\|severity=HIGH" tfsec-report.json; then
            exit 1
          fi
      - name: Checkov Scan
        run: |
          checkov -d . --framework terraform --output json > checkov-report.json
          if grep -q "\"check_result\": \"failed\"" checkov-report.json; then
            exit 1
          fi
```

### DAST (Dynamic Application Security Testing)

```yaml
# Automated penetration testing in staging
name: DAST Scan
on: [deployment]
jobs:
  dast:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to Staging
        run: |
          kubectl apply -f manifests/ --namespace=staging
          kubectl wait --for=condition=ready pod \
            -l app=web --timeout=300s --namespace=staging
      - name: OWASP ZAP Scan
        run: |
          docker run -t owasp/zap2docker-stable zap-baseline.py \
            -t http://staging-app:8080 \
            -r zap-report.html
      - name: Check Results
        run: |
          if grep -q "RISK: High\|RISK: Critical" zap-report.html; then
            exit 1
          fi
```

---

## 📋 Security Gates in Pipeline

```
Stage 1: Pre-Commit
├─ Detect secrets: Mandatory
├─ Lint: Recommended
└─ Format: Recommended

Stage 2: Pull Request
├─ SAST: Fail on CRITICAL
├─ Dependencies: Fail on HIGH
├─ Code review: Mandatory (2 approvals)
└─ Test coverage: Minimum 80%

Stage 3: Build
├─ Container scan: Fail on CRITICAL
├─ Malware scan: Fail on any detection
├─ Image sign: Mandatory
└─ Image push: Only signed images

Stage 4: Test (Staging)
├─ DAST: Fail on HIGH
├─ Load test: Fail if performance degrades
├─ Chaos test: Fail if not resilient
└─ Security test: Fail on vulnerabilities

Stage 5: Deploy (Production)
├─ Approval gate: Security team sign-off
├─ Canary deploy: Roll out to 5% first
├─ Monitor: Alert on anomalies
└─ Rollback: Automatic on critical alert
```

---

## 🎯 Preventing Common Issues

### Secret in Code

```python
# WRONG
password = "admin123"

# RIGHT: Fetch at runtime
import boto3
secrets = boto3.client('secretsmanager')
password = secrets.get_secret_value(SecretId='prod/db/password')['SecretString']
```

Pre-commit hook catches:
```bash
detect-secrets scan
# FOUND: Password pattern
# Commit blocked until fixed
```

### Vulnerable Dependency

```
Before:
pip install requests==2.25.0  # Has CVE

CI/CD scan:
snyk test
# CRITICAL: requests 2.25.0 has CVE-2023-12345
# Build fails

After:
pip install requests==2.31.0  # Patched
snyk test
# ✓ No vulnerabilities
# Build succeeds
```

### Unencrypted Database in IaC

```hcl
# WRONG
resource "aws_db_instance" "main" {
  storage_encrypted = false
}

# CI/CD scan:
tfsec .
# AWS002 (CRITICAL): Database not encrypted
# Deployment fails

# RIGHT
resource "aws_db_instance" "main" {
  storage_encrypted = true
  kms_key_id = aws_kms_key.db.arn
}

# tfsec .
# ✓ No critical issues
# Can deploy
```

---

## 📊 Metrics

```
Before DevSecOps:
├─ Vulnerability detection: Post-deployment (6+ months)
├─ Time to fix: Weeks (hot-patch on prod)
├─ False positives: High (manual review)
├─ Developer productivity: High (less process)
└─ Security incidents: High (preventable issues in prod)

After DevSecOps:
├─ Vulnerability detection: Pre-deployment (5 minutes)
├─ Time to fix: Minutes (easy when in dev)
├─ False positives: Low (automated scanning)
├─ Developer productivity: Same/Better (auto-tools help)
└─ Security incidents: Low (issues caught early)

Cost:
├─ Tools: $10-50K/year
├─ Training: $5K/year
├─ Process overhead: ~10% slower builds
└─ Total: ~$50K/year

Benefit:
├─ Prevents average data breach: $4.5M
├─ Prevents regulatory fines: $1-10M
├─ Prevents downtime: $100K-1M
└─ ROI: 90:1 to 180:1
```

---

## 🔑 Key Takeaways

- **Security shifts left** - catch bugs in dev, not prod
- **Automation catches what humans miss** - scan everything, every time
- **Fail fast** - block bad code early (cheap to fix)
- **No silver bullet** - need multiple tools (SAST, DAST, dependencies, secrets)
- **Pipeline as code** - version control your security
- **Continuous improvement** - metrics drive better practices

---

## 📚 Resources

- [OWASP Secure SDLC](https://owasp.org/www-project-secure-software-development-framework/)
- [DevSecOps Practices](https://www.devsecops.org/)
- [SAST vs. DAST](https://owasp.org/www-community/attacks/xss/)

---

## [⬅️ Day 076](../day076/) | [➡️ Day 078](../day078/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*