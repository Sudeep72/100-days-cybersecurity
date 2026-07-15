# Day 073 - Serverless Security: Functions, Containers, and Cold Starts

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Cloud Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

**Serverless** = No servers to manage. You write code, cloud runs it.

**AWS Lambda, Azure Functions, Google Cloud Functions = Modern attack surface.**

Different threat model than traditional VMs/containers.

```
Traditional VM:
├─ Full OS (large attack surface)
├─ You patch everything
├─ You secure everything
└─ Security is your responsibility

Serverless:
├─ Just your code
├─ Cloud manages OS, patches, infrastructure
├─ New security concerns: IAM, permissions, dependencies
├─ Shared responsibility (but different)
```

---

## 🔐 Serverless Security Model

### Shared Responsibility

```
AWS Responsibility:
├─ Hardware security
├─ Physical data center access
├─ Network infrastructure
├─ Function isolation (Firecracker VMs)
└─ Runtime patching

Your Responsibility:
├─ Code vulnerabilities
├─ Third-party dependencies
├─ IAM permissions (principle of least privilege)
├─ Environment secrets management
├─ Input validation
├─ Logging & monitoring
├─ DDoS protection (application layer)
└─ Cold start attacks
```

---

## ⚠️ Serverless-Specific Threats

### Threat 1: Over-Permissive IAM

```
BAD: Lambda with admin policy
├─ Lambda role: AdministratorAccess
├─ Code vulnerability allows attacker to assume role
├─ Attacker gets full AWS account access
└─ Entire infrastructure compromised

Lambda Code:
```python
import json
import boto3

s3 = boto3.client('s3')

def lambda_handler(event, context):
    bucket = event['bucket']
    # No validation - user can access ANY bucket
    response = s3.list_objects_v2(Bucket=bucket)
    return response
```

Attack:
1. Attacker sends: `{"bucket": "production-secrets"}`
2. Lambda (with admin role) lists all files
3. Attacker finds and exfiltrates secrets

GOOD: Least privilege policy
├─ Lambda role: Only S3 read on specific bucket
├─ Code vulnerability still exists but limited damage
└─ Attacker can only read from that bucket

IAM Policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-specific-bucket/*"
    }
  ]
}
```
```

### Threat 2: Cold Start Attacks

```
Cold Start:
├─ First invocation: Lambda container created (~1-2 seconds)
├─ Subsequent invocations: Reuse container (~100ms)
└─ Attacker can exploit delay

Attack: Timing-based side channel

Lambda Function (RSA decryption):
```python
from cryptography.hazmat.primitives.asymmetric import rsa
import time

def lambda_handler(event, context):
    start = time.time()
    
    # Decrypt secret
    private_key = get_private_key()
    decrypted = private_key.decrypt(event['ciphertext'])
    
    elapsed = time.time() - start
    return {'result': decrypted, 'time_ms': elapsed * 1000}
```

Attack:
1. Send many ciphertexts with guessed plaintexts
2. Measure response time
3. Shorter time = correct guess (due to early exit in comparison)
4. Binary search to find correct plaintext

Mitigation:
- Use constant-time comparison
- Don't expose timing information
- Use secure libraries (handles timing attacks)
```

### Threat 3: Dependency Vulnerabilities

```
Lambda Dependencies:
- Function code: 100 lines (reviewed)
- Requirements.txt: 50 packages (not reviewed)
- Transitive dependencies: 500+ packages (unknown)

Attack: Dependency confusion / supply chain

1. Popular package: `requests` library
2. Attacker publishes `requests-aws` (typo package)
3. Dev accidentally requires `requests-aws`
4. Attacker's code runs in Lambda
5. Attacker steals AWS credentials from environment

Prevention:
├─ Pin exact versions
├─ Use private package repository (CodeArtifact)
├─ Scan dependencies (OWASP Dependency-Check)
├─ Use Lambda Layers (isolate dependencies)
└─ Regular updates
```

### Threat 4: Secrets in Environment Variables

```
VULNERABLE:
```python
import os
import boto3

def lambda_handler(event, context):
    # Secret in environment variable
    db_password = os.environ['DB_PASSWORD']
    api_key = os.environ['API_KEY']
    
    # These appear in CloudWatch logs if printed
    print(f"Connecting with: {db_password}")
    
    # Available in /proc/self/environ in container
    # Available in Lambda configuration (visible to IAM principal with lambda:GetFunction)
```

SECURE:
```python
import json
import boto3
from botocore.exceptions import ClientError

def get_secret(secret_name):
    """Retrieve secret from Secrets Manager"""
    client = boto3.client('secretsmanager')
    try:
        response = client.get_secret_value(SecretId=secret_name)
        return json.loads(response['SecretString'])
    except ClientError as e:
        raise e

def lambda_handler(event, context):
    # Retrieve at runtime (encrypted in transit + at rest)
    secrets = get_secret('prod/database')
    db_password = secrets['password']
    
    # Never log secrets
    print("Connected to database")
```
```

### Threat 5: Log Injection & Sensitive Data Exposure

```
VULNERABLE:
```python
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    user_input = event.get('search_query', '')
    
    # Log user input without sanitization
    logger.info(f"User searched for: {user_input}")
    
    # Attacker sends: {"search_query": "x\n<CREDIT_CARD>"}
    # CloudWatch logs contain credit card
```

SECURE:
```python
import json
import logging
import re

logger = logging.getLogger()

def lambda_handler(event, context):
    user_input = event.get('search_query', '')
    
    # Sanitize before logging
    sanitized = re.sub(r'\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}', '[REDACTED]', user_input)
    logger.info(f"User searched for: {sanitized}")
    
    # Or: hash to pseudonymize
    import hashlib
    user_id = hashlib.sha256(user_input.encode()).hexdigest()
    logger.info(f"User {user_id} performed search")
```
```

### Threat 6: Unvalidated Invocation

```
Attacker directly invokes Lambda (not through API Gateway)

VULNERABLE:
```python
def lambda_handler(event, context):
    # No validation of invoker
    # Anyone with lambda:InvokeFunction can call
    delete_database = event.get('delete_db', False)
    
    if delete_database:
        # Delete entire production database
        dynamodb.delete_table(TableName='prod-data')
```

SECURE:
```python
def lambda_handler(event, context):
    # Validate invoker identity
    principal = context.invoked_function_arn
    
    # Only allow from API Gateway
    if not context.get('requestContext'):
        raise Exception("Direct invocation not allowed")
    
    # Validate authorization
    user_id = context['requestContext']['authorizer']['principalId']
    if not is_admin(user_id):
        raise Exception("Not authorized")
    
    # Process with authorization check
    delete_database = event.get('delete_db', False)
```
```

---

## 🛡️ Serverless Security Best Practices

### 1. IAM Least Privilege

```
For each Lambda:
├─ Create custom IAM role (not reuse)
├─ Grant only necessary permissions
├─ Use resource-level permissions
└─ Example: S3 read-only on one bucket

# Good: Custom policy per Lambda
Policy 1 (ImageProcessor Lambda):
  - s3:GetObject on input-images bucket only
  - s3:PutObject on processed-images bucket only
  
Policy 2 (DatabaseWriter Lambda):
  - dynamodb:PutItem on orders table only
  - No S3 access at all
```

### 2. Secrets Management

```
NEVER:
├─ Hardcode secrets in code
├─ Store in environment variables (except in-transit)
└─ Commit to Git

ALWAYS:
├─ Use AWS Secrets Manager (encrypted, rotatable)
├─ Or: AWS Systems Manager Parameter Store
├─ Or: AWS KMS for encryption
└─ Retrieve at runtime (not at deploy time)
```

### 3. Input Validation

```python
def lambda_handler(event, context):
    # Validate all inputs
    if 'user_id' not in event:
        return {'error': 'user_id required'}
    
    user_id = event['user_id']
    
    # Type validation
    if not isinstance(user_id, int):
        return {'error': 'user_id must be integer'}
    
    # Range validation
    if user_id < 0 or user_id > 999999:
        return {'error': 'user_id out of range'}
    
    # Process validated input
    return get_user(user_id)
```

### 4. Monitoring & Logging

```python
import json
import logging

logger = logging.getLogger()

def lambda_handler(event, context):
    # Log invocation (not sensitive data)
    logger.info(json.dumps({
        'function': context.function_name,
        'request_id': context.request_id,
        'memory_limit': context.memory_limit_in_mb,
        'duration_seconds': context.get_remaining_time_in_millis() / 1000
    }))
    
    try:
        result = process_request(event)
        logger.info('Request processed successfully')
        return result
    except Exception as e:
        logger.error(f'Error processing request: {str(e)}')
        raise
```

### 5. Dependency Management

```
requirements.txt:
├─ Pin exact versions
├─ Use hash verification
└─ Regular updates

Example:
```
boto3==1.26.45 --hash=sha256:abc123...
requests==2.28.1 --hash=sha256:def456...
```

Scan dependencies:
```bash
# Using Snyk
snyk test

# Using safety
safety check

# Using pip-audit
pip-audit
```
```

### 6. Function Timeouts

```
Set appropriate timeouts:

Short-running (< 5 sec):
├─ API response processing
├─ Simple data transformations
└─ Timeout: 10-30 seconds

Medium-running (5-60 sec):
├─ Database queries
├─ API calls to third-party
└─ Timeout: 60-300 seconds

Long-running (> 60 sec):
├─ Batch processing
├─ Heavy computations
└─ Use Step Functions instead of Lambda (max 15 min)

Don't set to max (15 min) - could mask problems
```

---

## 📊 Serverless Security Checklist

```
✅ IAM
├─ Custom role per function
├─ Least privilege permissions
└─ No wildcard resources

✅ Secrets
├─ Using Secrets Manager or Parameter Store
├─ Not in environment variables
└─ Encrypted in transit & at rest

✅ Code
├─ Input validation on all inputs
├─ Dependency scanning
├─ No hardcoded secrets
└─ Error handling (don't expose internals)

✅ Monitoring
├─ CloudWatch logs enabled
├─ X-Ray tracing enabled
├─ Alarms on errors/throttling
└─ No sensitive data in logs

✅ Network
├─ VPC configuration if needed
├─ Security groups configured
├─ API Gateway authorization
└─ WAF rules

✅ Compliance
├─ Encryption at rest
├─ Encryption in transit (TLS)
├─ Access logging
└─ Audit trail (CloudTrail)
```

---

## 🔑 Key Takeaways

- **Serverless != no security** - different threat model, not zero threat
- **IAM is critical** - Lambda's primary security control
- **Secrets management essential** - no hardcoding allowed
- **Input validation required** - untrusted data everywhere
- **Monitor everything** - cold starts, errors, throttling
- **Dependencies matter** - scan and update regularly
- **Timeouts important** - prevent resource exhaustion

---

## 📚 Resources

- [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/)
- [AWS Lambda Security Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/security.html)
- [Serverless Security Whitepaper](https://www.owasp.org/images/5/5c/OWASP_Serverless_Security_Top_10_1.1.pdf)

---

## [⬅️ Day 072](../day072/) | [➡️ Day 074](../day074/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*