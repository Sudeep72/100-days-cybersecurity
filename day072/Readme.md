# Day 072 - Container Security: Docker & Kubernetes Threats

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Cloud Security | **Difficulty:** Intermediate-Advanced

---

## 🧠 The Concept

Containers (Docker, Kubernetes) changed how we deploy applications.

They also introduced new attack surface:

```
Vulnerable Images → Container Escape → Host Compromise → Lateral Movement
```

Container security requires thinking about image security, runtime security, and orchestration security.

---

## 📦 Container Attack Surface

### 1. Vulnerable Image (Base Image)

```
Dockerfile:
FROM ubuntu:18.04  ← 5+ years old, hundreds of CVEs
RUN apt-get install nodejs
RUN npm install package@latest

Issues:
├─ Base image has known vulnerabilities
├─ Package versions not pinned (latest changes)
├─ No vulnerability scanning
├─ No image signing

Attacker can:
├─ Exploit CVE in ubuntu kernel
├─ Exploit CVE in nodejs
├─ Supply chain: compromised npm package
└─ Container escape (if kernel vuln)
```

### 2. Secrets in Images

```
Dockerfile:
FROM ubuntu:18.04
ENV AWS_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"
ENV AWS_SECRET="wJalrXUtnFEMI/K7MDENG..."
COPY app.jar /app/

Problem:
├─ Secrets hardcoded in image
├─ Image pushed to registry (shared)
├─ Every developer has AWS keys
├─ Keys in image history (forever)

Attacker finds image: Gets all AWS keys
```

### 3. Running as Root

```
Dockerfile:
FROM ubuntu:18.04
RUN apt-get install -y app
ENTRYPOINT /usr/bin/app

Problem:
├─ Container runs as root (UID 0)
├─ App has full host access
├─ If app has vulnerability: attacker is root
├─ Container escape becomes OS compromise

Better:
FROM ubuntu:18.04
RUN useradd -m appuser
USER appuser  ← Run as non-root
ENTRYPOINT /usr/bin/app

If app exploited: Attacker is appuser (limited)
```

### 4. No Resource Limits

```
Deployment without limits:
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    image: app:latest

Problem:
├─ Container can use all CPU/memory
├─ Cryptocurrency mining = consume all CPU
├─ Memory leak = OOM kill (DoS)
├─ Other containers starved (host-level DoS)

Better:
spec:
  containers:
  - name: app
    image: app:latest
    resources:
      requests:
        cpu: "250m"
        memory: "256Mi"
      limits:
        cpu: "500m"
        memory: "512Mi"

Container capped at 500m CPU, 512Mi RAM
Prevents resource exhaustion attacks
```

### 5. Privileged Containers

```
WRONG:
docker run --privileged -it app:latest

Privileged container = host access:
├─ Can mount host filesystem
├─ Can access all host devices
├─ Can modify host kernel
├─ Can escape to host

RIGHT:
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE app:latest

Drop all capabilities, add only what's needed
Principle of least privilege for containers
```

---

## 🔍 Container Image Scanning

### Scan for Vulnerabilities

```bash
# Trivy (free, open-source)
trivy image ubuntu:18.04

Output:
ubuntu:18.04 (debian 10.13)
Total: 156 vulnerabilities
HIGH: 89
MEDIUM: 45
LOW: 22

Top vulnerabilities:
├─ CVE-2023-12345 (Critical, OpenSSL)
├─ CVE-2023-54321 (High, Bash)
└─ CVE-2023-99999 (Medium, Curl)
```

### Scan for Secrets

```bash
# TruffleHog (find secrets in images)
trufflehog docker --image app:latest

Output:
Found: AWS_ACCESS_KEY_ID=AKIA...
Found: DATABASE_PASSWORD=admin123
Found: API_KEY=sk-...

These should NOT be in images!
```

### Scan for Malware

```bash
# ClamAV (malware scanning)
clamscan -r /app

Or in CI/CD:
docker run --rm -v $(pwd):/app clamav/clamav:latest clamscan -r /app
```

### Registry Scanning (ECR)

```bash
# AWS ECR image scanning
aws ecr describe-image-scan-findings \
  --repository-name app \
  --image-id imageTag=latest

Output:
{
  "imageScanFindings": {
    "imageScanStatus": {
      "status": "COMPLETE"
    },
    "findings": [
      {
        "name": "CVE-2023-12345",
        "severity": "CRITICAL",
        "uri": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"
      }
    ]
  }
}
```

---

## 🛡️ Container Security Best Practices

### Image Security

```dockerfile
# WRONG - Vulnerable base image
FROM ubuntu:18.04

# RIGHT - Minimal, current, signed base image
FROM gcr.io/distroless/base:nonroot

# WRONG - Secrets hardcoded
ENV AWS_KEY="AKIA..."

# RIGHT - Secrets from environment at runtime
# (Set in Kubernetes secrets, not in image)

# WRONG - Running as root
# (default user is root)

# RIGHT - Create non-root user
RUN useradd -m -u 1000 appuser
USER appuser

# WRONG - No resource limits

# RIGHT - Pod spec has limits (see below)
```

### Kubernetes Security

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  # Run as non-root
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    
  containers:
  - name: app
    image: app:latest
    
    # Resource limits
    resources:
      requests:
        cpu: "250m"
        memory: "256Mi"
      limits:
        cpu: "500m"
        memory: "512Mi"
    
    # Drop all capabilities, add only needed
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE
      readOnlyRootFilesystem: true
    
    # No privileged mode
    # privileged: false (default)
    
    # Health checks
    livenessProbe:
      httpGet:
        path: /health
        port: 8080
      initialDelaySeconds: 30
      periodSeconds: 10
    
    # Secrets (not in image)
    env:
    - name: DATABASE_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-secret
          key: password
    
    # Volume mounts (read-only)
    volumeMounts:
    - name: config
      mountPath: /etc/app
      readOnly: true
  
  # Pod Security Policy / Security Standards
  automountServiceAccountToken: false
  
  volumes:
  - name: config
    configMap:
      name: app-config
```

---

## 🔐 Container Image Best Practices

```
Dockerfile:

# 1. Use minimal base image (small attack surface)
FROM gcr.io/distroless/base:nonroot

# 2. Scan for vulnerabilities
# (In CI/CD: trivy image, grype, etc.)

# 3. DON'T hardcode secrets
# Wrong: ENV DB_PASSWORD="secret"
# Right: Use Kubernetes secrets at runtime

# 4. DON'T use latest tag
# Wrong: FROM ubuntu:latest
# Right: FROM ubuntu:22.04

# 5. Run as non-root user
RUN useradd -m appuser
USER appuser

# 6. Make filesystem read-only
RUN chmod -R a-w /app

# 7. Remove unnecessary tools
RUN apt-get remove -y gcc git curl

# 8. Multi-stage build (smaller final image)
FROM ubuntu:22.04 as builder
RUN apt-get install -y gcc
COPY . /src
WORKDIR /src
RUN gcc -o app app.c

FROM gcr.io/distroless/base:nonroot
COPY --from=builder /src/app /app
ENTRYPOINT ["/app"]

# 9. Sign image
# docker trust sign app:v1.0

# 10. Scan in registry
# (ECR, GCR, Docker Hub all offer scanning)
```

---

## 🚨 Container Security Checklist

```
Image Security
☐ Base image is current (< 6 months old)
☐ Base image is minimal (distroless preferred)
☐ Image scanned for vulnerabilities (Trivy, Grype)
☐ Image scanned for secrets (TruffleHog, Detect Secrets)
☐ Image scanned for malware (ClamAV)
☐ Image signed (docker content trust)
☐ Tag is specific (not latest)
☐ Build from Dockerfile in git (reproducible)

Runtime Security
☐ Container runs as non-root user
☐ Filesystem is read-only
☐ Resource limits set (CPU, memory)
☐ Capabilities dropped (CAP_DROP=ALL)
☐ Security context configured
☐ No privileged containers
☐ Health checks defined
☐ Secrets not in image (Kubernetes secrets)

Orchestration (Kubernetes)
☐ Pod Security Policy enforced
☐ Network policies configured
☐ RBAC configured (who can deploy)
☐ Secrets encrypted at rest
☐ Audit logging enabled
☐ Admission webhooks validate images
☐ Image pull secrets configured
☐ Service accounts limited (automountServiceAccountToken: false)

Registry Security
☐ Private registry (not Docker Hub public)
☐ Registry authentication required
☐ Images scanned on push
☐ Vulnerability scanning enabled
☐ Only signed images allowed
☐ Image retention policy (cleanup old)
☐ Audit logging for image pulls

Runtime Monitoring
☐ Container runtime monitoring (Falco, Sysdig)
☐ Alerts on suspicious syscalls
☐ Alerts on container escape attempts
☐ Alerts on privilege escalation
☐ Integration with SIEM (logs sent)
```

---

## 🔑 Key Takeaways

- **Container images are immutable** - secure at build time, stays secure at runtime
- **Minimal images reduce attack surface** - distroless < alpine < ubuntu
- **Secrets should never be in images** - use Kubernetes secrets, environment variables
- **Non-root is non-negotiable** - running as root enables container escape
- **Resource limits prevent DoS** - cryptocurrency mining, memory leaks
- **Scanning catches vulnerabilities early** - CI/CD pipeline, not production

---

## 📚 Resources

- [Container Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Trivy Scanner](https://github.com/aquasecurity/trivy)
- [Falco Runtime Security](https://falco.org/)
- [NIST Container Security](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)

---

## [⬅️ Day 071](../day071/) | [➡️ Day 073](../day073/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*