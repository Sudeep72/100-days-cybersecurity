# Day 058 - IDS/IPS: Writing Snort Rules

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

An alert is only valuable if it stops an attack.

IDS (Intrusion Detection System) watches network traffic and flags suspicious patterns.

IPS (Intrusion Prevention System) does the same but can block traffic automatically.

The engine that powers both: **rules**.

A well-written detection rule catches attacks. A poorly written rule generates noise and alert fatigue.

---

## 🔍 IDS vs IPS

```
IDS (Detection)
├─ Monitors network traffic
├─ Flags suspicious patterns
├─ SOC investigates
└─ No automatic blocking

IPS (Prevention)
├─ Monitors network traffic
├─ Automatically blocks/resets
├─ Prevents attack execution
└─ Risk of disrupting legitimate traffic
```

Most enterprises: **IDS first** (investigate), then **promote to IPS** (block).

---

## 🛠️ Snort Rule Anatomy

```
alert tcp any any -> 192.168.1.0/24 445 (
  msg:"SMB Lateral Movement Attempt";
  content:"SMB";
  sid:1000001;
  rev:1;
)
```

**Components:**
```
action      → alert, drop, reject, pass, log
protocol    → tcp, udp, icmp, ip
src_ip      → any, specific, CIDR, negation
src_port    → any, port number, range, negation
direction   → ->, <>, bidirectional
dst_ip      → any, specific, CIDR, negation
dst_port    → any, port number, range, negation
options     → msg, content, flow, sid, rev, etc.
```

---

## 💡 Rule Examples

### Rule 1: SQL Injection Detection

```snort
alert http any any -> any any (
  msg:"SQL Injection - Union Based";
  content:"GET|20|";
  http_uri;
  content:"union";
  http_uri;
  nocase;
  distance:0;
  within:50;
  classtype:web-application-attack;
  sid:1000101;
  rev:1;
)
```

Detects: `GET /page.php?id=1 UNION SELECT...`

---

### Rule 2: PowerShell Obfuscation

```snort
alert http any any -> any any (
  msg:"PowerShell Encoded Command";
  content:"powershell";
  nocase;
  content:"-EncodedCommand";
  nocase;
  http_uri;
  distance:0;
  within:50;
  classtype:suspicious-activity;
  sid:1000102;
  rev:1;
)
```

Detects: `powershell.exe -EncodedCommand JAB...` (hidden command)

---

### Rule 3: Lateral Movement (Admin Ports)

```snort
alert tcp any any -> any [445,3389,5985] (
  msg:"Remote Access Attempt - Admin Ports";
  flow:to_server,established;
  flags:S+;
  threshold:type both, track by_src, count 5, seconds 60;
  classtype:attempted-admin;
  sid:1000103;
  rev:1;
)
```

Detects: 5+ connections to SMB/RDP/WinRM in 60 seconds (brute force/lateral move)

---

### Rule 4: DNS Exfiltration (DGA)

```snort
alert dns any any -> any 53 (
  msg:"DNS Query - Suspicious Domain Pattern";
  dns_query;
  pcre:"/^[a-z0-9]{20,}\.com$/i";
  classtype:suspicious-activity;
  sid:1000104;
  rev:1;
)
```

Detects: Queries for domains like `xjkqmvnpqwertycvbnm.com` (DGA malware)

---

### Rule 5: Known C2 Infrastructure

```snort
alert http any any -> any any (
  msg:"Known C2 Communication - Evil Domain";
  flow:to_server,established;
  content:"Host|3a|";
  http_header;
  content:"attacker-c2.evil.com";
  http_header;
  nocase;
  classtype:trojan-activity;
  sid:1000105;
  rev:1;
)
```

Detects: HTTP requests to known C2 infrastructure (IOC-based)

---

### Rule 6: Potential Backdoor (Reverse Shell Port)

```snort
alert tcp any any -> any 4444 (
  msg:"Reverse Shell Communication - Common Backdoor Port";
  flow:to_server,established;
  classtype:suspicious-activity;
  sid:1000106;
  rev:1;
)
```

Detects: Outbound connections to port 4444 (common reverse shell)

---

## 📊 Classtype Categories

```
trojan-activity          Malware/C2 communication
web-application-attack   SQLi, XSS, command injection
attempted-recon          Port scanning, enumeration
attempted-admin          Privilege escalation
suspicious-activity      Unusual but not clearly malicious
policy-violation         Banned protocols (P2P, IM)
bad-unknown              Unknown suspicious traffic
```

---

## 🔑 Snort Options Reference

| Option | Purpose |
|--------|---------|
| `msg` | Alert message (what was detected) |
| `content` | Exact string match |
| `pcre` | Regex pattern match |
| `http_uri` | Match in HTTP URI only |
| `http_header` | Match in HTTP headers only |
| `http_method` | Match HTTP method (GET, POST, etc.) |
| `http_client_body` | Match in HTTP request body |
| `flow:to_server` | Only outgoing packets |
| `flow:established` | Only established connections |
| `flags:S+` | TCP SYN flag set |
| `distance` | Distance between content matches |
| `within` | Max distance for content search |
| `nocase` | Case-insensitive matching |
| `threshold` | Rate-based detection (brute force, DDoS) |
| `sid` | Signature ID (unique identifier) |
| `rev` | Revision number (for updates) |
| `classtype` | Attack category |
| `reference` | CVE or URL reference |

---

## ⚠️ Common Mistakes

```
TOO BROAD
❌ alert tcp any any -> any any (content:"GET";)
   Alerts on EVERY HTTP GET (millions/day)

✅ alert http $HOME_NET any -> $EXTERNAL_NET any (
     content:"GET";
     http_uri;
     content:"../../../";
     http_uri;
   )
   Only alerts on suspicious directory traversal attempts

---

MISSING CONTEXT
❌ alert tcp any any -> any 80 (content:"SELECT";)
   Could match binary data that coincidentally contains "SELECT"

✅ alert http any any -> any any (
     content:"SELECT";
     http_uri;
     pcre:"/SELECT\s+.*FROM/i";
   )
   Context: HTTP protocol, URI field, SQL pattern

---

DIRECTION ISSUES
❌ alert tcp any any any any (content:"password";)
   Bidirectional - might alert on password reset confirmations

✅ alert tcp any any -> 192.168.1.0/24 80 (
     content:"password";
     http_client_body;
   )
   Specific direction and field (incoming on HTTP body)
```

---

## 🧪 Testing Rules

```bash
# Install Snort
sudo apt-get install snort

# Test rule syntax
sudo snort -T -i eth0 -c /etc/snort/snort.conf

# Run in IDS mode (alert only)
sudo snort -A fast -l /var/log/snort -i eth0 -c /etc/snort/snort.conf

# Monitor alerts
tail -f /var/log/snort/alert

# Generate test traffic
curl "http://192.168.1.100/?id=1 UNION SELECT"  # Should alert
```

---

## 📋 Rule Writing Checklist

```
☐ Clear message describing the attack
☐ Correct protocol (tcp, udp, http, dns)
☐ Specific source/dest IPs (not too broad)
☐ Specific ports (not too broad)
☐ Content patterns match actual attack
☐ Proper distance/within for multi-pattern rules
☐ Classtype matches attack type
☐ Unique SID (use > 1000000 for custom)
☐ Test against known bad traffic (true positive)
☐ Test against known good traffic (false positive)
☐ Document what the rule detects and why
```

---

## 🔑 Key Takeaways

- **Rules are the detection engine** - IDS is blind without them
- **Specificity wins** - too broad = alert fatigue, too narrow = miss attacks
- **Test before deploying** - validate on real traffic
- **Combine content + context** - what + where + how
- **Rate-based rules catch brute force/DDoS** - threshold essential
- **Maintain rule library** - reuse patterns, share with team

---

## 📚 Resources

- [Snort Manual](https://docs.snort.org/)
- [Emerging Threats Rules](https://rules.emergingthreats.net/)
- [Snort Community Rules](https://www.snort.org/snort-rules)

---

## [⬅️ Day 057](../day057/) | [➡️ Day 059](../day059/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*