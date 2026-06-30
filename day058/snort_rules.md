# Day 058 - Snort Rule Examples
# 100 Days of Cybersecurity by Sudeep Ravichandran
# 
# These rules demonstrate common attack patterns:
# - Web application attacks (SQLi, XSS, command injection)
# - Malware communication (C2, DGA)
# - Lateral movement (brute force, admin ports)
# - Suspicious protocols (reverse shells, exfiltration)

# ============================================================================
# WEB APPLICATION ATTACKS
# ============================================================================

# SQL Injection - UNION based
alert http any any -> any any (
  msg:"SQL Injection - UNION SELECT";
  flow:to_server,established;
  content:"GET|20|";
  http_uri;
  content:"UNION";
  http_uri;
  nocase;
  distance:0;
  within:100;
  classtype:web-application-attack;
  sid:1000101;
  rev:1;
  reference:url,owasp.org/Top10;
)

# SQL Injection - Boolean based
alert http any any -> any any (
  msg:"SQL Injection - Boolean based (OR 1=1)";
  flow:to_server,established;
  content:"?id=";
  http_uri;
  content:"OR|20|1=1";
  http_uri;
  nocase;
  classtype:web-application-attack;
  sid:1000102;
  rev:1;
)

# XSS - Script tag injection
alert http any any -> any any (
  msg:"Cross-Site Scripting - Script Tag";
  flow:to_server,established;
  content:"<script";
  http_uri;
  nocase;
  classtype:web-application-attack;
  sid:1000103;
  rev:1;
)

# Command Injection - Backticks
alert http any any -> any any (
  msg:"Command Injection - Backtick Execution";
  flow:to_server,established;
  content:"POST";
  http_method;
  content:"`";
  http_uri;
  pcre:"`[a-zA-Z0-9\-_\.]+`";
  classtype:web-application-attack;
  sid:1000104;
  rev:1;
)

# Path Traversal
alert http any any -> any any (
  msg:"Path Traversal - Directory Escape";
  flow:to_server,established;
  content:"../../../";
  http_uri;
  classtype:web-application-attack;
  sid:1000105;
  rev:1;
)

# ============================================================================
# MALWARE & C2 COMMUNICATION
# ============================================================================

# PowerShell Obfuscated Command
alert http any any -> any any (
  msg:"PowerShell Encoded Command Execution";
  flow:to_server,established;
  content:"powershell";
  nocase;
  content:"-EncodedCommand";
  nocase;
  http_uri;
  distance:0;
  within:50;
  classtype:suspicious-activity;
  sid:1000201;
  rev:1;
)

# Known C2 Domain (IOC Example)
alert http any any -> any any (
  msg:"Known C2 Communication - Evil Domain";
  flow:to_server,established;
  content:"Host|3a|";
  http_header;
  content:"attacker-c2.evil.com";
  http_header;
  nocase;
  classtype:trojan-activity;
  sid:1000202;
  rev:1;
  reference:url,abuse.ch;
)

# DNS DGA Detection - Suspicious Domain Pattern
alert dns any any -> any 53 (
  msg:"DNS Query - Suspicious Domain (DGA)";
  flow:to_server,established;
  dns_query;
  pcre:"/^[a-z0-9]{20,}\.com$/i";
  classtype:suspicious-activity;
  sid:1000203;
  rev:1;
)

# Suspicious User Agent (Malware)
alert http any any -> any any (
  msg:"Suspicious User Agent - Potential Malware";
  flow:to_server,established;
  content:"User-Agent|3a|";
  http_header;
  pcre:"/User-Agent\x3a\s*(curl|wget|python|java|nc|powershell)/i";
  classtype:suspicious-activity;
  sid:1000204;
  rev:1;
)

# ============================================================================
# LATERAL MOVEMENT & BRUTE FORCE
# ============================================================================

# Brute Force - Multiple Failed RDP Attempts
alert tcp any any -> any 3389 (
  msg:"RDP Brute Force - Multiple Connection Attempts";
  flow:to_server;
  threshold:type both, track by_src, count 10, seconds 60;
  classtype:attempted-admin;
  sid:1000301;
  rev:1;
)

# Lateral Movement - SMB Admin Share Access
alert tcp any any -> any 445 (
  msg:"SMB Admin Share Access - Lateral Movement";
  flow:to_server,established;
  content:"SMB";
  classtype:attempted-admin;
  sid:1000302;
  rev:1;
)

# WinRM Remote Execution
alert tcp any any -> any 5985 (
  msg:"WinRM Remote Execution Attempt";
  flow:to_server,established;
  classtype:attempted-admin;
  sid:1000303;
  rev:1;
)

# SSH Access Attempt - Multiple Ports
alert tcp any any -> any [22,2222,22222] (
  msg:"SSH Brute Force - Multiple Ports";
  flow:to_server,established;
  threshold:type both, track by_src, count 5, seconds 60;
  classtype:attempted-admin;
  sid:1000304;
  rev:1;
)

# ============================================================================
# SUSPICIOUS NETWORK BEHAVIOR
# ============================================================================

# Reverse Shell - Common Ports
alert tcp any any -> any [4444,5555,6666,7777,8888] (
  msg:"Potential Reverse Shell - Common Backdoor Port";
  flow:to_server,established;
  classtype:suspicious-activity;
  sid:1000401;
  rev:1;
)

# Data Exfiltration - Large Outbound Transfer
alert tcp any any -> any any (
  msg:"Large Outbound Data Transfer - Potential Exfiltration";
  flow:to_server,established;
  threshold:type both, track by_src, count 1000, seconds 60;
  classtype:suspicious-activity;
  sid:1000402;
  rev:1;
)

# ICMP Tunneling Detection
alert icmp any any -> any any (
  msg:"ICMP Tunneling - Data Exfiltration";
  flow:to_server;
  threshold:type both, track by_src, count 100, seconds 60;
  classtype:suspicious-activity;
  sid:1000403;
  rev:1;
)

# DNS Tunneling - Unusual Query Size
alert dns any any -> any 53 (
  msg:"DNS Tunneling - Abnormally Large Query";
  flow:to_server,established;
  threshold:type both, track by_src, count 50, seconds 60;
  classtype:suspicious-activity;
  sid:1000404;
  rev:1;
)

# ============================================================================
# POLICY VIOLATIONS
# ============================================================================

# Torrent Traffic (P2P)
alert tcp any any -> any 6881:6889 (
  msg:"BitTorrent - P2P Policy Violation";
  classtype:policy-violation;
  sid:1000501;
  rev:1;
)

# Instant Messaging (Policy)
alert tcp any any -> any [5190,5222,5269] (
  msg:"Instant Messaging - Policy Violation";
  classtype:policy-violation;
  sid:1000502;
  rev:1;
)

# ============================================================================
# NOTES FOR DEPLOYMENT
# ============================================================================
#
# These rules are EXAMPLES for demonstration.
# 
# For production deployment:
#
# 1. Define your HOME_NET and EXTERNAL_NET variables
#    - HOME_NET: your internal network (e.g., 192.168.0.0/16)
#    - EXTERNAL_NET: !$HOME_NET
#
# 2. Replace example IOCs with your organization's threats
#    - Known C2 domains
#    - Malicious IPs
#    - Internal sensitive ports
#
# 3. Test rules in IDS mode first
#    - Alert only, do not block
#    - Monitor for false positives
#    - Tune thresholds
#
# 4. Promote to IPS mode after validation
#    - Change 'alert' to 'drop' or 'reject'
#    - Implement in phases (high confidence first)
#    - Maintain alert investigation process
#
# 5. Keep rules updated
#    - Subscribe to Emerging Threats
#    - Share rules with threat intel team
#    - Version control rules in git