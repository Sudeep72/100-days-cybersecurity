# Splunk SPL Query Reference

> Part of the [100 Days of Cybersecurity](../README.md) challenge - Day 048

Security-focused SPL queries organised by use case. Ready to copy into Splunk Search.

---

## 🔐 Authentication Attacks

```spl
-- Brute force: IPs with many failures in short window
index=main sourcetype=linux_secure "Failed password"
| bucket _time span=10m
| stats count by _time, src_ip
| where count > 10
| sort -count

-- Brute force success: failures followed by success
index=main sourcetype=linux_secure
| eval event_type=if(match(_raw,"Failed password"),"failure","success")
| stats count(eval(event_type="failure")) as failures,
        count(eval(event_type="success")) as successes by src_ip
| where failures > 5 AND successes > 0
| table src_ip, failures, successes

-- Root SSH login (should almost never happen)
index=main sourcetype=linux_secure "Accepted" "root"
| table _time, src_ip, _raw

-- New interactive session for service account
index=main sourcetype=linux_secure "session opened"
| rex "session opened for user (?<user>\S+)"
| search user IN ("www-data","apache","nginx","mysql","postgres")
| table _time, user, _raw

-- Password spray: one account, many source IPs
index=windows EventCode=4625
| stats dc(src_ip) as source_count count by user
| where source_count > 10
| sort -source_count

-- Credential stuffing: many accounts, one source IP
index=windows EventCode=4625
| stats dc(user) as account_count count by src_ip
| where account_count > 10
| sort -account_count
```

---

## 🌐 Web Application Attacks

```spl
-- SQL injection in URLs
index=main sourcetype=access_combined
| rex field=uri "(?<sqli>(?i)(union|select|insert|drop|%27|or\+1=1|1=1))"
| where isnotnull(sqli)
| stats count by clientip, uri
| sort -count

-- XSS attempts
index=main sourcetype=access_combined
| search uri="*script*" OR uri="*onerror*" OR uri="*javascript:*"
| stats count by clientip, uri
| sort -count

-- Directory scanning (high 404 rate)
index=main sourcetype=access_combined status=404
| bucket _time span=5m
| stats count by _time, clientip
| where count > 30
| sort -count

-- Path traversal
index=main sourcetype=access_combined
| search uri="*../*" OR uri="*..%2F*" OR uri="*etc/passwd*"
| table _time, clientip, uri, status

-- Known scanner user agents
index=main sourcetype=access_combined
| search useragent IN ("*sqlmap*","*nikto*","*nmap*","*gobuster*",
                        "*dirbuster*","*wfuzz*","*nuclei*","*masscan*")
| stats count by clientip, useragent
| sort -count

-- Webshell access pattern (POST to .php with 200 response)
index=main sourcetype=access_combined method=POST status=200
| rex field=uri "(?<ext>\.\w+)$"
| where ext IN (".php",".asp",".aspx",".jsp")
| stats count by clientip, uri
| sort -count
```

---

## 🪟 Windows Event Log Detections

```spl
-- New local admin account
index=windows EventCode=4720
| table _time, host, user, Account_Name

-- User added to admin group
index=windows EventCode=4732
| table _time, host, user, Group_Name, Account_Name

-- Scheduled task created (persistence)
index=windows EventCode=4698
| table _time, host, user, TaskName

-- Service installed (persistence)
index=windows EventCode=7045
| table _time, host, ServiceName, ServiceFileName, ServiceType

-- PowerShell encoded command
index=windows EventCode=4104
| search ScriptBlockText="*-enc*" OR ScriptBlockText="*EncodedCommand*"
         OR ScriptBlockText="*IEX*" OR ScriptBlockText="*Invoke-Expression*"
| table _time, host, user, ScriptBlockText

-- Pass-the-hash (explicit credential logon)
index=windows EventCode=4648
| table _time, host, user, TargetServerName, TargetUserName

-- Kerberoasting (SPN request)
index=windows EventCode=4769
| search TicketEncryptionType=0x17
| stats count by user, ServiceName
| sort -count

-- Lateral movement via PsExec
index=windows EventCode=7045 ServiceName="PSEXESVC"
| table _time, host, ServiceFileName

-- Mimikatz indicators
index=windows
| search (EventCode=4624 AND LogonType=9) OR
         (EventCode=4625 AND SubStatus="0xC000015B") OR
         process_name="lsass.exe"
```

---

## 🌍 Network Detections

```spl
-- DNS tunneling (unusually long query names)
index=main sourcetype=dns
| eval query_len=len(query)
| where query_len > 50
| stats count by src_ip, query
| sort -query_len

-- Beaconing (regular intervals to same destination)
index=main sourcetype=firewall action=allowed
| bucket _time span=1m
| stats count by _time, src_ip, dest_ip
| streamstats window=60 avg(count) as avg_rate stdev(count) as stdev_rate by src_ip, dest_ip
| eval is_beacon=if(stdev_rate < 2 AND count > 5, "YES", "NO")
| where is_beacon="YES"
| table src_ip, dest_ip, avg_rate, stdev_rate

-- Port scan (one src hitting many dest ports)
index=main sourcetype=firewall
| bucket _time span=1m
| stats dc(dest_port) as port_count by _time, src_ip, dest_ip
| where port_count > 20
| sort -port_count

-- Large data exfiltration (unusual outbound volume)
index=main sourcetype=firewall direction=outbound
| bucket _time span=1h
| stats sum(bytes_out) as total_bytes by _time, src_ip, dest_ip
| where total_bytes > 100000000   -- 100MB threshold
| eval size_mb=round(total_bytes/1024/1024, 1)
| sort -total_bytes
```

---

## ☁️ Cloud (AWS CloudTrail)

```spl
-- Root account usage (should be rare)
index=aws sourcetype=aws:cloudtrail userIdentity.type=Root
| table _time, eventName, sourceIPAddress, userAgent

-- IAM changes
index=aws sourcetype=aws:cloudtrail
| search eventName IN ("CreateUser","DeleteUser","AttachUserPolicy",
                        "CreateAccessKey","UpdateLoginProfile")
| table _time, userIdentity.arn, eventName, requestParameters

-- S3 public bucket changes
index=aws sourcetype=aws:cloudtrail
| search eventName="PutBucketAcl" requestParameters="*PublicRead*"
| table _time, userIdentity.arn, requestParameters.bucketName

-- Impossible travel (CloudTrail)
index=aws sourcetype=aws:cloudtrail
| stats dc(sourceIPAddress) as ip_count values(sourceIPAddress) as ips
        values(awsRegion) as regions by userIdentity.arn, date_hour
| where ip_count > 3
```

---

## 📊 Dashboard Panels

```spl
-- Panel: Failed logins last 24h (timechart)
index=main sourcetype=linux_secure "Failed password"
| timechart span=1h count as "Failed Logins"

-- Panel: Top attacking IPs (bar chart)
index=main sourcetype=linux_secure "Failed password"
| stats count by src_ip
| sort -count
| head 10

-- Panel: HTTP status distribution (pie chart)
index=main sourcetype=access_combined
| stats count by status
| sort -count

-- Panel: Critical alerts feed (table)
index=main
| where severity="CRITICAL"
| table _time, host, user, alert_name, description
| sort -_time

-- Panel: Geo map of attacks
index=main sourcetype=linux_secure "Failed password"
| iplocation src_ip
| geostats count by Country
```

---

## ⚡ Quick Investigation Workflow

```spl
-- Step 1: Alert fired for suspicious IP 10.0.0.50
-- What has this IP done in the last hour?
index=main earliest=-1h (src_ip="10.0.0.50" OR clientip="10.0.0.50" OR host="10.0.0.50")
| table _time, sourcetype, _raw
| sort _time

-- Step 2: What accounts did it access?
index=main earliest=-1h src_ip="10.0.0.50" "Accepted"
| rex "for (?<user>\S+) from"
| table _time, user, src_ip

-- Step 3: What did those accounts do after login?
index=main earliest=-1h user="compromised_user"
| table _time, sourcetype, host, _raw
| sort _time
```

---

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*