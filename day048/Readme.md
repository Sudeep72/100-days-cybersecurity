# Day 048 - Splunk: Searching, SPL Queries & Dashboards

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Defensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Yesterday we parsed logs with Python scripts.

Splunk does that at enterprise scale - billions of events, real-time ingestion, instant search across everything.

It's the most widely deployed SIEM in the world. If you work in a SOC, you'll use Splunk. If you're applying for detection engineering or SOC analyst roles - Splunk proficiency is on almost every job description.

Today: the core Search Processing Language (SPL) queries you'll use constantly, and how to build dashboards that surface attacks automatically.

---

## 🚀 Setup - Splunk Free

```bash
# Download Splunk Enterprise (free trial, then free with 500MB/day limit)
# https://www.splunk.com/en_us/download/splunk-enterprise.html

# Or use Splunk Cloud Trial (no install)
# https://www.splunk.com/en_us/download/splunk-cloud-trial.html

# TryHackMe has Splunk rooms with pre-loaded data (no setup)
# https://tryhackme.com/room/splunk101

# Start Splunk (Linux)
sudo /opt/splunk/bin/splunk start

# Access: http://localhost:8000
# Default: admin / changeme
```

---

## 🔍 SPL - Search Processing Language

SPL uses a pipe (`|`) syntax - output of one command feeds the next.

```
index=main sourcetype=auth | stats count by src_ip | sort -count
        ↑ data source        ↑ pipe   ↑ aggregate    ↑ sort
```

---

## 📋 Core SPL Commands

### Search & Filter

```spl
* index=main *                              -- all events in main index
index=main sourcetype=linux_secure         -- specific sourcetype
index=main "Failed password"               -- keyword search
index=main host="web-server-01"            -- filter by host
index=main earliest=-24h latest=now        -- time range
index=main earliest=-1h "Failed password" src_ip="10.0.0.*"
```

---

### Extraction & Fields

```spl
-- Extract fields from raw text
index=main "Failed password" 
| rex "Failed password for (?<user>\S+) from (?<src_ip>\S+)"
| table _time, user, src_ip

-- Use existing fields
index=main sourcetype=access_combined
| table _time, clientip, uri, status, bytes

-- Rename fields
| rename clientip as "Source IP", uri as "Requested URL"
```

---

### Aggregation & Statistics

```spl
-- Count events by field
index=main "Failed password"
| stats count by src_ip
| sort -count

-- Count unique values
index=main
| stats dc(src_ip) as unique_ips count as total_events by host

-- Average, min, max
index=main sourcetype=access_combined
| stats avg(bytes) as avg_size min(bytes) as min_size max(bytes) as max_size by uri

-- Events per hour
index=main
| timechart span=1h count by sourcetype
```

---

### Time Charts (for Dashboards)

```spl
-- Failed logins over time
index=main "Failed password"
| timechart span=1h count as "Failed Logins"

-- HTTP status codes over time
index=main sourcetype=access_combined
| timechart span=1h count by status

-- Top talkers over time
index=main sourcetype=firewall
| timechart span=1h count by src_ip limit=5
```

---

### Top / Rare

```spl
-- Top source IPs
index=main | top src_ip limit=10

-- Rarest user agents (anomaly hunting)
index=main sourcetype=access_combined | rare useragent limit=10

-- Top error pages
index=main status=404 | top uri limit=20
```

---

### Eval & Calculated Fields

```spl
-- Create a new field
index=main
| eval severity=if(count>100, "HIGH", if(count>10, "MEDIUM", "LOW"))

-- Convert bytes to MB
index=main sourcetype=access_combined
| eval size_mb=round(bytes/1024/1024, 2)

-- Calculate time difference
index=main
| eval age_hours=round((now()-_time)/3600, 1)
| where age_hours < 24
```

---

## 🔐 Security-Specific SPL Queries

### Brute Force Detection

```spl
-- IPs with > 10 failed SSH logins in 10 minutes
index=main sourcetype=linux_secure "Failed password"
| bucket _time span=10m
| stats count by _time, src_ip
| where count > 10
| sort -count
| rename src_ip as "Attacker IP", count as "Failed Attempts"
```

---

### Successful Login After Multiple Failures (Compromise Indicator)

```spl
-- Find IPs that failed then succeeded
index=main sourcetype=linux_secure
| eval event_type=if(match(_raw,"Failed password"),"failure","success")
| stats count(eval(event_type="failure")) as failures,
        count(eval(event_type="success")) as successes by src_ip
| where failures > 5 AND successes > 0
| eval risk="HIGH - Possible Brute Force Success"
| table src_ip, failures, successes, risk
```

---

### Web Application Attack Detection

```spl
-- SQL injection attempts
index=main sourcetype=access_combined
| rex field=uri "(?<sqli_attempt>(?i)(union|select|insert|drop|%27|or\+1=1))"
| where isnotnull(sqli_attempt)
| stats count by clientip, uri
| sort -count

-- Directory scanning (high 404 rate)
index=main sourcetype=access_combined status=404
| bucket _time span=5m
| stats count by _time, clientip
| where count > 50
| sort -count

-- Scanner user agent detection
index=main sourcetype=access_combined
| search useragent IN ("*sqlmap*","*nikto*","*nmap*","*gobuster*","*dirbuster*")
| stats count by clientip, useragent
| sort -count
```

---

### Privilege Escalation Detection (Windows)

```spl
-- New admin account created
index=windows EventCode=4720 OR EventCode=4732
| stats count by EventCode, user, dest
| eval event_type=case(
    EventCode=4720, "Account Created",
    EventCode=4732, "Added to Admin Group"
  )

-- Scheduled task created (persistence)
index=windows EventCode=4698
| table _time, host, user, TaskName, TaskContent

-- PowerShell encoded command (suspicious)
index=windows EventCode=4104
| search ScriptBlockText="*-enc*" OR ScriptBlockText="*EncodedCommand*"
| table _time, host, user, ScriptBlockText
```

---

### Lateral Movement Detection

```spl
-- Pass-the-hash indicator (Event 4648)
index=windows EventCode=4648
| stats count by user, dest, LogonType
| where count > 3

-- Multiple failed logins across many hosts (credential spraying)
index=windows EventCode=4625
| bucket _time span=1h
| stats dc(dest) as target_hosts count by _time, user
| where target_hosts > 5
```

---

## 📊 Building a Security Dashboard

Splunk dashboards aggregate multiple SPL queries into one view.

**Essential panels for a security dashboard:**

```
Panel 1: Failed Logins (last 24h) - timechart
Panel 2: Top Attacking IPs - bar chart
Panel 3: Web Attack Attempts - table
Panel 4: New User Accounts Created - table
Panel 5: Outbound Connections by Volume - pie chart
Panel 6: Critical Alerts Feed - live event list
```

**Creating a dashboard:**
```
Search & Reporting → Save As → Dashboard Panel
OR
Dashboards → Create New Dashboard → Add Panel → Add Search
```

---

## 📝 SPL Reference Card

```spl
COMMAND          PURPOSE
───────────────────────────────────────────────
search           filter events (implicit at start)
stats            aggregate: count, avg, sum, dc
timechart        time-based stats (for charts)
table            select and display specific fields
rex              regex field extraction
eval             create/modify fields
where            filter on field values
sort             order results
top              most common values
rare             least common values
dedup            remove duplicate events
join             join two searches
lookup           enrich with external data
transaction      group related events
bucket           round time values
rename           rename fields
fields           include/exclude fields
head/tail        first/last N results
```

---

## 📚 Splunk Quick Reference

```
Time modifiers:   -15m, -1h, -24h, -7d, -30d
Wildcards:        *, ?
Boolean:          AND, OR, NOT
Comparison:       =, !=, <, >, <=, >=
Field search:     field=value, field!=value
Phrase search:    "exact phrase"
```

---

## 🔑 Key Takeaways

- SPL pipe syntax: each command transforms the previous output
- `stats count by field` is your most-used aggregation
- `timechart` creates the time-series data that powers dashboards
- `rex` extracts structured fields from unstructured log text
- Security detections = search for known-bad patterns + statistical outliers
- TryHackMe Splunk rooms give you pre-loaded data to practice on immediately

---

## 📚 Resources
- [Splunk Free Training](https://www.splunk.com/en_us/training/free-courses/splunk-fundamentals-1.html)
- [TryHackMe - Splunk 101 (free)](https://tryhackme.com/room/splunk101)
- [Splunk Security Essentials (free app)](https://splunkbase.splunk.com/app/3435)
- [Boss of the SOC (BOTS) datasets](https://github.com/splunk/botsv3)

---

## [⬅️ Day 047](../day047/) | [➡️ Day 049](../day049/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*