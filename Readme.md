<div align="center">

# 🛡️ 100 Days of Cybersecurity

**A complete, beginner-to-advanced cybersecurity curriculum - built in public, one day at a time.**

[![Days Complete](https://img.shields.io/badge/Days%20Complete-2%2F100-red?style=flat-square)](#)
[![LinkedIn](https://img.shields.io/badge/Follow%20the%20Journey-LinkedIn-0A66C2?style=flat-square&logo=linkedin)](https://linkedin.com/in/sudeep72)
[![GitHub Stars](https://img.shields.io/github/stars/Sudeep72/100-days-cybersecurity?style=flat-square&color=yellow)](#)

*by [Sudeep Ravichandran](https://sudeepdev.netlify.app) - MS Cybersecurity @ Indiana University Bloomington*

</div>

---

## What is this?

This repository documents my 100-day public learning challenge in cybersecurity.

Every day has:
- 📖 A concept explained from scratch - no assumed knowledge
- 💻 Working code, scripts, or tool walkthroughs (most days)
- 🔗 A LinkedIn post where I share what I learned

The curriculum is structured to take **anyone** from zero cybersecurity knowledge to job-ready skills across offensive security, cloud security, and AI-driven detection.

If you're a complete beginner - start at Day 1. Every concept is introduced before it's used.  
If you have some experience - jump to the phase that matches your level.

---

## The Curriculum

```
Phase 1 │ Foundations         │ Days 001 – 020  │ Networking, Linux, Cryptography
Phase 2 │ Offensive Security  │ Days 021 – 045  │ Pen Testing, Web Attacks, Exploitation  
Phase 3 │ Defensive Security  │ Days 046 – 065  │ SIEM, Detection Engineering, IR
Phase 4 │ Cloud Security      │ Days 066 – 080  │ AWS/Azure, Cloud Attacks & Auditing
Phase 5 │ AI × Security       │ Days 081 – 095  │ ML for Detection, LLM Security
Phase 6 │ Portfolio Sprint    │ Days 096 – 100  │ Capstone Projects, Interview Prep
```

---

## 🔰 Phase 1: Foundations (Days 001-020)

> Build the mental model first. You can't secure or hack what you don't understand.

| Day | Topic | Code / Lab | Post |
|-----|-------|-----------|------|
| [001](./day001/) | The CIA Triad: Foundation of Everything | - | [🔗](./day001/linkedin_day001.md) |
| [002](./day002/) | How the Internet Works: TCP/IP Deep Dive | [packet_analyzer.py](./day002/packet_analyzer.py) | [🔗](./day002/linkedin_day002.md) |
| [003](./day003/) | The OSI Model: Why Every Layer Matters to Attackers | - | [🔗](./day003/linkedin_day003.md) |
| [004](./day004/) | DNS: The Protocol Hackers Love to Abuse | [dns_enum.py](./day004/dns_enum.py) | [🔗](./day004/linkedin_day004.md) |
| [005](./day005/) | Firewalls & What They Can't Stop | - | [🔗](./day005/linkedin_day005.md) |
| [006](./day006/) | Linux for Security: Commands That Actually Matter | [linux_cheatsheet.sh](./day006/linux_cheatsheet.sh) | [🔗](./day006/linkedin_day006.md) |
| [007](./day007/) | File Permissions & Why Misconfigs Get People Fired | [perm_audit.sh](./day007/perm_audit.sh) | [🔗](./day007/linkedin_day007.md) |
| [008](./day008/) | Cryptography 101: Symmetric vs Asymmetric | [crypto_basics.py](./day008/crypto_basics.py) | [🔗](./day008/linkedin_day008.md) |
| [009](./day009/) | Hashing: How Passwords Are (and Shouldn't Be) Stored | [hash_demo.py](./day009/hash_demo.py) | [🔗](./day009/linkedin_day009.md) |
| [010](./day010/) | PKI & Certificates: How HTTPS Actually Works | - | [🔗](./day010/linkedin_day010.md) |
| [011](./day011/) | Authentication vs Authorization: Not the Same Thing | - | [🔗](./day011/linkedin_day011.md) |
| [012](./day012/) | VPNs, Proxies, and Tor: Anonymity Explained | - | [🔗](./day012/linkedin_day012.md) |
| [013](./day013/) | Nmap: Your First Recon Tool | [nmap_basics.sh](./day013/nmap_basics.sh) | [🔗](./day013/linkedin_day013.md) |
| [014](./day014/) | Wireshark: Reading Network Traffic Like a Pro | [analysis_notes.md](./day014/analysis_notes.md) | [🔗](./day014/linkedin_day014.md) |
| [015](./day015/) | Common Attack Types: A Threat Taxonomy | - | [🔗](./day015/linkedin_day015.md) |
| [016](./day016/) | Social Engineering: The Human Vulnerability | - | [🔗](./day016/linkedin_day016.md) |
| [017](./day017/) | OWASP Top 10: The Web Hacker's Bible | - | [🔗](./day017/linkedin_day017.md) |
| [018](./day018/) | CVEs & the Vulnerability Lifecycle | [cve_lookup.py](./day018/cve_lookup.py) | [🔗](./day018/linkedin_day018.md) |
| [019](./day019/) | Setting Up a Free Home Lab (Legal & Safe) | [lab_setup.md](./day019/lab_setup.md) | [🔗](./day019/linkedin_day019.md) |
| [020](./day020/) | Phase 1 Recap + First CTF Attempt | [ctf_writeup.md](./day020/ctf_writeup.md) | [🔗](./day020/linkedin_day020.md) |

---

## ⚔️ Phase 2: Offensive Security (Days 021-045)

> Think like an attacker. Ethical hacking, web app exploitation, and pen testing methodology.

| Day | Topic | Code / Lab | Post |
|-----|-------|-----------|------|
| [021](./day021/) | Penetration Testing Methodology (PTES) | - | [🔗](./day021/linkedin_day021.md) |
| [022](./day022/) | Passive Recon: OSINT & Footprinting | [osint_toolkit.py](./day022/osint_toolkit.py) | [🔗](./day022/linkedin_day022.md) |
| [023](./day023/) | Active Recon: Banner Grabbing & Enumeration | [recon_enum.py](./day023/recon_enum.py) | [🔗](./day023/linkedin_day023.md) |
| [024](./day024/) | Vulnerability Scanning with OpenVAS | - | [🔗](./day024/linkedin_day024.md) |
| [025](./day025/) | Metasploit Framework: Basics | [msf_workflow.md](./day025/msf_workflow.md) | [🔗](./day025/linkedin_day025.md) |
| [026](./day026/) | SQL Injection: From Theory to Exploitation | [sqli_demo.py](./day026/sqli_demo.py) | [🔗](./day026/linkedin_day026.md) |
| [027](./day027/) | XSS: Stored, Reflected, and DOM-Based | [xss_payloads.md](./day027/xss_payloads.md) | [🔗](./day027/linkedin_day027.md) |
| [028](./day028/) | CSRF, IDOR, and Broken Access Control | - | [🔗](./day028/linkedin_day028.md) |
| [029](./day029/) | Burp Suite: Web App Proxy Masterclass | [burp_workflow.md](./day029/burp_workflow.md) | [🔗](./day029/linkedin_day029.md) |
| [030](./day030/) | Authentication Attacks: Brute Force & Credential Stuffing | [auth_attack_demo.py](./day030/auth_attack_demo.py) | [🔗](./day030/linkedin_day030.md) |
| [031](./day031/) | API Hacking: Vulnerabilities in REST APIs | [api_recon.py](./day031/api_recon.py) | [🔗](./day031/linkedin_day031.md) |
| [032](./day032/) | Server-Side Request Forgery (SSRF) | - | [🔗](./day032/linkedin_day032.md) |
| [033](./day033/) | File Upload Vulnerabilities & Bypasses | - | [🔗](./day033/linkedin_day033.md) |
| [034](./day034/) | Command Injection & OS Execution | - | [🔗](./day034/linkedin_day034.md) |
| [035](./day035/) | Privilege Escalation: Linux (GTFOBins & SUID) | [privesc_check.sh](./day035/privesc_check.sh) | [🔗](./day035/linkedin_day035.md) |
| [036](./day036/) | Privilege Escalation: Windows | [win_privesc.md](./day036/win_privesc.md) | [🔗](./day036/linkedin_day036.md) |
| [037](./day037/) | Password Cracking: Hashcat & John the Ripper | [crack_guide.md](./day037/crack_guide.md) | [🔗](./day037/linkedin_day037.md) |
| [038](./day038/) | Wireless Security: WPA2 Attacks & Defenses | - | [🔗](./day038/linkedin_day038.md) |
| [039](./day039/) | Post-Exploitation: What Happens After a Shell | - | [🔗](./day039/linkedin_day039.md) |
| [040](./day040/) | Writing a Professional Pen Test Report | [report_template.md](./day040/report_template.md) | [🔗](./day040/linkedin_day040.md) |
| [041](./day041/) | CTF Writeup: HackTheBox (Easy Machine) | [htb_writeup.md](./day041/htb_writeup.md) | [🔗](./day041/linkedin_day041.md) |
| [042](./day042/) | CTF Writeup: TryHackMe Room | [thm_writeup.md](./day042/thm_writeup.md) | [🔗](./day042/linkedin_day042.md) |
| [043](./day043/) | Building a Subdomain Scanner from Scratch | [subdomain_scanner.py](./day043/subdomain_scanner.py) | [🔗](./day043/linkedin_day043.md) |
| [044](./day044/) | OWASP Juice Shop: Full Walkthrough | [juiceshop_notes.md](./day044/juiceshop_notes.md) | [🔗](./day044/linkedin_day044.md) |
| [045](./day045/) | Phase 2 Capstone: Full Pen Test on Lab VM | [capstone_report.md](./day045/capstone_report.md) | [🔗](./day045/linkedin_day045.md) |

---

## 🔍 Phase 3: Defensive Security & Detection Engineering (Days 046-065)

> The blue team. SIEM, threat hunting, log analysis, and incident response.

| Day | Topic | Code / Lab | Post |
|-----|-------|-----------|------|
| [046](./day046/) | Blue Team vs Red Team: How Detection Engineering Works | - | [🔗](./day046/linkedin_day046.md) |
| [047](./day047/) | Log Analysis: What to Look For and Why | [log_parser.py](./day047/log_parser.py) | [🔗](./day047/linkedin_day047.md) |
| [048](./day048/) | Splunk: Searching, SPL Queries & Dashboards | [splunk_queries.md](./day048/splunk_queries.md) | [🔗](./day048/linkedin_day048.md) |
| [049](./day049/) | SIEM Architecture: How It All Fits Together | - | [🔗](./day049/linkedin_day049.md) |
| [050](./day050/) | Writing Detection Rules: Sigma & YARA | [detection_rules/](./day050/rules/) | [🔗](./day050/linkedin_day050.md) |
| [051](./day051/) | MITRE ATT&CK: A Defender's Map | [attack_mapper.py](./day051/attack_mapper.py) | [🔗](./day051/linkedin_day051.md) |
| [052](./day052/) | Threat Intelligence: IOCs, TTPs & Feeds | [ioc_enricher.py](./day052/ioc_enricher.py) | [🔗](./day052/linkedin_day052.md) |
| [053](./day053/) | Network Traffic Analysis: Spotting Anomalies | [traffic_baseline.py](./day053/traffic_baseline.py) | [🔗](./day053/linkedin_day053.md) |
| [054](./day054/) | UEBA: User and Entity Behavior Analytics | [ueba_demo.py](./day054/ueba_demo.py) | [🔗](./day054/linkedin_day054.md) |
| [055](./day055/) | Incident Response: The 6-Phase Process | [ir_playbook.md](./day055/ir_playbook.md) | [🔗](./day055/linkedin_day055.md) |
| [056](./day056/) | Digital Forensics: Disk & Memory Analysis | - | [🔗](./day056/linkedin_day056.md) |
| [057](./day057/) | Malware Analysis 101: Static vs Dynamic | [mal_analysis.md](./day057/mal_analysis.md) | [🔗](./day057/linkedin_day057.md) |
| [058](./day058/) | IDS/IPS: Writing Snort Rules | [snort_rules.md](./day058/snort_rules.md) | [🔗](./day058/linkedin_day058.md) |
| [059](./day059/) | Threat Hunting: Proactive Detection | [hunt_playbook.md](./day059/hunt_playbook.md) | [🔗](./day059/linkedin_day059.md) |
| [060](./day060/) | Ransomware: How It Works & How to Detect It | [ransomware_iocs.md](./day060/ransomware_iocs.md) | [🔗](./day060/linkedin_day060.md) |
| [061](./day061/) | SOC Analyst Workflow: A Day in the Life | - | [🔗](./day061/linkedin_day061.md) |
| [062](./day062/) | Building an Automated Alert Triage Tool | [alert_triage.py](./day062/alert_triage.py) | [🔗](./day062/linkedin_day062.md) |
| [063](./day063/) | Zero Trust Architecture Explained | - | [🔗](./day063/linkedin_day063.md) |
| [064](./day064/) | Security Metrics: What to Measure & Why | - | [🔗](./day064/linkedin_day064.md) |
| [065](./day065/) | Phase 3 Capstone: Building a Detection Lab | [detection_lab/](./day065/lab/) | [🔗](./day065/linkedin_day065.md) |

---

## ☁️ Phase 4: Cloud Security (Days 066-080)

> The future is cloud. Learn to attack and defend AWS and Azure environments.

| Day | Topic | Code / Lab | Post |
|-----|-------|-----------|------|
| [066](./day066/) | Cloud Security 101: Shared Responsibility Model | - | [🔗](./day066/linkedin_day066.md) |
| [067](./day067/) | AWS IAM: Permissions, Roles & Least Privilege | [iam_audit.py](./day067/iam_audit.py) | [🔗](./day067/linkedin_day067.md) |
| [068](./day068/) | S3 Misconfigurations: A Real-World Epidemic | [s3_audit.py](./day068/s3_audit.py) | [🔗](./day068/linkedin_day068.md) |
| [069](./day069/) | Cloud Attack Techniques: Top 10 | - | [🔗](./day069/linkedin_day069.md) |
| [070](./day070/) | AWS CloudTrail: Logging & Monitoring | [cloudtrail_parser.py](./day070/cloudtrail_parser.py) | [🔗](./day070/linkedin_day070.md) |
| [071](./day071/) | AWS GuardDuty: Threat Detection at Scale | - | [🔗](./day071/linkedin_day071.md) |
| [072](./day072/) | Container Security: Docker & Kubernetes Threats | [container_audit.sh](./day072/container_audit.sh) | [🔗](./day072/linkedin_day072.md) |
| [073](./day073/) | Serverless Security: Lambda Attack Vectors | - | [🔗](./day073/linkedin_day073.md) |
| [074](./day074/) | Azure Sentinel: Cloud-Native SIEM | - | [🔗](./day074/linkedin_day074.md) |
| [075](./day075/) | Cloud Pen Testing: Methodology & Tools | [cloud_enum.py](./day075/cloud_enum.py) | [🔗](./day075/linkedin_day075.md) |
| [076](./day076/) | Secrets Management: Vault & AWS Secrets Manager | - | [🔗](./day076/linkedin_day076.md) |
| [077](./day077/) | DevSecOps: Shifting Security Left in CI/CD | [ci_security_scan.yml](./day077/ci_security_scan.yml) | [🔗](./day077/linkedin_day077.md) |
| [078](./day078/) | IaC Security: Scanning Terraform for Misconfigs | [tf_security_check.py](./day078/tf_security_check.py) | [🔗](./day078/linkedin_day078.md) |
| [079](./day079/) | Cloud Incident Response: What's Different | [cloud_ir_playbook.md](./day079/cloud_ir_playbook.md) | [🔗](./day079/linkedin_day079.md) |
| [080](./day080/) | Phase 4 Capstone: Full Cloud Environment Audit | [cloud_audit/](./day080/capstone/) | [🔗](./day080/linkedin_day080.md) |

---

## 🤖 Phase 5: AI × Security (Days 081-095)

> Where my research lives. ML-driven detection, LLM vulnerabilities, and adversarial AI.

| Day | Topic | Code / Lab | Post |
|-----|-------|-----------|------|
| [081](./day081/) | Why AI is Changing Cybersecurity | - | [🔗](./day081/linkedin_day081.md) |
| [082](./day082/) | Anomaly Detection with Isolation Forest | [isolation_forest.py](./day082/isolation_forest.py) | [🔗](./day082/linkedin_day082.md) |
| [083](./day083/) | Network Intrusion Detection with ML | [nids_ml.py](./day083/nids_ml.py) | [🔗](./day083/linkedin_day083.md) |
| [084](./day084/) | Log Anomaly Detection: DeepLog vs LogREx | [log_anomaly.py](./day084/log_anomaly.py) | [🔗](./day084/linkedin_day084.md) |
| [085](./day085/) | Phishing Detection with NLP | [phishing_detector.py](./day085/phishing_detector.py) | [🔗](./day085/linkedin_day085.md) |
| [086](./day086/) | LLM Security: Prompt Injection Attacks | [prompt_injection.md](./day086/prompt_injection.md) | [🔗](./day086/linkedin_day086.md) |
| [087](./day087/) | Jailbreaking LLMs: AI Red Teaming | - | [🔗](./day087/linkedin_day087.md) |
| [088](./day088/) | RAG Poisoning & Data Exfiltration Attacks | - | [🔗](./day088/linkedin_day088.md) |
| [089](./day089/) | Adversarial ML: Evading AI-Based Detectors | [adversarial_demo.py](./day089/adversarial_demo.py) | [🔗](./day089/linkedin_day089.md) |
| [090](./day090/) | AI-Powered Threat Intelligence Pipelines | [ti_pipeline.py](./day090/ti_pipeline.py) | [🔗](./day090/linkedin_day090.md) |
| [091](./day091/) | Using LLMs for Alert Triage (Inspired by LogREx) | [llm_triage.py](./day091/llm_triage.py) | [🔗](./day091/linkedin_day091.md) |
| [092](./day092/) | Knowledge Graphs for Security Context | [kg_security.py](./day092/kg_security.py) | [🔗](./day092/linkedin_day092.md) |
| [093](./day093/) | Deepfake & Synthetic Media Threats | - | [🔗](./day093/linkedin_day093.md) |
| [094](./day094/) | AI Governance & Responsible Security AI | - | [🔗](./day094/linkedin_day094.md) |
| [095](./day095/) | Phase 5 Capstone: AI-Powered SIEM Alert Explainer | [ai_siem_explainer/](./day095/project/) | [🔗](./day095/linkedin_day095.md) |

---

## 🏆 Phase 6: Professional Portfolio Sprint (Days 096-100)

> The job hunt. Real projects, a polished portfolio, and strategy to land the offer.

| Day | Topic | Code / Lab | Post |
|-----|-------|-----------|------|
| [096](./day096/) | Building a Security Portfolio That Gets Interviews | - | [🔗](./day096/linkedin_day096.md) |
| [097](./day097/) | HTB / TryHackMe: Advanced Machine Writeup | [advanced_writeup.md](./day097/advanced_writeup.md) | [🔗](./day097/linkedin_day097.md) |
| [098](./day098/) | Contributing to Open Source Security Tools | - | [🔗](./day098/linkedin_day098.md) |
| [099](./day099/) | Top 30 Cybersecurity Interview Q&A | [interview_prep.md](./day099/interview_prep.md) | [🔗](./day099/linkedin_day099.md) |
| [100](./day100/) | Day 100: What I Learned & What's Next | - | [🔗](./day100/linkedin_day100.md) |

---

## 🛠️ Tools & Technologies Covered

**Offensive**
Kali Linux · Metasploit · Burp Suite · Nmap · OWASP ZAP · Wireshark · Hashcat · SQLMap · Gobuster

**Defensive**
Splunk · Snort · Sigma · YARA · Volatility · Elastic Stack

**Cloud**
AWS (IAM, GuardDuty, CloudTrail, S3) · Azure Sentinel · Terraform · Docker · Kubernetes

**AI & Data Science**
Python · scikit-learn · TensorFlow · Hugging Face · LangChain · NetworkX

**Frameworks**
MITRE ATT&CK · OWASP Top 10 · NIST CSF · Zero Trust · PTES

---

## About Me

I'm Sudeep Ravichandran - MS Cybersecurity student at Indiana University Bloomington (4.0 GPA), published researcher in AI-driven threat detection, and international student building toward a full-time security engineering role by May 2027.

My published research:
- **LogREx** - LLM + Knowledge Graph based log anomaly detection (Springer LNNS, CIS 2025)
- **PCMedIR** - Privacy-preserving medical image retrieval (Springer LNNS, ICCIS 2024)

📫 [LinkedIn](https://linkedin.com/in/sudeep72) · [Portfolio](https://sudeepdev.netlify.app) · sudeep7217@gmail.com

---

<div align="center">

*If this repo helps your cybersecurity journey, please ⭐ star it.*

*Recruiter? I graduate May 2027 and I'm actively looking for security engineering roles.*

</div>