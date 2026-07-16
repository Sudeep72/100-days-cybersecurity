# Day 074 - Azure Sentinel: Cloud-Native SIEM

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Cloud Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Azure Sentinel is Microsoft's cloud-native SIEM (Security Information & Event Management).

Unlike traditional SIEM (Splunk, ELK):
- No infrastructure to manage (fully managed)
- ML-driven threat detection (automatic anomaly detection)
- Integrates with Microsoft ecosystem (Office 365, Teams, Defender)
- Scales infinitely (pay for what you use)

**Sentinel is SIEM for the cloud era.**

---

## 🏗️ Azure Sentinel Architecture

```
Data Sources:
├─ Azure Activity Logs (what happened in Azure)
├─ Azure AD Sign-in Logs (who logged in)
├─ Azure Defender Alerts (threat detections)
├─ Office 365 Logs (email, teams, sharepoint)
├─ Windows Security Event Logs (via agents)
├─ Third-party logs (via connectors)
└─ Custom data sources (via API)

↓

Data Ingestion & Normalization
├─ Parse logs (extract fields)
├─ Normalize format (different sources → same schema)
├─ Enrich data (add context, threat intel)
└─ Store in Log Analytics Workspace

↓

Detection & Correlation
├─ Built-in detection rules (ransomware, lateral movement)
├─ ML detection (anomaly detection, behavioral analysis)
├─ Custom rules (KQL queries you write)
└─ UEBA (User and Entity Behavior Analytics)

↓

Response & Investigation
├─ Incidents (grouped related alerts)
├─ Playbooks (automated response)
├─ Investigation Graph (visualize relationships)
└─ Hunting (proactive threat searching)

↓

Dashboards & Reports
├─ Real-time dashboards
├─ Security metrics
├─ Compliance reports
└─ Executive summary
```

---

## 📊 Setting Up Azure Sentinel

### Enable Sentinel

```bash
# Create Log Analytics Workspace
az monitor log-analytics workspace create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace

# Enable Sentinel on workspace
az sentinel workspace create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace
```

### Connect Data Sources

```bash
# Connect Azure Activity Logs
az monitor log-analytics solution create \
  --resource-group security-rg \
  --solution-name AzureActivity

# Connect Azure AD Sign-in Logs
az monitor log-analytics solution create \
  --resource-group security-rg \
  --solution-name AzureADAssessment

# Connect Azure Defender
az monitor log-analytics solution create \
  --resource-group security-rg \
  --solution-name SecurityCenterFree

# Connect Windows Security Events (via agent)
az monitor log-analytics solution create \
  --resource-group security-rg \
  --solution-name SecurityInsights
```

---

## 🔍 Sentinel Detection Rules (KQL)

### KQL (Kusto Query Language)

```kusto
// Example 1: Detect multiple failed login attempts
SigninLogs
| where ResultType == "50058"  // Invalid user or password
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress
| where FailedAttempts > 10
| project UserPrincipalName, IPAddress, FailedAttempts

// Example 2: Detect impossible travel
SigninLogs
| extend Country = tostring(LocationDetails.countryOrRegion)
| sort by UserPrincipalName, TimeGenerated
| serialize rn = row_number()
| where rn > 1
| extend PrevCountry = prev(Country), 
         PrevTime = prev(TimeGenerated)
| where Country != PrevCountry
| extend TravelSpeed = 900 / ((TimeGenerated - PrevTime) / 1h)  // km/hour
| where TravelSpeed > 900  // Physically impossible (plane speed is ~900km/h)
| project UserPrincipalName, PrevCountry, Country, TravelSpeed, TimeGenerated

// Example 3: Detect data exfiltration (large file downloads)
CloudAppEvents
| where ActionType == "FileDownloaded"
| summarize TotalSize = sum(FileSize), 
           DownloadCount = count() 
           by UserPrincipalName, IPAddress
| where TotalSize > 1000000000  // > 1GB in short time
| project UserPrincipalName, IPAddress, TotalSize, DownloadCount

// Example 4: Detect privilege escalation (PIM assignments)
AuditLogs
| where OperationName == "Add member to role"
| extend PrivilegeLevel = case(
    TargetResources[0].displayName contains "Admin", "High",
    TargetResources[0].displayName contains "Owner", "High",
    "Medium")
| where PrivilegeLevel == "High"
| project InitiatedBy, TargetResources[0].displayName, TimeGenerated, PrivilegeLevel

// Example 5: Detect ransomware activity (mass file encryption)
DeviceProcessEvents
| where ProcessName contains "encrypt" or ProcessName contains "crypt"
| summarize ProcessCount = dcount(ProcessName) by DeviceId, InitiatingProcessName
| where ProcessCount > 5
| project DeviceId, InitiatingProcessName, ProcessCount

// Example 6: Detect suspicious Azure resource creation
AzureActivity
| where OperationName startswith "Create" or OperationName startswith "Write"
| where Caller !in ("trusted-admin@company.com", "service-principal")
| summarize ResourcesCreated = count() by Caller, ActivityStatus
| where ResourcesCreated > 10  // Unusual burst
| project Caller, ResourcesCreated, ActivityStatus
```

### Create Detection Rule in Sentinel

```yaml
name: Brute Force RDP Attack
description: Detects multiple failed RDP login attempts from single IP
severity: High
query: |
  SecurityEvent
  | where EventID == 4625  // Failed login
  | where LogonType == 3    // Network logon (RDP)
  | summarize FailedAttempts = count() by SourceIpAddr, Computer
  | where FailedAttempts > 10
  | project SourceIpAddr, Computer, FailedAttempts
queryFrequency: PT5M        # Run every 5 minutes
queryPeriod: PT30M          # Look back 30 minutes
triggerOperator: GreaterThan
triggerThreshold: 5
suppressionDuration: PT1H
suppressionEnabled: true
tactics:
  - Credential Access
techniques:
  - T1110  # Brute Force
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIpAddr
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: Computer
```

---

## 🤖 ML-Driven Detection

### Anomaly Detection

```kusto
// ML Anomaly Detection - Built-in function
let baseline = SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 4688  // Process creation
| summarize ProcessCount = count() by Computer, bin(TimeGenerated, 1h);

let today = SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4688
| summarize ProcessCount = count() by Computer, bin(TimeGenerated, 1h);

baseline
| join kind=rightouter (today) on Computer, TimeGenerated
| extend Anomaly = case(
    ProcessCount1 == 0, "New activity detected",
    (ProcessCount > ProcessCount1 * 2), "Spike detected",
    "Normal")
| where Anomaly != "Normal"
| project Computer, TimeGenerated, ProcessCount, ProcessCount1, Anomaly
```

### UEBA (User & Entity Behavior Analytics)

```kusto
// Detect unusual user behavior
SigninLogs
| extend LocationHash = hash(tostring(LocationDetails))
| summarize 
  LocationCount = dcount(LocationHash),
  LastSigninTime = max(TimeGenerated),
  SuccessCount = countif(ResultType == 0),
  FailureCount = countif(ResultType != 0)
  by UserPrincipalName
| where LocationCount > 5  // Logged in from 5+ locations in 24h
| where FailureCount > SuccessCount  // More failures than successes
| project UserPrincipalName, LocationCount, SuccessCount, FailureCount
```

---

## 🎯 Sentinel Playbooks (Automated Response)

### Example: Auto-Disable Compromised User

```json
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/logicAppDefinition.json#",
    "actions": {
      "Alert": {
        "type": "ApiConnection",
        "inputs": {
          "host": {
            "connection": {
              "name": "@parameters('$connections')['azuread']['connectionId']"
            }
          },
          "method": "post",
          "path": "/me/disableUser",
          "body": {
            "userId": "@triggerBody()?['properties']?['relatedEntities'][0]?['properties']?['userPrincipalName']"
          }
        }
      },
      "Create_Incident": {
        "type": "ApiConnection",
        "inputs": {
          "host": {
            "connection": {
              "name": "@parameters('$connections')['azuresentinel']['connectionId']"
            }
          },
          "method": "post",
          "path": "/incidents",
          "body": {
            "title": "User Disabled - Brute Force Attack Detected",
            "description": "Automated response disabled user due to failed login attempts"
          }
        }
      },
      "Send_Email_Alert": {
        "type": "ApiConnection",
        "inputs": {
          "host": {
            "connection": {
              "name": "@parameters('$connections')['office365']['connectionId']"
            }
          },
          "method": "post",
          "path": "/Mail",
          "body": {
            "To": "security@company.com",
            "Subject": "CRITICAL: User Disabled - Brute Force Attack",
            "Body": "User @{triggerBody()?['properties']?['relatedEntities'][0]?['properties']?['userPrincipalName']} has been disabled due to brute force attack"
          }
        }
      }
    }
  }
}
```

---

## 📊 Sentinel vs. Other SIEMs

```
Feature                 Sentinel        Splunk          ELK
─────────────────────────────────────────────────────────────
Infrastructure          Managed         Self-hosted     Self-hosted
ML Detection            Built-in        Add-on          Limited
Azure Integration       Native          Connector       Connector
Office 365 Support      Native          Connector       Connector
Scaling                 Infinite        Limited         Limited
Setup Time              Minutes         Days            Weeks
Cost Model              Pay-per-GB      Per instance    Infrastructure
SOAR Integration        Native          Add-on          Add-on
```

---

## 🔑 Key Takeaways

- **Cloud-native SIEM** - no infrastructure management
- **ML-driven detection** - finds anomalies automatically
- **Microsoft integration** - works natively with Azure, O365
- **KQL queries** - powerful threat hunting language
- **Playbooks** - automated response (no manual action)
- **Scalability** - handles petabytes of data

---

## 📚 Resources

- [Azure Sentinel Documentation](https://docs.microsoft.com/en-us/azure/sentinel/)
- [KQL Query Language Reference](https://docs.microsoft.com/en-us/azure/kusto/query/)
- [Sentinel Sample Queries](https://github.com/Azure/Azure-Sentinel/tree/master/Queries)

---

## [⬅️ Day 073](../day073/) | [➡️ Day 075](../day075/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*