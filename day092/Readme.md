# Day 092 - Knowledge Graphs for Security Context

> **Challenge:** 100 Days of Cybersecurity | **Phase:** AI × Security | **Difficulty:** Advanced

---

## 🧠 The Concept

**Knowledge Graph** = Network of entities (people, systems, threats) and relationships.

Instead of isolated data, connect everything.

```
Traditional:
├─ IP 203.0.113.1 is malicious
├─ Malware ABC123 connects to 203.0.113.1
├─ User john.doe opened malware ABC123
└─ [disconnected facts]

Knowledge Graph:
IP 203.0.113.1 ←→ Malware ABC123 ←→ User john.doe
                ↓
           Campaign X (Lazarus)
                ↓
           Target: Finance Sector
```

Knowledge Graphs reveal **hidden connections**.

---

## 🔗 Knowledge Graph Structure

### Entities

```
People:
├─ john.doe (employee)
├─ admin (system admin)
├─ attacker1 (unknown)
└─ threat_actor_lazarus (known APT)

Systems:
├─ server.example.com
├─ workstation_john (john's computer)
├─ honeypot_1
└─ dc.example.com (domain controller)

Threats:
├─ malware_abc123 (trojan)
├─ ransomware_x (encryption)
├─ campaign_2024_q1 (operation)
└─ exploit_cve_2024_1234

Artifacts:
├─ ip_203.0.113.1
├─ domain_evil.com
├─ hash_abc123def456
└─ url_malicious.site/payload
```

### Relationships

```
INFECTED_BY:
├─ workstation_john INFECTED_BY malware_abc123
├─ server.example.com INFECTED_BY ransomware_x
└─ honeypot_1 INFECTED_BY malware_abc123

CONNECTED_TO:
├─ workstation_john CONNECTED_TO ip_203.0.113.1
├─ malware_abc123 CONNECTED_TO evil.com
└─ campaign_2024_q1 CONNECTED_TO lazarus

COMPROMISED_BY:
├─ user_john.doe COMPROMISED_BY attacker1
├─ system_server.example.com COMPROMISED_BY campaign_2024_q1
└─ domain_dc.example.com COMPROMISED_BY threat_actor_lazarus

PART_OF:
├─ malware_abc123 PART_OF campaign_2024_q1
├─ exploit_cve_2024_1234 PART_OF attack_chain_1
└─ workstation_john PART_OF department_finance

TARGETS:
├─ campaign_2024_q1 TARGETS finance_sector
├─ threat_actor_lazarus TARGETS banks
└─ malware_ransomware_x TARGETS windows_systems
```

---

## 💡 Use Cases

### Use Case 1: Threat Attribution

```
Detection: Malware found on system

Query Graph:
"Find all entities connected to this malware"

Path:
Malware ABC123 
  ↓ (CONNECTED_TO)
evil.com (C2 server)
  ↓ (HOSTS)
ip_203.0.113.1 (ASN=China Telecom)
  ↓ (USED_BY)
campaign_2024_q1
  ↓ (ATTRIBUTED_TO)
threat_actor_lazarus

Result: "This malware is Lazarus with high confidence"
```

### Use Case 2: Attack Pattern Recognition

```
Detection: Series of failed logins

Query:
"Find users with multiple failed logins in past hour"
"Check if any of those users exist in known attack campaigns"

Path Discovery:
failed_login_1 ← user_john
failed_login_2 ← user_john
failed_login_3 ← user_john
...
user_john ← PART_OF department_finance
department_finance ← TARGET_OF campaign_lazarus

Result: "Finance department users under targeted attack"
```

### Use Case 3: Lateral Movement Detection

```
Detection: Unusual network activity

Query:
"Find all systems accessible from compromised workstation"
"Check if those systems contain sensitive data"

Path:
workstation_compromised
  ↓ (CAN_ACCESS)
file_server_1
  ↓ (CONTAINS)
customer_data
  ↓ (VALUE=HIGH)

Result: "Compromised workstation can access high-value data"
Action: Isolate workstation immediately
```

### Use Case 4: Supply Chain Risk

```
Detection: Vendor software compromised

Query:
"Find all systems using this vendor software"
"Check what data they can access"

Path:
software_vendor_A
  ↓ (INSTALLED_ON)
system_1, system_2, system_3, ... system_100
  ↓ (CAN_ACCESS)
customer_db, source_code, secrets_vault

Result: "100 systems affected, 3 critical data stores at risk"
```

---

## 🏗️ Implementation

### Graph Database Choice

```
Options:

Neo4j:
✓ Most popular for security
✓ Excellent query language (Cypher)
✓ High-performance graph queries
✗ Licensing (community vs. enterprise)

TigerGraph:
✓ Extremely fast for large graphs
✓ Good analytics
✗ Less security-focused tooling

Amazon Neptune:
✓ Managed (no ops)
✓ AWS integration
✗ Cloud-only

For security: Neo4j typically best choice.
```

### Building a Security Knowledge Graph

```python
from neo4j import GraphDatabase

class SecurityKnowledgeGraph:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
    
    def create_entity(self, entity_type, name, attributes):
        """Create a node in the graph"""
        query = """
        CREATE (node:""" + entity_type + """ {name: $name, ...attributes})
        """
        with self.driver.session() as session:
            session.run(query, name=name, attributes=attributes)
    
    def create_relationship(self, entity1, rel_type, entity2, properties=None):
        """Create relationship between entities"""
        query = """
        MATCH (a {name: $entity1})
        MATCH (b {name: $entity2})
        CREATE (a)-[rel:""" + rel_type + """]->(b)
        """
        with self.driver.session() as session:
            session.run(query, entity1=entity1, entity2=entity2)
    
    def query_threat_chain(self, initial_entity):
        """Find all threats connected to entity"""
        query = """
        MATCH (start {name: $entity})-[*0..5]-(threat)
        WHERE threat:THREAT or threat:MALWARE or threat:CAMPAIGN
        RETURN threat, COUNT(DISTINCT threat) as connections
        """
        with self.driver.session() as session:
            results = session.run(query, entity=initial_entity)
            return results.data()
    
    def find_lateral_movement_paths(self, compromised_system):
        """Find attack paths from compromised system"""
        query = """
        MATCH (start {name: $system})
        MATCH (start)-[*1..3]-(sensitive_data)
        WHERE sensitive_data:DATA_STORE and sensitive_data.sensitivity="HIGH"
        RETURN DISTINCT sensitive_data.name as at_risk
        """
        with self.driver.session() as session:
            results = session.run(query, system=compromised_system)
            return results.data()
    
    def attribution_analysis(self, malware_hash):
        """Attribute malware to threat actor"""
        query = """
        MATCH (malware {hash: $hash})
        MATCH (malware)-[:CONNECTED_TO]->(c2)
        MATCH (c2)-[:HOSTED_BY]->(ip)
        MATCH (ip)-[:USED_BY]->(campaign)
        MATCH (campaign)-[:ATTRIBUTED_TO]->(actor)
        RETURN actor, campaign, c2, ip
        """
        with self.driver.session() as session:
            results = session.run(query, hash=malware_hash)
            return results.data()
```

### Populating the Graph

```python
# Create entities
kg.create_entity('SYSTEM', 'workstation_john', 
    {'os': 'Windows 10', 'department': 'Finance'})
kg.create_entity('IP_ADDRESS', '203.0.113.1',
    {'asn': '9808', 'country': 'CN'})
kg.create_entity('MALWARE', 'trojan_abc123',
    {'type': 'trojan', 'first_seen': '2024-01-01'})
kg.create_entity('CAMPAIGN', 'lazarus_2024_q1',
    {'actor': 'lazarus', 'start_date': '2024-01-01'})
kg.create_entity('THREAT_ACTOR', 'lazarus',
    {'country': 'KP', 'known_targets': 'Finance, Government'})

# Create relationships
kg.create_relationship('workstation_john', 'INFECTED_BY', 'trojan_abc123')
kg.create_relationship('trojan_abc123', 'CONNECTED_TO', '203.0.113.1')
kg.create_relationship('203.0.113.1', 'USED_BY', 'lazarus_2024_q1')
kg.create_relationship('lazarus_2024_q1', 'ATTRIBUTED_TO', 'lazarus')

# Query: Find all threats connected to john's workstation
threats = kg.query_threat_chain('workstation_john')
# Result: ["lazarus_2024_q1", "lazarus", "trojan_abc123"]
```

---

## 📊 Advanced Queries

### Find Compromised Infrastructure

```cypher
MATCH (malware:MALWARE)-[:HOSTED_ON]->(server:SYSTEM)
MATCH (server)-[:PART_OF]->(network:NETWORK)
WHERE malware.detected_as_malicious = true
RETURN server, network, COUNT(DISTINCT malware) as malware_count
ORDER BY malware_count DESC
```

### Identify High-Risk Users

```cypher
MATCH (user:USER)-[:HAS_CREDENTIAL]->(cred:CREDENTIAL)
MATCH (cred)-[:USED_BY]->(system:SYSTEM)
MATCH (system)-[:COMPROMISED_BY]->(malware:MALWARE)
RETURN user, COUNT(DISTINCT system) as compromised_systems
ORDER BY compromised_systems DESC
```

### Supply Chain Attack Detection

```cypher
MATCH (vendor:VENDOR)-[:PRODUCES]->(software:SOFTWARE)
MATCH (software)-[:INSTALLED_ON]->(system:SYSTEM)
MATCH (system)-[:CAN_ACCESS]->(data:DATA_STORE)
WHERE data.sensitivity = 'HIGH'
WITH vendor, COUNT(DISTINCT system) as affected_count
WHERE affected_count > 10
RETURN vendor, affected_count
```

---

## 🔑 Key Takeaways

- **Relationships matter** - isolated data points miss patterns
- **Graph queries powerful** - find paths, identify clusters
- **Scalability challenges** - millions of nodes/relationships
- **Real-time updates critical** - new threat data must update graph
- **Privacy concerns** - personal data in graphs needs protection
- **Attribution enabled** - connect IoCs to actors
- **Prevention possible** - proactive defense based on paths

---

## 📚 Resources

- [Neo4j for Security](https://neo4j.com/blog/security/)
- [Knowledge Graphs in Cybersecurity](https://arxiv.org/abs/2403.16222)
- [Cypher Query Language](https://neo4j.com/developer/cypher/)

---

## [⬅️ Day 091](../day091/) | [➡️ Day 093](../day093/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*