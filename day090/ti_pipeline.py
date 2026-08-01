class ThreatIntelligencePipeline:
    def __init__(self):
        self.ioc_db = {}  # Indicators of Compromise
        self.campaigns = {}  # Known campaigns
        self.threat_actors = {}  # Known actors
        
    def ingest_data(self, raw_data):
        """Collect and normalize data"""
        normalized = normalize(raw_data)
        self.validate_quality(normalized)
        return normalized
    
    def extract_iocs(self, data):
        """Extract indicators"""
        iocs = {
            'ips': extract_ips(data),
            'domains': extract_domains(data),
            'hashes': extract_hashes(data),
            'urls': extract_urls(data),
        }
        return iocs
    
    def enrich(self, iocs):
        """Add context"""
        enriched = {}
        for ioc_type, ioc_list in iocs.items():
            enriched[ioc_type] = [
                {
                    'value': ioc,
                    'threat_score': self.score_threat(ioc),
                    'seen_before': self.check_historical(ioc),
                    'geolocation': self.geolocate(ioc),
                    'attribution': self.attribute(ioc),
                }
                for ioc in ioc_list
            ]
        return enriched
    
    def correlate(self, enriched_iocs):
        """Find patterns and link to campaigns"""
        clusters = self.cluster_iocs(enriched_iocs)
        campaigns = self.link_to_campaigns(clusters)
        actors = self.attribute_to_actors(campaigns)
        return actors
    
    def generate_detections(self, actors):
        """Create actionable detections"""
        detections = []
        for actor in actors:
            # Create IDS rule
            ioc_rule = create_snort_rule(actor['iocs'])
            # Create firewall rules
            fw_rules = create_firewall_rules(actor['iocs'])
            # Create alert
            alert = {
                'threat_actor': actor['name'],
                'confidence': actor['confidence'],
                'iocs': actor['iocs'],
                'ttps': actor['ttps'],
                'recommendations': actor['recommendations'],
            }
            detections.append((ioc_rule, fw_rules, alert))
        
        return detections
    
    def process(self, raw_data):
        """End-to-end pipeline"""
        data = self.ingest_data(raw_data)
        iocs = self.extract_iocs(data)
        enriched = self.enrich(iocs)
        actors = self.correlate(enriched)
        detections = self.generate_detections(actors)
        return detections