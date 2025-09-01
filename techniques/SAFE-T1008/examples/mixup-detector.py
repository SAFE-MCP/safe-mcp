#!/usr/bin/env python3
"""
OAuth Mix-up Attack Detector
Scans MCP OAuth configurations for suspicious domains

Usage: python mixup-detector.py [config.json]
"""

import json
import sys
import re
import urllib.parse
from typing import List, Dict, Tuple
import Levenshtein

# Known legitimate OAuth authorization servers
LEGITIMATE_AS_DOMAINS = {
    "accounts.google.com",
    "login.microsoftonline.com",
    "github.com",
    "facebook.com",
    "api.twitter.com",
    "linkedin.com",
    "amazon.com",
    "slack.com",
    "auth0.com",
    "okta.com",
    "login.salesforce.com",
    "appleid.apple.com"
}

# Common typosquatting patterns
SUSPICIOUS_PATTERNS = [
    r'xn--',  # Punycode
    r'[0-9].*\.(com|org|net)',  # Numbers in domain
    r'[а-яА-Я]',  # Cyrillic characters
    r'[αβγδεζηθικλμνξοπρστυφχψω]',  # Greek characters
    r'(.)\1{3,}',  # Repeated characters
    r'@',  # Username in URL
]

class OAuthMixupDetector:
    def __init__(self):
        self.alerts = []
        
    def check_domain_similarity(self, domain: str) -> List[Dict]:
        """Check if domain is suspiciously similar to known AS domains"""
        alerts = []
        
        # Extract base domain
        if '/' in domain:
            domain = domain.split('/')[0]
            
        for legit_domain in LEGITIMATE_AS_DOMAINS:
            # Calculate Levenshtein distance
            distance = Levenshtein.distance(domain, legit_domain)
            
            # If very similar but not exact match
            if 0 < distance <= 3:
                similarity = 1 - (distance / max(len(domain), len(legit_domain)))
                alerts.append({
                    "type": "DOMAIN_SIMILARITY",
                    "severity": "HIGH" if similarity > 0.85 else "MEDIUM",
                    "domain": domain,
                    "similar_to": legit_domain,
                    "similarity": f"{similarity:.2%}",
                    "distance": distance
                })
                
        return alerts
    
    def check_suspicious_patterns(self, url: str) -> List[Dict]:
        """Check for suspicious patterns in URLs"""
        alerts = []
        
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, url):
                alerts.append({
                    "type": "SUSPICIOUS_PATTERN",
                    "severity": "HIGH",
                    "url": url,
                    "pattern": pattern,
                    "description": self.get_pattern_description(pattern)
                })
                
        return alerts
    
    def get_pattern_description(self, pattern: str) -> str:
        """Get human-readable description of pattern"""
        descriptions = {
            r'xn--': "Punycode domain (internationalized domain name)",
            r'[0-9].*\.(com|org|net)': "Numbers in domain name",
            r'[а-яА-Я]': "Cyrillic characters (possible homograph attack)",
            r'[αβγδεζηθικλμνξοπρστυφχψω]': "Greek characters (possible homograph attack)",
            r'(.)\1{3,}': "Repeated characters",
            r'@': "Username in URL (possible credential harvesting)"
        }
        return descriptions.get(pattern, "Suspicious pattern")
    
    def check_oauth_config(self, config: Dict) -> List[Dict]:
        """Check an OAuth configuration for security issues"""
        alerts = []
        
        if 'oauth_config' not in config:
            return alerts
            
        oauth_config = config['oauth_config']
        tool_name = config.get('tool_name', 'Unknown')
        
        # Check authorization URL
        if 'authorization_url' in oauth_config:
            auth_url = oauth_config['authorization_url']
            parsed = urllib.parse.urlparse(auth_url)
            domain = parsed.netloc
            
            # Check domain similarity
            domain_alerts = self.check_domain_similarity(domain)
            for alert in domain_alerts:
                alert['tool'] = tool_name
                alerts.append(alert)
            
            # Check suspicious patterns
            pattern_alerts = self.check_suspicious_patterns(auth_url)
            for alert in pattern_alerts:
                alert['tool'] = tool_name
                alerts.append(alert)
            
            # Check for HTTP instead of HTTPS
            if parsed.scheme == 'http':
                alerts.append({
                    "type": "INSECURE_PROTOCOL",
                    "severity": "HIGH",
                    "tool": tool_name,
                    "url": auth_url,
                    "description": "OAuth authorization URL uses HTTP instead of HTTPS"
                })
        
        # Check redirect URI
        if 'redirect_uri' in oauth_config:
            redirect_uri = oauth_config['redirect_uri']
            parsed = urllib.parse.urlparse(redirect_uri)
            
            # Check for localhost in production
            if parsed.netloc in ['localhost', '127.0.0.1', '0.0.0.0']:
                alerts.append({
                    "type": "LOCALHOST_REDIRECT",
                    "severity": "MEDIUM",
                    "tool": tool_name,
                    "url": redirect_uri,
                    "description": "Redirect URI points to localhost"
                })
                
        return alerts
    
    def scan_file(self, filepath: str) -> Tuple[List[Dict], List[Dict]]:
        """Scan a configuration file for OAuth security issues"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error reading file {filepath}: {e}")
            return [], []
        
        configs = []
        if isinstance(data, list):
            configs = data
        elif isinstance(data, dict):
            configs = [data]
        
        all_alerts = []
        for config in configs:
            alerts = self.check_oauth_config(config)
            all_alerts.extend(alerts)
            
        return all_alerts, configs
    
    def print_report(self, alerts: List[Dict], configs: List[Dict]):
        """Print security scan report"""
        print("\n" + "=" * 60)
        print("OAuth Mix-up Attack Detection Report")
        print("=" * 60)
        
        if not alerts:
            print("\n✓ No security issues detected!")
            print(f"  Scanned {len(configs)} OAuth configuration(s)")
            return
            
        # Group alerts by severity
        high_alerts = [a for a in alerts if a['severity'] == 'HIGH']
        medium_alerts = [a for a in alerts if a['severity'] == 'MEDIUM']
        
        print(f"\n⚠️  Found {len(alerts)} security issue(s):")
        print(f"  - HIGH severity: {len(high_alerts)}")
        print(f"  - MEDIUM severity: {len(medium_alerts)}")
        
        # Print high severity alerts
        if high_alerts:
            print("\n🔴 HIGH SEVERITY ISSUES:")
            for alert in high_alerts:
                self.print_alert(alert)
                
        # Print medium severity alerts
        if medium_alerts:
            print("\n🟡 MEDIUM SEVERITY ISSUES:")
            for alert in medium_alerts:
                self.print_alert(alert)
                
    def print_alert(self, alert: Dict):
        """Print a single alert"""
        print(f"\n  Tool: {alert.get('tool', 'Unknown')}")
        print(f"  Type: {alert['type']}")
        
        if alert['type'] == 'DOMAIN_SIMILARITY':
            print(f"  Domain: {alert['domain']}")
            print(f"  Similar to: {alert['similar_to']}")
            print(f"  Similarity: {alert['similarity']} (distance: {alert['distance']})")
        elif alert['type'] == 'SUSPICIOUS_PATTERN':
            print(f"  URL: {alert['url']}")
            print(f"  Description: {alert['description']}")
        else:
            print(f"  URL: {alert.get('url', 'N/A')}")
            print(f"  Description: {alert.get('description', 'N/A')}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python mixup-detector.py [config.json]")
        sys.exit(1)
        
    filepath = sys.argv[1]
    detector = OAuthMixupDetector()
    
    print(f"Scanning {filepath} for OAuth security issues...")
    alerts, configs = detector.scan_file(filepath)
    detector.print_report(alerts, configs)
    
    # Exit with error code if high severity issues found
    high_alerts = [a for a in alerts if a['severity'] == 'HIGH']
    if high_alerts:
        sys.exit(1)

if __name__ == "__main__":
    main()