#!/usr/bin/env python3
"""
SAFE-T1403: Consent-Fatigue Exploit - Detection Implementation

This detector identifies indicators of consent-fatigue exploit attacks in MCP environments.
Generated from detection-rule.yml and pseudocode.md.
"""

import json
import re
from typing import Dict, List, Any
from datetime import datetime


class T1403Detector:
    """Detector for Consent-Fatigue Exploit attacks in MCP environments"""
    
    def __init__(self):
        # Detection patterns from detection-rule.yml
        self.patterns = ['*suspicious*', '*malicious*', '*unauthorized*']
    
    def scan(self, data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Scan for consent-fatigue exploit indicators"""
        findings = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        # Detection patterns from detection-rule.yml
        if re.search(r'\.\*suspicious\.\*', str(data), re.IGNORECASE):
            findings['high'].append(f'Pattern matched: *suspicious*')
        if re.search(r'\.\*malicious\.\*', str(data), re.IGNORECASE):
            findings['high'].append(f'Pattern matched: *malicious*')
        if re.search(r'\.\*unauthorized\.\*', str(data), re.IGNORECASE):
            findings['high'].append(f'Pattern matched: *unauthorized*')

        
        # Additional detection logic based on technique specifics
        # See README.md and pseudocode.md for complete attack flow
        
        return findings
    
    def scan_logs(self, log_file: str) -> Dict[str, Any]:
        """Scan log file for consent-fatigue exploit indicators"""
        try:
            with open(log_file, 'r') as f:
                logs = json.load(f)
        except Exception as e:
            return {'error': f"Failed to load log file: {e}"}
        
        all_findings = {
            'events_analyzed': 0,
            'findings': {
                'critical': [],
                'high': [],
                'medium': [],
                'low': [],
            },
            'summary': {}
        }
        
        for event in logs:
            all_findings['events_analyzed'] += 1
            event_findings = self.scan(event)
            
            # Merge findings
            for severity in event_findings:
                if severity in all_findings['findings']:
                    all_findings['findings'][severity].extend(event_findings[severity])
        
        # Generate summary
        all_findings['summary'] = {
            'critical': len(all_findings['findings']['critical']),
            'high': len(all_findings['findings']['high']),
            'medium': len(all_findings['findings']['medium']),
            'low': len(all_findings['findings']['low']),
        }
        
        return all_findings
    
    def generate_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate human-readable report"""
        if 'error' in scan_results:
            return f"Error: {scan_results['error']}\n"
        
        report = f"\n=== SAFE-T1403 Detection Report ===\n\n"
        report += f"Technique: Consent-Fatigue Exploit\n"
        report += f"Events Analyzed: {scan_results.get('events_analyzed', 0)}\n\n"
        
        if 'summary' in scan_results:
            summary = scan_results['summary']
            report += "Summary:\n"
            report += f"  Critical: {summary.get('critical', 0)}\n"
            report += f"  High: {summary.get('high', 0)}\n"
            report += f"  Medium: {summary.get('medium', 0)}\n"
            report += f"  Low: {summary.get('low', 0)}\n\n"
        
        findings = scan_results.get('findings', {})
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        icons = {
            'critical': '🚨',
            'high': '⚠️ ',
            'medium': '⚡',
            'low': '📌',
            'info': 'ℹ️ '
        }
        
        for severity in severity_order:
            if findings.get(severity):
                report += f"{icons.get(severity, '')} {severity.upper()} ({len(findings[severity])} findings)\n"
                for finding in findings[severity][:10]:
                    report += f"  - {finding}\n"
                if len(findings[severity]) > 10:
                    report += f"  ... and {len(findings[severity]) - 10} more\n"
                report += "\n"
        
        if all(not findings.get(s, []) for s in severity_order):
            report += "✓ No indicators detected\n"
        
        return report


def main():
    """Main entry point"""
    import sys
    
    detector = T1403Detector()
    
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
        results = detector.scan_logs(log_file)
        report = detector.generate_report(results)
        print(report)
    else:
        print(f"Usage: python {sys.argv[0]} <log_file.json>")
        print(f"\nSAFE-T1403: Consent-Fatigue Exploit Detector")
        print("See README.md and detection-rule.yml for more information.")


if __name__ == "__main__":
    main()
