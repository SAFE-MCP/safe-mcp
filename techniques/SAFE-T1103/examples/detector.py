#!/usr/bin/env python3
"""
SAFE-T1103: Fake Tool Invocation (Function Spoofing) - Detection Implementation

This detector identifies indicators of fake tool invocation (function spoofing) attacks in MCP environments.
Generated from detection-rule.yml and pseudocode.md.
"""

import json
import re
from typing import Dict, List, Any
from datetime import datetime


class T1103Detector:
    """Detector for Fake Tool Invocation (Function Spoofing) attacks in MCP environments"""
    
    def __init__(self):
        # Detection patterns from detection-rule.yml
        self.patterns = ['*tools/call*', '*method*: *tools/call*', '*tool_name*', '*system_admin*', '*admin_tool*', '*bypass*', '*elevated*']
    
    def scan(self, data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Scan for fake tool invocation (function spoofing) indicators"""
        findings = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        # Detection patterns from detection-rule.yml
        if re.search(r'\.\*tools/call\.\*', str(data), re.IGNORECASE):
            findings['high'].append(f'Pattern matched: *tools/call*')
        if re.search(r'\.\*method\.\*:\ \.\*tools/call\.\*', str(data), re.IGNORECASE):
            findings['high'].append(f'Pattern matched: *method*: *tools/call*')
        if re.search(r'\.\*tool_name\.\*', str(data), re.IGNORECASE):
            findings['high'].append(f'Pattern matched: *tool_name*')
        if re.search(r'\.\*system_admin\.\*', str(data), re.IGNORECASE):
            findings['high'].append(f'Pattern matched: *system_admin*')
        if re.search(r'\.\*admin_tool\.\*', str(data), re.IGNORECASE):
            findings['high'].append(f'Pattern matched: *admin_tool*')
        if re.search(r'\.\*bypass\.\*', str(data), re.IGNORECASE):
            findings['high'].append(f'Pattern matched: *bypass*')
        if re.search(r'\.\*elevated\.\*', str(data), re.IGNORECASE):
            findings['high'].append(f'Pattern matched: *elevated*')

        
        # Additional detection logic based on technique specifics
        # See README.md and pseudocode.md for complete attack flow
        
        return findings
    
    def scan_logs(self, log_file: str) -> Dict[str, Any]:
        """Scan log file for fake tool invocation (function spoofing) indicators"""
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
        
        report = f"\n=== SAFE-T1103 Detection Report ===\n\n"
        report += f"Technique: Fake Tool Invocation (Function Spoofing)\n"
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
    
    detector = T1103Detector()
    
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
        results = detector.scan_logs(log_file)
        report = detector.generate_report(results)
        print(report)
    else:
        print(f"Usage: python {sys.argv[0]} <log_file.json>")
        print(f"\nSAFE-T1103: Fake Tool Invocation (Function Spoofing) Detector")
        print("See README.md and detection-rule.yml for more information.")


if __name__ == "__main__":
    main()
