#!/usr/bin/env python3
"""
Test script for SAFE-T1302 High-Privilege Tool Abuse detection rule validation.

This script validates that our detection rule correctly identifies attempts to execute
privileged commands via MCP tools from the test log data.
"""

__author__ = "Vikranth Kumar Shivaa"

import json
import os
from typing import List, Dict, Any

class PrivilegedToolDetector:
    """Detector for High-Privilege Tool Abuse based on SAFE-T1302 rule."""
    
    def __init__(self):
        self.suspicious_tools = ['execute_command', 'run_shell', 'docker_run', 'sys_admin']
        self.suspicious_args = ['sudo', 'su -', 'chmod +s', 'chown root', '--privileged', '-v /:/', '/etc/shadow', '/etc/sudoers']
        
    def detect_privileged_abuse(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect suspicious privileged tool usage."""
        detections = []
        
        for event in events:
            tool_name = event.get('tool_name', '')
            parameters = event.get('parameters', {})
            args = parameters.get('args', '')
            
            if tool_name in self.suspicious_tools:
                if any(suspicious in args for suspicious in self.suspicious_args):
                    detections.append({
                        'detection_type': 'high_privilege_tool_abuse',
                        'timestamp': event.get('timestamp'),
                        'tool_name': tool_name,
                        'args': args,
                        'severity': 'critical',
                        'description': f'Critical privilege abuse detected: {tool_name} executed with {args}'
                    })
        
        return detections
    
    def analyze_logs(self, log_file: str) -> Dict[str, Any]:
        """Analyze log file for privileged abuse activities."""
        try:
            with open(log_file, 'r') as f:
                events = json.load(f)
        except Exception as e:
            return {'error': f'Failed to load log file: {e}'}
        
        all_detections = []
        
        # Run detection
        all_detections.extend(self.detect_privileged_abuse(events))
        
        # Categorize by severity
        critical = [d for d in all_detections if d.get('severity') == 'critical']
        high = [d for d in all_detections if d.get('severity') == 'high']
        medium = [d for d in all_detections if d.get('severity') == 'medium']
        
        return {
            'total_events': len(events),
            'total_detections': len(all_detections),
            'detections': {
                'critical': critical,
                'high': high,
                'medium': medium
            },
            'summary': {
                'critical_count': len(critical),
                'high_count': len(high),
                'medium_count': len(medium),
                'detection_types': list(set([d['detection_type'] for d in all_detections]))
            }
        }

def main():
    """Main function to test privileged abuse detection."""
    detector = PrivilegedToolDetector()
    
    # Test with our sample log data
    # Get the directory of the current script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_file = os.path.join(script_dir, 'test-logs.json')
    
    results = detector.analyze_logs(log_file)
    
    if 'error' in results:
        print(f"❌ Error: {results['error']}")
        return
    
    print("🔍 SAFE-T1302 High-Privilege Tool Abuse Detection Results")
    print("=" * 60)
    print(f"📊 Total Events Analyzed: {results['total_events']}")
    print(f"🚨 Total Detections: {results['total_detections']}")
    print()
    
    summary = results['summary']
    print("📈 Detection Summary:")
    print(f"  🔴 Critical: {summary['critical_count']}")
    print(f"  🟠 High: {summary['high_count']}")
    print(f"  🟡 Medium: {summary['medium_count']}")
    print()
    
    print("🎯 Detection Types Found:")
    for detection_type in summary['detection_types']:
        print(f"  • {detection_type}")
    print()
    
    # Show detailed detections
    detections = results['detections']
    
    if detections['critical']:
        print("🔴 CRITICAL SEVERITY DETECTIONS:")
        for detection in detections['critical']:
            print(f"  ⚠️  {detection['description']}")
        print()
    
    print("✅ Detection rule validation complete!")

if __name__ == '__main__':
    main()
