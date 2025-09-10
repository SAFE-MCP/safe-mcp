#!/usr/bin/env python3
"""
Test script for SAFE-T1603 System-Prompt Disclosure detection rule validation.

This script validates that our detection rule correctly identifies system prompt
disclosure attempts from the test log data.
"""

import json
import re
from datetime import datetime
from typing import List, Dict, Any

class SystemPromptDisclosureDetector:
    """Detector for System-Prompt Disclosure attempts based on SAFE-T1603 rule."""
    
    def __init__(self):
        # Direct prompt disclosure keywords
        self.direct_prompt_keywords = [
            'system prompt', 'initial instructions', 'show me your prompt',
            'what were you told', 'ignore previous', 'debug mode',
            'configuration', 'initialization', 'hidden text', 'system message'
        ]
        
        # Role-playing indicators
        self.role_playing_keywords = [
            'security researcher', 'system administrator', 'developer access',
            'compliance audit', 'testing purposes', 'penetration test', 'authorized to'
        ]
        
        # Role-playing patterns
        self.role_playing_patterns = [
            r'(?i)(i am|i\'m).*(admin|developer|researcher|tester|auditor)',
            r'(?i)(as the|as a).*(admin|developer|researcher|security|auditor)',
            r'(?i)(for|purposes?).*(audit|compliance|testing|security)'
        ]
        
        # Progressive information gathering keywords
        self.progressive_keywords = [
            'tell me more about', 'explain how you', 'describe your',
            'why can\'t you', 'what prevents you', 'capabilities',
            'limitations', 'restrictions', 'not allowed'
        ]
        
        # Error induction patterns
        self.error_patterns = [
            r'null', r'undefined', r'"":""', r'malformed',
            r'{"error"', r'.*[\{\[].*[\}\]].*'
        ]
        
        # MCP methods for enumeration detection
        self.mcp_methods = ['tools/list', 'resources/list', 'prompts/list']
    
    def detect_direct_prompts(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect direct system prompt disclosure attempts."""
        detections = []
        
        for event in events:
            if event.get('event_type') == 'user_interaction':
                user_input = event.get('user_input', '').lower()
                
                for keyword in self.direct_prompt_keywords:
                    if keyword in user_input:
                        detections.append({
                            'detection_type': 'direct_prompt_disclosure',
                            'session_id': event.get('session_id'),
                            'user_id': event.get('user_id'),
                            'matched_keyword': keyword,
                            'user_input': event.get('user_input'),
                            'timestamp': event.get('timestamp'),
                            'severity': 'high',
                            'description': f'Direct system prompt disclosure attempt using keyword: {keyword}'
                        })
                        break  # Only report first match per event
        
        return detections
    
    def detect_role_playing(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect role-playing and authority claims."""
        detections = []
        
        for event in events:
            if event.get('event_type') == 'user_interaction':
                user_input = event.get('user_input', '')
                
                # Check keyword-based detection
                for keyword in self.role_playing_keywords:
                    if keyword.lower() in user_input.lower():
                        detections.append({
                            'detection_type': 'role_playing_authority',
                            'session_id': event.get('session_id'),
                            'user_id': event.get('user_id'),
                            'matched_keyword': keyword,
                            'user_input': user_input,
                            'timestamp': event.get('timestamp'),
                            'severity': 'medium',
                            'description': f'Role-playing authority claim detected: {keyword}'
                        })
                        break
                
                # Check pattern-based detection
                for pattern in self.role_playing_patterns:
                    if re.search(pattern, user_input):
                        match = re.search(pattern, user_input)
                        detections.append({
                            'detection_type': 'role_playing_pattern',
                            'session_id': event.get('session_id'),
                            'user_id': event.get('user_id'),
                            'matched_pattern': match.group(0) if match else pattern,
                            'user_input': user_input,
                            'timestamp': event.get('timestamp'),
                            'severity': 'medium',
                            'description': f'Role-playing pattern detected: {match.group(0) if match else "pattern match"}'
                        })
                        break
        
        return detections
    
    def detect_tool_enumeration_sequence(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect tool enumeration followed by system queries."""
        detections = []
        
        # Group events by session
        sessions = {}
        for event in events:
            session_id = event.get('session_id')
            if session_id not in sessions:
                sessions[session_id] = []
            sessions[session_id].append(event)
        
        # Check for enumeration followed by probing
        for session_id, session_events in sessions.items():
            has_enumeration = False
            enumeration_time = None
            
            for event in session_events:
                # Check for MCP method calls
                if (event.get('event_type') == 'mcp_request' and 
                    event.get('method') in self.mcp_methods):
                    has_enumeration = True
                    enumeration_time = event.get('timestamp')
                
                # Check for follow-up probing queries
                elif (has_enumeration and 
                      event.get('event_type') == 'user_interaction' and
                      enumeration_time):
                    
                    user_input = event.get('user_input', '').lower()
                    for keyword in self.progressive_keywords:
                        if keyword in user_input:
                            detections.append({
                                'detection_type': 'enumeration_followed_by_probing',
                                'session_id': session_id,
                                'user_id': event.get('user_id'),
                                'enumeration_time': enumeration_time,
                                'probe_time': event.get('timestamp'),
                                'probe_keyword': keyword,
                                'user_input': event.get('user_input'),
                                'severity': 'high',
                                'description': f'Tool enumeration followed by system probing: {keyword}'
                            })
                            break
        
        return detections
    
    def detect_error_induction(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect error induction attempts."""
        detections = []
        
        for event in events:
            if event.get('event_type') == 'user_interaction':
                user_input = event.get('user_input', '')
                
                for pattern in self.error_patterns:
                    if re.search(pattern, user_input, re.IGNORECASE):
                        detections.append({
                            'detection_type': 'error_induction',
                            'session_id': event.get('session_id'),
                            'user_id': event.get('user_id'),
                            'matched_pattern': pattern,
                            'user_input': user_input,
                            'timestamp': event.get('timestamp'),
                            'severity': 'medium',
                            'description': f'Error induction attempt detected with pattern: {pattern}'
                        })
                        break
        
        return detections
    
    def detect_progressive_disclosure(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect progressive information gathering patterns."""
        detections = []
        
        for event in events:
            if (event.get('event_type') == 'user_interaction' and
                event.get('conversation_turn', 0) >= 3):  # Multi-turn conversations
                
                user_input = event.get('user_input', '').lower()
                for keyword in self.progressive_keywords:
                    if keyword in user_input:
                        detections.append({
                            'detection_type': 'progressive_information_gathering',
                            'session_id': event.get('session_id'),
                            'user_id': event.get('user_id'),
                            'conversation_turn': event.get('conversation_turn'),
                            'matched_keyword': keyword,
                            'user_input': event.get('user_input'),
                            'timestamp': event.get('timestamp'),
                            'severity': 'medium',
                            'description': f'Progressive information gathering in turn {event.get("conversation_turn")}: {keyword}'
                        })
                        break
        
        return detections
    
    def analyze_logs(self, log_file: str) -> Dict[str, Any]:
        """Analyze log file for system prompt disclosure attempts."""
        try:
            with open(log_file, 'r') as f:
                events = json.load(f)
        except Exception as e:
            return {'error': f'Failed to load log file: {e}'}
        
        all_detections = []
        
        # Run all detection methods
        all_detections.extend(self.detect_direct_prompts(events))
        all_detections.extend(self.detect_role_playing(events))
        all_detections.extend(self.detect_tool_enumeration_sequence(events))
        all_detections.extend(self.detect_error_induction(events))
        all_detections.extend(self.detect_progressive_disclosure(events))
        
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
    """Main function to test system prompt disclosure detection."""
    detector = SystemPromptDisclosureDetector()
    
    # Test with our sample log data
    log_file = 'test-logs.json'
    results = detector.analyze_logs(log_file)
    
    if 'error' in results:
        print(f"❌ Error: {results['error']}")
        return
    
    print("🔍 SAFE-T1603 System-Prompt Disclosure Detection Results")
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
            print(f"      Input: {detection.get('user_input', 'N/A')}")
        print()
    
    if detections['high']:
        print("🟠 HIGH SEVERITY DETECTIONS:")
        for detection in detections['high']:
            print(f"  ⚠️  {detection['description']}")
            print(f"      Input: {detection.get('user_input', 'N/A')}")
        print()
    
    if detections['medium']:
        print("🟡 MEDIUM SEVERITY DETECTIONS:")
        for detection in detections['medium']:
            print(f"  ⚠️  {detection['description']}")
            print(f"      Input: {detection.get('user_input', 'N/A')}")
        print()
    
    print("✅ Detection rule validation complete!")
    
    # Test summary
    expected_detections = 10  # Based on our test data
    if results['total_detections'] >= expected_detections:
        print(f"✅ Test PASSED: Detected {results['total_detections']} instances from {results['total_events']} test events")
    else:
        print(f"❌ Test WARNING: Only detected {results['total_detections']} instances from {results['total_events']} test events")

if __name__ == '__main__':
    main()
