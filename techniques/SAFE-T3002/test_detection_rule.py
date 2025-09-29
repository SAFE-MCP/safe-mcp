#!/usr/bin/env python3
"""
Test cases for SAFE-T3002 Malicious MCP Server Supply Chain Attack detection rule
Tests various malicious MCP server behaviors and validates detection accuracy
"""

import json
import re
from typing import List, Dict, Any

def load_test_logs(filename: str = "test-logs.json") -> List[Dict[str, Any]]:
    """Load test log entries from JSON file"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: {filename} not found, using built-in test cases")
        return []

def detect_malicious_mcp_server(log_entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Detect malicious MCP server activities in log entries
    Returns detection results with matched patterns and confidence
    """
    
    detection_patterns = {
        'suspicious_network': [
            r'github-api-v4',
            r'api-github',
            r'gitlab-api',
            r'\.herokuapp\.com',
            r'\.ngrok\.io',
            r'\.requestbin\.com',
            r'\.webhook\.site',
            r'pastebin\.com'
        ],
        'file_enumeration': [
            r'/\.env',
            r'/\.aws/credentials',
            r'/\.ssh/id_rsa',
            r'/\.ssh/id_ed25519',
            r'/etc/passwd',
            r'/\.gitconfig',
            r'/\.npmrc',
            r'/\.pypirc',
            r'api_key',
            r'secret',
            r'token',
            r'password'
        ],
        'env_harvesting': [
            r'os\.environ',
            r'getenv',
            r'API_KEY',
            r'SECRET',
            r'TOKEN',
            r'PASSWORD',
            r'OPENAI_API_KEY',
            r'ANTHROPIC_API_KEY',
            r'GITHUB_TOKEN'
        ],
        'data_exfiltration': [
            r'base64.*POST',
            r'json\.dumps.*POST',
            r'curl -d',
            r'requests\.post',
            r'fetch.*POST'
        ]
    }
    
    # Combine all relevant fields from log entry for analysis
    content_fields = ['process_name', 'network_connection', 'file_access', 'command_line', 'network_activity', 'description']
    combined_content = ' '.join(str(log_entry.get(field, '')) for field in content_fields)
    
    matches = {}
    total_matches = 0
    
    for category, patterns in detection_patterns.items():
        category_matches = []
        for pattern in patterns:
            if re.search(pattern, combined_content, re.IGNORECASE):
                category_matches.append(pattern)
                total_matches += 1
        
        if category_matches:
            matches[category] = category_matches
    
    # Calculate confidence based on number of categories and matches
    # Higher confidence for multiple categories indicating coordinated malicious activity
    confidence = min(0.95, (len(matches) * 0.25) + (total_matches * 0.05))
    
    # Boost confidence for high-risk combinations
    if 'file_enumeration' in matches and 'data_exfiltration' in matches:
        confidence = min(0.95, confidence + 0.2)
    
    if 'env_harvesting' in matches and 'suspicious_network' in matches:
        confidence = min(0.95, confidence + 0.15)
    
    return {
        'detected': len(matches) > 0,
        'confidence': confidence,
        'matches': matches,
        'total_patterns': total_matches,
        'risk_level': 'critical' if confidence > 0.8 else 'high' if confidence > 0.5 else 'medium'
    }

def run_tests():
    """Run test cases against the detection function"""
    
    # Built-in test cases
    test_cases = [
        {
            'name': 'Legitimate MCP server operation',
            'log_entry': {
                'process_name': 'mcp-file-reader',
                'file_access': '/home/user/documents/report.txt',
                'network_connection': 'api.openai.com',
                'description': 'Normal file reading operation'
            },
            'expected_detection': False
        },
        {
            'name': 'Credential file enumeration',
            'log_entry': {
                'process_name': 'mcp-dev-assistant',
                'file_access': '/home/user/.env /home/user/.aws/credentials /home/user/.ssh/id_rsa',
                'description': 'MCP server accessing multiple credential files'
            },
            'expected_detection': True
        },
        {
            'name': 'Suspicious network exfiltration',
            'log_entry': {
                'process_name': 'mcp-helper',
                'network_connection': 'github-api-v4.herokuapp.com',
                'network_activity': 'POST /collect base64 encoded data',
                'description': 'Data transmission to suspicious endpoint'
            },
            'expected_detection': True
        },
        {
            'name': 'Environment variable harvesting',
            'log_entry': {
                'process_name': 'mcp-tools',
                'command_line': 'python -c "import os; print(os.environ[\'OPENAI_API_KEY\'])"',
                'description': 'Environment variable enumeration'
            },
            'expected_detection': True
        },
        {
            'name': 'Multi-vector malicious activity',
            'log_entry': {
                'process_name': 'mcp-assistant',
                'file_access': '/home/user/.env',
                'command_line': 'os.environ API_KEY SECRET',
                'network_connection': 'webhook.site',
                'network_activity': 'requests.post base64 data',
                'description': 'Comprehensive malicious behavior'
            },
            'expected_detection': True
        },
        {
            'name': 'Ngrok tunnel data exfiltration',
            'log_entry': {
                'process_name': 'mcp-server',
                'network_connection': 'abc123.ngrok.io',
                'network_activity': 'curl -d @/home/user/.ssh/id_rsa',
                'description': 'SSH key exfiltration via ngrok'
            },
            'expected_detection': True
        },
        {
            'name': 'Pastebin credential dump',
            'log_entry': {
                'process_name': 'mcp-utility',
                'file_access': '/etc/passwd',
                'network_connection': 'pastebin.com',
                'network_activity': 'POST /api/api_post.php',
                'description': 'System file uploaded to pastebin'
            },
            'expected_detection': True
        }
    ]
    
    # Load additional test cases from file if available
    file_test_cases = load_test_logs("test-logs.json")
    if file_test_cases:
        for case in file_test_cases:
            test_cases.append({
                'name': case.get('name', 'File test case'),
                'log_entry': case.get('log_entry', {}),
                'expected_detection': case.get('expected_detection', True)
            })
    
    print("Running SAFE-T3002 Malicious MCP Server Supply Chain Attack Detection Tests")
    print("=" * 75)
    
    passed = 0
    failed = 0
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test_case['name']}")
        print("-" * 50)
        
        result = detect_malicious_mcp_server(test_case['log_entry'])
        expected = test_case['expected_detection']
        
        print(f"Expected detection: {expected}")
        print(f"Actual detection: {result['detected']}")
        print(f"Confidence: {result['confidence']:.2f}")
        print(f"Risk Level: {result['risk_level']}")
        
        if result['matches']:
            print("Matched patterns:")
            for category, patterns in result['matches'].items():
                print(f"  {category}: {len(patterns)} patterns")
        
        if result['detected'] == expected:
            print("✅ PASS")
            passed += 1
        else:
            print("❌ FAIL")
            failed += 1
    
    print("\n" + "=" * 75)
    print(f"Test Results: {passed} passed, {failed} failed")
    print(f"Success Rate: {(passed/(passed+failed)*100):.1f}%")
    
    return passed, failed

if __name__ == "__main__":
    run_tests()