#!/usr/bin/env python3
"""Test script for SAFE-T1007 detection rule validation"""

import json
import re
import yaml
from pathlib import Path

def load_sigma_rule(rule_path):
    """Load and parse Sigma rule"""
    with open(rule_path, 'r') as f:
        return yaml.safe_load(f)

def convert_sigma_pattern_to_regex(pattern):
    """Convert Sigma wildcard pattern to regex"""
    # Handle unicode escape sequences
    if '\\u' in pattern:
        try:
            pattern = pattern.encode().decode('unicode-escape')
        except:
            pass
    
    # Escape special regex characters except *
    pattern = re.escape(pattern)
    # Replace escaped \* with .*
    pattern = pattern.replace(r'\*', '.*')
    return pattern

def test_detection_rule():
    """Test the detection rule against known samples"""
    # Load rule
    rule_path = Path(__file__).parent / 'detection-rule.yml'
    rule = load_sigma_rule(rule_path)
    
    # Extract patterns
    detection = rule.get('detection', {})
    selection = detection.get('selection', {})
    
    # Find the field with patterns
    patterns = []
    for key, value in selection.items():
        if isinstance(value, list):
            patterns = value
            break
        elif isinstance(value, dict) and 'contains' in key:
            patterns = list(value.values())[0] if value else []
            break
    
    if not patterns:
        print("Warning: No patterns found in detection rule")
        return False
    
    # Load test logs
    test_logs_path = Path(__file__).parent / 'test-logs.json'
    if not test_logs_path.exists():
        print("Warning: test-logs.json not found")
        return False
    
    results = {}
    
    with open(test_logs_path, 'r') as f:
        for line in f:
            if not line.strip():
                continue
            log = json.loads(line.strip())
            tool_name = log.get('tool_name', 'unknown')
            description = log.get('tool_description', '')
            
            # Check if any pattern matches
            detected = False
            matched_pattern = None
            
            for pattern in patterns:
                regex = convert_sigma_pattern_to_regex(pattern)
                if re.search(regex, description, re.IGNORECASE) or re.search(regex, tool_name, re.IGNORECASE):
                    detected = True
                    matched_pattern = pattern
                    break
            
            results[tool_name] = {
                'detected': detected,
                'matched_pattern': matched_pattern,
                'description': description
            }
    
    # Print results
    print(f"SAFE-T1007 Detection Rule Test Results")
    print("=" * 50)
    
    total_tests = len(results)
    detected_count = sum(1 for r in results.values() if r['detected'])
    
    for tool_name, result in results.items():
        status = "✓" if result['detected'] else "✗"
        print(f"{status} {tool_name}: Detected={result['detected']}")
        if result['matched_pattern']:
            print(f"  Matched pattern: {result['matched_pattern']}")
    
    print("\n" + "=" * 50)
    print(f"Test Summary: {detected_count}/{total_tests} tools detected")
    
    return True

if __name__ == "__main__":
    success = test_detection_rule()
    exit(0 if success else 1)
