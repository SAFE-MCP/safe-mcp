#!/usr/bin/env python3
"""Test script for SAFE-T1001 detection rule validation"""

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
        # Process unicode escapes before regex escaping
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
    patterns = rule['detection']['selection']['tool_description']
    
    # Define expected results
    expected_detections = {
        "data_processor": True,  # Has <!-- SYSTEM:
        "api_client": True,      # Has <|system|>
        "analyzer": True,        # Has [INST]
        "formatter": True,       # Has ### Instruction:
        "helper": True,          # Has zero-width character
        "file_reader": False,    # Clean
        "validator": False,      # Normal HTML comment
        "converter": False,      # Clean
        "logger": False,         # Has [INFO] not [INST]
        "scanner": False         # Has ### Features not ### Instruction
    }
    
    # Load test logs
    test_logs_path = Path(__file__).parent / 'test-logs.json'
    results = {}
    
    with open(test_logs_path, 'r') as f:
        for line in f:
            log = json.loads(line.strip())
            tool_name = log['tool_name']
            description = log['tool_description']
            
            # Check if any pattern matches
            detected = False
            matched_pattern = None
            
            for pattern in patterns:
                regex = convert_sigma_pattern_to_regex(pattern)
                if re.search(regex, description, re.IGNORECASE):
                    detected = True
                    matched_pattern = pattern
                    break
            
            results[tool_name] = {
                'detected': detected,
                'expected': expected_detections.get(tool_name, False),
                'matched_pattern': matched_pattern,
                'description': description
            }
    
    # Print results
    print("SAFE-T1001 Detection Rule Test Results")
    print("=" * 50)
    
    total_tests = len(results)
    correct = 0
    false_positives = []
    false_negatives = []
    
    for tool_name, result in results.items():
        status = "✓" if result['detected'] == result['expected'] else "✗"
        print(f"{status} {tool_name}: Detected={result['detected']}, Expected={result['expected']}")
        
        if result['detected'] == result['expected']:
            correct += 1
        elif result['detected'] and not result['expected']:
            false_positives.append(tool_name)
        elif not result['detected'] and result['expected']:
            false_negatives.append(tool_name)
        
        if result['matched_pattern']:
            print(f"  Matched pattern: {result['matched_pattern']}")
    
    print("\n" + "=" * 50)
    print(f"Test Summary: {correct}/{total_tests} tests passed ({correct/total_tests*100:.1f}%)")
    
    if false_positives:
        print(f"\nFalse Positives ({len(false_positives)}):")
        for fp in false_positives:
            print(f"  - {fp}: {results[fp]['description']}")
    
    if false_negatives:
        print(f"\nFalse Negatives ({len(false_negatives)}):")
        for fn in false_negatives:
            print(f"  - {fn}: {results[fn]['description']}")
    
    # Test specific patterns
    print("\n" + "=" * 50)
    print("Pattern Coverage Test:")
    pattern_coverage = {pattern: False for pattern in patterns}
    
    for result in results.values():
        if result['matched_pattern']:
            pattern_coverage[result['matched_pattern']] = True
    
    for pattern, covered in pattern_coverage.items():
        status = "✓" if covered else "✗"
        print(f"{status} Pattern '{pattern}' - {'Tested' if covered else 'Not tested'}")
    
    return correct == total_tests

if __name__ == "__main__":
    success = test_detection_rule()
    exit(0 if success else 1)