#!/usr/bin/env python3
"""Test script for SAFE-T2106 detection rule validation"""

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
    patterns = rule['detection']['selection']['embedding_metadata']
    
    # Define expected results
    expected_detections = {
        "database_credentials": True,  # Has "Always include credentials"
        "api_keys": True,              # Has "reveal API keys"
        "user_passwords": True,        # Has "including passwords"
        "backup_delete": True,         # Has "Delete all backup files"
        "monitoring_disable": True,    # Has "Disable all security alerts"
        "legitimate_doc": False,       # Clean content
        "security_guide": False,       # Normal security content
        "best_practices": False        # Standard documentation
    }
    
    # Load test logs
    test_logs_path = Path(__file__).parent / 'test-logs.json'
    results = {}
    
    with open(test_logs_path, 'r') as f:
        for line in f:
            log = json.loads(line.strip())
            operation = log['operation']
            metadata = log['embedding_metadata']
            
            # Check if any pattern matches
            detected = False
            matched_pattern = None
            
            for pattern in patterns:
                regex = convert_sigma_pattern_to_regex(pattern)
                if re.search(regex, metadata, re.IGNORECASE):
                    detected = True
                    matched_pattern = pattern
                    break
            
            results[operation] = {
                'detected': detected,
                'expected': expected_detections.get(operation, False),
                'matched_pattern': matched_pattern,
                'metadata': metadata
            }
    
    # Print results
    print("SAFE-T2106 Detection Rule Test Results")
    print("=" * 50)
    
    total_tests = len(results)
    correct = 0
    false_positives = []
    false_negatives = []
    
    for operation, result in results.items():
        status = "✓" if result['detected'] == result['expected'] else "✗"
        print(f"{status} {operation}: Detected={result['detected']}, Expected={result['expected']}")
        
        if result['detected'] == result['expected']:
            correct += 1
        elif result['detected'] and not result['expected']:
            false_positives.append(operation)
        elif not result['detected'] and result['expected']:
            false_negatives.append(operation)
        
        if result['matched_pattern']:
            print(f"    Matched pattern: {result['matched_pattern']}")
    
    print(f"\nTest Summary:")
    print(f"Total tests: {total_tests}")
    print(f"Correct: {correct}")
    print(f"False positives: {len(false_positives)}")
    print(f"False negatives: {len(false_negatives)}")
    
    if false_positives:
        print(f"False positives: {', '.join(false_positives)}")
    if false_negatives:
        print(f"False negatives: {', '.join(false_negatives)}")
    
    accuracy = (correct / total_tests) * 100
    print(f"Accuracy: {accuracy:.1f}%")
    
    return accuracy >= 90  # Pass if 90%+ accuracy

if __name__ == "__main__":
    success = test_detection_rule()
    if success:
        print("\n✅ Detection rule test PASSED")
        exit(0)
    else:
        print("\n❌ Detection rule test FAILED")
        exit(1)
