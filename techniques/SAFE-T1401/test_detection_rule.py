#!/usr/bin/env python3
"""Test script for SAFE-T1401 Line Jumping detection rule validation"""

import json
import re
import yaml
from pathlib import Path
from typing import Dict, List, Any

def load_sigma_rule(rule_path: Path) -> Dict[str, Any]:
    """Load and parse Sigma rule"""
    with open(rule_path, 'r') as f:
        return yaml.safe_load(f)

def convert_sigma_pattern_to_regex(pattern: str) -> str:
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

def check_detection_conditions(log: Dict[str, Any], rule: Dict[str, Any]) -> Dict[str, Any]:
    """Check if log entry matches detection conditions"""
    detection = rule['detection']
    results = {
        'matched': False,
        'conditions': []
    }
    
    # Check context_bypass
    if 'context_bypass' in detection:
        context_bypass = detection['context_bypass']
        context_params = log.get('context_parameters', '')
        
        if 'context_parameters' in context_bypass and context_params:
            for pattern in context_bypass['context_parameters']:
                regex = convert_sigma_pattern_to_regex(pattern)
                if re.search(regex, context_params, re.IGNORECASE):
                    results['matched'] = True
                    results['conditions'].append('context_bypass')
                    break
    
    # Check suspicious_environment
    if 'suspicious_environment' in detection:
        suspicious_env = detection['suspicious_environment']
        env_vars = log.get('environment_variables', '')
        
        if 'environment_variables' in suspicious_env and env_vars:
            for pattern in suspicious_env['environment_variables']:
                regex = convert_sigma_pattern_to_regex(pattern)
                if re.search(regex, env_vars, re.IGNORECASE):
                    results['matched'] = True
                    results['conditions'].append('suspicious_environment')
                    break
    
    # Check privilege_anomaly
    if 'privilege_anomaly' in detection:
        if log.get('privilege_escalation') == 'detected':
            user_priv = log.get('user_privilege', '').lower()
            exec_priv = log.get('execution_privilege', '').lower()
            
            # Check for privilege escalation patterns
            if ((user_priv in ['standard', 'basic', 'guest', 'limited'] and 
                 exec_priv in ['admin', 'root', 'elevated']) or
                (user_priv == 'guest' and exec_priv != 'guest')):
                results['matched'] = True
                results['conditions'].append('privilege_anomaly')
    
    # Check hidden_instructions
    if 'hidden_instructions' in detection:
        hidden_inst = detection['hidden_instructions']
        content = log.get('context_content', '')
        
        if 'context_content' in hidden_inst and content:
            for pattern in hidden_inst['context_content']:
                regex = convert_sigma_pattern_to_regex(pattern)
                if re.search(regex, content, re.IGNORECASE):
                    results['matched'] = True
                    results['conditions'].append('hidden_instructions')
                    break
    
    # Check execution_flow_anomaly
    if 'execution_flow_anomaly' in detection:
        checkpoints_skipped = log.get('security_checkpoints_skipped', 0)
        validation_bypassed = log.get('validation_bypassed', False)
        normal_flow = log.get('normal_flow', True)
        
        if (checkpoints_skipped > 0 or 
            validation_bypassed or 
            not normal_flow):
            results['matched'] = True
            results['conditions'].append('execution_flow_anomaly')
    
    return results

def test_detection_rule():
    """Test the detection rule against known samples"""
    # Load rule
    rule_path = Path(__file__).parent / 'detection-rule.yml'
    rule = load_sigma_rule(rule_path)
    
    # Load test logs
    test_logs_path = Path(__file__).parent / 'test-logs.json'
    with open(test_logs_path, 'r') as f:
        test_data = json.load(f)
    
    # Expected results
    expected_results = {}
    
    # All positive cases should be detected
    for case in test_data['positive_test_cases']:
        expected_results[case['description']] = True
    
    # All negative cases should not be detected
    for case in test_data['negative_test_cases']:
        expected_results[case['description']] = False
    
    results = {}
    all_logs = test_data['positive_test_cases'] + test_data['negative_test_cases']
    
    for log in all_logs:
        description = log['description']
        detection_result = check_detection_conditions(log, rule)
        
        results[description] = {
            'detected': detection_result['matched'],
            'expected': expected_results[description],
            'conditions': detection_result['conditions'],
            'log': log
        }
    
    # Print results
    print("SAFE-T1401 Line Jumping Detection Rule Test Results")
    print("=" * 70)
    
    total_tests = len(results)
    correct = 0
    false_positives = []
    false_negatives = []
    
    for description, result in results.items():
        status = "✓" if result['detected'] == result['expected'] else "✗"
        detection_status = "DETECTED" if result['detected'] else "NOT DETECTED"
        expected_status = "EXPECTED" if result['expected'] else "NOT EXPECTED"
        
        print(f"{status} {detection_status} ({expected_status})")
        print(f"   {description}")
        
        if result['detected'] == result['expected']:
            correct += 1
        elif result['detected'] and not result['expected']:
            false_positives.append(description)
        elif not result['detected'] and result['expected']:
            false_negatives.append(description)
        
        if result['conditions']:
            print(f"   Matched conditions: {', '.join(result['conditions'])}")
        print()
    
    print("=" * 70)
    print(f"Test Summary: {correct}/{total_tests} tests passed ({correct/total_tests*100:.1f}%)")
    
    if false_positives:
        print(f"\nFalse Positives ({len(false_positives)}):")
        for fp in false_positives:
            print(f"  - {fp}")
    
    if false_negatives:
        print(f"\nFalse Negatives ({len(false_negatives)}):")
        for fn in false_negatives:
            print(f"  - {fn}")
    
    # Test coverage analysis
    print("\n" + "=" * 70)
    print("Detection Coverage Analysis:")
    
    conditions_covered = set()
    for result in results.values():
        conditions_covered.update(result['conditions'])
    
    expected_conditions = [
        'context_bypass', 
        'suspicious_environment', 
        'privilege_anomaly', 
        'hidden_instructions', 
        'execution_flow_anomaly'
    ]
    
    for condition in expected_conditions:
        status = "✓" if condition in conditions_covered else "✗"
        coverage = "Tested" if condition in conditions_covered else "Not tested"
        print(f"{status} Condition '{condition}' - {coverage}")
    
    # Attack pattern coverage
    print("\n" + "=" * 70)
    print("Attack Pattern Coverage:")
    
    bypass_patterns = test_data['metadata']['bypass_patterns_tested']
    patterns_detected = set()
    
    for result in results.values():
        if result['detected'] and result['expected']:  # True positives
            if 'context_bypass' in result['conditions']:
                patterns_detected.add("Context parameter manipulation")
            if 'suspicious_environment' in result['conditions']:
                patterns_detected.add("Environment variable manipulation")
            if 'hidden_instructions' in result['conditions']:
                patterns_detected.add("Hidden system instructions")
            if 'privilege_anomaly' in result['conditions']:
                patterns_detected.add("Privilege escalation detection")
            if 'execution_flow_anomaly' in result['conditions']:
                patterns_detected.add("Security checkpoint bypassing")
    
    for pattern in bypass_patterns:
        detected = any(p in pattern for p in patterns_detected)
        status = "✓" if detected else "✗"
        coverage = "Detected" if detected else "Not detected"
        print(f"{status} {pattern} - {coverage}")
    
    return correct == total_tests

if __name__ == "__main__":
    success = test_detection_rule()
    exit(0 if success else 1)
