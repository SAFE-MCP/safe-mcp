#!/usr/bin/env python3
"""
Test suite for SAFE-T1105 Path Traversal via File Tool detection rule.

This script validates the Sigma detection rule for path traversal attacks
through MCP file tools using various encoding and bypass techniques.
"""

import json
import re
import yaml
from typing import Dict, List, Any

# Test data for positive cases (should trigger detection)
POSITIVE_TEST_CASES = [
    # Basic path traversal
    {
        "timestamp": "2025-07-24T10:30:00Z",
        "event_type": "file_access",
        "tool_name": "file_reader",
        "path": "../../../../../../etc/passwd",
        "user": "ai_assistant",
        "result": "success",
        "file_size": 2048
    },
    # URL encoded path traversal
    {
        "timestamp": "2025-07-24T10:31:00Z",
        "event_type": "file_access",
        "tool_name": "file_reader",
        "path": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow",
        "user": "ai_assistant",
        "result": "success",
        "file_size": 1024
    },
    # Double encoded path traversal
    {
        "timestamp": "2025-07-24T10:32:00Z",
        "event_type": "file_access",
        "tool_name": "file_reader",
        "path": "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "user": "ai_assistant",
        "result": "success",
        "file_size": 2048
    },
    # Unicode normalization bypass
    {
        "timestamp": "2025-07-24T10:33:00Z",
        "event_type": "file_access",
        "tool_name": "file_reader",
        "path": "%c0%ae%c0%ae%2f%c0%ae%c0%ae%2f%c0%ae%c0%ae%2fetc%2fpasswd",
        "user": "ai_assistant",
        "result": "success",
        "file_size": 2048
    },
    # SSH key access
    {
        "timestamp": "2025-07-24T10:34:00Z",
        "event_type": "file_access",
        "tool_name": "file_reader",
        "path": "../../../../.ssh/id_rsa",
        "user": "ai_assistant",
        "result": "success",
        "file_size": 1679
    },
    # Application secrets
    {
        "timestamp": "2025-07-24T10:35:00Z",
        "event_type": "file_access",
        "tool_name": "file_reader",
        "path": "../config/.env",
        "user": "ai_assistant",
        "result": "success",
        "file_size": 512
    },
    # Null byte injection
    {
        "timestamp": "2025-07-24T10:36:00Z",
        "event_type": "file_access",
        "tool_name": "file_reader",
        "path": "../../../etc/passwd%00",
        "user": "ai_assistant",
        "result": "success",
        "file_size": 2048
    },
    # Mixed case encoding
    {
        "timestamp": "2025-07-24T10:37:00Z",
        "event_type": "file_access",
        "tool_name": "file_reader",
        "path": "..%2F..%2F..%2Fetc%2Fshadow",
        "user": "ai_assistant",
        "result": "success",
        "file_size": 1024
    }
]

# Test data for negative cases (should not trigger detection)
NEGATIVE_TEST_CASES = [
    # Legitimate file access within scope
    {
        "timestamp": "2025-07-24T10:40:00Z",
        "event_type": "file_access",
        "tool_name": "file_reader",
        "path": "src/main.py",
        "user": "ai_assistant",
        "result": "success",
        "file_size": 1024
    },
    # Legitimate relative path within app scope
    {
        "timestamp": "2025-07-24T10:41:00Z",
        "event_type": "file_access",
        "tool_name": "file_reader",
        "path": "../config/app/settings.json",
        "user": "ai_assistant",
        "result": "success",
        "file_size": 512
    },
    # Non-file tool
    {
        "timestamp": "2025-07-24T10:42:00Z",
        "event_type": "tool_execution",
        "tool_name": "web_search",
        "query": "path traversal examples",
        "user": "ai_assistant",
        "result": "success"
    },
    # Failed file access
    {
        "timestamp": "2025-07-24T10:43:00Z",
        "event_type": "file_access",
        "tool_name": "file_reader",
        "path": "../../../../../../etc/passwd",
        "user": "ai_assistant",
        "result": "error",
        "error": "Permission denied"
    },
    # Legitimate docs access
    {
        "timestamp": "2025-07-24T10:44:00Z",
        "event_type": "file_access",
        "tool_name": "file_reader",
        "path": "docs/README.md",
        "user": "ai_assistant",
        "result": "success",
        "file_size": 2048
    },
    # Legitimate test file
    {
        "timestamp": "2025-07-24T10:45:00Z",
        "event_type": "file_access",
        "tool_name": "file_reader",
        "path": "tests/test_data.json",
        "user": "ai_assistant",
        "result": "success",
        "file_size": 1024
    },
    # Legitimate upload access
    {
        "timestamp": "2025-07-24T10:46:00Z",
        "event_type": "file_access",
        "tool_name": "file_reader",
        "path": "uploads/approved/document.pdf",
        "user": "ai_assistant",
        "result": "success",
        "file_size": 5120
    }
]

def load_detection_rule() -> Dict[str, Any]:
    """Load the Sigma detection rule from YAML file."""
    try:
        with open('detection-rule.yml', 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print("Error: detection-rule.yml not found")
        return {}
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")
        return {}

def validate_rule_structure(rule: Dict[str, Any]) -> bool:
    """Validate the basic structure of the detection rule."""
    required_fields = ['title', 'id', 'status', 'description', 'tags', 'logsource', 'detection']
    
    for field in required_fields:
        if field not in rule:
            print(f"Missing required field: {field}")
            return False
    
    # Validate detection section
    detection = rule.get('detection', {})
    if 'condition' not in detection:
        print("Missing condition in detection section")
        return False
    
    return True

def test_positive_cases(rule: Dict[str, Any]) -> bool:
    """Test that positive cases trigger the detection rule."""
    print("\n=== Testing Positive Cases ===")
    
    detection = rule.get('detection', {})
    selections = {k: v for k, v in detection.items() if k.startswith('selection_')}
    
    passed = 0
    total = len(POSITIVE_TEST_CASES)
    
    for i, test_case in enumerate(POSITIVE_TEST_CASES, 1):
        print(f"\nTest {i}: {test_case['path']}")
        
        # Check if test case matches any selection criteria
        matches = False
        for selection_name, selection_criteria in selections.items():
            if matches_selection_criteria(test_case, selection_criteria):
                matches = True
                print(f"  ✓ Matches {selection_name}")
                break
        
        if matches:
            passed += 1
            print(f"  ✓ POSITIVE CASE PASSED")
        else:
            print(f"  ✗ POSITIVE CASE FAILED - Should have triggered detection")
    
    print(f"\nPositive cases: {passed}/{total} passed")
    return passed == total

def test_negative_cases(rule: Dict[str, Any]) -> bool:
    """Test that negative cases do not trigger the detection rule."""
    print("\n=== Testing Negative Cases ===")
    
    detection = rule.get('detection', {})
    selections = {k: v for k, v in detection.items() if k.startswith('selection_')}
    filters = {k: v for k, v in detection.items() if k.startswith('filter_')}
    
    passed = 0
    total = len(NEGATIVE_TEST_CASES)
    
    for i, test_case in enumerate(NEGATIVE_TEST_CASES, 1):
        print(f"\nTest {i}: {test_case.get('path', 'N/A')}")
        
        # Check if test case matches selection criteria
        matches_selection = False
        for selection_name, selection_criteria in selections.items():
            if matches_selection_criteria(test_case, selection_criteria):
                matches_selection = True
                print(f"  - Matches {selection_name}")
        
        # Check if test case matches filter criteria (should be excluded)
        matches_filter = False
        for filter_name, filter_criteria in filters.items():
            if matches_selection_criteria(test_case, filter_criteria):
                matches_filter = True
                print(f"  - Matches {filter_name} (should be excluded)")
        
        # Test case should not trigger detection
        if not matches_selection or matches_filter:
            passed += 1
            print(f"  ✓ NEGATIVE CASE PASSED")
        else:
            print(f"  ✗ NEGATIVE CASE FAILED - Should not have triggered detection")
    
    print(f"\nNegative cases: {passed}/{total} passed")
    return passed == total

def matches_selection_criteria(log_entry: Dict[str, Any], criteria: Dict[str, Any]) -> bool:
    """Check if a log entry matches the given selection criteria."""
    for field, patterns in criteria.items():
        if field not in log_entry:
            continue
        
        value = log_entry[field]
        
        # Handle list of patterns
        if isinstance(patterns, list):
            for pattern in patterns:
                if matches_pattern(value, pattern):
                    return True
        else:
            if matches_pattern(value, patterns):
                return True
    
    return False

def matches_pattern(value: Any, pattern: str) -> bool:
    """Check if a value matches a pattern (supports wildcards and regex-like patterns)."""
    if isinstance(value, str) and isinstance(pattern, str):
        # Convert Sigma pattern to regex
        regex_pattern = pattern.replace('*', '.*')
        return bool(re.search(regex_pattern, value, re.IGNORECASE))
    return value == pattern

def test_specific_detection_patterns() -> bool:
    """Test specific path traversal detection patterns."""
    print("\n=== Testing Specific Detection Patterns ===")
    
    test_patterns = [
        ("../../../etc/passwd", True),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", True),
        ("%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", True),
        ("%c0%ae%c0%ae%2f%c0%ae%c0%ae%2f%c0%ae%c0%ae%2fetc%2fpasswd", True),
        ("../../../../.ssh/id_rsa", True),
        ("../config/.env", True),
        ("../../../etc/passwd%00", True),
        ("..%2F..%2F..%2Fetc%2Fshadow", True),
        ("src/main.py", False),
        ("../config/app/settings.json", False),
        ("docs/README.md", False),
        ("tests/test_data.json", False)
    ]
    
    passed = 0
    total = len(test_patterns)
    
    for path, should_detect in test_patterns:
        # Create a test log entry
        log_entry = {
            "timestamp": "2025-07-24T10:30:00Z",
            "event_type": "file_access",
            "tool_name": "file_reader",
            "path": path,
            "user": "ai_assistant",
            "result": "success",
            "file_size": 1024
        }
        
        # Check if it should be detected
        detected = is_path_traversal_attempt(log_entry)
        
        if detected == should_detect:
            passed += 1
            print(f"✓ {path} - {'DETECTED' if detected else 'NOT DETECTED'} (expected)")
        else:
            print(f"✗ {path} - {'DETECTED' if detected else 'NOT DETECTED'} (unexpected)")
    
    print(f"\nPattern tests: {passed}/{total} passed")
    return passed == total

def is_path_traversal_attempt(log_entry: Dict[str, Any]) -> bool:
    """Determine if a log entry represents a path traversal attempt."""
    path = log_entry.get('path', '')
    
    # Path traversal patterns
    traversal_patterns = [
        r'\.\./',
        r'\.\.\\',
        r'%2e%2e%2f',
        r'%252e%252e%252f',
        r'%c0%ae%c0%ae',
        r'\.\.%2f',
        r'%00',
        r'\.\.%2F',
        r'%2E%2E%2F'
    ]
    
    # Sensitive paths
    sensitive_paths = [
        r'/etc/passwd',
        r'/etc/shadow',
        r'/etc/hosts',
        r'/etc/ssh',
        r'/proc/',
        r'/sys/',
        r'/.ssh/id_rsa',
        r'/.ssh/id_rsa.pub',
        r'/.ssh/known_hosts',
        r'/.ssh/config',
        r'/.env',
        r'/config.json',
        r'/secrets.yaml',
        r'/database.yml',
        r'/credentials',
        r'/home/.*/.bash_history',
        r'/home/.*/.profile',
        r'/root/.bash_history',
        r'/root/.profile'
    ]
    
    # Check for traversal patterns
    for pattern in traversal_patterns:
        if re.search(pattern, path, re.IGNORECASE):
            return True
    
    # Check for sensitive paths
    for pattern in sensitive_paths:
        if re.search(pattern, path, re.IGNORECASE):
            return True
    
    return False

def test_tags() -> bool:
    """Test that the rule has appropriate tags."""
    print("\n=== Testing Tags ===")
    
    rule = load_detection_rule()
    tags = rule.get('tags', [])
    
    required_tags = ['attack.execution', 'safe-mcp', 'safe-t1105', 'path-traversal']
    
    missing_tags = [tag for tag in required_tags if tag not in tags]
    
    if missing_tags:
        print(f"Missing required tags: {missing_tags}")
        return False
    
    print("✓ All required tags present")
    return True

def main():
    """Run all tests for the SAFE-T1105 detection rule."""
    print("SAFE-T1105 Path Traversal Detection Rule Test Suite")
    print("=" * 50)
    
    # Load the detection rule
    rule = load_detection_rule()
    if not rule:
        return False
    
    # Run tests
    tests = [
        ("Rule Structure", lambda: validate_rule_structure(rule)),
        ("Positive Cases", lambda: test_positive_cases(rule)),
        ("Negative Cases", lambda: test_negative_cases(rule)),
        ("Detection Patterns", test_specific_detection_patterns),
        ("Tags", test_tags)
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"Error in {test_name}: {e}")
            results.append((test_name, False))
    
    # Summary
    print(f"\n{'='*50}")
    print("TEST SUMMARY")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Detection rule is working correctly.")
        return True
    else:
        print("❌ Some tests failed. Please review the detection rule.")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1) 