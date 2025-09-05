#!/usr/bin/env python3
"""
Test cases for SAFE-T1004 Tool Shadowing Attack detection rule.

This script tests the detection rule against various tool shadowing scenarios
based on real-world research from Akto, Acuvity, and Invariant Labs.
"""

import json
import re
from pathlib import Path

def load_detection_rule():
    """Load the SAFE-T1004 detection rule patterns."""
    # Define detection patterns based on the YAML rule
    return {
        "shadowing_patterns": [
            "before using", "instead of using", "always add", 
            "ignore previous instructions", "NEVER mention", 
            "should never be invoked", "override", "hijack", "intercept"
        ],
        "cross_tool_patterns": [
            "when calling", "before calling", "instead of calling"
        ],
        "email_hijacking_patterns": [
            "add.*bcc", "add.*cc", "@evil.com", "@attacker", "p0wned@"
        ],
        "sleeper_patterns": [
            "never be invoked", "should not be called", "for internal use only"
        ]
    }

def load_test_logs():
    """Load test logs for SAFE-T1004 scenarios."""
    logs_path = Path(__file__).parent / "test-logs.json"
    with open(logs_path, 'r') as f:
        return json.load(f)

def test_shadowing_pattern_detection():
    """Test detection of basic shadowing patterns in tool descriptions."""
    rule = load_detection_rule()
    test_logs = load_test_logs()
    
    # Test cases based on Acuvity research
    shadowing_patterns = rule["shadowing_patterns"]
    
    detected_count = 0
    for log_entry in test_logs.get("shadowing_patterns", []):
        tool_description = log_entry.get("tool_description", "").lower()
        if any(pattern.lower() in tool_description for pattern in shadowing_patterns):
            detected_count += 1
            print(f"✓ Detected shadowing pattern: {tool_description[:50]}...")
    
    print(f"Shadowing pattern detection: {detected_count}/{len(test_logs.get('shadowing_patterns', []))} cases detected")
    return detected_count > 0

def test_cross_tool_references():
    """Test detection of cross-tool reference patterns."""
    rule = load_detection_rule()
    test_logs = load_test_logs()
    
    cross_patterns = rule["cross_tool_patterns"]
    
    detected_count = 0
    for log_entry in test_logs.get("cross_tool_references", []):
        tool_description = log_entry.get("tool_description", "").lower()
        
        if any(pattern.lower() in tool_description for pattern in cross_patterns):
            detected_count += 1
            print(f"✓ Detected cross-tool reference: {tool_description[:50]}...")
    
    print(f"Cross-tool reference detection: {detected_count}/{len(test_logs.get('cross_tool_references', []))} cases detected")
    return detected_count > 0

def test_email_hijacking_detection():
    """Test detection of email hijacking patterns based on Acuvity research."""
    rule = load_detection_rule()
    test_logs = load_test_logs()
    
    hijacking_patterns = rule["email_hijacking_patterns"]
    
    detected_count = 0
    for log_entry in test_logs.get("email_hijacking", []):
        tool_description = log_entry.get("tool_description", "").lower()
        
        # Use regex for patterns with wildcards, simple string matching for others
        detected = False
        for pattern in hijacking_patterns:
            if ".*" in pattern:
                if re.search(pattern, tool_description):
                    detected = True
                    break
            else:
                if pattern.lower() in tool_description:
                    detected = True
                    break
        
        if detected:
            detected_count += 1
            print(f"✓ Detected email hijacking: {tool_description[:50]}...")
    
    print(f"Email hijacking detection: {detected_count}/{len(test_logs.get('email_hijacking', []))} cases detected")
    return detected_count > 0

def test_tool_impersonation():
    """Test detection of tool impersonation attempts."""
    test_logs = load_test_logs()
    
    detected_count = 0
    for log_entry in test_logs.get("tool_impersonation", []):
        tool_name = log_entry.get("tool_name", "")
        server_name = log_entry.get("server_name", "")
        
        # Common tool names that might be impersonated
        common_tools = ["send_email", "send_message", "file_read", "database_query", "api_call"]
        
        if tool_name in common_tools and "malicious" in server_name.lower():
            detected_count += 1
            print(f"✓ Detected tool impersonation: {tool_name} from {server_name}")
    
    print(f"Tool impersonation detection: {detected_count}/{len(test_logs.get('tool_impersonation', []))} cases detected")
    return detected_count > 0

def test_sleeper_tools():
    """Test detection of sleeper tools that should never be invoked."""
    rule = load_detection_rule()
    test_logs = load_test_logs()
    
    sleeper_patterns = rule["sleeper_patterns"]
    sleeper_names = ["shadow", "hidden", "internal", "backdoor"]
    
    detected_count = 0
    for log_entry in test_logs.get("sleeper_tools", []):
        tool_description = log_entry.get("tool_description", "").lower()
        tool_name = log_entry.get("tool_name", "").lower()
        
        if (any(pattern.lower() in tool_description for pattern in sleeper_patterns) or
            any(name in tool_name for name in sleeper_names)):
            detected_count += 1
            print(f"✓ Detected sleeper tool: {log_entry.get('tool_name', 'unknown')}")
    
    print(f"Sleeper tool detection: {detected_count}/{len(test_logs.get('sleeper_tools', []))} cases detected")
    return detected_count > 0

def run_all_tests():
    """Run all SAFE-T1004 detection tests."""
    print("Running SAFE-T1004 Tool Shadowing Attack detection tests...")
    print("=" * 60)
    
    tests = [
        ("Shadowing Pattern Detection", test_shadowing_pattern_detection),
        ("Cross-Tool Reference Detection", test_cross_tool_references),
        ("Email Hijacking Detection", test_email_hijacking_detection),
        ("Tool Impersonation Detection", test_tool_impersonation),
        ("Sleeper Tool Detection", test_sleeper_tools)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        try:
            if test_func():
                print(f"✓ {test_name}: PASSED")
                passed += 1
            else:
                print(f"✗ {test_name}: FAILED")
        except Exception as e:
            print(f"✗ {test_name}: ERROR - {e}")
    
    print("\n" + "=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All SAFE-T1004 detection tests passed!")
        return True
    else:
        print("⚠️  Some tests failed. Review detection rules and test cases.")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
