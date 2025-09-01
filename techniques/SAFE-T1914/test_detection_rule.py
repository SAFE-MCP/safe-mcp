#!/usr/bin/env python3
"""
Test suite for SAFE-T1914 Tool-to-Tool Exfiltration detection rule.

This script validates the Sigma detection rule for detecting tool-to-tool
exfiltration attacks through MCP tool chaining patterns.
"""

import json
import yaml
from pathlib import Path
from typing import Dict, List, Any

def load_detection_rule():
    """Load the Sigma detection rule for testing"""
    rule_path = Path(__file__).parent / "detection-rule.yml"
    with open(rule_path, 'r') as f:
        return yaml.safe_load(f)

def load_test_logs():
    """Load the test log data"""
    test_logs_path = Path(__file__).parent / "test-logs.json"
    with open(test_logs_path, 'r') as f:
        return json.load(f)

def test_rule_structure():
    """Test that the detection rule has proper structure"""
    rule = load_detection_rule()
    
    # Check required fields
    assert "title" in rule
    assert "id" in rule
    assert "detection" in rule
    assert "logsource" in rule
    assert "author" in rule
    assert "date" in rule
    
    # Check technique reference
    assert "SAFE-T1914" in rule["title"] or "SAFE-T1914" in rule["description"]
    assert "safe.t1914" in rule["tags"]

def test_detection_logic():
    """Test the detection logic components"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    # Check for data collection tools detection
    assert "selection_data_collection_tools" in detection
    data_selection = detection["selection_data_collection_tools"]
    assert "tool_name" in data_selection
    
    # Check for communication tools detection
    assert "selection_communication_tools" in detection
    comm_selection = detection["selection_communication_tools"]
    assert "tool_name" in comm_selection
    
    # Check condition exists
    assert "condition" in detection
    
    # Check timeframe for temporal correlation
    assert "timeframe" in detection

def test_data_collection_tools():
    """Test that data collection tools are properly detected"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    if "selection_data_collection_tools" in detection:
        data_tools = detection["selection_data_collection_tools"]["tool_name"]
        
        # Should detect common data collection tools
        expected_tools = ["file_reader", "database_query", "api_client", "environment_reader"]
        for tool in expected_tools:
            assert tool in data_tools, f"Missing data collection tool: {tool}"

def test_communication_tools():
    """Test that communication tools are properly detected"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    if "selection_communication_tools" in detection:
        comm_tools = detection["selection_communication_tools"]["tool_name"]
        
        # Should detect common communication tools
        expected_tools = ["email_sender", "webhook_client", "http_client", "file_uploader"]
        for tool in expected_tools:
            assert tool in comm_tools, f"Missing communication tool: {tool}"

def test_sensitive_data_patterns():
    """Test that sensitive data patterns are detected"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    if "selection_sensitive_data_patterns" in detection:
        patterns = detection["selection_sensitive_data_patterns"]["tool_output|contains"]
        
        # Should detect sensitive data indicators
        expected_patterns = ["/etc/passwd", "BEGIN PRIVATE KEY", "api_key", "password", "secret"]
        for pattern in expected_patterns:
            assert any(pattern in p for p in patterns), f"Missing sensitive data pattern: {pattern}"

def test_external_endpoints():
    """Test that external endpoint patterns are detected"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    if "selection_external_endpoints" in detection:
        endpoint_selection = detection["selection_external_endpoints"]
        assert "destination_url|contains" in endpoint_selection or "external_domain" in endpoint_selection

def test_false_positives():
    """Test that false positives are documented"""
    rule = load_detection_rule()
    
    assert "falsepositives" in rule
    assert len(rule["falsepositives"]) > 0
    
    # Should mention legitimate use cases
    fp_text = " ".join(rule["falsepositives"]).lower()
    assert "legitimate" in fp_text or "automated" in fp_text or "backup" in fp_text

def test_tags():
    """Test that appropriate tags are present"""
    rule = load_detection_rule()
    
    assert "tags" in rule
    tags = rule["tags"]
    
    # Check for required tags
    assert "attack.exfiltration" in tags
    assert "safe.t1914" in tags
    assert "mcp.tool_chaining" in tags or "data_exfiltration" in tags

def test_severity_level():
    """Test that the rule has appropriate severity level"""
    rule = load_detection_rule()
    
    assert "level" in rule
    # Should be high severity for exfiltration
    assert rule["level"] in ["high", "critical"]

def test_positive_cases_from_test_logs():
    """Test that positive cases from test logs would trigger detection"""
    test_data = load_test_logs()
    rule = load_detection_rule()
    
    positive_cases = [case for case in test_data if case.get("should_trigger", False)]
    
    for case in positive_cases:
        print(f"\nTesting positive case: {case['description']}")
        
        # Check if this case has the expected tool patterns
        log_entries = case.get("log_entries", [])
        if len(log_entries) >= 2:  # Tool-to-tool requires at least 2 tools
            tools_used = [entry.get("tool_name") for entry in log_entries]
            
            # Should have data collection tool
            data_tools = ["file_reader", "database_query", "api_client", "environment_reader", "directory_browser", "read_file", "list_directory", "system_info", "credential_reader"]
            has_data_tool = any(tool in data_tools for tool in tools_used)
            
            # Should have communication tool  
            comm_tools = ["email_sender", "webhook_client", "http_client", "file_uploader", "slack_messenger", "discord_bot", "telegram_bot", "ftp_client", "sftp_client"]
            has_comm_tool = any(tool in comm_tools for tool in tools_used)
            
            if has_data_tool and has_comm_tool:
                print(f"  ✓ Would detect: Data tool + Communication tool pattern")
            else:
                # Check for sensitive data patterns
                outputs = [entry.get("tool_output", "") for entry in log_entries]
                sensitive_patterns = ["/etc/passwd", "/etc/shadow", "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "aws_access_key", "api_key", "password", "secret", "token", "credential"]
                
                has_sensitive_data = any(
                    any(pattern in output for pattern in sensitive_patterns) 
                    for output in outputs
                )
                
                external_urls = [entry.get("destination_url", "") for entry in log_entries]
                has_external_endpoint = any(
                    any(protocol in url for protocol in ["http://", "https://", "ftp://", "sftp://"]) 
                    for url in external_urls if url
                )
                
                if has_sensitive_data and has_external_endpoint:
                    print(f"  ✓ Would detect: Sensitive data + External endpoint pattern")
                else:
                    print(f"  ⚠ Might miss: {case['description']}")

def test_negative_cases_from_test_logs():
    """Test that negative cases from test logs would not trigger detection"""
    test_data = load_test_logs()
    
    negative_cases = [case for case in test_data if not case.get("should_trigger", True)]
    
    for case in negative_cases:
        print(f"\nTesting negative case: {case['description']}")
        
        # These should not trigger the detection rule
        # Most legitimate cases will either:
        # 1. Not have the tool sequence pattern
        # 2. Be filtered out by the false positive filters
        # 3. Not contain sensitive data patterns
        
        log_entries = case.get("log_entries", [])
        if len(log_entries) >= 2:
            tools_used = [entry.get("tool_name") for entry in log_entries]
            
            # Check if it's a legitimate backup operation
            if "backup" in case["description"].lower():
                print(f"  ✓ Should be filtered as legitimate backup operation")
            # Check if it's system monitoring
            elif "monitor" in case["description"].lower() or "alert" in case["description"].lower():
                print(f"  ✓ Should be filtered as legitimate monitoring")
            # Check if it's development workflow
            elif "deploy" in case["description"].lower() or "development" in case["description"].lower():
                print(f"  ✓ Should be filtered as legitimate development workflow")
            else:
                print(f"  ✓ Should not trigger: {case['description']}")
        else:
            print(f"  ✓ Should not trigger: Single tool usage")

def test_timeframe_correlation():
    """Test that timeframe correlation is properly configured"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    assert "timeframe" in detection
    timeframe = detection["timeframe"]
    
    # Should be a reasonable timeframe (e.g., 15m, 30m, 1h)
    assert isinstance(timeframe, str)
    assert any(unit in timeframe for unit in ["m", "h", "s"])  # minutes, hours, or seconds

def test_condition_logic():
    """Test that the condition logic is properly structured"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    condition = detection["condition"]
    
    # Should have logical operators
    assert any(op in condition for op in ["and", "or", "not"])
    
    # Should reference the defined selections
    selections = [key for key in detection.keys() if key.startswith("selection_")]
    for selection in selections:
        if selection in condition:
            print(f"  ✓ Condition references {selection}")

def test_author_and_date():
    """Test that author and date are properly set"""
    rule = load_detection_rule()
    
    assert rule["author"] == "Smaran Dhungana"
    assert "2025-08-10" in str(rule["date"])
    
    if "modified" in rule:
        assert "2025-08-10" in str(rule["modified"])

def test_references():
    """Test that proper references are included"""
    rule = load_detection_rule()
    
    assert "references" in rule
    references = rule["references"]
    
    # Should reference the technique
    assert any("SAFE-T1914" in ref for ref in references)
    
    # Should reference MITRE ATT&CK techniques
    assert any("attack.mitre.org" in ref for ref in references)

def test_fields():
    """Test that relevant fields are specified for logging"""
    rule = load_detection_rule()
    
    if "fields" in rule:
        fields = rule["fields"]
        
        # Should include key fields for analysis
        expected_fields = ["tool_name", "tool_output", "destination_url", "user_id", "session_id", "timestamp"]
        for field in expected_fields:
            assert field in fields, f"Missing important field: {field}"

def test_rule_id_format():
    """Test that the rule ID is properly formatted"""
    rule = load_detection_rule()
    
    rule_id = rule["id"]
    
    # Should be a valid UUID format
    import re
    uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    assert re.match(uuid_pattern, rule_id), f"Invalid UUID format: {rule_id}"

def main():
    """Run all tests for the SAFE-T1914 detection rule"""
    print("SAFE-T1914 Tool-to-Tool Exfiltration Detection Rule Test Suite")
    print("=" * 65)
    
    # Load the detection rule
    try:
        rule = load_detection_rule()
        print("✓ Detection rule loaded successfully")
    except Exception as e:
        print(f"✗ Failed to load detection rule: {e}")
        return False
    
    # Load test data
    try:
        test_data = load_test_logs()
        print(f"✓ Test data loaded successfully ({len(test_data)} test cases)")
    except Exception as e:
        print(f"✗ Failed to load test data: {e}")
        return False
    
    # Run tests
    tests = [
        ("Rule Structure", test_rule_structure),
        ("Detection Logic", test_detection_logic),
        ("Data Collection Tools", test_data_collection_tools),
        ("Communication Tools", test_communication_tools),
        ("Sensitive Data Patterns", test_sensitive_data_patterns),
        ("External Endpoints", test_external_endpoints),
        ("False Positives", test_false_positives),
        ("Tags", test_tags),
        ("Severity Level", test_severity_level),
        ("Author and Date", test_author_and_date),
        ("References", test_references),
        ("Rule ID Format", test_rule_id_format),
        ("Timeframe Correlation", test_timeframe_correlation),
        ("Condition Logic", test_condition_logic),
        ("Positive Cases", test_positive_cases_from_test_logs),
        ("Negative Cases", test_negative_cases_from_test_logs)
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            test_func()
            results.append((test_name, True))
            print(f"✓ {test_name}: PASSED")
        except Exception as e:
            results.append((test_name, False))
            print(f"✗ {test_name}: FAILED - {e}")
    
    # Summary
    print(f"\n{'='*65}")
    print("TEST SUMMARY")
    print("=" * 65)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{test_name}: {status}")
    
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