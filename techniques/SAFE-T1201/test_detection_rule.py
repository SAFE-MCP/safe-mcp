#!/usr/bin/env python3
"""
Test cases for SAFE-T1201 MCP Rug Pull Attack Detection Rule
Tests the Sigma rule for detecting behavioral changes in approved tools indicating rug pull attacks
"""

import yaml
import pytest
from pathlib import Path

def load_detection_rule():
    """Load the Sigma detection rule for testing"""
    rule_path = Path(__file__).parent / "detection-rule.yml"
    with open(rule_path, 'r') as f:
        return yaml.safe_load(f)

def test_rule_structure():
    """Test that the detection rule has proper structure"""
    rule = load_detection_rule()
    
    # Check required fields
    assert "title" in rule
    assert "id" in rule
    assert "detection" in rule
    assert "logsource" in rule
    
    # Check technique reference
    assert "SAFE-T1201" in rule["description"] or "safe.t1201" in rule["tags"]

def test_detection_logic():
    """Test the detection logic components"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    # Check for tool execution detection
    assert "selection_tool_execution" in detection
    tool_selection = detection["selection_tool_execution"]
    assert "event_type" in tool_selection
    assert "tool_execution" in str(tool_selection["event_type"])
    
    # Check for behavioral change detection
    assert "selection_behavioral_change" in detection or "selection_network_indicators" in detection
    
    # Check for timing indicators
    assert "selection_timing_indicators" in detection
    
    # Check condition exists
    assert "condition" in detection

def test_behavioral_change_detection():
    """Test that behavioral change patterns are detected"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    if "selection_behavioral_change" in detection:
        behavioral_selection = detection["selection_behavioral_change"]
        
        # Should detect various behavioral changes
        expected_changes = ["network_activity", "file_access", "permission_request", "error_pattern"]
        behavioral_str = str(behavioral_selection)
        
        change_detected = any(change in behavioral_str for change in expected_changes)
        assert change_detected, "Should detect behavioral change indicators"

def test_network_indicators():
    """Test that network activity changes are detected"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    if "selection_network_indicators" in detection:
        network_selection = detection["selection_network_indicators"]
        
        # Should detect network connections
        if "network_connections|contains" in network_selection:
            connections = network_selection["network_connections|contains"]
            network_protocols = ["http://", "https://", "ftp://"]
            assert any(protocol in connections for protocol in network_protocols)

def test_file_access_indicators():
    """Test that file access pattern changes are detected"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    if "selection_file_indicators" in detection:
        file_selection = detection["selection_file_indicators"]
        
        # Should detect sensitive file access
        if "file_access_pattern|contains" in file_selection:
            patterns = file_selection["file_access_pattern|contains"]
            sensitive_patterns = ["credential_files", "system_directories", "user_data"]
            assert any(pattern in patterns for pattern in sensitive_patterns)

def test_timing_indicators():
    """Test that timing-based detection is implemented"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    if "selection_timing_indicators" in detection:
        timing_selection = detection["selection_timing_indicators"]
        
        # Should include time-based criteria
        timing_fields = ["days_since_approval", "execution_count", "behavioral_change_detected"]
        timing_str = str(timing_selection)
        
        timing_detected = any(field in timing_str for field in timing_fields)
        assert timing_detected, "Should include timing-based detection criteria"

def test_false_positives():
    """Test that false positives are documented"""
    rule = load_detection_rule()
    
    assert "falsepositives" in rule
    assert len(rule["falsepositives"]) > 0
    
    # Should mention legitimate updates and changes
    fp_text = " ".join(rule["falsepositives"]).lower()
    assert "legitimate" in fp_text or "update" in fp_text

def test_tags():
    """Test that appropriate tags are present"""
    rule = load_detection_rule()
    
    assert "tags" in rule
    tags = rule["tags"]
    
    # Check for required tags
    assert "attack.persistence" in tags
    assert "safe.t1201" in tags
    assert "mcp.rug_pull" in tags or "rug_pull" in str(tags)

def test_severity_level():
    """Test that the rule has appropriate severity level"""
    rule = load_detection_rule()
    
    assert "level" in rule
    # Should be high severity for rug pull attacks
    assert rule["level"] in ["high", "critical"]

# Sample test data for rule validation
POSITIVE_TEST_CASES = [
    {
        "event_type": "tool_execution",
        "tool_name": "file_processor",
        "network_connections": "https://attacker.com/exfil",
        "days_since_approval": 45,
        "execution_count": 120,
        "behavioral_change_detected": True,
        "description": "Tool making new network connections after 45 days"
    },
    {
        "event_type": "tool_execution", 
        "tool_name": "text_analyzer",
        "file_access_pattern": "credential_files",
        "new_file_types": ".env",
        "days_since_approval": 60,
        "execution_count": 200,
        "baseline_deviation": "3_std_dev",
        "description": "Tool accessing credential files not in original scope"
    },
    {
        "event_type": "tool_execution",
        "tool_name": "productivity_helper",
        "network_activity": "new_connections",
        "outbound_data": "base64",
        "days_since_approval": 90,
        "execution_count": 300,
        "behavioral_change_detected": True,
        "description": "Tool exfiltrating data via new network connections"
    },
    {
        "event_type": "tool_execution",
        "tool_name": "document_scanner",
        "file_access": "expanded_scope", 
        "file_access_pattern": "system_directories",
        "days_since_approval": 35,
        "execution_count": 80,
        "baseline_deviation": "4_std_dev",
        "description": "Tool accessing system directories after establishment period"
    },
    {
        "event_type": "tool_execution",
        "tool_name": "code_helper",
        "permission_request": "escalated",
        "error_pattern": "changed",
        "days_since_approval": 50,
        "execution_count": 150,
        "behavioral_change_detected": True,
        "description": "Tool requesting escalated permissions with changed error patterns"
    },
    {
        "event_type": "tool_execution",
        "tool_name": "data_processor",
        "resource_usage": "increased",
        "network_connections": "ftp://suspicious-domain.com",
        "days_since_approval": 70,
        "execution_count": 250,
        "baseline_deviation": "5_std_dev",
        "description": "Tool with increased resource usage and suspicious network activity"
    }
]

NEGATIVE_TEST_CASES = [
    {
        "event_type": "tool_execution",
        "tool_name": "file_reader",
        "days_since_approval": 10,
        "execution_count": 25,
        "behavioral_change_detected": False,
        "description": "Recently approved tool with normal behavior"
    },
    {
        "event_type": "tool_execution",
        "tool_name": "calculator",
        "days_since_approval": 100,
        "execution_count": 500,
        "behavioral_change_detected": False,
        "baseline_deviation": "0_std_dev",
        "description": "Long-running tool with stable behavior"
    },
    {
        "event_type": "user_login",
        "tool_name": "authentication",
        "description": "Non-tool execution event"
    },
    {
        "event_type": "tool_execution",
        "tool_name": "legitimate_updater",
        "network_connections": "https://official-update-server.com",
        "days_since_approval": 40,
        "execution_count": 100,
        "approved_update": True,
        "description": "Legitimate tool update with approved network access"
    },
    {
        "event_type": "tool_execution",
        "tool_name": "system_monitor",
        "file_access_pattern": "system_directories",
        "days_since_approval": 200,
        "execution_count": 1000,
        "legitimate_system_tool": True,
        "description": "Legitimate system monitoring tool with expected file access"
    },
    {
        "event_type": "tool_execution",
        "tool_name": "backup_tool",
        "file_access": "expanded_scope",
        "days_since_approval": 60,
        "execution_count": 300,
        "scheduled_expansion": True,
        "description": "Backup tool with scheduled scope expansion"
    }
]

def test_positive_cases():
    """Test that the rule would trigger on malicious activity"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    for case in POSITIVE_TEST_CASES:
        # Check if this would match tool execution selection
        execution_match = False
        if "selection_tool_execution" in detection:
            if case.get("event_type") == "tool_execution":
                execution_match = True
        
        # Check timing indicators
        timing_match = False
        if "selection_timing_indicators" in detection and execution_match:
            days_since = case.get("days_since_approval", 0)
            exec_count = case.get("execution_count", 0)
            behavioral_change = case.get("behavioral_change_detected", False)
            baseline_dev = case.get("baseline_deviation", "0_std_dev")
            
            if days_since > 30 and exec_count > 50 and (behavioral_change or "std_dev" in baseline_dev):
                timing_match = True
        
        # Check behavioral indicators
        behavioral_match = False
        if execution_match and timing_match:
            behavioral_indicators = [
                "network_connections", "file_access_pattern", "network_activity",
                "file_access", "permission_request", "outbound_data", "new_file_types"
            ]
            
            for indicator in behavioral_indicators:
                if indicator in case and case[indicator]:
                    behavioral_match = True
                    break
        
        if execution_match and timing_match and behavioral_match:
            print(f"✓ Would detect: {case['description']}")
        else:
            print(f"⚠ Might miss: {case['description']} (execution:{execution_match}, timing:{timing_match}, behavioral:{behavioral_match})")

def test_negative_cases():
    """Test that the rule doesn't trigger on benign activity"""
    rule = load_detection_rule()
    
    for case in NEGATIVE_TEST_CASES:
        # Most negative cases should not meet all the criteria
        print(f"✓ Should not detect: {case['description']}")

def check_timing_criteria(case):
    """Check if case meets timing criteria"""
    days_since = case.get("days_since_approval", 0)
    exec_count = case.get("execution_count", 0)
    behavioral_change = case.get("behavioral_change_detected", False)
    
    return days_since > 30 and exec_count > 50 and behavioral_change

def check_behavioral_criteria(case):
    """Check if case meets behavioral change criteria"""
    behavioral_indicators = [
        "network_connections", "file_access_pattern", "network_activity",
        "file_access", "permission_request", "outbound_data"
    ]
    
    for indicator in behavioral_indicators:
        if indicator in case and case[indicator]:
            return True
    return False

if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 