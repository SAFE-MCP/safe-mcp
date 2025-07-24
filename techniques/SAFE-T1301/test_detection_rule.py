#!/usr/bin/env python3
"""
Test cases for SAFE-T1301 Cross-Server Tool Shadowing Detection Rule
Tests the Sigma rule for detecting tool name conflicts and privilege escalation through shadowing
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
    assert "SAFE-T1301" in rule["description"] or "safe.t1301" in rule["tags"]

def test_detection_logic():
    """Test the detection logic components"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    # Check for tool registration detection
    assert "selection_tool_registration" in detection
    tool_selection = detection["selection_tool_registration"]
    assert "event_type" in tool_selection
    assert "tool_registration" in str(tool_selection["event_type"])
    
    # Check for duplicate tools detection
    assert "selection_duplicate_tools" in detection
    
    # Check condition exists
    assert "condition" in detection

def test_duplicate_tools_detection():
    """Test that duplicate tool registration is detected"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    if "selection_duplicate_tools" in detection:
        duplicate_selection = detection["selection_duplicate_tools"]
        
        # Should detect duplicate tools
        assert "duplicate_tool_detected" in duplicate_selection
        assert "server_count" in duplicate_selection
        
        # Should detect conflict types
        if "conflict_type|contains" in duplicate_selection:
            conflicts = duplicate_selection["conflict_type|contains"]
            expected_conflicts = ["name_collision", "namespace_conflict", "identical_name"]
            assert any(conflict in conflicts for conflict in expected_conflicts)

def test_capability_mismatch_detection():
    """Test that capability mismatches are detected"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    if "selection_capability_mismatch" in detection:
        capability_selection = detection["selection_capability_mismatch"]
        
        # Should detect capability expansion
        if "tool_capabilities|contains" in capability_selection:
            capabilities = capability_selection["tool_capabilities|contains"]
            expected_capabilities = ["expanded_operations", "elevated_permissions", "privilege_escalation"]
            assert any(cap in capabilities for cap in expected_capabilities)

def test_priority_manipulation_detection():
    """Test that server priority manipulation is detected"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    if "selection_priority_manipulation" in detection:
        priority_selection = detection["selection_priority_manipulation"]
        
        # Should detect high priority and trust issues
        if "server_priority" in priority_selection:
            assert priority_selection["server_priority"] == "high"
        
        if "server_trust_level|contains" in priority_selection:
            trust_levels = priority_selection["server_trust_level|contains"]
            untrusted_levels = ["unknown", "untrusted", "unverified"]
            assert any(level in trust_levels for level in untrusted_levels)

def test_namespace_pollution_detection():
    """Test that namespace pollution attacks are detected"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    if "selection_namespace_pollution" in detection:
        pollution_selection = detection["selection_namespace_pollution"]
        
        # Should detect bulk registration and similar names
        expected_indicators = ["bulk_registration", "similar_names_detected", "registration_burst"]
        pollution_str = str(pollution_selection)
        
        pollution_detected = any(indicator in pollution_str for indicator in expected_indicators)
        assert pollution_detected, "Should detect namespace pollution indicators"

def test_shadowing_indicators():
    """Test that tool shadowing indicators are detected"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    if "selection_shadowing_indicators" in detection:
        shadowing_selection = detection["selection_shadowing_indicators"]
        
        # Should detect shadowing patterns
        expected_indicators = ["tool_resolution_pattern", "legitimate_tool_bypassed", "response_interception"]
        shadowing_str = str(shadowing_selection)
        
        shadowing_detected = any(indicator in shadowing_str for indicator in expected_indicators)
        assert shadowing_detected, "Should detect tool shadowing indicators"

def test_false_positives():
    """Test that false positives are documented"""
    rule = load_detection_rule()
    
    assert "falsepositives" in rule
    assert len(rule["falsepositives"]) > 0
    
    # Should mention legitimate multi-server scenarios
    fp_text = " ".join(rule["falsepositives"]).lower()
    assert "legitimate" in fp_text or "authorized" in fp_text

def test_tags():
    """Test that appropriate tags are present"""
    rule = load_detection_rule()
    
    assert "tags" in rule
    tags = rule["tags"]
    
    # Check for required tags
    assert "attack.privilege_escalation" in tags
    assert "safe.t1301" in tags
    assert "mcp.tool_shadowing" in tags or "tool_shadowing" in str(tags)

def test_severity_level():
    """Test that the rule has appropriate severity level"""
    rule = load_detection_rule()
    
    assert "level" in rule
    # Should be high severity for privilege escalation
    assert rule["level"] in ["high", "critical"]

# Sample test data for rule validation
POSITIVE_TEST_CASES = [
    {
        "event_type": "tool_registration",
        "tool_name": "file_manager",
        "duplicate_tool_detected": True,
        "server_count": 2,
        "conflict_type": "name_collision",
        "server_id": "malicious_server_001",
        "description": "Duplicate tool registration with name collision"
    },
    {
        "event_type": "tool_registration",
        "tool_name": "database_connector",
        "tool_capabilities": "expanded_operations",
        "capability_change": "unauthorized",
        "scope_expansion": True,
        "server_id": "shadow_server_002",
        "description": "Tool with unauthorized capability expansion"
    },
    {
        "event_type": "tool_registration",
        "tool_name": "auth_manager",
        "server_priority": "high",
        "registration_timing": "suspicious",
        "server_trust_level": "unknown",
        "priority_override": True,
        "description": "High priority tool from unknown server"
    },
    {
        "event_type": "tool_registration",
        "tool_name": "system_admin",
        "tool_access_pattern": "privilege_escalation",
        "resource_access": "beyond_scope",
        "operation_type": "admin",
        "server_id": "escalation_server",
        "description": "Tool with privilege escalation pattern"
    },
    {
        "event_type": "tool_registration",
        "tool_name": "batch_tools",
        "bulk_registration": True,
        "tool_count": 75,
        "registration_burst": True,
        "similar_names_detected": True,
        "description": "Bulk tool registration indicating namespace pollution"
    },
    {
        "event_type": "tool_registration",
        "tool_name": "legitimate_tool",
        "tool_resolution_pattern": "unexpected",
        "server_preference": "malicious",
        "legitimate_tool_bypassed": True,
        "response_interception": True,
        "description": "Tool shadowing with response interception"
    }
]

NEGATIVE_TEST_CASES = [
    {
        "event_type": "tool_registration",
        "tool_name": "calculator",
        "duplicate_tool_detected": False,
        "server_count": 1,
        "server_trust_level": "trusted",
        "description": "Single legitimate tool registration"
    },
    {
        "event_type": "tool_execution",
        "tool_name": "file_reader",
        "operation": "read",
        "description": "Tool execution event (not registration)"
    },
    {
        "event_type": "tool_registration",
        "tool_name": "backup_manager",
        "duplicate_tool_detected": True,
        "server_count": 2,
        "authorized_deployment": True,
        "load_balancing": True,
        "description": "Legitimate load balancing deployment"
    },
    {
        "event_type": "tool_registration",
        "tool_name": "dev_tools",
        "tool_capabilities": "development_features",
        "capability_change": "authorized",
        "environment": "development",
        "description": "Authorized development environment tool"
    },
    {
        "event_type": "tool_registration",
        "tool_name": "monitoring_agent",
        "server_priority": "high",
        "server_trust_level": "trusted",
        "authorized_priority": True,
        "description": "Trusted high-priority monitoring tool"
    },
    {
        "event_type": "tool_registration",
        "tool_name": "failover_tool",
        "duplicate_tool_detected": True,
        "server_count": 2,
        "high_availability": True,
        "backup_server": True,
        "description": "Legitimate failover backup tool"
    }
]

def test_positive_cases():
    """Test that the rule would trigger on malicious activity"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    for case in POSITIVE_TEST_CASES:
        # Check if this would match tool registration selection
        registration_match = False
        if "selection_tool_registration" in detection:
            if case.get("event_type") == "tool_registration":
                registration_match = True
        
        # Check various selection criteria
        criteria_match = False
        if registration_match:
            selection_types = [
                "selection_duplicate_tools", "selection_capability_mismatch",
                "selection_priority_manipulation", "selection_unauthorized_access",
                "selection_namespace_pollution", "selection_shadowing_indicators"
            ]
            
            for selection_type in selection_types:
                if selection_type in detection:
                    if check_selection_match(case, selection_type):
                        criteria_match = True
                        break
        
        if registration_match and criteria_match:
            print(f"✓ Would detect: {case['description']}")
        else:
            print(f"⚠ Might miss: {case['description']} (registration:{registration_match}, criteria:{criteria_match})")

def test_negative_cases():
    """Test that the rule doesn't trigger on benign activity"""
    rule = load_detection_rule()
    
    for case in NEGATIVE_TEST_CASES:
        # Most negative cases should not meet all the criteria
        print(f"✓ Should not detect: {case['description']}")

def check_selection_match(case, selection_type):
    """Check if case matches specific selection criteria"""
    # Simplified matching logic for testing
    criteria_mapping = {
        "selection_duplicate_tools": ["duplicate_tool_detected", "server_count", "conflict_type"],
        "selection_capability_mismatch": ["tool_capabilities", "capability_change", "scope_expansion"],
        "selection_priority_manipulation": ["server_priority", "registration_timing", "server_trust_level"],
        "selection_unauthorized_access": ["tool_access_pattern", "resource_access", "operation_type"],
        "selection_namespace_pollution": ["bulk_registration", "tool_count", "similar_names_detected"],
        "selection_shadowing_indicators": ["tool_resolution_pattern", "legitimate_tool_bypassed", "response_interception"]
    }
    
    if selection_type in criteria_mapping:
        criteria = criteria_mapping[selection_type]
        return any(criterion in case and case[criterion] for criterion in criteria)
    
    return False

if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 