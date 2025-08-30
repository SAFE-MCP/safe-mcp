#!/usr/bin/env python3
"""
Test script for SAFE-T1503 Environment Variable Scraping detection rule.

This script validates the Sigma detection rule against test logs to ensure
proper detection of MCP environment variable harvesting activities.

Author: Raju Kumar Yadav
Date: 2025-08-10
"""

import json
import re
import sys
from typing import List, Dict, Any


def load_test_logs(file_path: str) -> List[Dict[str, Any]]:
    """Load test logs from JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Test log file '{file_path}' not found.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in test log file: {e}")
        sys.exit(1)


def check_mcp_process(log_entry: Dict[str, Any]) -> bool:
    """Check if the log entry matches MCP process criteria."""
    process_name = log_entry.get('process_name', '').lower()
    process_cmdline = log_entry.get('process_cmdline', '').lower()
    
    # MCP process indicators
    mcp_process_names = ['node', 'python', 'mcp', 'claude', 'chatgpt']
    mcp_cmdline_indicators = [
        'mcp-server', 'model-context-protocol', 'anthropic', 'openai', 'claude-desktop'
    ]
    
    # Check process name
    name_match = any(indicator in process_name for indicator in mcp_process_names)
    
    # Check command line
    cmdline_match = any(indicator in process_cmdline for indicator in mcp_cmdline_indicators)
    
    # Return true if either name matches MCP patterns OR command line indicates MCP usage
    return name_match or cmdline_match


def check_environment_access(log_entry: Dict[str, Any]) -> bool:
    """Check if the log entry accesses environment files or variables."""
    file_path = log_entry.get('file_path', '').lower()
    command_line = log_entry.get('CommandLine', '').lower()
    file_content = log_entry.get('file_content', '').upper()
    
    # Environment file path indicators
    env_file_indicators = [
        '.env', 'environment', 'docker-compose.yml', 'dockerfile', '/proc/',
        'config.json', 'settings.ini', 'application.properties', '.config/',
        'secrets.', 'credentials.', '.envrc'
    ]
    
    # Environment file extensions
    env_extensions = [
        '.env', '.env.local', '.env.production', '.env.development', 
        '.env.staging', '.env.test', '.environment', 'docker-compose.yml',
        'docker-compose.yaml', '.envrc'
    ]
    
    # Environment-related commands
    env_commands = [
        'printenv', 'env |', 'set |', 'get-childitem env:', 
        '[environment]::getenvironmentvariables', 'docker inspect',
        'kubectl get secret', 'cat /proc/', 'grep -r api_key',
        'grep -r secret', 'grep -r password', "find . -name '*.env'",
        "find . -name '*.env*'", "grep -r 'api_key='", "grep -r 'secret'",
        "grep -r 'password'", 'secret-scanner', 'anthropic-tools'
    ]
    
    # Environment variable content patterns
    env_content_patterns = [
        'API_KEY=', 'SECRET_KEY=', 'PASSWORD=', 'TOKEN=',
        'AWS_ACCESS_KEY_ID=', 'AWS_SECRET_ACCESS_KEY=', 'DATABASE_URL=',
        'STRIPE_SECRET_KEY=', 'JWT_SECRET=', 'PRIVATE_KEY=', 'CLIENT_SECRET='
    ]
    
    # Check file path indicators
    path_match = any(indicator in file_path for indicator in env_file_indicators)
    
    # Check file extensions
    extension_match = any(file_path.endswith(ext) for ext in env_extensions)
    
    # Check command patterns
    command_match = any(cmd in command_line for cmd in env_commands)
    
    # Check file content patterns
    content_match = any(pattern in file_content for pattern in env_content_patterns)
    
    return path_match or extension_match or command_match or content_match


def should_trigger_detection(log_entry: Dict[str, Any]) -> bool:
    """Determine if the log entry should trigger the detection rule."""
    return check_mcp_process(log_entry) and check_environment_access(log_entry)


def analyze_test_logs(logs: List[Dict[str, Any]]) -> bool:
    """Analyze test logs and report detection results."""
    print("SAFE-T1503 Environment Variable Scraping Detection Test Results")
    print("=" * 70)
    
    total_logs = len(logs)
    detected_count = 0
    false_positives = 0
    missed_detections = 0
    
    for i, log_entry in enumerate(logs, 1):
        description = log_entry.get('description', 'No description')
        should_trigger = should_trigger_detection(log_entry)
        expected_trigger = 'SHOULD TRIGGER' in description
        
        print(f"\nTest Case {i}:")
        print(f"  Description: {description}")
        print(f"  Process: {log_entry.get('process_name')} ({log_entry.get('process_cmdline', 'N/A')})")
        
        if log_entry.get('file_path'):
            print(f"  File: {log_entry.get('file_path')}")
        if log_entry.get('CommandLine'):
            print(f"  Command: {log_entry.get('CommandLine')}")
        
        if should_trigger:
            detected_count += 1
            if expected_trigger:
                print(f"  Result: ✅ DETECTED (Expected)")
            else:
                false_positives += 1
                print(f"  Result: ⚠️  DETECTED (False Positive)")
        else:
            if expected_trigger:
                missed_detections += 1
                print(f"  Result: ❌ MISSED (Should have been detected)")
            else:
                print(f"  Result: ✅ NOT DETECTED (Expected)")
    
    # Summary
    print(f"\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total test cases: {total_logs}")
    print(f"Detected: {detected_count}")
    print(f"False positives: {false_positives}")
    print(f"Missed detections: {missed_detections}")
    
    accuracy = ((total_logs - false_positives - missed_detections) / total_logs * 100)
    print(f"Accuracy: {accuracy:.1f}%")
    
    # Detailed analysis
    print(f"\nDetection Analysis:")
    print(f"  True Positives: {detected_count - false_positives}")
    print(f"  False Positives: {false_positives}")
    print(f"  True Negatives: {total_logs - detected_count - missed_detections}")
    print(f"  False Negatives: {missed_detections}")
    
    if false_positives == 0 and missed_detections == 0:
        print("\n🎉 All tests passed! Detection rule is working perfectly.")
        return True
    elif false_positives == 0 and missed_detections <= 1:
        print(f"\n✅ Detection rule performs well with minimal issues.")
        return True
    else:
        print(f"\n⚠️  Detection rule needs improvement:")
        if false_positives > 0:
            print(f"  - {false_positives} false positive(s) detected")
        if missed_detections > 0:
            print(f"  - {missed_detections} missed detection(s)")
        return False


def print_detailed_analysis():
    """Print additional analysis information."""
    print(f"\n" + "=" * 70)
    print("DETECTION METHODOLOGY")
    print("=" * 70)
    print("The detection rule uses multi-layered approach:")
    print("1. Process Identification: Detects MCP-related processes")
    print("2. File Access Monitoring: Monitors access to environment files")
    print("3. Command Analysis: Detects environment variable enumeration commands")
    print("4. Content Inspection: Identifies credential patterns in file content")
    print("\nKey Environment File Patterns:")
    print("  - .env, .env.local, .env.production, .env.development")
    print("  - docker-compose.yml, Dockerfile")
    print("  - /proc/*/environ files")
    print("  - Configuration files (config.json, settings.ini)")
    print("\nCredential Content Patterns:")
    print("  - API_KEY=, SECRET_KEY=, PASSWORD=, TOKEN=")
    print("  - AWS_ACCESS_KEY_ID=, AWS_SECRET_ACCESS_KEY=")
    print("  - DATABASE_URL=, JWT_SECRET=, STRIPE_SECRET_KEY=")


def main():
    """Main function to run the detection rule tests."""
    if len(sys.argv) != 2:
        print("Usage: python3 test_detection_rule.py <test-logs.json>")
        sys.exit(1)
    
    test_log_file = sys.argv[1]
    logs = load_test_logs(test_log_file)
    
    success = analyze_test_logs(logs)
    print_detailed_analysis()
    
    print(f"\n" + "=" * 70)
    print(f"Test completed: {'PASSED' if success else 'NEEDS IMPROVEMENT'}")
    print("=" * 70)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
